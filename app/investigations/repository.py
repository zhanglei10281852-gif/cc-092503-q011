from __future__ import annotations

import json
import sqlite3
from typing import Any

from app.core.errors import ConflictError, NotFoundError

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}

CLOSED_STATUSES = ("closed", "dismissed")


def row_dict(row: sqlite3.Row | None, message: str = "调查案件不存在") -> dict[str, Any]:
    if row is None:
        raise NotFoundError(message)
    return dict(row)


def _loads(value: str | None) -> Any:
    return json.loads(value) if value else {}


class InvestigationRepository:
    def __init__(self, connection: sqlite3.Connection):
        self.connection = connection

    # ------------------------------------------------------------------ cases
    def create(self, data: dict[str, Any], created_by: int, case_code: str, now: str) -> dict[str, Any]:
        cursor = self.connection.execute(
            """INSERT INTO investigations(
                   case_code,title,hypothesis,status,severity,owner_user_id,due_at,
                   evidence_version,created_by,created_at,updated_at
               ) VALUES(?,?,?,'open',?,?,?,0,?,?,?)""",
            (
                case_code, data["title"], data.get("hypothesis", ""), data["severity"],
                data["owner_user_id"], data.get("due_at"), created_by, now, now,
            ),
        )
        return self.get(cursor.lastrowid)

    def get(self, investigation_id: int) -> dict[str, Any]:
        row = self.connection.execute(
            """SELECT i.*,
                      owner.display_name AS owner_name,
                      creator.display_name AS creator_name,
                      releaser.display_name AS release_approver_name
               FROM investigations i
               JOIN users owner ON owner.id=i.owner_user_id
               JOIN users creator ON creator.id=i.created_by
               LEFT JOIN users releaser ON releaser.id=i.release_approved_by
               WHERE i.id=?""",
            (investigation_id,),
        ).fetchone()
        case = row_dict(row)
        case["overdue"] = bool(
            case["due_at"]
            and case["status"] not in CLOSED_STATUSES
            and case["due_at"] < now_iso()
        )
        return case

    def list(
        self,
        *,
        status: str | None = None,
        overdue_only: bool = False,
        owner_user_id: int | None = None,
        limit: int = 100,
        now_value: str | None = None,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if status:
            clauses.append("i.status=?")
            params.append(status)
        else:
            clauses.append("i.status NOT IN ('closed','dismissed')")
        if overdue_only:
            clauses.append("i.due_at IS NOT NULL AND i.due_at<?")
            params.append(now_value or now_iso())
        if owner_user_id is not None:
            clauses.append("i.owner_user_id=?")
            params.append(owner_user_id)
        where = " WHERE " + " AND ".join(clauses)
        params.append(limit)
        rows = self.connection.execute(
            """SELECT i.*,u.display_name AS owner_name
               FROM investigations i JOIN users u ON u.id=i.owner_user_id"""
            + where
            + " ORDER BY CASE i.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,"
              " i.due_at IS NULL, i.due_at, i.id DESC LIMIT ?",
            tuple(params),
        ).fetchall()
        result = [dict(row) for row in rows]
        today = now_value or now_iso()
        for case in result:
            case["overdue"] = bool(case["due_at"] and case["due_at"] < today)
        return result

    def update(self, investigation_id: int, fields: dict[str, Any], expected_version: int, now: str) -> dict[str, Any]:
        current = self.get(investigation_id)
        if current["status"] in CLOSED_STATUSES:
            raise ConflictError("案件已结案，不能再修改")
        sets: list[str] = []
        params: list[Any] = []
        if "title" in fields and fields["title"] is not None:
            sets.append("title=?")
            params.append(fields["title"])
        if "hypothesis" in fields and fields["hypothesis"] is not None:
            sets.append("hypothesis=?")
            params.append(fields["hypothesis"])
        if "owner_user_id" in fields and fields["owner_user_id"] is not None:
            sets.append("owner_user_id=?")
            params.append(fields["owner_user_id"])
        if "due_at" in fields and fields["due_at"] is not None:
            sets.append("due_at=?")
            params.append(fields["due_at"])
        if "severity" in fields and fields["severity"] is not None:
            if SEVERITY_ORDER[fields["severity"]] < SEVERITY_ORDER[current["severity"]]:
                raise ConflictError("严重度只能升级，不能被较低等级的旧更新覆盖")
            if fields["severity"] != current["severity"]:
                sets.append("severity=?")
                params.append(fields["severity"])
        if not sets:
            return current
        sets.append("version=version+1")
        sets.append("updated_at=?")
        params.extend([now, investigation_id, expected_version])
        cursor = self.connection.execute(
            f"UPDATE investigations SET {', '.join(sets)} WHERE id=? AND version=?",
            tuple(params),
        )
        if cursor.rowcount != 1:
            raise ConflictError("案件版本已变化，请刷新后重试（严重度升级不会被旧更新覆盖）")
        return self.get(investigation_id)

    def set_status(self, investigation_id: int, status: str, now: str, **extra: Any) -> None:
        assignments = ["status=?", "updated_at=?"]
        params: list[Any] = [status, now]
        for key, value in extra.items():
            assignments.append(f"{key}=?")
            params.append(value)
        if status in CLOSED_STATUSES:
            assignments.append("closed_at=COALESCE(closed_at,?)")
            params.append(now)
        params.extend([investigation_id])
        self.connection.execute(
            f"UPDATE investigations SET {', '.join(assignments)} WHERE id=?", tuple(params)
        )

    # ------------------------------------------------------------------ links
    def link_anomaly(self, investigation_id: int, anomaly_id: int, basis: dict[str, Any], now: str) -> dict[str, Any]:
        self.connection.execute(
            """INSERT INTO investigation_anomaly_links(investigation_id,anomaly_id,basis_json,created_at)
               VALUES(?,?,?,?)
               ON CONFLICT(investigation_id,anomaly_id) DO UPDATE SET
                   basis_json=excluded.basis_json""",
            (investigation_id, anomaly_id, json.dumps(basis, ensure_ascii=False, sort_keys=True), now),
        )
        return self.get_anomaly_link(investigation_id, anomaly_id)

    def get_anomaly_link(self, investigation_id: int, anomaly_id: int) -> dict[str, Any]:
        row = self.connection.execute(
            "SELECT * FROM investigation_anomaly_links WHERE investigation_id=? AND anomaly_id=?",
            (investigation_id, anomaly_id),
        ).fetchone()
        return row_dict(row, "异常关联不存在")

    def set_anomaly_link_status(
        self, investigation_id: int, anomaly_id: int, status: str, user_id: int, now: str
    ) -> dict[str, Any]:
        cursor = self.connection.execute(
            """UPDATE investigation_anomaly_links SET status=?,confirmed_by=?,confirmed_at=?
               WHERE investigation_id=? AND anomaly_id=?""",
            (status, user_id if status == "confirmed" else None, now if status == "confirmed" else None,
             investigation_id, anomaly_id),
        )
        if cursor.rowcount != 1:
            raise NotFoundError("异常关联不存在")
        return self.get_anomaly_link(investigation_id, anomaly_id)

    def anomaly_links(self, investigation_id: int) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            """SELECT l.*,a.case_code AS anomaly_code,a.anomaly_type,a.severity AS anomaly_severity,a.state AS anomaly_state
               FROM investigation_anomaly_links l
               JOIN anomaly_cases a ON a.id=l.anomaly_id
               WHERE l.investigation_id=? ORDER BY l.id""",
            (investigation_id,),
        ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["basis"] = _loads(item.pop("basis_json"))
            result.append(item)
        return result

    def upsert_affected(self, investigation_id: int, sample_id: int, basis: dict[str, Any], now: str) -> dict[str, Any]:
        self.connection.execute(
            """INSERT INTO investigation_affected_samples(
                   investigation_id,sample_id,status,basis_json,created_at,updated_at
               ) VALUES(?,?,'proposed',?,?,?)
               ON CONFLICT(investigation_id,sample_id) DO UPDATE SET
                   basis_json=excluded.basis_json, updated_at=excluded.updated_at""",
            (investigation_id, sample_id, json.dumps(basis, ensure_ascii=False, sort_keys=True), now, now),
        )
        return self.get_affected(investigation_id, sample_id)

    def get_affected(self, investigation_id: int, sample_id: int) -> dict[str, Any]:
        row = self.connection.execute(
            "SELECT * FROM investigation_affected_samples WHERE investigation_id=? AND sample_id=?",
            (investigation_id, sample_id),
        ).fetchone()
        return row_dict(row, "受影响样品记录不存在")

    def affected_rows(self, investigation_id: int, *, status: str | None = None) -> list[dict[str, Any]]:
        sql = (
            """SELECT a.*,s.sample_code,s.lifecycle_state,s.batch_id,s.location_id,s.root_sample_id,s.version AS sample_version
               FROM investigation_affected_samples a
               JOIN samples s ON s.id=a.sample_id
               WHERE a.investigation_id=?"""
        )
        params: list[Any] = [investigation_id]
        if status:
            sql += " AND a.status=?"
            params.append(status)
        sql += " ORDER BY a.id"
        rows = self.connection.execute(sql, tuple(params)).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["basis"] = _loads(item.pop("basis_json"))
            result.append(item)
        return result

    def confirm_affected(self, investigation_id: int, sample_id: int, measure: str, now: str) -> None:
        cursor = self.connection.execute(
            """UPDATE investigation_affected_samples SET status='confirmed',measure=?,updated_at=?
               WHERE investigation_id=? AND sample_id=? AND status='proposed'""",
            (measure, now, investigation_id, sample_id),
        )
        if cursor.rowcount != 1:
            raise ConflictError("候选样品不存在或已经被确认/排除")

    def exclude_affected(self, investigation_id: int, sample_id: int, now: str) -> None:
        cursor = self.connection.execute(
            """UPDATE investigation_affected_samples SET status='excluded',updated_at=?
               WHERE investigation_id=? AND sample_id=? AND status='proposed'""",
            (now, investigation_id, sample_id),
        )
        if cursor.rowcount != 1:
            raise ConflictError("候选样品不存在或已经被确认/排除")

    def mark_measure(
        self,
        investigation_id: int,
        sample_id: int,
        measure_status: str,
        now: str,
        *,
        prior_state: str | None = None,
        applied_by: int | None = None,
        applied_at: str | None = None,
        lifted_at: str | None = None,
    ) -> None:
        sets = ["measure_status=?", "updated_at=?"]
        params: list[Any] = [measure_status, now]
        if prior_state is not None:
            sets.append("prior_state=?")
            params.append(prior_state)
        if applied_by is not None:
            sets.append("measure_applied_by=?")
            params.append(applied_by)
        if applied_at is not None:
            sets.append("measure_applied_at=?")
            params.append(applied_at)
        if lifted_at is not None:
            sets.append("lifted_at=?")
            params.append(lifted_at)
        params.extend([investigation_id, sample_id])
        self.connection.execute(
            f"UPDATE investigation_affected_samples SET {', '.join(sets)} WHERE investigation_id=? AND sample_id=?",
            tuple(params),
        )

    def explain_affected(self, investigation_id: int, sample_id: int, note: str, user_id: int, now: str) -> None:
        cursor = self.connection.execute(
            """UPDATE investigation_affected_samples
               SET disposition_note=?,explained_by=?,explained_at=?,updated_at=?
               WHERE investigation_id=? AND sample_id=?""",
            (note, user_id, now, now, investigation_id, sample_id),
        )
        if cursor.rowcount != 1:
            raise NotFoundError("受影响样品记录不存在")

    # -------------------------------------------------------------- evidence
    def add_evidence(
        self,
        investigation_id: int,
        data: dict[str, Any],
        idempotency_key: str | None,
        user_id: int,
        now: str,
    ) -> dict[str, Any]:
        if idempotency_key:
            existing = self.connection.execute(
                "SELECT * FROM investigation_evidence WHERE investigation_id=? AND idempotency_key=?",
                (investigation_id, idempotency_key),
            ).fetchone()
            if existing:
                return dict(existing), True
        next_version = self.connection.execute(
            "SELECT COALESCE(MAX(version),0)+1 FROM investigation_evidence WHERE investigation_id=?",
            (investigation_id,),
        ).fetchone()[0]
        try:
            cursor = self.connection.execute(
                """INSERT INTO investigation_evidence(
                       investigation_id,version,source_type,source_reference,note,idempotency_key,recorded_by,created_at
                   ) VALUES(?,?,?,?,?,?,?,?)""",
                (
                    investigation_id, next_version, data["source_type"], data.get("source_reference", ""),
                    data.get("note", ""), idempotency_key, user_id, now,
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise ConflictError("证据幂等键冲突") from exc
        self.connection.execute(
            "UPDATE investigations SET evidence_version=?,updated_at=? WHERE id=?",
            (next_version, now, investigation_id),
        )
        row = self.connection.execute(
            "SELECT * FROM investigation_evidence WHERE id=?", (cursor.lastrowid,)
        ).fetchone()
        return dict(row), False

    def evidence_list(self, investigation_id: int) -> list[dict[str, Any]]:
        return [
            dict(row)
            for row in self.connection.execute(
                "SELECT * FROM investigation_evidence WHERE investigation_id=? ORDER BY version",
                (investigation_id,),
            ).fetchall()
        ]

    # ----------------------------------------------------------------- steps
    def create_action(self, investigation_id: int, data: dict[str, Any], user_id: int, now: str) -> dict[str, Any]:
        try:
            cursor = self.connection.execute(
                """INSERT INTO investigation_actions(
                       investigation_id,step_code,title,instruction,assignee_user_id,due_at,
                       status,created_by,created_at,updated_at
                   ) VALUES(?,?,?,?,?,?,'pending',?,?,?)""",
                (
                    investigation_id, data["step_code"], data["title"], data.get("instruction", ""),
                    data.get("assignee_user_id"), data.get("due_at"), user_id, now, now,
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise ConflictError("处置步骤编码已存在") from exc
        return self.get_action(cursor.lastrowid)

    def get_action(self, action_id: int) -> dict[str, Any]:
        return row_dict(
            self.connection.execute("SELECT * FROM investigation_actions WHERE id=?", (action_id,)).fetchone(),
            "处置步骤不存在",
        )

    def action_by_code(self, investigation_id: int, step_code: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM investigation_actions WHERE investigation_id=? AND step_code=?",
            (investigation_id, step_code),
        ).fetchone()
        return dict(row) if row else None

    def actions(self, investigation_id: int, *, status: str | None = None) -> list[dict[str, Any]]:
        sql = "SELECT * FROM investigation_actions WHERE investigation_id=?"
        params: list[Any] = [investigation_id]
        if status:
            sql += " AND status=?"
            params.append(status)
        sql += " ORDER BY id"
        return [dict(row) for row in self.connection.execute(sql, tuple(params)).fetchall()]

    def complete_action(self, action_id: int, user_id: int, result: str, now: str) -> dict[str, Any]:
        current = self.get_action(action_id)
        if current["status"] == "completed":
            return current
        if current["status"] == "cancelled":
            raise ConflictError("处置步骤已取消")
        self.connection.execute(
            """UPDATE investigation_actions SET status='completed',completed_by=?,completed_at=?,result=?,updated_at=?
               WHERE id=? AND status='pending'""",
            (user_id, now, result, now, action_id),
        )
        return self.get_action(action_id)

    def cancel_action(self, action_id: int, now: str) -> dict[str, Any]:
        current = self.get_action(action_id)
        if current["status"] == "completed":
            raise ConflictError("已完成的处置步骤不能取消")
        self.connection.execute(
            "UPDATE investigation_actions SET status='cancelled',updated_at=? WHERE id=? AND status='pending'",
            (now, action_id),
        )
        return self.get_action(action_id)

    # --------------------------------------------------------------- journal
    def journal_add(
        self,
        investigation_id: int,
        event_type: str,
        actor_user_id: int | None,
        payload: dict[str, Any],
        now: str,
        *,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        if idempotency_key:
            existing = self.connection.execute(
                "SELECT * FROM investigation_journal WHERE investigation_id=? AND idempotency_key=?",
                (investigation_id, idempotency_key),
            ).fetchone()
            if existing:
                return dict(existing)
        cursor = self.connection.execute(
            """INSERT INTO investigation_journal(investigation_id,event_type,actor_user_id,payload_json,idempotency_key,created_at)
               VALUES(?,?,?,?,?,?)""",
            (
                investigation_id, event_type, actor_user_id,
                json.dumps(payload, ensure_ascii=False, sort_keys=True), idempotency_key, now,
            ),
        )
        return dict(
            self.connection.execute("SELECT * FROM investigation_journal WHERE id=?", (cursor.lastrowid,)).fetchone()
        )

    def journal_list(self, investigation_id: int) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT * FROM investigation_journal WHERE investigation_id=? ORDER BY id",
            (investigation_id,),
        ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["payload"] = _loads(item.pop("payload_json"))
            result.append(item)
        return result


def now_iso() -> str:
    from app.core.clock import to_storage, utc_now

    return to_storage(utc_now())

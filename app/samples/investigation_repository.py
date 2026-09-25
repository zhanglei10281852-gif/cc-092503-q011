from __future__ import annotations

import json
import sqlite3
from typing import Any

from app.core.errors import ConflictError, NotFoundError

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_CASE_SQL = "CASE severity WHEN 'low' THEN 1 WHEN 'medium' THEN 2 WHEN 'high' THEN 3 ELSE 4 END"


def _row(row: sqlite3.Row | None, message: str = "记录不存在") -> dict[str, Any]:
    if row is None:
        raise NotFoundError(message)
    return dict(row)


class InvestigationRepository:
    def __init__(self, connection: sqlite3.Connection):
        self.connection = connection

    # ---------- 案件 ----------
    def create_case(self, data: dict[str, Any], case_code: str, created_by: int, now: str) -> dict[str, Any]:
        cursor = self.connection.execute(
            """INSERT INTO investigation_cases(case_code,title,hypothesis,severity,status,owner_user_id,due_at,
               overdue,version,created_by,created_at,updated_at)
               VALUES(?,?,?,?,'open',?,?,0,1,?,?,?)""",
            (
                case_code, data["title"], data.get("hypothesis", ""), data["severity"],
                data["owner_user_id"], data.get("due_at"), created_by, now, now,
            ),
        )
        return self.get_case(cursor.lastrowid)

    def get_case(self, case_id: int) -> dict[str, Any]:
        return _row(
            self.connection.execute("SELECT * FROM investigation_cases WHERE id=?", (case_id,)).fetchone(),
            "调查案件不存在",
        )

    def list_cases(self, status: str | None = None, overdue: bool | None = None) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if status:
            clauses.append("status=?")
            params.append(status)
        if overdue is not None:
            clauses.append("overdue=?")
            params.append(1 if overdue else 0)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        rows = self.connection.execute(
            "SELECT * FROM investigation_cases" + where + " ORDER BY id DESC", tuple(params)
        ).fetchall()
        return [dict(row) for row in rows]

    def touch_case(self, case_id: int, now: str) -> None:
        self.connection.execute(
            "UPDATE investigation_cases SET version=version+1,updated_at=? WHERE id=?",
            (now, case_id),
        )

    def set_status(self, case_id: int, status: str, now: str, **extra: Any) -> None:
        assignments = ["status=?", "version=version+1", "updated_at=?"]
        params: list[Any] = [status, now]
        for column, value in extra.items():
            assignments.append(f"{column}=?")
            params.append(value)
        params.append(case_id)
        self.connection.execute(
            f"UPDATE investigation_cases SET {','.join(assignments)} WHERE id=?", tuple(params)
        )

    def escalate_severity(self, case_id: int, severity: str, now: str) -> bool:
        """仅当传入严重度不低于当前值时生效，返回是否实际提升。旧更新携带的更低严重度不会覆盖已升级结果。"""
        cursor = self.connection.execute(
            f"""UPDATE investigation_cases SET severity=?,version=version+1,updated_at=?
                WHERE id=? AND {SEVERITY_CASE_SQL} < ?""",
            (severity, now, case_id, SEVERITY_RANK[severity]),
        )
        return cursor.rowcount == 1

    def mark_overdue(self, now: str) -> list[int]:
        rows = self.connection.execute(
            """SELECT id FROM investigation_cases
               WHERE overdue=0 AND due_at IS NOT NULL AND due_at<? AND status NOT IN ('closed','dismissed')
               ORDER BY id""",
            (now,),
        ).fetchall()
        ids = [int(row[0]) for row in rows]
        if ids:
            placeholders = ",".join("?" for _ in ids)
            self.connection.execute(
                f"UPDATE investigation_cases SET overdue=1,version=version+1,updated_at=? WHERE id IN ({placeholders})",
                (now, *ids),
            )
        return ids

    # ---------- 异常关联 ----------
    def get_link(self, case_id: int, anomaly_id: int) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM investigation_case_links WHERE case_id=? AND anomaly_id=?",
            (case_id, anomaly_id),
        ).fetchone()
        return self._decode_link(dict(row)) if row else None

    def insert_link(
        self,
        case_id: int,
        anomaly_id: int,
        status: str,
        basis: list[str],
        basis_detail: dict[str, Any],
        now: str,
        confirmed_by: int | None = None,
    ) -> dict[str, Any]:
        cursor = self.connection.execute(
            """INSERT INTO investigation_case_links(case_id,anomaly_id,status,basis_json,basis_detail_json,
               confirmed_by,confirmed_at,created_at,updated_at)
               VALUES(?,?,?,?,?,?,?,?,?)""",
            (
                case_id, anomaly_id, status, json.dumps(sorted(basis), ensure_ascii=False),
                json.dumps(basis_detail, ensure_ascii=False, sort_keys=True),
                confirmed_by, now if confirmed_by else None, now, now,
            ),
        )
        return self._decode_link(_row(self.connection.execute(
            "SELECT * FROM investigation_case_links WHERE id=?", (cursor.lastrowid,)
        ).fetchone()))

    def update_link(
        self,
        link_id: int,
        now: str,
        *,
        status: str | None = None,
        basis: list[str] | None = None,
        basis_detail: dict[str, Any] | None = None,
        confirmed_by: int | None = None,
    ) -> None:
        assignments = ["updated_at=?"]
        params: list[Any] = [now]
        if status is not None:
            assignments.append("status=?")
            params.append(status)
        if basis is not None:
            assignments.append("basis_json=?")
            params.append(json.dumps(sorted(basis), ensure_ascii=False))
        if basis_detail is not None:
            assignments.append("basis_detail_json=?")
            params.append(json.dumps(basis_detail, ensure_ascii=False, sort_keys=True))
        if confirmed_by is not None:
            assignments.append("confirmed_by=?")
            assignments.append("confirmed_at=?")
            params.extend([confirmed_by, now])
        params.append(link_id)
        self.connection.execute(
            f"UPDATE investigation_case_links SET {','.join(assignments)} WHERE id=?", tuple(params)
        )

    def list_links(self, case_id: int, status: str | None = None) -> list[dict[str, Any]]:
        sql = """SELECT l.*,a.case_code AS anomaly_code,a.anomaly_type,a.severity AS anomaly_severity,
                        a.state AS anomaly_state,a.sample_id,a.batch_id,a.description AS anomaly_description
                 FROM investigation_case_links l JOIN anomaly_cases a ON a.id=l.anomaly_id
                 WHERE l.case_id=?"""
        params: list[Any] = [case_id]
        if status:
            sql += " AND l.status=?"
            params.append(status)
        sql += " ORDER BY l.anomaly_id"
        rows = self.connection.execute(sql, tuple(params)).fetchall()
        return [self._decode_link(dict(row)) for row in rows]

    def link_map(self, case_id: int) -> dict[int, dict[str, Any]]:
        return {link["anomaly_id"]: link for link in self.list_links(case_id)}

    def seed_anomalies(self, case_id: int) -> list[dict[str, Any]]:
        """已确认关联的异常及其样品定位信息，作为候选扫描的种子。候选需人工确认后才参与扩展。"""
        rows = self.connection.execute(
            """SELECT a.id,a.sample_id,a.batch_id,a.created_at,
                      s.batch_id AS sample_batch_id,s.location_id,s.root_sample_id
               FROM investigation_case_links l
               JOIN anomaly_cases a ON a.id=l.anomaly_id
               LEFT JOIN samples s ON s.id=a.sample_id
               WHERE l.case_id=? AND l.status='confirmed'
               ORDER BY a.id""",
            (case_id,),
        ).fetchall()
        return [dict(row) for row in rows]

    def scannable_anomalies(self) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            """SELECT a.*,s.batch_id AS sample_batch_id,s.location_id,s.root_sample_id
               FROM anomaly_cases a LEFT JOIN samples s ON s.id=a.sample_id
               WHERE a.state IN ('open','investigating','contained')
               ORDER BY a.id"""
        ).fetchall()
        return [dict(row) for row in rows]

    # ---------- 受影响样品与措施 ----------
    def get_case_sample(self, case_id: int, sample_id: int) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM investigation_case_samples WHERE case_id=? AND sample_id=?",
            (case_id, sample_id),
        ).fetchone()
        return self._decode_case_sample(dict(row)) if row else None

    def insert_case_sample(
        self,
        case_id: int,
        sample_id: int,
        measure: str,
        basis: list[str],
        previous_state: str | None,
        applied_by: int,
        now: str,
    ) -> None:
        self.connection.execute(
            """INSERT INTO investigation_case_samples(case_id,sample_id,measure,measure_state,basis_json,
               previous_lifecycle_state,applied_by,applied_at,created_at,updated_at)
               VALUES(?,?,?,'active',?,?,?,?,?,?)""",
            (
                case_id, sample_id, measure, json.dumps(sorted(basis), ensure_ascii=False),
                previous_state, applied_by, now, now, now,
            ),
        )

    def update_case_sample(self, row_id: int, now: str, **changes: Any) -> None:
        assignments = ["updated_at=?"]
        params: list[Any] = [now]
        for column, value in changes.items():
            assignments.append(f"{column}=?")
            if column == "basis_json" and isinstance(value, list):
                value = json.dumps(sorted(value), ensure_ascii=False)
            params.append(value)
        params.append(row_id)
        self.connection.execute(
            f"UPDATE investigation_case_samples SET {','.join(assignments)} WHERE id=?", tuple(params)
        )

    def list_case_samples(self, case_id: int, measure_state: str | None = None) -> list[dict[str, Any]]:
        sql = """SELECT cs.*,s.sample_code,s.lifecycle_state,s.location_id,s.batch_id
                 FROM investigation_case_samples cs JOIN samples s ON s.id=cs.sample_id
                 WHERE cs.case_id=?"""
        params: list[Any] = [case_id]
        if measure_state:
            sql += " AND cs.measure_state=?"
            params.append(measure_state)
        sql += " ORDER BY cs.sample_id"
        rows = self.connection.execute(sql, tuple(params)).fetchall()
        return [self._decode_case_sample(dict(row)) for row in rows]

    def active_quarantine_count(self, sample_id: int) -> int:
        return int(self.connection.execute(
            """SELECT COUNT(*) FROM investigation_case_samples
               WHERE sample_id=? AND measure='quarantine' AND measure_state='active'""",
            (sample_id,),
        ).fetchone()[0])

    def earliest_quarantine_previous(self, sample_id: int) -> str | None:
        """最早一条隔离措施记录的隔离前状态，即该样品被任何案件隔离前的原始状态。"""
        row = self.connection.execute(
            """SELECT previous_lifecycle_state FROM investigation_case_samples
               WHERE sample_id=? AND measure='quarantine' ORDER BY id LIMIT 1""",
            (sample_id,),
        ).fetchone()
        return row[0] if row else None

    # ---------- 证据版本 ----------
    def append_evidence(self, case_id: int, content: str, source_uri: str | None, recorded_by: int, now: str) -> dict[str, Any]:
        version_no = int(self.connection.execute(
            "SELECT COALESCE(MAX(version_no),0)+1 FROM investigation_evidence WHERE case_id=?",
            (case_id,),
        ).fetchone()[0])
        cursor = self.connection.execute(
            """INSERT INTO investigation_evidence(case_id,version_no,content,source_uri,recorded_by,recorded_at)
               VALUES(?,?,?,?,?,?)""",
            (case_id, version_no, content, source_uri, recorded_by, now),
        )
        return _row(self.connection.execute(
            "SELECT * FROM investigation_evidence WHERE id=?", (cursor.lastrowid,)
        ).fetchone())

    def list_evidence(self, case_id: int) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT * FROM investigation_evidence WHERE case_id=? ORDER BY version_no", (case_id,)
        ).fetchall()
        return [dict(row) for row in rows]

    # ---------- 处置步骤 ----------
    def append_step(self, case_id: int, description: str, due_at: str | None, created_by: int, now: str) -> dict[str, Any]:
        step_no = int(self.connection.execute(
            "SELECT COALESCE(MAX(step_no),0)+1 FROM investigation_steps WHERE case_id=?",
            (case_id,),
        ).fetchone()[0])
        cursor = self.connection.execute(
            """INSERT INTO investigation_steps(case_id,step_no,description,status,due_at,created_by,created_at)
               VALUES(?,?,?,'pending',?,?,?)""",
            (case_id, step_no, description, due_at, created_by, now),
        )
        return _row(self.connection.execute(
            "SELECT * FROM investigation_steps WHERE id=?", (cursor.lastrowid,)
        ).fetchone())

    def get_step(self, case_id: int, step_id: int) -> dict[str, Any]:
        return _row(
            self.connection.execute(
                "SELECT * FROM investigation_steps WHERE id=? AND case_id=?", (step_id, case_id)
            ).fetchone(),
            "处置步骤不存在",
        )

    def complete_step(self, step_id: int, completed_by: int, now: str) -> None:
        cursor = self.connection.execute(
            """UPDATE investigation_steps SET status='done',completed_by=?,completed_at=?
               WHERE id=? AND status='pending'""",
            (completed_by, now, step_id),
        )
        if cursor.rowcount != 1:
            raise ConflictError("处置步骤已完成或状态已变化")

    def list_steps(self, case_id: int) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT * FROM investigation_steps WHERE case_id=? ORDER BY step_no", (case_id,)
        ).fetchall()
        return [dict(row) for row in rows]

    # ---------- 解除审批 ----------
    def append_release_decision(self, case_id: int, decision: str, comment: str, decided_by: int, now: str) -> dict[str, Any]:
        cursor = self.connection.execute(
            """INSERT INTO investigation_release_decisions(case_id,decision,comment,decided_by,decided_at)
               VALUES(?,?,?,?,?)""",
            (case_id, decision, comment, decided_by, now),
        )
        return _row(self.connection.execute(
            "SELECT * FROM investigation_release_decisions WHERE id=?", (cursor.lastrowid,)
        ).fetchone())

    def list_release_decisions(self, case_id: int) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT * FROM investigation_release_decisions WHERE case_id=? ORDER BY id", (case_id,)
        ).fetchall()
        return [dict(row) for row in rows]

    # ---------- 解码 ----------
    @staticmethod
    def _decode_link(link: dict[str, Any]) -> dict[str, Any]:
        link["basis"] = json.loads(link.pop("basis_json"))
        link["basis_detail"] = json.loads(link.pop("basis_detail_json"))
        return link

    @staticmethod
    def _decode_case_sample(row: dict[str, Any]) -> dict[str, Any]:
        row["basis"] = json.loads(row.pop("basis_json"))
        return row

from __future__ import annotations

import sqlite3
import uuid
from typing import Any

from app.core.clock import Clock, SystemClock, to_storage
from app.core.errors import ConflictError, NotFoundError, ValidationError
from app.core.security import Principal
from app.investigations.association import AssociationService
from app.investigations.repository import InvestigationRepository
from app.samples.repository import SampleRepository
from app.services.audit import AuditService

ACTIVE_WORK_STATUSES = ("open", "observing", "contained")
CLOSED_STATUSES = ("closed", "dismissed")


class InvestigationService:
    def __init__(self, connection: sqlite3.Connection, clock: Clock | None = None):
        self.connection = connection
        self.clock = clock or SystemClock()
        self.repo = InvestigationRepository(connection)
        self.samples = SampleRepository(connection)
        self.association = AssociationService(connection, self.clock)
        self.audit = AuditService(connection, self.clock)

    # ----------------------------------------------------------------- cases
    def create(self, principal: Principal, data: dict[str, Any]) -> dict[str, Any]:
        principal.require("investigations.manage")
        self._user_exists(data["owner_user_id"])
        now = to_storage(self.clock.now())
        case_code = data.get("case_code") or f"INV-{uuid.uuid4().hex[:12]}"
        case = self.repo.create(data, principal.user_id, case_code, now)
        self.repo.journal_add(case["id"], "created", principal.user_id, {"case_code": case_code}, now)
        for anomaly_id in data.get("anomaly_ids", []):
            self._link_anomaly(case["id"], anomaly_id, {"source": "create_case"}, now, confirm=True, confirmed_by=principal.user_id)
        self.audit.record(principal, "investigation.create", "investigation", str(case["id"]), after=case)
        return self.detail(principal, case["id"])

    def list(self, principal: Principal, *, status: str | None, overdue_only: bool, owner_user_id: int | None) -> list[dict[str, Any]]:
        principal.require("samples.read")
        now = to_storage(self.clock.now())
        cases = self.repo.list(status=status, overdue_only=overdue_only, owner_user_id=owner_user_id, now_value=now)
        result = []
        for case in cases:
            case["pending_action_count"] = self.connection.execute(
                "SELECT COUNT(*) FROM investigation_actions WHERE investigation_id=? AND status='pending'",
                (case["id"],),
            ).fetchone()[0]
            case["active_measure_count"] = self.connection.execute(
                "SELECT COUNT(*) FROM investigation_affected_samples WHERE investigation_id=? AND measure_status='active'",
                (case["id"],),
            ).fetchone()[0]
            result.append(case)
        return result

    def detail(self, principal: Principal, investigation_id: int) -> dict[str, Any]:
        principal.require("samples.read")
        case = self.repo.get(investigation_id)
        case["anomaly_links"] = self.repo.anomaly_links(investigation_id)
        affected = self.repo.affected_rows(investigation_id)
        actions = self.repo.actions(investigation_id)
        now = self.clock.now()
        for action in actions:
            action["overdue"] = bool(action["due_at"] and action["status"] == "pending" and action["due_at"] < to_storage(now))
        confirmed = [item for item in affected if item["status"] == "confirmed"]
        case["affected_samples"] = affected
        case["evidence"] = self.repo.evidence_list(investigation_id)
        case["actions"] = actions
        case["journal"] = self.repo.journal_list(investigation_id)
        case["pending_action_count"] = sum(1 for item in actions if item["status"] == "pending")
        case["overdue_action_count"] = sum(1 for item in actions if item["overdue"])
        case["active_measure_count"] = sum(1 for item in affected if item["measure_status"] == "active")
        case["confirmed_sample_count"] = len(confirmed)
        case["explained_confirmed_count"] = sum(1 for item in confirmed if item["disposition_note"])
        case["all_confirmed_explained"] = len(confirmed) == case["explained_confirmed_count"]
        case["can_request_closure"] = (
            case["status"] in ACTIVE_WORK_STATUSES
            and case["all_confirmed_explained"]
            and case["pending_action_count"] == 0
        )
        case["overdue"] = bool(case["due_at"] and case["status"] not in CLOSED_STATUSES and case["due_at"] < to_storage(now))
        return case

    def update(self, principal: Principal, investigation_id: int, data: dict[str, Any]) -> dict[str, Any]:
        principal.require("investigations.manage")
        if data.get("owner_user_id"):
            self._user_exists(data["owner_user_id"])
        before = self.repo.get(investigation_id)
        now = to_storage(self.clock.now())
        updated = self.repo.update(investigation_id, data, data["expected_version"], now)
        if updated["severity"] != before["severity"]:
            self.repo.journal_add(
                investigation_id, "severity_changed", principal.user_id,
                {"from": before["severity"], "to": updated["severity"]}, now,
            )
        self.audit.record(principal, "investigation.update", "investigation", str(investigation_id), before=before, after=updated)
        return self.detail(principal, investigation_id)

    # ------------------------------------------------------------ candidates
    def candidates(self, principal: Principal, query: dict[str, Any]) -> dict[str, Any]:
        return self.association.propose(principal, query)

    def import_candidates(self, principal: Principal, investigation_id: int, query: dict[str, Any]) -> dict[str, Any]:
        """按维度生成候选并写入案件（候选状态）。全部使用自然唯一键 upsert，可安全重复扫描。"""
        principal.require("investigations.manage")
        case = self.repo.get(investigation_id)
        if case["status"] in CLOSED_STATUSES:
            raise ConflictError("案件已结案，不能再导入候选")
        proposal = self.association.propose(principal, query)
        now = to_storage(self.clock.now())
        new_anomalies = 0
        new_samples = 0
        for candidate in proposal["anomaly_candidates"]:
            before = self.connection.execute(
                "SELECT id FROM investigation_anomaly_links WHERE investigation_id=? AND anomaly_id=?",
                (investigation_id, candidate["anomaly_id"]),
            ).fetchone()
            self.repo.link_anomaly(investigation_id, candidate["anomaly_id"], {"reasons": candidate["basis"]}, now)
            if not before:
                new_anomalies += 1
        for candidate in proposal["sample_candidates"]:
            before = self.connection.execute(
                "SELECT id FROM investigation_affected_samples WHERE investigation_id=? AND sample_id=?",
                (investigation_id, candidate["sample_id"]),
            ).fetchone()
            self.repo.upsert_affected(investigation_id, candidate["sample_id"], {"reasons": candidate["basis"]}, now)
            if not before:
                new_samples += 1
        self.repo.journal_add(
            investigation_id, "candidates_imported", principal.user_id,
            {"new_anomalies": new_anomalies, "new_samples": new_samples, "dimensions": proposal["dimensions"]}, now,
        )
        self.audit.record(
            principal, "investigation.import_candidates", "investigation", str(investigation_id),
            metadata={"new_anomalies": new_anomalies, "new_samples": new_samples},
        )
        return {
            "new_anomaly_candidates": new_anomalies,
            "new_sample_candidates": new_samples,
            "anomaly_candidate_count": len(proposal["anomaly_candidates"]),
            "sample_candidate_count": len(proposal["sample_candidates"]),
            "replayed": new_anomalies == 0 and new_samples == 0,
        }

    # -------------------------------------------------------- anomaly links
    def add_anomalies(self, principal: Principal, investigation_id: int, anomaly_ids: list[int]) -> dict[str, Any]:
        principal.require("investigations.manage")
        case = self.repo.get(investigation_id)
        if case["status"] in CLOSED_STATUSES:
            raise ConflictError("案件已结案")
        now = to_storage(self.clock.now())
        added = 0
        for anomaly_id in anomaly_ids:
            before = self.connection.execute(
                "SELECT id FROM investigation_anomaly_links WHERE investigation_id=? AND anomaly_id=?",
                (investigation_id, anomaly_id),
            ).fetchone()
            self._link_anomaly(investigation_id, anomaly_id, {"source": "manual"}, now, confirm=True, confirmed_by=principal.user_id)
            if not before:
                added += 1
        return {"added": added, "total": len(self.repo.anomaly_links(investigation_id))}

    def _link_anomaly(
        self, investigation_id: int, anomaly_id: int, basis: dict[str, Any], now: str,
        *, confirm: bool, confirmed_by: int,
    ) -> dict[str, Any]:
        anomaly = self.connection.execute("SELECT * FROM anomaly_cases WHERE id=?", (anomaly_id,)).fetchone()
        if not anomaly:
            raise NotFoundError(f"异常 {anomaly_id} 不存在")
        link = self.repo.link_anomaly(investigation_id, anomaly_id, basis, now)
        if confirm and link["status"] != "confirmed":
            link = self.repo.set_anomaly_link_status(investigation_id, anomaly_id, "confirmed", confirmed_by, now)
        anomaly = dict(anomaly)
        if anomaly["sample_id"]:
            self.repo.upsert_affected(
                investigation_id, anomaly["sample_id"],
                {"reasons": [{"type": "anomaly", "anomaly_id": anomaly_id, "label": anomaly["case_code"]}]},
                now,
            )
        return link

    def confirm_anomalies(self, principal: Principal, investigation_id: int, anomaly_ids: list[int]) -> dict[str, Any]:
        principal.require("investigations.manage")
        now = to_storage(self.clock.now())
        for anomaly_id in anomaly_ids:
            link = self.repo.get_anomaly_link(investigation_id, anomaly_id)
            if link["status"] != "confirmed":
                self.repo.set_anomaly_link_status(investigation_id, anomaly_id, "confirmed", principal.user_id, now)
            anomaly = self.connection.execute("SELECT sample_id FROM anomaly_cases WHERE id=?", (anomaly_id,)).fetchone()
            if anomaly and anomaly["sample_id"]:
                self.repo.upsert_affected(
                    investigation_id, anomaly["sample_id"],
                    {"reasons": [{"type": "anomaly", "anomaly_id": anomaly_id}]}, now,
                )
        return {"confirmed": len(anomaly_ids)}

    def exclude_anomaly(self, principal: Principal, investigation_id: int, anomaly_id: int) -> dict:
        principal.require("investigations.manage")
        now = to_storage(self.clock.now())
        link = self.repo.set_anomaly_link_status(investigation_id, anomaly_id, "excluded", principal.user_id, now)
        self.repo.journal_add(investigation_id, "anomaly_excluded", principal.user_id, {"anomaly_id": anomaly_id}, now)
        return link

    # ------------------------------------------------------------ affected
    def confirm_affected(self, principal: Principal, investigation_id: int, items: list[dict[str, Any]]) -> dict[str, Any]:
        principal.require("investigations.manage")
        case = self.repo.get(investigation_id)
        if case["status"] in CLOSED_STATUSES:
            raise ConflictError("案件已结案")
        now = to_storage(self.clock.now())
        confirmed = 0
        for item in items:
            row = self.repo.get_affected(investigation_id, item["sample_id"])
            if row["status"] == "confirmed":
                if row["measure"] != item["measure"]:
                    raise ConflictError(f"样品 {item['sample_id']} 已确认且措施不同，请先解除原措施")
                continue
            self.repo.confirm_affected(investigation_id, item["sample_id"], item["measure"], now)
            confirmed += 1
        self.repo.journal_add(investigation_id, "affected_confirmed", principal.user_id, {"count": confirmed}, now)
        return {"confirmed": confirmed, "requested": len(items)}

    def exclude_affected(self, principal: Principal, investigation_id: int, sample_id: int) -> dict:
        principal.require("investigations.manage")
        row = self.repo.get_affected(investigation_id, sample_id)
        if row["measure_status"] == "active":
            raise ConflictError("样品措施执行中，不能排除，请先解除措施")
        now = to_storage(self.clock.now())
        self.repo.exclude_affected(investigation_id, sample_id, now)
        self.repo.journal_add(investigation_id, "affected_excluded", principal.user_id, {"sample_id": sample_id}, now)
        return {"sample_id": sample_id, "status": "excluded"}

    # ------------------------------------------------------------- measures
    def apply_measures(
        self, principal: Principal, investigation_id: int, measure: str, sample_ids: list[int]
    ) -> dict[str, Any]:
        principal.require("investigations.manage")
        case = self.repo.get(investigation_id)
        if case["status"] in CLOSED_STATUSES or case["status"] == "pending_closure":
            raise ConflictError("案件当前状态不能执行措施")
        if not sample_ids:
            sample_ids = [
                row["sample_id"]
                for row in self.repo.affected_rows(investigation_id, status="confirmed")
                if row["measure"] == measure and row["measure_status"] != "active"
            ]
        if not sample_ids:
            raise ValidationError("没有可执行措施的已确认样品")
        now = to_storage(self.clock.now())
        applied: list[int] = []
        replayed: list[int] = []
        for sample_id in sample_ids:
            row = self.repo.get_affected(investigation_id, sample_id)
            if row["status"] != "confirmed":
                raise ConflictError(f"样品 {sample_id} 尚未经人工确认，不能执行措施")
            if row["measure"] != measure:
                raise ConflictError(f"样品 {sample_id} 确认的措施与本次请求不一致")
            if row["measure_status"] == "active":
                replayed.append(sample_id)
                continue
            self._apply_one_measure(investigation_id, sample_id, measure, principal.user_id, now)
            applied.append(sample_id)
        if applied:
            self._recompute_status(investigation_id)
            self.repo.journal_add(
                investigation_id, "measures_applied", principal.user_id,
                {"measure": measure, "sample_ids": applied}, now,
            )
            self.audit.record(
                principal, "investigation.apply_measure", "investigation", str(investigation_id),
                metadata={"measure": measure, "sample_ids": applied},
            )
        return {"measure": measure, "applied": applied, "replayed": replayed}

    def _apply_one_measure(self, investigation_id: int, sample_id: int, measure: str, user_id: int, now: str) -> None:
        sample = self.samples.get(sample_id)
        if measure == "quarantine":
            if sample["lifecycle_state"] in {"destroyed", "pending_destruction", "loaned"}:
                raise ConflictError(f"样品 {sample['sample_code']} 当前状态 {sample['lifecycle_state']} 不能隔离")
            other = self.connection.execute(
                """SELECT i.id FROM investigation_affected_samples a JOIN investigations i ON i.id=a.investigation_id
                   WHERE a.sample_id=? AND a.measure='quarantine' AND a.measure_status='active'
                     AND a.investigation_id<>? AND i.status NOT IN ('closed','dismissed') LIMIT 1""",
                (sample_id, investigation_id),
            ).fetchone()
            if other:
                raise ConflictError(f"样品 {sample['sample_code']} 已被其他调查案件隔离")
            prior_state = sample["lifecycle_state"]
            self.connection.execute(
                "UPDATE samples SET lifecycle_state='quarantined',version=version+1,updated_at=? WHERE id=?",
                (now, sample_id),
            )
            self.samples.append_event(
                sample_id, "investigation.quarantined", user_id, now,
                from_state=prior_state, to_state="quarantined",
                details={"investigation_id": investigation_id}, correlation_id=f"INV-{investigation_id}",
            )
            self.repo.mark_measure(
                investigation_id, sample_id, "active", now,
                prior_state=prior_state, applied_by=user_id, applied_at=now,
            )
        else:
            self.repo.mark_measure(
                investigation_id, sample_id, "active", now, applied_by=user_id, applied_at=now,
            )

    def _recompute_status(self, investigation_id: int) -> None:
        case = self.repo.get(investigation_id)
        if case["status"] not in ACTIVE_WORK_STATUSES:
            return
        active = self.repo.affected_rows(investigation_id)
        quarantined = sum(1 for row in active if row["measure"] == "quarantine" and row["measure_status"] == "active")
        observing = sum(1 for row in active if row["measure"] == "observe" and row["measure_status"] == "active")
        target = "contained" if quarantined else ("observing" if observing else "open")
        if target != case["status"]:
            self.repo.set_status(investigation_id, target, to_storage(self.clock.now()))

    # -------------------------------------------------------------- explain
    def explain_affected(self, principal: Principal, investigation_id: int, sample_id: int, note: str) -> dict[str, Any]:
        principal.require("investigations.manage")
        row = self.repo.get_affected(investigation_id, sample_id)
        if row["status"] != "confirmed":
            raise ConflictError("只能逐项解释已确认受影响的样品")
        now = to_storage(self.clock.now())
        self.repo.explain_affected(investigation_id, sample_id, note, principal.user_id, now)
        self.repo.journal_add(
            investigation_id, "affected_explained", principal.user_id,
            {"sample_id": sample_id}, now,
        )
        return {"sample_id": sample_id, "explained": True}

    # -------------------------------------------------------------- evidence
    def add_evidence(self, principal: Principal, investigation_id: int, data: dict[str, Any]) -> dict[str, Any]:
        principal.require("investigations.manage")
        case = self.repo.get(investigation_id)
        if case["status"] in CLOSED_STATUSES:
            raise ConflictError("案件已结案")
        now = to_storage(self.clock.now())
        evidence, replayed = self.repo.add_evidence(investigation_id, data, data.get("idempotency_key"), principal.user_id, now)
        self.repo.journal_add(
            investigation_id, "evidence_added", principal.user_id,
            {"version": evidence["version"], "replayed": replayed}, now,
        )
        return {**evidence, "replayed": replayed}

    # ---------------------------------------------------------------- actions
    def create_action(self, principal: Principal, investigation_id: int, data: dict[str, Any]) -> dict[str, Any]:
        principal.require("investigations.manage")
        case = self.repo.get(investigation_id)
        if case["status"] in CLOSED_STATUSES:
            raise ConflictError("案件已结案")
        if data.get("assignee_user_id"):
            self._user_exists(data["assignee_user_id"])
        now = to_storage(self.clock.now())
        existing = self.repo.action_by_code(investigation_id, data["step_code"])
        if existing:
            return {**existing, "replayed": True}
        action = self.repo.create_action(investigation_id, data, principal.user_id, now)
        self.repo.journal_add(investigation_id, "action_created", principal.user_id, {"step_code": data["step_code"]}, now)
        return {**action, "replayed": False}

    def complete_action(self, principal: Principal, investigation_id: int, action_id: int, result: str) -> dict[str, Any]:
        principal.require("investigations.manage")
        action = self.repo.get_action(action_id)
        if action["investigation_id"] != investigation_id:
            raise NotFoundError("处置步骤不存在")
        now = to_storage(self.clock.now())
        updated = self.repo.complete_action(action_id, principal.user_id, result, now)
        self.repo.journal_add(investigation_id, "action_completed", principal.user_id, {"step_code": action["step_code"]}, now)
        return updated

    def cancel_action(self, principal: Principal, investigation_id: int, action_id: int) -> dict[str, Any]:
        principal.require("investigations.manage")
        action = self.repo.get_action(action_id)
        if action["investigation_id"] != investigation_id:
            raise NotFoundError("处置步骤不存在")
        now = to_storage(self.clock.now())
        return self.repo.cancel_action(action_id, now)

    # ---------------------------------------------------------------- closure
    def request_closure(self, principal: Principal, investigation_id: int, summary: str) -> dict[str, Any]:
        principal.require("investigations.manage")
        case = self.repo.get(investigation_id)
        if case["status"] == "pending_closure":
            raise ConflictError("案件已经在等待解除措施批准")
        if case["status"] in CLOSED_STATUSES:
            raise ConflictError("案件已结案")
        confirmed = [row for row in self.repo.affected_rows(investigation_id, status="confirmed")]
        unexplained = [row["sample_id"] for row in confirmed if not row["disposition_note"]]
        if unexplained:
            raise ConflictError("仍有受影响样品未逐项解释", context={"sample_ids": unexplained})
        pending = self.repo.actions(investigation_id, status="pending")
        if pending:
            raise ConflictError("仍有未完成的处置步骤，不能申请结案", context={"step_codes": [p["step_code"] for p in pending]})
        now = to_storage(self.clock.now())
        self.repo.set_status(
            investigation_id, "pending_closure", now,
            pre_closure_status=case["status"], closure_summary=summary,
            closure_requested_by=principal.user_id, closure_requested_at=now,
        )
        self.repo.journal_add(investigation_id, "closure_requested", principal.user_id, {"summary": summary}, now)
        self.audit.record(principal, "investigation.request_closure", "investigation", str(investigation_id), after=self.repo.get(investigation_id))
        return self.detail(principal, investigation_id)

    def decide_closure(self, principal: Principal, investigation_id: int, decision: str, comment: str) -> dict[str, Any]:
        principal.require("investigations.approve_release")
        case = self.repo.get(investigation_id)
        if case["status"] != "pending_closure":
            raise ConflictError("案件不在等待解除措施批准状态")
        if principal.user_id in {case["owner_user_id"], case["closure_requested_by"], case["created_by"]}:
            raise ConflictError("必须由责任人/申请人/创建人之外的另一名人员批准解除措施")
        now = to_storage(self.clock.now())
        if decision == "reject":
            fallback = case["pre_closure_status"] or "open"
            self.repo.set_status(
                investigation_id, fallback, now,
                pre_closure_status=None, closure_summary=None,
                closure_requested_by=None, closure_requested_at=None,
            )
            self.repo.journal_add(investigation_id, "closure_rejected", principal.user_id, {"comment": comment}, now)
            self.audit.record(principal, "investigation.closure_rejected", "investigation", str(investigation_id))
            return self.detail(principal, investigation_id)

        lifted = self._lift_all_measures(investigation_id, principal.user_id, now)
        self.repo.set_status(
            investigation_id, "closed", now,
            release_approved_by=principal.user_id, release_approved_at=now, closed_at=now,
        )
        self.repo.journal_add(
            investigation_id, "closed", principal.user_id,
            {"comment": comment, "lifted_sample_ids": lifted}, now,
        )
        self.audit.record(principal, "investigation.closed", "investigation", str(investigation_id), after=self.repo.get(investigation_id))
        return self.detail(principal, investigation_id)

    def _lift_all_measures(self, investigation_id: int, user_id: int, now: str) -> list[int]:
        lifted: list[int] = []
        for row in self.repo.affected_rows(investigation_id):
            if row["measure_status"] != "active":
                continue
            if row["measure"] == "quarantine":
                prior = row["prior_state"] or "available"
                self.connection.execute(
                    "UPDATE samples SET lifecycle_state=?,version=version+1,updated_at=? "
                    "WHERE id=? AND lifecycle_state='quarantined'",
                    (prior, now, row["sample_id"]),
                )
                self.samples.append_event(
                    row["sample_id"], "investigation.released", user_id, now,
                    from_state="quarantined", to_state=prior,
                    details={"investigation_id": investigation_id}, correlation_id=f"INV-{investigation_id}",
                )
            self.repo.mark_measure(investigation_id, row["sample_id"], "lifted", now, lifted_at=now)
            lifted.append(row["sample_id"])
        return lifted

    # --------------------------------------------------------------- helpers
    def _user_exists(self, user_id: int) -> None:
        row = self.connection.execute("SELECT id FROM users WHERE id=?", (user_id,)).fetchone()
        if not row:
            raise NotFoundError(f"用户 {user_id} 不存在")

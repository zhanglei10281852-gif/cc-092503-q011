from __future__ import annotations

import sqlite3
import uuid
from typing import Any

from app.core.clock import Clock, SystemClock, from_storage, to_storage
from app.core.errors import ConflictError, NotFoundError, ValidationError
from app.core.security import Principal
from app.samples.investigation_repository import SEVERITY_RANK, InvestigationRepository
from app.samples.repository import AnomalyRepository, SampleRepository
from app.services.audit import AuditService

INVESTIGATION_JOB_TYPES = ("investigation.candidate_scan", "investigation.overdue_check")

# 案件允许执行扫描、确认关联与执行措施的状态
ACTIVE_STATUSES = ("open", "investigating", "measures_applied")


def _normalize_due_at(value: str | None) -> str | None:
    if value is None:
        return None
    try:
        parsed = from_storage(value)
    except ValueError:
        raise ValidationError("截止时间格式不正确") from None
    if parsed is None:
        return None
    return to_storage(parsed)


def _merge_basis_detail(existing: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
    """合并关联依据明细：标识列表取并集，时间窗口保留最小间隔。合并是幂等的。"""
    merged: dict[str, Any] = {}
    for key in sorted(set(existing) | set(incoming)):
        old = existing.get(key)
        new = incoming.get(key)
        if old is None:
            merged[key] = new
            continue
        if new is None:
            merged[key] = old
            continue
        if key == "time_window":
            merged[key] = {
                "window_hours": new["window_hours"],
                "min_gap_seconds": min(old["min_gap_seconds"], new["min_gap_seconds"]),
            }
            continue
        combined: dict[str, Any] = {}
        for field in sorted(set(old) | set(new)):
            values = set()
            for source in (old.get(field), new.get(field)):
                if isinstance(source, list):
                    values.update(source)
                elif source is not None:
                    values.add(source)
            combined[field] = sorted(values)
        merged[key] = combined
    return merged


class InvestigationService:
    def __init__(self, connection: sqlite3.Connection, clock: Clock | None = None):
        self.connection = connection
        self.clock = clock or SystemClock()
        self.cases = InvestigationRepository(connection)
        self.anomalies = AnomalyRepository(connection)
        self.audit = AuditService(connection, self.clock)

    def _require_owner(self, user_id: int) -> None:
        if not self.connection.execute("SELECT 1 FROM users WHERE id=?", (user_id,)).fetchone():
            raise NotFoundError("责任人不存在")

    def create(self, principal: Principal, data: dict[str, Any]) -> dict[str, Any]:
        principal.require("anomalies.manage")
        self._require_owner(data["owner_user_id"])
        now = to_storage(self.clock.now())
        values = dict(data)
        values["due_at"] = _normalize_due_at(values.get("due_at"))
        case_code = values.get("case_code") or f"INV-{uuid.uuid4().hex[:12]}"
        case = self.cases.create_case(values, case_code, principal.user_id, now)
        for anomaly_id in dict.fromkeys(values.get("anomaly_ids", [])):
            anomaly = self.anomalies.get(anomaly_id)
            self.cases.insert_link(
                case["id"], anomaly_id, "confirmed", ["manual"],
                {"manual": {"reason": "创建案件时指定"}}, now, confirmed_by=principal.user_id,
            )
            self.connection.execute(
                "UPDATE anomaly_cases SET state='investigating',version=version+1,updated_at=? WHERE id=? AND state='open'",
                (now, anomaly_id),
            )
            self.cases.escalate_severity(case["id"], anomaly["severity"], now)
        if values.get("anomaly_ids"):
            self.cases.set_status(case["id"], "investigating", now)
        case = self.cases.get_case(case["id"])
        self.audit.record(principal, "investigation.create", "investigation_case", str(case["id"]), after=case)
        return case

    def update(self, principal: Principal, case_id: int, data: dict[str, Any]) -> dict[str, Any]:
        principal.require("anomalies.manage")
        case = self.cases.get_case(case_id)
        if case["status"] in ("closed", "dismissed"):
            raise ConflictError("案件已结束，不能修改")
        if data["expected_version"] != case["version"]:
            raise ConflictError("案件已被他人更新，请刷新后重试")
        now = to_storage(self.clock.now())
        fields: dict[str, Any] = {}
        for key in ("title", "hypothesis"):
            if data.get(key) is not None:
                fields[key] = data[key]
        if data.get("owner_user_id") is not None:
            self._require_owner(data["owner_user_id"])
            fields["owner_user_id"] = data["owner_user_id"]
        severity_applied: bool | None = None
        incoming = data.get("severity")
        if incoming is not None:
            if SEVERITY_RANK[incoming] > SEVERITY_RANK[case["severity"]]:
                fields["severity"] = incoming
                severity_applied = True
            else:
                # 严重度只升不降：旧更新携带的更低严重度被忽略，不覆盖已升级结果
                severity_applied = False
        if data.get("due_at") is not None:
            due_at = _normalize_due_at(data["due_at"])
            fields["due_at"] = due_at
            fields["overdue"] = 1 if due_at and due_at < now else 0
        if not fields:
            raise ValidationError("没有可更新的案件字段")
        assignments = ", ".join(f"{key}=?" for key in fields)
        cursor = self.connection.execute(
            f"UPDATE investigation_cases SET {assignments},version=version+1,updated_at=? WHERE id=? AND version=?",
            (*fields.values(), now, case_id, data["expected_version"]),
        )
        if cursor.rowcount != 1:
            raise ConflictError("案件已被他人更新，请刷新后重试")
        updated = self.cases.get_case(case_id)
        self.audit.record(
            principal, "investigation.update", "investigation_case", str(case_id),
            before=case, after=updated, metadata={"severity_applied": severity_applied},
        )
        return {**updated, "severity_applied": severity_applied}

    def dismiss(self, principal: Principal, case_id: int, reason: str) -> dict[str, Any]:
        principal.require("anomalies.manage")
        case = self.cases.get_case(case_id)
        if case["status"] not in ("open", "investigating"):
            raise ConflictError("已执行措施或已结案的案件不能排除")
        now = to_storage(self.clock.now())
        for link in self.cases.list_links(case_id, status="confirmed"):
            self.connection.execute(
                "UPDATE anomaly_cases SET state='open',version=version+1,updated_at=? WHERE id=? AND state='investigating'",
                (now, link["anomaly_id"]),
            )
        self.cases.set_status(case_id, "dismissed", now, dismiss_reason=reason)
        updated = self.cases.get_case(case_id)
        self.audit.record(
            principal, "investigation.dismiss", "investigation_case", str(case_id),
            before=case, after=updated, metadata={"reason": reason},
        )
        return updated

    def detail(self, principal: Principal, case_id: int) -> dict[str, Any]:
        principal.require("samples.read")
        case = self.cases.get_case(case_id)
        links = self.cases.list_links(case_id)
        affected = self.cases.list_case_samples(case_id)
        steps = self.cases.list_steps(case_id)
        pending_actions = {
            "unconfirmed_candidate_anomaly_ids": [link["anomaly_id"] for link in links if link["status"] == "candidate"],
            "samples_missing_disposition_ids": [row["sample_id"] for row in affected if row["measure_state"] == "active" and not row["disposition_note"]],
            "pending_step_ids": [step["id"] for step in steps if step["status"] != "done"],
            "active_measure_sample_ids": [row["sample_id"] for row in affected if row["measure_state"] == "active"],
            "overdue": bool(case["overdue"]),
        }
        return {
            "case": case,
            "links": links,
            "affected_samples": affected,
            "evidence": self.cases.list_evidence(case_id),
            "steps": steps,
            "release_decisions": self.cases.list_release_decisions(case_id),
            "pending_actions": pending_actions,
        }

    def list(self, principal: Principal, status: str | None, overdue: bool | None) -> list[dict[str, Any]]:
        principal.require("samples.read")
        return self.cases.list_cases(status, overdue)

    def add_evidence(self, principal: Principal, case_id: int, data: dict[str, Any]) -> dict[str, Any]:
        principal.require("anomalies.manage")
        case = self.cases.get_case(case_id)
        if case["status"] in ("closed", "dismissed"):
            raise ConflictError("案件已结束，不能追加证据")
        now = to_storage(self.clock.now())
        evidence = self.cases.append_evidence(case_id, data["content"], data.get("source_uri"), principal.user_id, now)
        self.cases.touch_case(case_id, now)
        self.audit.record(
            principal, "investigation.evidence.append", "investigation_case", str(case_id),
            metadata={"version_no": evidence["version_no"]},
        )
        return evidence

    def add_step(self, principal: Principal, case_id: int, data: dict[str, Any]) -> dict[str, Any]:
        principal.require("anomalies.manage")
        case = self.cases.get_case(case_id)
        if case["status"] in ("closed", "dismissed"):
            raise ConflictError("案件已结束，不能新增处置步骤")
        now = to_storage(self.clock.now())
        step = self.cases.append_step(case_id, data["description"], _normalize_due_at(data.get("due_at")), principal.user_id, now)
        self.cases.touch_case(case_id, now)
        self.audit.record(
            principal, "investigation.step.add", "investigation_case", str(case_id),
            metadata={"step_no": step["step_no"]},
        )
        return step

    def complete_step(self, principal: Principal, case_id: int, step_id: int) -> dict[str, Any]:
        principal.require("anomalies.manage")
        case = self.cases.get_case(case_id)
        if case["status"] in ("closed", "dismissed"):
            raise ConflictError("案件已结束，不能更新处置步骤")
        step = self.cases.get_step(case_id, step_id)
        now = to_storage(self.clock.now())
        self.cases.complete_step(step_id, principal.user_id, now)
        self.cases.touch_case(case_id, now)
        updated = self.cases.get_step(case_id, step_id)
        self.audit.record(
            principal, "investigation.step.complete", "investigation_case", str(case_id),
            before=step, after=updated,
        )
        return updated


class CandidateScanService:
    """按接收批次、保管位置、谱系祖先和时间窗口生成候选关联。重复扫描安全：已有关联只合并依据，不产生重复行。"""

    def __init__(self, connection: sqlite3.Connection, clock: Clock | None = None):
        self.connection = connection
        self.clock = clock or SystemClock()
        self.cases = InvestigationRepository(connection)
        self.audit = AuditService(connection, self.clock)

    def scan(self, case_id: int, window_hours: int = 24, actor: Principal | None = None) -> dict[str, Any]:
        case = self.cases.get_case(case_id)
        if case["status"] not in ACTIVE_STATUSES:
            raise ConflictError("当前状态不能执行候选扫描")
        seeds = self.cases.seed_anomalies(case_id)
        now = to_storage(self.clock.now())
        if not seeds:
            return {"case_id": case_id, "created_anomaly_ids": [], "merged_anomaly_ids": [], "skipped_dismissed_ids": [], "candidate_count": 0}
        seed_batch_ids = {seed["batch_id"] for seed in seeds if seed["batch_id"]}
        seed_batch_ids |= {seed["sample_batch_id"] for seed in seeds if seed["sample_batch_id"]}
        seed_location_ids = {seed["location_id"] for seed in seeds if seed["location_id"]}
        seed_root_ids = {seed["root_sample_id"] for seed in seeds if seed["root_sample_id"]}
        seed_times = [from_storage(seed["created_at"]) for seed in seeds]
        window_seconds = window_hours * 3600
        existing = self.cases.link_map(case_id)
        created_ids: list[int] = []
        merged_ids: list[int] = []
        skipped_dismissed: list[int] = []
        for anomaly in self.cases.scannable_anomalies():
            basis: list[str] = []
            detail: dict[str, Any] = {}
            batches = {anomaly["batch_id"], anomaly["sample_batch_id"]} - {None}
            shared_batches = sorted(batches & seed_batch_ids)
            if shared_batches:
                basis.append("batch")
                detail["batch"] = {"batch_ids": shared_batches}
            if anomaly["location_id"] and anomaly["location_id"] in seed_location_ids:
                basis.append("location")
                detail["location"] = {"location_ids": [anomaly["location_id"]]}
            if anomaly["root_sample_id"] and anomaly["root_sample_id"] in seed_root_ids:
                basis.append("lineage")
                detail["lineage"] = {"root_sample_ids": [anomaly["root_sample_id"]]}
            created_at = from_storage(anomaly["created_at"])
            gap = min(abs((created_at - seed).total_seconds()) for seed in seed_times)
            if gap <= window_seconds:
                basis.append("time_window")
                detail["time_window"] = {"window_hours": window_hours, "min_gap_seconds": int(gap)}
            if not basis:
                continue
            link = existing.get(anomaly["id"])
            if link is None:
                self.cases.insert_link(case_id, anomaly["id"], "candidate", basis, detail, now)
                created_ids.append(anomaly["id"])
            elif link["status"] == "confirmed":
                continue  # 已确认关联是扫描种子，不与自身匹配
            elif link["status"] == "dismissed":
                skipped_dismissed.append(anomaly["id"])
            else:
                merged_basis = sorted(set(link["basis"]) | set(basis))
                merged_detail = _merge_basis_detail(link["basis_detail"], detail)
                if merged_basis != link["basis"] or merged_detail != link["basis_detail"]:
                    self.cases.update_link(link["id"], now, basis=merged_basis, basis_detail=merged_detail)
                    merged_ids.append(anomaly["id"])
        candidate_count = len(self.cases.list_links(case_id, status="candidate"))
        result = {
            "case_id": case_id,
            "created_anomaly_ids": created_ids,
            "merged_anomaly_ids": merged_ids,
            "skipped_dismissed_ids": skipped_dismissed,
            "candidate_count": candidate_count,
        }
        if created_ids or merged_ids:
            self.cases.touch_case(case_id, now)
        self.audit.record(
            actor, "investigation.scan", "investigation_case", str(case_id),
            metadata={"window_hours": window_hours, **result},
        )
        return result


class CaseLinkService:
    def __init__(self, connection: sqlite3.Connection, clock: Clock | None = None):
        self.connection = connection
        self.clock = clock or SystemClock()
        self.cases = InvestigationRepository(connection)
        self.anomalies = AnomalyRepository(connection)
        self.audit = AuditService(connection, self.clock)

    def confirm(self, principal: Principal, case_id: int, anomaly_ids: list[int]) -> dict[str, Any]:
        principal.require("anomalies.manage")
        case = self.cases.get_case(case_id)
        if case["status"] not in ACTIVE_STATUSES:
            raise ConflictError("当前状态不能确认关联")
        now = to_storage(self.clock.now())
        confirmed: list[int] = []
        created_manual: list[int] = []
        for anomaly_id in dict.fromkeys(anomaly_ids):
            anomaly = self.anomalies.get(anomaly_id)
            link = self.cases.get_link(case_id, anomaly_id)
            if link is None:
                self.cases.insert_link(
                    case_id, anomaly_id, "confirmed", ["manual"],
                    {"manual": {"reason": "人工确认时直接指定"}}, now, confirmed_by=principal.user_id,
                )
                created_manual.append(anomaly_id)
            elif link["status"] == "candidate":
                self.cases.update_link(link["id"], now, status="confirmed", confirmed_by=principal.user_id)
                confirmed.append(anomaly_id)
            elif link["status"] == "confirmed":
                continue
            else:
                raise ConflictError("关联已被排除，不能确认", context={"anomaly_id": anomaly_id})
            self.connection.execute(
                "UPDATE anomaly_cases SET state='investigating',version=version+1,updated_at=? WHERE id=? AND state='open'",
                (now, anomaly_id),
            )
            # 严重度单调升级：案件严重度不低于任何已确认异常
            self.cases.escalate_severity(case_id, anomaly["severity"], now)
        if confirmed or created_manual:
            if case["status"] in ("open", "measures_applied"):
                self.cases.set_status(case_id, "investigating", now)
            else:
                self.cases.touch_case(case_id, now)
        self.audit.record(
            principal, "investigation.links.confirm", "investigation_case", str(case_id),
            metadata={"confirmed_anomaly_ids": confirmed, "created_manual_ids": created_manual},
        )
        return {
            "confirmed_anomaly_ids": confirmed,
            "created_manual_ids": created_manual,
            "case": self.cases.get_case(case_id),
        }

    def dismiss_link(self, principal: Principal, case_id: int, anomaly_id: int) -> dict[str, Any]:
        principal.require("anomalies.manage")
        case = self.cases.get_case(case_id)
        if case["status"] not in ACTIVE_STATUSES:
            raise ConflictError("当前状态不能排除关联")
        link = self.cases.get_link(case_id, anomaly_id)
        if link is None:
            raise NotFoundError("关联不存在")
        if link["status"] != "candidate":
            raise ConflictError("只能排除候选状态的关联")
        now = to_storage(self.clock.now())
        self.cases.update_link(link["id"], now, status="dismissed")
        self.cases.touch_case(case_id, now)
        self.audit.record(
            principal, "investigation.links.dismiss", "investigation_case", str(case_id),
            metadata={"anomaly_id": anomaly_id},
        )
        return self.cases.get_link(case_id, anomaly_id)


class CaseMeasureService:
    def __init__(self, connection: sqlite3.Connection, clock: Clock | None = None):
        self.connection = connection
        self.clock = clock or SystemClock()
        self.cases = InvestigationRepository(connection)
        self.samples = SampleRepository(connection)
        self.audit = AuditService(connection, self.clock)

    def apply(self, principal: Principal, case_id: int, measure: str) -> dict[str, Any]:
        principal.require("anomalies.manage")
        case = self.cases.get_case(case_id)
        if case["status"] not in ("investigating", "measures_applied"):
            raise ConflictError("需要先确认关联异常后再统一执行措施")
        links = self.cases.list_links(case_id, status="confirmed")
        if not links:
            raise ConflictError("没有已确认的关联异常")
        affected: dict[int, set[str]] = {}
        for link in links:
            basis = set(link["basis"])
            if link["sample_id"]:
                affected.setdefault(link["sample_id"], set()).update(basis)
            if link["batch_id"]:
                rows = self.connection.execute(
                    "SELECT id FROM samples WHERE batch_id=? AND lifecycle_state NOT IN ('destroyed','consumed') ORDER BY id",
                    (link["batch_id"],),
                ).fetchall()
                for row in rows:
                    affected.setdefault(int(row[0]), set()).update(basis | {"batch"})
        if not affected:
            raise ConflictError("已确认异常没有可作用的在库样品")
        now = to_storage(self.clock.now())
        applied: list[int] = []
        skipped: list[int] = []
        upgraded: list[int] = []
        for sample_id in sorted(affected):
            sample = self.samples.get(sample_id)
            basis = sorted(affected[sample_id])
            existing = self.cases.get_case_sample(case_id, sample_id)
            if existing:
                merged_basis = sorted(set(existing["basis"]) | set(basis))
                if existing["measure"] == measure:
                    if merged_basis != existing["basis"]:
                        self.cases.update_case_sample(existing["id"], now, basis_json=merged_basis)
                    skipped.append(sample_id)
                    continue
                if existing["measure"] == "observe" and measure == "quarantine":
                    previous = sample["lifecycle_state"] if sample["lifecycle_state"] != "quarantined" else existing["previous_lifecycle_state"]
                    self.cases.update_case_sample(
                        existing["id"], now, measure="quarantine", basis_json=merged_basis,
                        previous_lifecycle_state=previous,
                    )
                    self._quarantine_sample(sample, case, principal, now)
                    upgraded.append(sample_id)
                    continue
                raise ConflictError("样品已处于隔离措施，不能降级为观察", context={"sample_id": sample_id})
            self.cases.insert_case_sample(
                case_id, sample_id, measure, basis,
                sample["lifecycle_state"] if measure == "quarantine" else None,
                principal.user_id, now,
            )
            if measure == "quarantine":
                self._quarantine_sample(sample, case, principal, now)
            applied.append(sample_id)
        self.cases.set_status(case_id, "measures_applied", now)
        result = {
            "measure": measure,
            "applied_sample_ids": applied,
            "skipped_sample_ids": skipped,
            "upgraded_sample_ids": upgraded,
        }
        self.audit.record(
            principal, "investigation.measures.apply", "investigation_case", str(case_id),
            metadata=result,
        )
        return {**result, "case": self.cases.get_case(case_id)}

    def _quarantine_sample(self, sample: dict[str, Any], case: dict[str, Any], principal: Principal, now: str) -> None:
        cursor = self.connection.execute(
            """UPDATE samples SET lifecycle_state='quarantined',version=version+1,updated_at=?
               WHERE id=? AND lifecycle_state NOT IN ('destroyed','consumed','quarantined')""",
            (now, sample["id"]),
        )
        if cursor.rowcount == 1:
            self.samples.append_event(
                sample["id"], "quarantined", principal.user_id, now,
                from_state=sample["lifecycle_state"], to_state="quarantined",
                details={"case_id": case["id"], "case_code": case["case_code"]},
            )

    def set_disposition(self, principal: Principal, case_id: int, sample_id: int, note: str) -> dict[str, Any]:
        principal.require("anomalies.manage")
        case = self.cases.get_case(case_id)
        if case["status"] not in ("investigating", "measures_applied"):
            raise ConflictError("当前状态不能登记样品处置说明")
        row = self.cases.get_case_sample(case_id, sample_id)
        if row is None:
            raise NotFoundError("样品不在案件影响范围内")
        now = to_storage(self.clock.now())
        self.cases.update_case_sample(
            row["id"], now, disposition_note=note,
            disposition_by=principal.user_id, disposition_at=now,
        )
        self.cases.touch_case(case_id, now)
        self.audit.record(
            principal, "investigation.samples.disposition", "investigation_case", str(case_id),
            metadata={"sample_id": sample_id},
        )
        return self.cases.get_case_sample(case_id, sample_id)


class CaseClosureService:
    def __init__(self, connection: sqlite3.Connection, clock: Clock | None = None):
        self.connection = connection
        self.clock = clock or SystemClock()
        self.cases = InvestigationRepository(connection)
        self.samples = SampleRepository(connection)
        self.audit = AuditService(connection, self.clock)

    def request_close(self, principal: Principal, case_id: int, note: str) -> dict[str, Any]:
        principal.require("anomalies.manage")
        case = self.cases.get_case(case_id)
        if case["status"] != "measures_applied":
            raise ConflictError("案件需要先统一执行措施后才能申请结案")
        blockers: dict[str, Any] = {}
        confirmed = self.cases.list_links(case_id, status="confirmed")
        if not confirmed:
            blockers["confirmed_links"] = "缺少已确认关联"
        candidates = self.cases.list_links(case_id, status="candidate")
        if candidates:
            blockers["pending_candidate_anomaly_ids"] = [link["anomaly_id"] for link in candidates]
        missing = [row["sample_id"] for row in self.cases.list_case_samples(case_id) if not row["disposition_note"]]
        if missing:
            blockers["samples_missing_disposition_ids"] = missing
        pending_steps = [step["id"] for step in self.cases.list_steps(case_id) if step["status"] != "done"]
        if pending_steps:
            blockers["pending_step_ids"] = pending_steps
        if blockers:
            raise ConflictError("结案条件未满足", context=blockers)
        now = to_storage(self.clock.now())
        self.cases.set_status(
            case_id, "release_pending", now,
            close_requested_by=principal.user_id, close_requested_at=now, close_note=note,
        )
        updated = self.cases.get_case(case_id)
        self.audit.record(
            principal, "investigation.close.request", "investigation_case", str(case_id),
            before=case, after=updated,
        )
        return updated

    def decide_release(self, principal: Principal, case_id: int, decision: str, comment: str) -> dict[str, Any]:
        principal.require("approvals.decide")
        case = self.cases.get_case(case_id)
        if case["status"] != "release_pending":
            raise ConflictError("案件不在待解除审批状态")
        if case["close_requested_by"] == principal.user_id:
            raise ValidationError("解除措施必须由另一名人员批准")
        now = to_storage(self.clock.now())
        record = self.cases.append_release_decision(
            case_id, "approved" if decision == "approve" else "rejected", comment, principal.user_id, now
        )
        if decision == "reject":
            self.cases.set_status(case_id, "measures_applied", now, close_requested_by=None, close_requested_at=None)
            updated = self.cases.get_case(case_id)
            self.audit.record(
                principal, "investigation.release.rejected", "investigation_case", str(case_id),
                before=case, after=updated, metadata={"comment": comment},
            )
            return {"case": updated, "released_sample_ids": [], "decision": record}
        released: list[int] = []
        for row in self.cases.list_case_samples(case_id, measure_state="active"):
            self._release_measure(case, row, principal, now)
            released.append(row["sample_id"])
        for link in self.cases.list_links(case_id, status="confirmed"):
            self.connection.execute(
                """UPDATE anomaly_cases SET state='resolved',resolution=?,version=version+1,updated_at=?
                   WHERE id=? AND state NOT IN ('resolved','dismissed')""",
                (f"调查案件 {case['case_code']} 结案", now, link["anomaly_id"]),
            )
        self.cases.set_status(case_id, "closed", now, closed_at=now)
        updated = self.cases.get_case(case_id)
        self.audit.record(
            principal, "investigation.release.approved", "investigation_case", str(case_id),
            before=case, after=updated, metadata={"released_sample_ids": released},
        )
        return {"case": updated, "released_sample_ids": released, "decision": record}

    def _release_measure(self, case: dict[str, Any], row: dict[str, Any], principal: Principal, now: str) -> None:
        self.cases.update_case_sample(
            row["id"], now, measure_state="released",
            released_by=principal.user_id, released_at=now,
        )
        if row["measure"] != "quarantine":
            return
        sample = self.samples.get(row["sample_id"])
        if sample["lifecycle_state"] != "quarantined":
            return
        if self.cases.active_quarantine_count(row["sample_id"]):
            return  # 其他案件仍在隔离该样品，不能提前恢复
        target = self.cases.earliest_quarantine_previous(row["sample_id"]) or "available"
        cursor = self.connection.execute(
            "UPDATE samples SET lifecycle_state=?,version=version+1,updated_at=? WHERE id=? AND lifecycle_state='quarantined'",
            (target, now, row["sample_id"]),
        )
        if cursor.rowcount == 1:
            self.samples.append_event(
                row["sample_id"], "quarantine.released", principal.user_id, now,
                from_state="quarantined", to_state=target,
                details={"case_id": case["id"], "case_code": case["case_code"]},
            )


class OverdueScanService:
    """逾期检查：标记超过截止时间的未结案件。条件更新保证重复执行安全。"""

    def __init__(self, connection: sqlite3.Connection, clock: Clock | None = None):
        self.connection = connection
        self.clock = clock or SystemClock()
        self.cases = InvestigationRepository(connection)
        self.audit = AuditService(connection, self.clock)

    def check(self, actor: Principal | None = None) -> dict[str, Any]:
        now = to_storage(self.clock.now())
        marked = self.cases.mark_overdue(now)
        for case_id in marked:
            self.audit.record(
                actor, "investigation.overdue", "investigation_case", str(case_id),
                metadata={"marked_overdue": True},
            )
        return {"marked_case_ids": marked, "marked_count": len(marked)}


class InvestigationJobHandler:
    """调查后台任务处理器：候选扫描与逾期检查均为幂等操作，逾期任务被重新领取后可安全重跑。"""

    def __init__(self, connection: sqlite3.Connection, clock: Clock | None = None):
        self.connection = connection
        self.clock = clock or SystemClock()

    def execute(self, job_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        if job_type == "investigation.candidate_scan":
            return CandidateScanService(self.connection, self.clock).scan(
                int(payload["case_id"]), int(payload.get("window_hours", 24))
            )
        if job_type == "investigation.overdue_check":
            return OverdueScanService(self.connection, self.clock).check()
        raise ValidationError(f"未知的调查任务类型：{job_type}")

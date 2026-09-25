from __future__ import annotations

import json
import sqlite3
from typing import Any

from app.core.clock import Clock, SystemClock, to_storage
from app.core.security import Principal
from app.investigations.association import AssociationService
from app.investigations.repository import InvestigationRepository
from app.services.audit import AuditContext, AuditService
from app.services.jobs import JobService

SCAN_JOB_TYPE = "investigation.association_scan"
OVERDUE_JOB_TYPE = "investigation.overdue_sweep"

ACTIVE_WORK_STATUSES = ("open", "observing", "contained", "pending_closure")


class InvestigationJobs:
    """调查案件的后台任务：候选关联扫描与逾期巡检。

    所有写入都走自然唯一键 upsert 或幂等键，任务被重复领取（如租约过期后重跑）
    不会产生重复候选、重复日志或重复通知。
    """

    def __init__(self, connection: sqlite3.Connection, clock: Clock | None = None):
        self.connection = connection
        self.clock = clock or SystemClock()
        self.jobs = JobService(connection, self.clock)

    def enqueue_scan(self, investigation_id: int, query: dict[str, Any]) -> dict[str, Any]:
        dedupe_key = (
            f"investigation-scan:{investigation_id}:"
            f"{query.get('batch_id') or '-'}:{query.get('location_id') or '-'}:"
            f"{query.get('root_sample_id') or '-'}:{query.get('window_hours', 72)}"
        )
        payload = {"investigation_id": investigation_id, "query": query}
        return self.jobs.enqueue(SCAN_JOB_TYPE, dedupe_key, payload)

    def enqueue_overdue_sweep(self) -> dict[str, Any]:
        today = to_storage(self.clock.now())[:10]
        return self.jobs.enqueue(OVERDUE_JOB_TYPE, f"investigation-overdue:{today}", {"date": today})

    def dispatch(self, job: dict[str, Any]) -> dict[str, Any]:
        if job["job_type"] == SCAN_JOB_TYPE:
            return self.process_scan(job)
        if job["job_type"] == OVERDUE_JOB_TYPE:
            return self.process_overdue(job)
        raise ValueError(f"未知任务类型：{job['job_type']}")

    def process_scan(self, job: dict[str, Any]) -> dict[str, Any]:
        payload = json.loads(job["payload_json"])
        investigation_id = int(payload["investigation_id"])
        query = payload.get("query", {})
        repo = InvestigationRepository(self.connection)
        case = self.connection.execute("SELECT * FROM investigations WHERE id=?", (investigation_id,)).fetchone()
        if not case:
            return {"skipped": "investigation_missing", "investigation_id": investigation_id}
        if case["status"] in ("closed", "dismissed"):
            return {"skipped": "investigation_closed", "investigation_id": investigation_id}
        system_principal = Principal(
            user_id=0, username="system", display_name="关联扫描任务",
            department_id=None, permissions=frozenset({"*"}), session_id=0,
        )
        proposal = AssociationService(self.connection, self.clock).propose(system_principal, query)
        now = to_storage(self.clock.now())
        for candidate in proposal["anomaly_candidates"]:
            repo.link_anomaly(investigation_id, candidate["anomaly_id"], {"reasons": candidate["basis"]}, now)
        for candidate in proposal["sample_candidates"]:
            repo.upsert_affected(investigation_id, candidate["sample_id"], {"reasons": candidate["basis"]}, now)
        journal = repo.journal_add(
            investigation_id, "candidates_scanned", None,
            {"job_id": job["id"], "anomaly_candidates": len(proposal["anomaly_candidates"]),
             "sample_candidates": len(proposal["sample_candidates"]), "dimensions": proposal["dimensions"]},
            now, idempotency_key=f"scan:{job['id']}",
        )
        return {
            "investigation_id": investigation_id,
            "anomaly_candidates": len(proposal["anomaly_candidates"]),
            "sample_candidates": len(proposal["sample_candidates"]),
            "journal_id": journal["id"],
        }

    def process_overdue(self, job: dict[str, Any]) -> dict[str, Any]:
        repo = InvestigationRepository(self.connection)
        now_dt = self.clock.now()
        now = to_storage(now_dt)
        day = now[:10]
        rows = self.connection.execute(
            """SELECT id,case_code,owner_user_id,due_at,severity FROM investigations
               WHERE status NOT IN ('closed','dismissed') AND due_at IS NOT NULL AND due_at<?
               ORDER BY due_at""",
            (now,),
        ).fetchall()
        flagged: list[dict[str, Any]] = []
        for row in rows:
            entry = repo.journal_add(
                row["id"], "overdue_flagged", None,
                {"job_id": job["id"], "due_at": row["due_at"], "severity": row["severity"]},
                now, idempotency_key=f"overdue:{row['id']}:{day}",
            )
            flagged.append({"investigation_id": row["id"], "case_code": row["case_code"], "journal_id": entry["id"]})
        AuditService(self.connection, self.clock).record(
            AuditContext(actor_user_id=None, actor_name="逾期巡检任务"),
            "investigation.overdue_sweep", "investigation", None,
            metadata={"job_id": job["id"], "overdue_count": len(flagged)},
        )
        return {"overdue_count": len(flagged), "overdue_cases": flagged}


def run_pending_jobs(connection: sqlite3.Connection, worker: str = "investigation-worker", *, limit: int = 10) -> list[dict[str, Any]]:
    """领取并执行至多 limit 个调查相关任务，供 CLI/测试驱动。"""
    jobs = JobService(connection)
    handler = InvestigationJobs(connection)
    results: list[dict[str, Any]] = []
    handled_types = {SCAN_JOB_TYPE, OVERDUE_JOB_TYPE}
    for _ in range(limit):
        job = jobs.claim(worker)
        if job is None:
            break
        if job["job_type"] not in handled_types:
            jobs.fail(job["id"], worker, "非调查任务，跳过", retry_seconds=300)
            continue
        try:
            result = handler.dispatch(job)
            jobs.complete(job["id"], worker, result)
            results.append({"job_id": job["id"], "job_type": job["job_type"], "result": result})
        except Exception as exc:  # noqa: BLE001 - 任务失败后回到队列稍后重试
            jobs.fail(job["id"], worker, str(exc), retry_seconds=60)
            results.append({"job_id": job["id"], "job_type": job["job_type"], "error": str(exc)})
    return results

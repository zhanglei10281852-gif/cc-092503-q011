from __future__ import annotations

from fastapi import APIRouter, Depends

from app.api.dependencies import current_principal
from app.core.security import Principal
from app.database import get_connection, transaction
from app.investigations.jobs import InvestigationJobs, run_pending_jobs
from app.services.jobs import JobService

router = APIRouter(prefix="/api/system", tags=["系统运维"])


@router.get("/health")
def health() -> dict:
    connection = get_connection()
    foreign_keys = int(connection.execute("PRAGMA foreign_keys").fetchone()[0])
    journal_mode = str(connection.execute("PRAGMA journal_mode").fetchone()[0])
    return {"status": "ok", "foreign_keys": foreign_keys, "journal_mode": journal_mode}


@router.post("/jobs/example", status_code=201)
def enqueue_example(principal: Principal = Depends(current_principal)) -> dict:
    principal.require("jobs.run")
    with transaction(immediate=True) as connection:
        return JobService(connection).enqueue("system.example", f"example:{principal.user_id}", {"actor": principal.user_id})


@router.post("/investigations/overdue-sweep", status_code=201)
def enqueue_overdue_sweep(principal: Principal = Depends(current_principal)) -> dict:
    principal.require("investigations.manage")
    with transaction(immediate=True) as connection:
        return InvestigationJobs(connection).enqueue_overdue_sweep()


@router.post("/investigations/run-jobs")
def run_investigation_jobs(principal: Principal = Depends(current_principal)) -> dict:
    principal.require("jobs.run")
    with transaction(immediate=True) as connection:
        return {"results": run_pending_jobs(connection, worker=f"api:{principal.user_id}")}

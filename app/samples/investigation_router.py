from __future__ import annotations

import json

from fastapi import APIRouter, Depends, Query, status

from app.api.dependencies import current_principal
from app.core.clock import SystemClock, to_storage
from app.core.errors import DomainError
from app.core.security import Principal
from app.database import get_connection, transaction
from app.samples.investigation_repository import InvestigationRepository
from app.samples.investigation_schemas import (
    CloseRequestCreate,
    DispositionWrite,
    DismissRequest,
    EvidenceCreate,
    InvestigationCreate,
    InvestigationUpdate,
    LinkConfirm,
    MeasureApply,
    ReleaseDecisionCreate,
    ScanJobCreate,
    ScanRequest,
    StepCreate,
)
from app.samples.investigations import (
    INVESTIGATION_JOB_TYPES,
    CandidateScanService,
    CaseClosureService,
    CaseLinkService,
    CaseMeasureService,
    InvestigationJobHandler,
    InvestigationService,
    OverdueScanService,
)
from app.services.jobs import JobService

router = APIRouter(prefix="/api/investigations", tags=["调查案件"])


@router.post("", status_code=status.HTTP_201_CREATED)
def create_investigation(payload: InvestigationCreate, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return InvestigationService(connection).create(principal, payload.model_dump())


@router.get("")
def list_investigations(
    status_filter: str | None = Query(default=None, alias="status"),
    overdue: bool | None = Query(default=None),
    principal: Principal = Depends(current_principal),
):
    return InvestigationService(get_connection()).list(principal, status_filter, overdue)


@router.post("/overdue-checks")
def run_overdue_check(principal: Principal = Depends(current_principal)):
    principal.require("anomalies.manage")
    with transaction(immediate=True) as connection:
        return OverdueScanService(connection).check(actor=principal)


@router.post("/overdue-check-jobs", status_code=status.HTTP_201_CREATED)
def enqueue_overdue_check_job(principal: Principal = Depends(current_principal)):
    principal.require("anomalies.manage")
    with transaction(immediate=True) as connection:
        clock = SystemClock()
        return JobService(connection, clock).enqueue(
            "investigation.overdue_check",
            f"investigation.overdue_check:{to_storage(clock.now())[:10]}",
            {},
        )


@router.post("/jobs/run-due")
def run_due_investigation_jobs(principal: Principal = Depends(current_principal)):
    """领取并执行到期的调查后台任务。扫描与逾期检查均幂等，逾期被重新领取的任务可安全重跑。"""
    principal.require("anomalies.manage")
    processed = []
    with transaction(immediate=True) as connection:
        clock = SystemClock()
        jobs = JobService(connection, clock)
        handler = InvestigationJobHandler(connection, clock)
        worker = f"api-worker-{principal.user_id}"
        for _ in range(50):
            job = jobs.claim(worker, job_types=INVESTIGATION_JOB_TYPES)
            if job is None:
                break
            try:
                result = handler.execute(job["job_type"], json.loads(job["payload_json"]))
            except DomainError as exc:
                jobs.fail(job["id"], worker, exc.message)
                processed.append({"job_id": job["id"], "job_type": job["job_type"], "status": "failed", "error": exc.message})
            else:
                jobs.complete(job["id"], worker, result)
                processed.append({"job_id": job["id"], "job_type": job["job_type"], "status": "completed", "result": result})
    return {"processed": processed}


@router.get("/{case_id}")
def investigation_detail(case_id: int, principal: Principal = Depends(current_principal)):
    return InvestigationService(get_connection()).detail(principal, case_id)


@router.patch("/{case_id}")
def update_investigation(case_id: int, payload: InvestigationUpdate, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return InvestigationService(connection).update(principal, case_id, payload.model_dump())


@router.post("/{case_id}/dismiss")
def dismiss_investigation(case_id: int, payload: DismissRequest, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return InvestigationService(connection).dismiss(principal, case_id, payload.reason)


@router.post("/{case_id}/evidence", status_code=status.HTTP_201_CREATED)
def append_evidence(case_id: int, payload: EvidenceCreate, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return InvestigationService(connection).add_evidence(principal, case_id, payload.model_dump())


@router.post("/{case_id}/steps", status_code=status.HTTP_201_CREATED)
def append_step(case_id: int, payload: StepCreate, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return InvestigationService(connection).add_step(principal, case_id, payload.model_dump())


@router.post("/{case_id}/steps/{step_id}/complete")
def complete_step(case_id: int, step_id: int, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return InvestigationService(connection).complete_step(principal, case_id, step_id)


@router.post("/{case_id}/scans")
def run_candidate_scan(case_id: int, payload: ScanRequest, principal: Principal = Depends(current_principal)):
    principal.require("anomalies.manage")
    with transaction(immediate=True) as connection:
        return CandidateScanService(connection).scan(case_id, payload.window_hours, actor=principal)


@router.post("/{case_id}/scan-jobs", status_code=status.HTTP_201_CREATED)
def enqueue_scan_job(case_id: int, payload: ScanJobCreate, principal: Principal = Depends(current_principal)):
    principal.require("anomalies.manage")
    data = payload.model_dump()
    with transaction(immediate=True) as connection:
        InvestigationRepository(connection).get_case(case_id)
        clock = SystemClock()
        token = data.get("scan_token") or to_storage(clock.now())[:10]
        return JobService(connection, clock).enqueue(
            "investigation.candidate_scan",
            f"investigation.candidate_scan:{case_id}:{token}",
            {"case_id": case_id, "window_hours": data["window_hours"]},
        )


@router.post("/{case_id}/links/confirm")
def confirm_links(case_id: int, payload: LinkConfirm, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return CaseLinkService(connection).confirm(principal, case_id, payload.anomaly_ids)


@router.post("/{case_id}/links/{anomaly_id}/dismiss")
def dismiss_link(case_id: int, anomaly_id: int, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return CaseLinkService(connection).dismiss_link(principal, case_id, anomaly_id)


@router.post("/{case_id}/measures/apply")
def apply_measures(case_id: int, payload: MeasureApply, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return CaseMeasureService(connection).apply(principal, case_id, payload.measure)


@router.post("/{case_id}/samples/{sample_id}/disposition")
def write_disposition(case_id: int, sample_id: int, payload: DispositionWrite, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return CaseMeasureService(connection).set_disposition(principal, case_id, sample_id, payload.note)


@router.post("/{case_id}/close-requests")
def request_close(case_id: int, payload: CloseRequestCreate, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return CaseClosureService(connection).request_close(principal, case_id, payload.note)


@router.post("/{case_id}/release-decisions")
def decide_release(case_id: int, payload: ReleaseDecisionCreate, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return CaseClosureService(connection).decide_release(principal, case_id, payload.decision, payload.comment)

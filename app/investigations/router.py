from __future__ import annotations

from fastapi import APIRouter, Depends, Query, status

from app.api.dependencies import current_principal
from app.core.security import Principal
from app.database import get_connection, transaction
from app.investigations.jobs import InvestigationJobs
from app.investigations.schemas import (
    ActionComplete,
    ActionCreate,
    AffectedConfirmRequest,
    AnomalyLinkRequest,
    CandidateQuery,
    ClosureDecision,
    ClosureRequest,
    EvidenceCreate,
    ExplainRequest,
    InvestigationCreate,
    InvestigationUpdate,
    MeasureApplyRequest,
)
from app.investigations.service import InvestigationService

router = APIRouter(prefix="/api/investigations", tags=["调查案件"])


@router.post("", status_code=status.HTTP_201_CREATED)
def create_investigation(payload: InvestigationCreate, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return InvestigationService(connection).create(principal, payload.model_dump())


@router.get("")
def list_investigations(
    state: str | None = Query(default=None),
    overdue: bool = Query(default=False),
    owner_user_id: int | None = Query(default=None),
    principal: Principal = Depends(current_principal),
):
    return InvestigationService(get_connection()).list(
        principal, status=state, overdue_only=overdue, owner_user_id=owner_user_id
    )


@router.get("/{investigation_id}")
def get_investigation(investigation_id: int, principal: Principal = Depends(current_principal)):
    return InvestigationService(get_connection()).detail(principal, investigation_id)


@router.patch("/{investigation_id}")
def update_investigation(investigation_id: int, payload: InvestigationUpdate, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return InvestigationService(connection).update(principal, investigation_id, payload.model_dump(exclude_unset=True))


@router.post("/associations/preview")
def preview_candidates(payload: CandidateQuery, principal: Principal = Depends(current_principal)):
    return InvestigationService(get_connection()).candidates(principal, payload.model_dump(exclude_unset=True))


@router.post("/{investigation_id}/associations/import")
def import_candidates(investigation_id: int, payload: CandidateQuery, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return InvestigationService(connection).import_candidates(principal, investigation_id, payload.model_dump(exclude_unset=True))


@router.post("/{investigation_id}/associations/scan-jobs", status_code=status.HTTP_201_CREATED)
def enqueue_scan_job(investigation_id: int, payload: CandidateQuery, principal: Principal = Depends(current_principal)):
    principal.require("investigations.manage")
    query = payload.model_dump(exclude_unset=True)
    with transaction(immediate=True) as connection:
        return InvestigationJobs(connection).enqueue_scan(investigation_id, query)


@router.post("/{investigation_id}/anomalies")
def link_anomalies(investigation_id: int, payload: AnomalyLinkRequest, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return InvestigationService(connection).add_anomalies(principal, investigation_id, payload.anomaly_ids)


@router.post("/{investigation_id}/anomalies/confirm")
def confirm_anomalies(investigation_id: int, payload: AnomalyLinkRequest, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return InvestigationService(connection).confirm_anomalies(principal, investigation_id, payload.anomaly_ids)


@router.post("/{investigation_id}/anomalies/{anomaly_id}/exclude")
def exclude_anomaly(investigation_id: int, anomaly_id: int, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return InvestigationService(connection).exclude_anomaly(principal, investigation_id, anomaly_id)


@router.post("/{investigation_id}/affected/confirm")
def confirm_affected(investigation_id: int, payload: AffectedConfirmRequest, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return InvestigationService(connection).confirm_affected(principal, investigation_id, payload.model_dump()["items"])


@router.post("/{investigation_id}/affected/{sample_id}/exclude")
def exclude_affected(investigation_id: int, sample_id: int, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return InvestigationService(connection).exclude_affected(principal, investigation_id, sample_id)


@router.post("/{investigation_id}/affected/{sample_id}/explain")
def explain_affected(investigation_id: int, sample_id: int, payload: ExplainRequest, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return InvestigationService(connection).explain_affected(principal, investigation_id, sample_id, payload.note)


@router.post("/{investigation_id}/measures/apply")
def apply_measures(investigation_id: int, payload: MeasureApplyRequest, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return InvestigationService(connection).apply_measures(principal, investigation_id, payload.measure, payload.sample_ids)


@router.post("/{investigation_id}/evidence")
def add_evidence(investigation_id: int, payload: EvidenceCreate, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return InvestigationService(connection).add_evidence(principal, investigation_id, payload.model_dump())


@router.post("/{investigation_id}/actions", status_code=status.HTTP_201_CREATED)
def create_action(investigation_id: int, payload: ActionCreate, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return InvestigationService(connection).create_action(principal, investigation_id, payload.model_dump())


@router.post("/{investigation_id}/actions/{action_id}/complete")
def complete_action(investigation_id: int, action_id: int, payload: ActionComplete, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return InvestigationService(connection).complete_action(principal, investigation_id, action_id, payload.result)


@router.post("/{investigation_id}/actions/{action_id}/cancel")
def cancel_action(investigation_id: int, action_id: int, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return InvestigationService(connection).cancel_action(principal, investigation_id, action_id)


@router.post("/{investigation_id}/closure/request")
def request_closure(investigation_id: int, payload: ClosureRequest, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return InvestigationService(connection).request_closure(principal, investigation_id, payload.summary)


@router.post("/{investigation_id}/closure/decision")
def decide_closure(investigation_id: int, payload: ClosureDecision, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return InvestigationService(connection).decide_closure(
            principal, investigation_id, payload.decision, payload.comment
        )

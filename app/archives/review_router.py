from __future__ import annotations

from fastapi import APIRouter, Depends, Query, status

from app.api.dependencies import current_principal
from app.archives.review_schemas import (
    ReviewAccessCreate,
    ReviewDecisionBatch,
    ReviewGrantRevoke,
    ReviewRequestCreate,
    ReviewSessionRenew,
    ReviewSessionRevoke,
)
from app.archives.review_service import (
    ReviewAccessService,
    ReviewRequestService,
    ReviewSessionService,
    ReviewStatsService,
    sweep_expired,
)
from app.core.security import Principal
from app.database import get_connection, transaction

router = APIRouter(prefix="/api/reviews", tags=["外部顾问查阅授权"])


@router.post("/requests", status_code=status.HTTP_201_CREATED)
def create_review_request(payload: ReviewRequestCreate, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return ReviewRequestService(connection).create(principal, payload.model_dump())


@router.get("/requests")
def list_review_requests(
    state: str | None = Query(default=None),
    principal: Principal = Depends(current_principal),
):
    return ReviewRequestService(get_connection()).list(principal, state)


@router.get("/requests/{request_id}")
def get_review_request(request_id: int, principal: Principal = Depends(current_principal)):
    return ReviewRequestService(get_connection()).get(principal, request_id)


@router.post("/requests/{request_id}/decisions")
def decide_review_request(request_id: int, payload: ReviewDecisionBatch, principal: Principal = Depends(current_principal)):
    connection = get_connection()
    sweep_expired(connection)
    with transaction(immediate=True):
        return ReviewRequestService(connection).decide(principal, request_id, payload.model_dump())


@router.post("/requests/{request_id}/cancel")
def cancel_review_request(request_id: int, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return ReviewRequestService(connection).cancel(principal, request_id)


@router.get("/sessions/{session_id}")
def get_review_session(session_id: int, principal: Principal = Depends(current_principal)):
    sweep_expired(get_connection())
    return ReviewSessionService(get_connection()).detail(principal, session_id)


@router.post("/sessions/{session_id}/renew")
def renew_review_session(session_id: int, payload: ReviewSessionRenew, principal: Principal = Depends(current_principal)):
    connection = get_connection()
    sweep_expired(connection)
    with transaction(immediate=True):
        return ReviewSessionService(connection).renew(principal, session_id, payload.model_dump())


@router.post("/sessions/{session_id}/revoke")
def revoke_review_session(session_id: int, payload: ReviewSessionRevoke, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return ReviewSessionService(connection).revoke(principal, session_id, payload.model_dump())


@router.post("/grants/{grant_id}/revoke")
def revoke_review_grant(grant_id: int, payload: ReviewGrantRevoke, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return ReviewSessionService(connection).revoke_grant(principal, grant_id, payload.model_dump())


@router.post("/accesses", status_code=status.HTTP_201_CREATED)
def record_review_access(payload: ReviewAccessCreate, principal: Principal = Depends(current_principal)):
    connection = get_connection()
    sweep_expired(connection)
    with transaction(immediate=True):
        return ReviewAccessService(connection).record_access(principal, payload.model_dump())


@router.get("/sessions/{session_id}/accesses")
def list_review_accesses(session_id: int, principal: Principal = Depends(current_principal)):
    service = ReviewAccessService(get_connection())
    return {"data": service.list_records(principal, session_id)}


@router.get("/stats/summary")
def review_stats_summary(principal: Principal = Depends(current_principal)):
    return ReviewStatsService(get_connection()).summary(principal)

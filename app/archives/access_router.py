from __future__ import annotations

from fastapi import APIRouter, Depends, Query, status

from app.api.dependencies import current_principal
from app.database import get_connection, transaction
from app.core.security import Principal
from app.archives.access_schemas import (
    AccessRecordCreate,
    AccessRequestCreate,
    AccessRequestDecide,
    AccessSessionOpen,
    AccessSessionRenew,
    AccessSessionRevoke,
)
from app.archives.access_requests import AccessRequestService, AccessSessionService, AccessStatisticsService

router = APIRouter(prefix="/api/access-requests", tags=["外部查阅申请"])
session_router = APIRouter(prefix="/api/access-sessions", tags=["外部查阅会话"])


@router.post("", status_code=status.HTTP_201_CREATED)
def create_access_request(payload: AccessRequestCreate, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return AccessRequestService(connection).create(principal, payload.model_dump())


@router.get("")
def list_access_requests(
    state: str | None = Query(default=None),
    principal: Principal = Depends(current_principal),
):
    return AccessRequestService(get_connection()).list(principal, state)


@router.get("/statistics")
def access_statistics(principal: Principal = Depends(current_principal)):
    return AccessStatisticsService(get_connection()).overview(principal)


@router.get("/{request_id}")
def get_access_request(request_id: int, principal: Principal = Depends(current_principal)):
    return AccessRequestService(get_connection()).detail(principal, request_id)


@router.post("/{request_id}/decisions")
def decide_access_request(request_id: int, payload: AccessRequestDecide, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return AccessRequestService(connection).decide(principal, request_id, payload.model_dump()["decisions"])


@router.post("/{request_id}/cancel")
def cancel_access_request(request_id: int, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return AccessRequestService(connection).cancel(principal, request_id)


@router.post("/{request_id}/sessions", status_code=status.HTTP_201_CREATED)
def open_access_session(request_id: int, payload: AccessSessionOpen, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return AccessRequestService(connection).open_session(principal, request_id, payload.model_dump())


@session_router.get("/{session_id}")
def get_access_session(session_id: int, principal: Principal = Depends(current_principal)):
    return AccessSessionService(get_connection()).detail(principal, session_id)


@session_router.post("/{session_id}/renew")
def renew_access_session(session_id: int, payload: AccessSessionRenew, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return AccessSessionService(connection).renew(principal, session_id, payload.model_dump())


@session_router.post("/{session_id}/revoke")
def revoke_access_session(session_id: int, payload: AccessSessionRevoke, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return AccessSessionService(connection).revoke(principal, session_id, payload.reason)


@session_router.post("/{session_id}/records", status_code=status.HTTP_201_CREATED)
def create_access_record(session_id: int, payload: AccessRecordCreate, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return AccessSessionService(connection).record(principal, session_id, payload.model_dump())

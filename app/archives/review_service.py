from __future__ import annotations

import sqlite3
import uuid
from datetime import timedelta
from typing import Any

from app.archives.repository import DossierRepository
from app.archives.review_repository import ReviewRequestRepository, ReviewSessionRepository
from app.core.clock import Clock, SystemClock, from_storage, to_storage
from app.core.errors import ConflictError, NotFoundError, PermissionDeniedError, ValidationError
from app.core.security import Principal, request_fingerprint
from app.database import transaction as db_transaction
from app.services.audit import AuditContext, AuditService

# 密级 -> 所需额外审批人数：内部无需审批，秘密一人，机密与绝密双人
APPROVALS_BY_SECRECY = {
    "internal": 0,
    "confidential": 1,
    "restricted": 2,
    "top_secret": 2,
}

REQUEST_AUDIT_RESOURCE = "review_request"
SESSION_AUDIT_RESOURCE = "review_session"
ACCESS_AUDIT_RESOURCE = "review_access"
# 供统计区分的三类事件族
EVENT_FAMILY = {
    "review.request.submitted": "request",
    "review.request.auto_approved": "approval",
    "review.request.decided": "approval",
    "review.request.finalized": "approval",
    "review.request.expired": "request",
    "review.request.cancelled": "request",
    "review.session.opened": "approval",
    "review.session.expired": "approval",
    "review.session.renewed": "approval",
    "review.session.revoked": "approval",
    "review.grant.revoked": "approval",
    "review.access.viewed": "access",
    "review.access.downloaded": "access",
    "review.access.denied": "access",
}


def sweep_expired(connection: sqlite3.Connection, clock: Clock | None = None) -> dict[str, list[int]]:
    """在独立短事务内把到期申请与会话标记为过期，避免被后续业务回滚。"""
    active_clock = clock or SystemClock()
    now = to_storage(active_clock.now())
    audit = AuditService(connection, active_clock)
    context = AuditContext(None, "系统")
    with db_transaction(immediate=True):
        request_repo = ReviewRequestRepository(connection)
        session_repo = ReviewSessionRepository(connection)
        request_ids = request_repo.expire_due_requests(now)
        session_ids = session_repo.expire_due_sessions(now)
        for request_id in request_ids:
            audit.record(context, "review.request.expired", REQUEST_AUDIT_RESOURCE, request_id, after={"state": "expired"})
        for session_id in session_ids:
            audit.record(context, "review.session.expired", SESSION_AUDIT_RESOURCE, session_id, after={"state": "expired"})
    return {"request_ids": request_ids, "session_ids": session_ids}


class ReviewRequestService:
    def __init__(self, connection: sqlite3.Connection, clock: Clock | None = None):
        self.connection = connection
        self.clock = clock or SystemClock()
        self.requests = ReviewRequestRepository(connection)
        self.sessions = ReviewSessionRepository(connection)
        self.dossiers = DossierRepository(connection)
        self.audit = AuditService(connection, self.clock)

    def _parse_window(self, starts_at: str | None, expires_at: str) -> tuple[str, str]:
        try:
            end_dt = from_storage(expires_at)
            start_dt = from_storage(starts_at) if starts_at else self.clock.now()
        except (ValueError, TypeError) as exc:
            raise ValidationError("时间格式不正确，需要 ISO 8601 时间") from exc
        if end_dt is None or start_dt is None:
            raise ValidationError("时间格式不正确")
        if end_dt <= self.clock.now():
            raise ValidationError("访问截止时间必须晚于当前时间")
        if end_dt <= start_dt:
            raise ValidationError("访问截止时间必须晚于开始时间")
        if end_dt - start_dt > timedelta(days=14):
            raise ValidationError("外部顾问单次授权窗口不能超过 14 天")
        return to_storage(start_dt), to_storage(end_dt)

    def create(self, principal: Principal, data: dict[str, Any]) -> dict[str, Any]:
        principal.require("review.requests")
        now_dt = self.clock.now()
        now = to_storage(now_dt)
        starts, expires = self._parse_window(data.get("starts_at"), data["expires_at"])
        approval_expires = to_storage(now_dt + timedelta(days=7))
        if from_storage(approval_expires) > from_storage(expires):
            approval_expires = expires

        payload = {
            "visitor_name": data["visitor_name"],
            "visitor_organization": data["visitor_organization"],
            "note": data.get("note", ""),
            "starts_at": starts,
            "expires_at": expires,
            "items": [
                {
                    "dossier_id": item["dossier_id"],
                    "purpose": item["purpose"],
                    "action": item["action"],
                    "download_limit": item["download_limit"],
                }
                for item in data["items"]
            ],
        }
        fingerprint = request_fingerprint(payload)

        # 并发创建：同一申请人使用同一幂等键，无论请求体是否一致都返回同一申请
        existing = self.requests.by_idempotency(principal.user_id, data["idempotency_key"])
        if existing is not None:
            if existing["request_hash"] != fingerprint:
                raise ConflictError("同一幂等键不能用于不同申请内容")
            return self.requests.get_request(existing["id"])

        request_code = f"REV-{uuid.uuid4().hex[:12]}"
        values = {
            "requested_by": principal.user_id,
            "visitor_name": data["visitor_name"],
            "visitor_organization": data["visitor_organization"],
            "idempotency_key": data["idempotency_key"],
            "request_hash": fingerprint,
            "note": data.get("note", ""),
            "approval_expires_at": approval_expires,
            "starts_at": starts,
            "expires_at": expires,
        }
        request = self.requests.create_request(values, request_code, now)

        auto_items: list[dict[str, Any]] = []
        for item in data["items"]:
            dossier = self.dossiers.get(item["dossier_id"])
            if dossier["lifecycle_state"] in {"disposed", "pending_disposal"}:
                raise ConflictError(f"档案 {dossier['dossier_code']} 已处置，不能申请查阅")
            secrecy = dossier.get("secrecy_level", "internal")
            if item["action"] == "view":
                item["download_limit"] = 0
            item["secrecy_level"] = secrecy
            required = APPROVALS_BY_SECRECY[secrecy]
            saved = self.requests.add_item(request["id"], item, required, now)
            if required == 0:
                auto_items.append(saved)

        self.audit.record(
            principal,
            "review.request.submitted",
            REQUEST_AUDIT_RESOURCE,
            request["id"],
            after={"request_code": request_code, "item_count": len(data["items"]), "visitor": data["visitor_name"]},
            metadata={"idempotency_key": data["idempotency_key"]},
        )

        if auto_items and len(auto_items) == len(data["items"]):
            # 全部为低密级档案：申请定稿并直接开通会话
            request = self.requests.refresh_request_state(request["id"], now)
            request = self._open_session_for_request(principal, request, now)
            self.audit.record(
                principal,
                "review.request.auto_approved",
                REQUEST_AUDIT_RESOURCE,
                request["id"],
                after={"state": request["state"], "session_id": request.get("session_id")},
            )
        elif auto_items:
            # 部分低密级条目不参与审批，先自动通过，但会话等全部定稿后再开通
            self.audit.record(
                principal,
                "review.request.auto_approved",
                REQUEST_AUDIT_RESOURCE,
                request["id"],
                after={"auto_item_ids": [item["id"] for item in auto_items]},
            )
        return self.requests.get_request(request["id"])

    def _open_session_for_request(self, principal: Principal, request: dict[str, Any], now: str) -> dict[str, Any]:
        approved_items = [item for item in request["items"] if item["state"] == "approved"]
        if not approved_items:
            return request
        session_code = f"RVS-{uuid.uuid4().hex[:12]}"
        session_id = self.sessions.create_session(request, session_code, now)
        for item in approved_items:
            self.sessions.add_grant(session_id, item, request["access_expires_at"], now)
        self.connection.execute(
            "UPDATE review_requests SET finalized_by=? WHERE id=?",
            (principal.user_id, request["id"]),
        )
        self.audit.record(
            principal,
            "review.session.opened",
            SESSION_AUDIT_RESOURCE,
            session_id,
            after={"session_code": session_code, "request_id": request["id"], "grant_count": len(approved_items)},
        )
        return self.requests.get_request(request["id"])

    def get(self, principal: Principal, request_id: int) -> dict[str, Any]:
        self._require_read(principal)
        request = self.requests.get_request(request_id)
        request["sessions"] = self.sessions.list_sessions(request_id=request_id)
        for item in request["items"]:
            item["decisions"] = self.requests.decisions_of_item(item["id"])
        return request

    def list(self, principal: Principal, state: str | None) -> dict[str, Any]:
        self._require_read(principal)
        requests = self.requests.list_requests(state=state)
        return {"total": len(requests), "data": requests}

    @staticmethod
    def _require_read(principal: Principal) -> None:
        if not (principal.can("review.requests") or principal.can("review.decide") or principal.can("review.stats")):
            raise PermissionDeniedError("缺少权限：review.requests")

    def decide(self, principal: Principal, request_id: int, data: dict[str, Any]) -> dict[str, Any]:
        principal.require("review.decide")
        request = self.requests.get_request(request_id)
        now = to_storage(self.clock.now())
        if request["state"] != "pending":
            raise ConflictError("申请已经结束，不能继续审批")
        if request["requested_by"] == principal.user_id:
            raise ValidationError("申请人不能审批自己的申请")
        if from_storage(request["expires_at"]) <= self.clock.now():
            raise ConflictError("申请已超过审批期限")

        touched = False
        for entry in data["items"]:
            item = self.requests.get_item(entry["item_id"])
            if item["request_id"] != request_id:
                raise NotFoundError("查阅申请条目不存在")
            if item["state"] != "pending":
                # 已经定稿的条目（如自动通过）跳过，但显式对 pending 条目重复决定需报错
                raise ConflictError("该条目已经完成审批")
            try:
                self.requests.add_decision(item["id"], principal.user_id, entry["decision"], entry.get("comment", ""), now)
            except sqlite3.IntegrityError as exc:
                raise ConflictError("同一审批人不能对同一条目重复决定") from exc
            touched = True
            decisions = self.requests.decisions_of_item(item["id"])
            approvals = [row for row in decisions if row["decision"] == "approve"]
            rejects = [row for row in decisions if row["decision"] == "reject"]
            if rejects:
                self.requests.set_item_state(
                    item["id"], "rejected", now, reject_reason=rejects[0].get("comment") or "审批未通过",
                )
            elif len(approvals) >= item["required_approvals"]:
                self.requests.set_item_state(item["id"], "approved", now)
        if not touched:
            raise ValidationError("没有需要审批的条目")

        before_state = request["state"]
        updated = self.requests.refresh_request_state(request_id, now)
        self.audit.record(
            principal,
            "review.request.decided",
            REQUEST_AUDIT_RESOURCE,
            request_id,
            before={"state": before_state},
            after={"state": updated["state"]},
            metadata={"items": [entry["item_id"] for entry in data["items"]]},
        )
        if updated["state"] != "pending":
            updated = self._open_session_for_request(principal, updated, now)
            self.audit.record(
                principal,
                "review.request.finalized",
                REQUEST_AUDIT_RESOURCE,
                request_id,
                after={"state": updated["state"]},
            )
        return self.get(principal, request_id)

    def cancel(self, principal: Principal, request_id: int) -> dict[str, Any]:
        principal.require("review.requests")
        request = self.requests.get_request(request_id)
        if request["requested_by"] != principal.user_id and not principal.can("review.sessions"):
            raise ValidationError("只能撤销本人提交的申请")
        if request["state"] != "pending":
            raise ConflictError("申请已经结束，不能撤销")
        now = to_storage(self.clock.now())
        self.requests.set_request_state(request_id, "cancelled", now)
        self.connection.execute(
            "UPDATE review_request_items SET state='cancelled',updated_at=? WHERE request_id=? AND state='pending'",
            (now, request_id),
        )
        self.audit.record(
            principal,
            "review.request.cancelled",
            REQUEST_AUDIT_RESOURCE,
            request_id,
            after={"state": "cancelled"},
        )
        return self.requests.get_request(request_id)


class ReviewSessionService:
    def __init__(self, connection: sqlite3.Connection, clock: Clock | None = None):
        self.connection = connection
        self.clock = clock or SystemClock()
        self.sessions = ReviewSessionRepository(connection)
        self.requests = ReviewRequestRepository(connection)
        self.audit = AuditService(connection, self.clock)

    def list_for_request(self, principal: Principal, request_id: int) -> list[dict[str, Any]]:
        principal.require("review.requests")
        return self.sessions.list_sessions(request_id=request_id)

    def detail(self, principal: Principal, session_id: int) -> dict[str, Any]:
        principal.require("review.sessions")
        session = self.sessions.get_session(session_id)
        session["grants"] = self.sessions.list_grants(session_id)
        session["access_records"] = self.sessions.list_access_records(session_id)
        return session

    def renew(self, principal: Principal, session_id: int, data: dict[str, Any]) -> dict[str, Any]:
        principal.require("review.sessions")
        session = self.sessions.get_session(session_id)
        now = to_storage(self.clock.now())
        if session["state"] != "active":
            raise ConflictError("会话已结束，不能续期")
        try:
            new_end = from_storage(data["new_expires_at"])
        except (ValueError, TypeError) as exc:
            raise ValidationError("时间格式不正确，需要 ISO 8601 时间") from exc
        if new_end is None or new_end <= self.clock.now():
            raise ValidationError("续期截止时间必须晚于当前时间")
        if new_end - from_storage(session["starts_at"]) > timedelta(days=90):
            raise ValidationError("累计授权窗口不能超过 90 天")
        new_expires = to_storage(new_end)
        renew_count = self.sessions.renew(session_id, new_expires, data.get("grant_ids"), now)
        self.audit.record(
            principal,
            "review.session.renewed",
            SESSION_AUDIT_RESOURCE,
            session_id,
            after={"expires_at": new_expires, "renew_count": renew_count, "grant_ids": data.get("grant_ids")},
        )
        return self.detail(principal, session_id)

    def revoke(self, principal: Principal, session_id: int, data: dict[str, Any]) -> dict[str, Any]:
        principal.require("review.sessions")
        session = self.sessions.get_session(session_id)
        if session["state"] != "active":
            raise ConflictError("会话已经结束")
        now = to_storage(self.clock.now())
        self.sessions.revoke_session(session_id, data.get("reason", ""), principal.user_id, now)
        self.audit.record(
            principal,
            "review.session.revoked",
            SESSION_AUDIT_RESOURCE,
            session_id,
            after={"reason": data.get("reason", "")},
        )
        return self.detail(principal, session_id)

    def revoke_grant(self, principal: Principal, grant_id: int, data: dict[str, Any]) -> dict[str, Any]:
        principal.require("review.sessions")
        grant = self.sessions.get_grant(grant_id)
        now = to_storage(self.clock.now())
        self.sessions.revoke_grant(grant_id, data.get("reason", ""), principal.user_id, now)
        self.audit.record(
            principal,
            "review.grant.revoked",
            SESSION_AUDIT_RESOURCE,
            grant["session_id"],
            after={"grant_id": grant_id, "dossier_id": grant["dossier_id"], "reason": data.get("reason", "")},
        )
        return self.detail(principal, grant["session_id"])


class ReviewAccessService:
    def __init__(self, connection: sqlite3.Connection, clock: Clock | None = None):
        self.connection = connection
        self.clock = clock or SystemClock()
        self.sessions = ReviewSessionRepository(connection)
        self.requests = ReviewRequestRepository(connection)
        self.dossiers = DossierRepository(connection)
        self.audit = AuditService(connection, self.clock)

    def _deny(self, principal: Principal, reason: str, session_id: int | None, dossier_id: int | None) -> None:
        self.audit.record(
            principal,
            "review.access.denied",
            ACCESS_AUDIT_RESOURCE,
            session_id,
            outcome="denied",
            metadata={"reason": reason, "dossier_id": dossier_id},
        )
        # 拒绝审计必须保留：先提交再抛出，避免随业务事务一起回滚
        self.connection.commit()
        raise ConflictError(reason)

    def record_access(self, principal: Principal, data: dict[str, Any]) -> dict[str, Any]:
        principal.require("review.sessions")
        now_dt = self.clock.now()
        now = to_storage(now_dt)

        session = self.sessions.get_session_by_code(data["session_code"])
        if session is None:
            self._deny(principal, "查阅会话不存在", None, data["dossier_id"])
        if session["state"] != "active":
            self._deny(principal, "查阅会话已撤销或过期", session["id"], data["dossier_id"])
        if not (from_storage(session["starts_at"]) <= now_dt <= from_storage(session["expires_at"])):
            self._deny(principal, "不在查阅会话有效窗口内", session["id"], data["dossier_id"])

        grant = self.sessions.find_grant(session["id"], data["dossier_id"])
        if grant is None:
            self._deny(principal, "会话未授权该档案", session["id"], data["dossier_id"])
        if grant["state"] != "active":
            self._deny(principal, "该档案授权已撤销或过期", session["id"], data["dossier_id"])
        if from_storage(grant["expires_at"]) < now_dt:
            self._deny(principal, "该档案授权已过期", session["id"], data["dossier_id"])

        action = data["action"]
        if action == "download" and grant["action"] != "download":
            self._deny(principal, "该档案仅允许在线查阅，禁止下载", session["id"], data["dossier_id"])

        if action == "download":
            if grant["download_limit"] <= 0 or grant["download_count"] >= grant["download_limit"]:
                self._deny(principal, "下载次数已达上限", session["id"], data["dossier_id"])
            if not self.sessions.increment_download(grant["id"], now):
                self._deny(principal, "下载授权已失效或次数已达上限", session["id"], data["dossier_id"])

        record_id = self.sessions.add_access_record(
            session["id"], grant["id"], data["dossier_id"], principal.user_id, action, data.get("file_ref", ""), now,
        )
        record = dict(self.connection.execute("SELECT * FROM review_access_records WHERE id=?", (record_id,)).fetchone())
        audit_action = "review.access.downloaded" if action == "download" else "review.access.viewed"
        self.audit.record(
            principal,
            audit_action,
            ACCESS_AUDIT_RESOURCE,
            record_id,
            after={"session_id": session["id"], "dossier_id": data["dossier_id"]},
            metadata={"session_code": session["session_code"], "action": action},
        )
        grant = self.sessions.get_grant(grant["id"])
        return {"record": record, "session_code": session["session_code"], "grant": grant}

    def list_records(self, principal: Principal, session_id: int) -> list[dict[str, Any]]:
        principal.require("review.sessions")
        self.sessions.get_session(session_id)
        return self.sessions.list_access_records(session_id)


class ReviewStatsService:
    def __init__(self, connection: sqlite3.Connection, clock: Clock | None = None):
        self.connection = connection
        self.clock = clock or SystemClock()

    def summary(self, principal: Principal) -> dict[str, Any]:
        principal.require("review.stats")
        request_rows = self.connection.execute(
            "SELECT state,COUNT(*) AS count FROM review_requests GROUP BY state"
        ).fetchall()
        session_rows = self.connection.execute(
            "SELECT state,COUNT(*) AS count FROM review_sessions GROUP BY state"
        ).fetchall()
        grant_rows = self.connection.execute(
            """SELECT action,state,COUNT(*) AS count,COALESCE(SUM(download_count),0) AS downloads
               FROM review_session_grants GROUP BY action,state"""
        ).fetchall()
        totals_row = self.connection.execute(
            """SELECT
                  SUM(CASE WHEN action='view' THEN 1 ELSE 0 END) AS view_count,
                  SUM(CASE WHEN action='download' THEN 1 ELSE 0 END) AS download_count,
                  COUNT(DISTINCT session_id) AS session_count,
                  COUNT(DISTINCT dossier_id) AS dossier_count
               FROM review_access_records"""
        ).fetchone()

        action_rows = self.connection.execute(
            "SELECT action,outcome,COUNT(*) AS count FROM audit_events "
            "WHERE action LIKE 'review.%' GROUP BY action,outcome ORDER BY action"
        ).fetchall()
        families = {"request": 0, "approval": 0, "access": 0}
        events_by_action: dict[str, dict[str, int]] = {}
        for row in action_rows:
            family = EVENT_FAMILY.get(row["action"], "request")
            families[family] += int(row["count"])
            events_by_action.setdefault(row["action"], {})[row["outcome"]] = int(row["count"])

        return {
            "requests_by_state": {row["state"]: int(row["count"]) for row in request_rows},
            "sessions_by_state": {row["state"]: int(row["count"]) for row in session_rows},
            "grants": [
                {"action": row["action"], "state": row["state"], "count": int(row["count"]), "downloads": int(row["downloads"])}
                for row in grant_rows
            ],
            "actual_access": {
                "view_count": int(totals_row["view_count"] or 0),
                "download_count": int(totals_row["download_count"] or 0),
                "session_count": int(totals_row["session_count"] or 0),
                "dossier_count": int(totals_row["dossier_count"] or 0),
            },
            "event_family_counts": families,
            "events_by_action": events_by_action,
        }

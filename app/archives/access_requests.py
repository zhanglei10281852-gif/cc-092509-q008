"""外部顾问查阅申请与临时会话授权。

内部经办人一次为外部顾问申请多个档案的查阅权限，每个档案单独声明用途与
动作（在线查看 / 下载副本）。系统根据档案密级决定是否需要额外审批：
机密、绝密档案进入人工审批，其余密级自动批准。审批人可以逐份批准或拒绝
（部分批准）。批准后可为顾问开启有时效的查阅会话，会话支持续期与提前
撤销，到期后临时权限自动收回；已过期或已撤销的会话不能再建立查阅记录。
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from datetime import timedelta
from typing import Any

from app.core.clock import Clock, SystemClock, from_storage, to_storage
from app.core.errors import ConflictError, NotFoundError, ValidationError
from app.core.security import Principal
from app.archives.repository import DossierRepository
from app.archives.validation import parse_timestamp
from app.services.audit import AuditService

# 机密、绝密档案对外提供查阅前必须经过人工审批，其余密级自动批准。
APPROVAL_REQUIRED_SECRECY_LEVELS = frozenset({"restricted", "top_secret"})

# 开启或续期会话时的默认有效期，且始终不超过申请声明的使用期限。
DEFAULT_SESSION_DURATION = timedelta(days=14)

# 已结束生命周期的档案不允许对外提供查阅。
BLOCKED_LIFECYCLE_STATES = frozenset({"disposed", "pending_disposal", "quarantined"})


def _request_digest(data: dict[str, Any]) -> str:
    """对申请的业务内容生成稳定摘要，用于识别并发或重放的相同申请。"""
    canonical = {
        "consultant_name": data["consultant_name"],
        "consultant_organization": data["consultant_organization"],
        "reason": data["reason"],
        "needed_until": data["needed_until"],
        "items": sorted(
            (
                {
                    "dossier_id": item["dossier_id"],
                    "purpose": item["purpose"],
                    "actions": sorted(item["actions"]),
                }
                for item in data["items"]
            ),
            key=lambda item: item["dossier_id"],
        ),
    }
    compact = json.dumps(canonical, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(compact.encode("utf-8")).hexdigest()


def _request_state(item_states: list[str]) -> str:
    states = set(item_states)
    if "pending" in states:
        return "pending"
    if states == {"approved"}:
        return "approved"
    if states == {"rejected"}:
        return "rejected"
    return "partially_approved"


def _session_detail(requests: "AccessRequestRepository", session_id: int) -> dict[str, Any]:
    session = requests.get_session(session_id)
    approved = [item for item in requests.items(session["request_id"]) if item["state"] == "approved"]
    session["approved_items"] = approved
    session["records"] = requests.records_for_session(session_id)
    return session


class AccessRequestRepository:
    def __init__(self, connection: sqlite3.Connection):
        self.connection = connection

    def create_request(self, data: dict[str, Any], requested_by: int, request_code: str, digest: str, now: str) -> dict[str, Any]:
        cursor = self.connection.execute(
            """INSERT INTO access_requests(request_code,consultant_name,consultant_organization,reason,needed_until,
               state,requested_by,idempotency_key,request_digest,created_at,updated_at)
               VALUES(?,?,?,?,?,'pending',?,?,?,?,?)""",
            (
                request_code, data["consultant_name"], data["consultant_organization"], data["reason"],
                data["needed_until"], requested_by, data["idempotency_key"], digest, now, now,
            ),
        )
        return self.get_request(cursor.lastrowid)

    def get_request(self, request_id: int) -> dict[str, Any]:
        row = self.connection.execute("SELECT * FROM access_requests WHERE id=?", (request_id,)).fetchone()
        if row is None:
            raise NotFoundError("查阅申请不存在")
        return dict(row)

    def by_idempotency_key(self, requested_by: int, idempotency_key: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM access_requests WHERE requested_by=? AND idempotency_key=?",
            (requested_by, idempotency_key),
        ).fetchone()
        return dict(row) if row else None

    def by_code(self, request_code: str) -> dict[str, Any] | None:
        row = self.connection.execute("SELECT * FROM access_requests WHERE request_code=?", (request_code,)).fetchone()
        return dict(row) if row else None

    def list_requests(self, state: str | None = None) -> list[dict[str, Any]]:
        sql = """SELECT r.*,(SELECT COUNT(*) FROM access_request_items i WHERE i.request_id=r.id) AS item_count,
                        (SELECT COUNT(*) FROM access_sessions s WHERE s.request_id=r.id AND s.state='active') AS active_session_count
                 FROM access_requests r"""
        params: tuple[Any, ...] = ()
        if state:
            sql += " WHERE r.state=?"
            params = (state,)
        sql += " ORDER BY r.id DESC LIMIT 100"
        return [dict(row) for row in self.connection.execute(sql, params).fetchall()]

    def update_request_state(self, request_id: int, state: str, now: str) -> dict[str, Any]:
        self.connection.execute(
            "UPDATE access_requests SET state=?,version=version+1,updated_at=? WHERE id=?",
            (state, now, request_id),
        )
        return self.get_request(request_id)

    def add_item(self, request_id: int, item: dict[str, Any], requires_approval: bool, state: str, now: str) -> None:
        self.connection.execute(
            """INSERT INTO access_request_items(request_id,dossier_id,purpose,actions_json,requires_approval,state,created_at,updated_at)
               VALUES(?,?,?,?,?,?,?,?)""",
            (
                request_id, item["dossier_id"], item["purpose"], json.dumps(sorted(item["actions"]), ensure_ascii=False),
                int(requires_approval), state, now, now,
            ),
        )

    def items(self, request_id: int) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            """SELECT i.*,s.dossier_code,s.secrecy_level
               FROM access_request_items i JOIN dossiers s ON s.id=i.dossier_id
               WHERE i.request_id=? ORDER BY i.id""",
            (request_id,),
        ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["actions"] = json.loads(item.pop("actions_json"))
            item["requires_approval"] = bool(item["requires_approval"])
            result.append(item)
        return result

    def item_for_dossier(self, request_id: int, dossier_id: int) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM access_request_items WHERE request_id=? AND dossier_id=?",
            (request_id, dossier_id),
        ).fetchone()
        if row is None:
            return None
        item = dict(row)
        item["actions"] = json.loads(item.pop("actions_json"))
        item["requires_approval"] = bool(item["requires_approval"])
        return item

    def decide_item(self, item_id: int, decision: str, decided_by: int, comment: str, now: str) -> None:
        self.connection.execute(
            """UPDATE access_request_items SET state=?,decided_by=?,decided_at=?,decision_comment=?,updated_at=?
               WHERE id=?""",
            ("approved" if decision == "approve" else "rejected", decided_by, now, comment, now, item_id),
        )

    def create_session(self, request: dict[str, Any], session_code: str, issued_by: int, expires_at: str, now: str) -> dict[str, Any]:
        cursor = self.connection.execute(
            """INSERT INTO access_sessions(session_code,request_id,consultant_name,issued_by,issued_at,expires_at,state,created_at,updated_at)
               VALUES(?,?,?,?,?,?,'active',?,?)""",
            (session_code, request["id"], request["consultant_name"], issued_by, now, expires_at, now, now),
        )
        return self.get_session(cursor.lastrowid)

    def get_session(self, session_id: int) -> dict[str, Any]:
        row = self.connection.execute("SELECT * FROM access_sessions WHERE id=?", (session_id,)).fetchone()
        if row is None:
            raise NotFoundError("查阅会话不存在")
        return dict(row)

    def sessions_for_request(self, request_id: int) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT * FROM access_sessions WHERE request_id=? ORDER BY id DESC",
            (request_id,),
        ).fetchall()
        return [dict(row) for row in rows]

    def active_session_for_request(self, request_id: int) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM access_sessions WHERE request_id=? AND state='active' ORDER BY id DESC LIMIT 1",
            (request_id,),
        ).fetchone()
        return dict(row) if row else None

    def expire_sessions(self, now: str) -> None:
        """把已过有效期的会话标记为过期，临时权限随之自动收回。"""
        self.connection.execute(
            "UPDATE access_sessions SET state='expired',updated_at=? WHERE state='active' AND expires_at<=?",
            (now, now),
        )

    def renew_session(self, session_id: int, expires_at: str, now: str) -> dict[str, Any]:
        self.connection.execute(
            "UPDATE access_sessions SET expires_at=?,renewed_count=renewed_count+1,updated_at=? WHERE id=?",
            (expires_at, now, session_id),
        )
        return self.get_session(session_id)

    def revoke_session(self, session_id: int, reason: str, now: str) -> dict[str, Any]:
        self.connection.execute(
            "UPDATE access_sessions SET state='revoked',revoked_at=?,revoke_reason=?,updated_at=? WHERE id=?",
            (now, reason, now, session_id),
        )
        return self.get_session(session_id)

    def revoke_sessions_for_request(self, request_id: int, reason: str, now: str) -> None:
        self.connection.execute(
            "UPDATE access_sessions SET state='revoked',revoked_at=?,revoke_reason=?,updated_at=? WHERE request_id=? AND state='active'",
            (now, reason, now, request_id),
        )

    def add_record(self, session_id: int, dossier_id: int, action: str, actor_user_id: int, idempotency_key: str, now: str) -> dict[str, Any]:
        cursor = self.connection.execute(
            """INSERT INTO access_records(session_id,dossier_id,action,actor_user_id,idempotency_key,occurred_at,created_at)
               VALUES(?,?,?,?,?,?,?)""",
            (session_id, dossier_id, action, actor_user_id, idempotency_key, now, now),
        )
        return dict(
            self.connection.execute("SELECT * FROM access_records WHERE id=?", (cursor.lastrowid,)).fetchone()
        )

    def record_by_key(self, session_id: int, idempotency_key: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM access_records WHERE session_id=? AND idempotency_key=?",
            (session_id, idempotency_key),
        ).fetchone()
        return dict(row) if row else None

    def records_for_session(self, session_id: int) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            """SELECT r.*,s.dossier_code FROM access_records r JOIN dossiers s ON s.id=r.dossier_id
               WHERE r.session_id=? ORDER BY r.id""",
            (session_id,),
        ).fetchall()
        return [dict(row) for row in rows]


class AccessRequestService:
    def __init__(self, connection: sqlite3.Connection, clock: Clock | None = None):
        self.connection = connection
        self.clock = clock or SystemClock()
        self.requests = AccessRequestRepository(connection)
        self.dossiers = DossierRepository(connection)
        self.audit = AuditService(connection, self.clock)

    def detail(self, principal: Principal, request_id: int) -> dict[str, Any]:
        principal.require("access_requests.manage")
        self.requests.expire_sessions(to_storage(self.clock.now()))
        return self._detail(request_id)

    def list(self, principal: Principal, state: str | None) -> list[dict[str, Any]]:
        principal.require("access_requests.manage")
        self.requests.expire_sessions(to_storage(self.clock.now()))
        return self.requests.list_requests(state)

    def create(self, principal: Principal, data: dict[str, Any]) -> dict[str, Any]:
        principal.require("access_requests.manage")
        now_dt = self.clock.now()
        needed_until = parse_timestamp(data["needed_until"], "使用期限")
        if needed_until <= now_dt:
            raise ValidationError("使用期限必须晚于当前时间")
        dossier_ids = [item["dossier_id"] for item in data["items"]]
        if len(set(dossier_ids)) != len(dossier_ids):
            raise ValidationError("同一申请中档案不能重复")
        for item in data["items"]:
            if len(set(item["actions"])) != len(item["actions"]):
                raise ValidationError("同一档案的动作不能重复")
        normalized = {**data, "needed_until": to_storage(needed_until)}
        digest = _request_digest(normalized)
        existing = self.requests.by_idempotency_key(principal.user_id, data["idempotency_key"])
        if existing is not None:
            if existing["request_digest"] != digest:
                raise ConflictError("同一幂等键不能用于不同的查阅申请")
            return {**self._detail(existing["id"]), "replayed": True}
        item_states: list[tuple[dict[str, Any], bool]] = []
        for item in data["items"]:
            dossier = self.dossiers.get(item["dossier_id"])
            if dossier["lifecycle_state"] in BLOCKED_LIFECYCLE_STATES:
                raise ConflictError(
                    "档案当前状态不允许申请查阅",
                    context={"dossier_code": dossier["dossier_code"], "lifecycle_state": dossier["lifecycle_state"]},
                )
            item_states.append((item, dossier["secrecy_level"] in APPROVAL_REQUIRED_SECRECY_LEVELS))
        now = to_storage(now_dt)
        request_code = data.get("request_code") or f"ACR-{uuid.uuid4().hex[:12]}"
        if self.requests.by_code(request_code):
            raise ConflictError("申请编号已经存在")
        try:
            request = self.requests.create_request(normalized, principal.user_id, request_code, digest, now)
        except sqlite3.IntegrityError:
            # 并发提交的相同申请：唯一约束兜底，返回先提交成功的同一份结果。
            concurrent = self.requests.by_idempotency_key(principal.user_id, data["idempotency_key"])
            if concurrent is None:
                raise ConflictError("申请编号已经存在")
            if concurrent["request_digest"] != digest:
                raise ConflictError("同一幂等键不能用于不同的查阅申请")
            return {**self._detail(concurrent["id"]), "replayed": True}
        for item, requires_approval in item_states:
            self.requests.add_item(
                request["id"], item, requires_approval, "pending" if requires_approval else "approved", now
            )
        state = _request_state(["pending" if requires else "approved" for _, requires in item_states])
        self.requests.update_request_state(request["id"], state, now)
        result = self._detail(request["id"])
        self.audit.record(
            principal,
            "access_request.create",
            "access_request",
            str(request["id"]),
            after=result,
            metadata={"consultant_name": data["consultant_name"], "item_count": len(data["items"]), "state": state},
        )
        return {**result, "replayed": False}

    def decide(self, principal: Principal, request_id: int, decisions: list[dict[str, Any]]) -> dict[str, Any]:
        principal.require("access_requests.decide")
        before = self._detail(request_id)
        if before["state"] != "pending":
            raise ConflictError("申请没有待审批的档案")
        if before["requested_by"] == principal.user_id:
            raise ValidationError("申请人不能审批自己的查阅申请")
        items_by_id = {item["id"]: item for item in before["items"]}
        now = to_storage(self.clock.now())
        for decision in decisions:
            item = items_by_id.get(decision["item_id"])
            if item is None:
                raise ValidationError("审批项不属于该查阅申请", context={"item_id": decision["item_id"]})
            if item["state"] != "pending":
                raise ConflictError("审批项已完成审批", context={"item_id": decision["item_id"]})
            self.requests.decide_item(item["id"], decision["decision"], principal.user_id, decision.get("comment", ""), now)
        states = [item["state"] for item in self.requests.items(request_id)]
        self.requests.update_request_state(request_id, _request_state(states), now)
        result = self._detail(request_id)
        self.audit.record(
            principal,
            "access_request.decide",
            "access_request",
            str(request_id),
            before=before,
            after=result,
            metadata={"decisions": decisions},
        )
        return result

    def cancel(self, principal: Principal, request_id: int) -> dict[str, Any]:
        principal.require("access_requests.manage")
        now = to_storage(self.clock.now())
        self.requests.expire_sessions(now)
        before = self._detail(request_id)
        if before["state"] in {"rejected", "cancelled"}:
            raise ConflictError("申请已结束，不能撤销")
        self.requests.update_request_state(request_id, "cancelled", now)
        self.requests.revoke_sessions_for_request(request_id, "request_cancelled", now)
        result = self._detail(request_id)
        self.audit.record(principal, "access_request.cancel", "access_request", str(request_id), before=before, after=result)
        return result

    def open_session(self, principal: Principal, request_id: int, data: dict[str, Any]) -> dict[str, Any]:
        principal.require("access_requests.manage")
        now_dt = self.clock.now()
        now = to_storage(now_dt)
        self.requests.expire_sessions(now)
        request = self._detail(request_id)
        if request["state"] not in {"approved", "partially_approved"}:
            raise ConflictError("申请尚未获得批准，不能开启查阅会话")
        needed_until = from_storage(request["needed_until"])
        if needed_until is None or needed_until <= now_dt:
            raise ConflictError("申请的使用期限已过，不能开启查阅会话")
        if self.requests.active_session_for_request(request_id):
            raise ConflictError("该申请已有进行中的查阅会话")
        expires_at = self._resolve_expiry(data.get("expires_at"), now_dt, needed_until, "会话到期时间")
        session_code = f"ACS-{uuid.uuid4().hex[:12]}"
        session = self.requests.create_session(request, session_code, principal.user_id, expires_at, now)
        self.audit.record(
            principal,
            "access_session.open",
            "access_session",
            str(session["id"]),
            after=session,
            metadata={"request_id": request_id, "expires_at": expires_at},
        )
        return _session_detail(self.requests, session["id"])

    def _resolve_expiry(self, raw: str | None, now_dt, needed_until, field: str) -> str:
        if raw:
            expires_at = parse_timestamp(raw, field)
        else:
            expires_at = min(now_dt + DEFAULT_SESSION_DURATION, needed_until)
        if expires_at <= now_dt:
            raise ValidationError(f"{field}必须晚于当前时间")
        if expires_at > needed_until:
            raise ValidationError(f"{field}不能超过申请的使用期限")
        return to_storage(expires_at)

    def _detail(self, request_id: int) -> dict[str, Any]:
        request = self.requests.get_request(request_id)
        request["items"] = self.requests.items(request_id)
        request["sessions"] = self.requests.sessions_for_request(request_id)
        return request


class AccessSessionService:
    def __init__(self, connection: sqlite3.Connection, clock: Clock | None = None):
        self.connection = connection
        self.clock = clock or SystemClock()
        self.requests = AccessRequestRepository(connection)
        self.audit = AuditService(connection, self.clock)

    def detail(self, principal: Principal, session_id: int) -> dict[str, Any]:
        principal.require("access_requests.manage")
        self.requests.expire_sessions(to_storage(self.clock.now()))
        return _session_detail(self.requests, session_id)

    def renew(self, principal: Principal, session_id: int, data: dict[str, Any]) -> dict[str, Any]:
        principal.require("access_requests.manage")
        now_dt = self.clock.now()
        now = to_storage(now_dt)
        self.requests.expire_sessions(now)
        before = self.requests.get_session(session_id)
        if before["state"] != "active":
            raise ConflictError("会话已过期或已撤销，不能续期")
        request = self.requests.get_request(before["request_id"])
        needed_until = from_storage(request["needed_until"])
        raw = data.get("expires_at")
        if raw:
            expires_at = parse_timestamp(raw, "会话到期时间")
        else:
            expires_at = min(now_dt + DEFAULT_SESSION_DURATION, needed_until)
        current_expiry = from_storage(before["expires_at"])
        if expires_at <= current_expiry:
            raise ValidationError("新的到期时间必须晚于当前到期时间")
        if expires_at > needed_until:
            raise ValidationError("会话到期时间不能超过申请的使用期限")
        session = self.requests.renew_session(session_id, to_storage(expires_at), now)
        self.audit.record(
            principal,
            "access_session.renew",
            "access_session",
            str(session_id),
            before=before,
            after=session,
            metadata={"renewed_count": session["renewed_count"]},
        )
        return _session_detail(self.requests, session_id)

    def revoke(self, principal: Principal, session_id: int, reason: str) -> dict[str, Any]:
        principal.require("access_requests.manage")
        now = to_storage(self.clock.now())
        self.requests.expire_sessions(now)
        before = self.requests.get_session(session_id)
        if before["state"] != "active":
            raise ConflictError("会话已结束，不能重复撤销")
        session = self.requests.revoke_session(session_id, reason or "manual_revoke", now)
        self.audit.record(
            principal,
            "access_session.revoke",
            "access_session",
            str(session_id),
            before=before,
            after=session,
            metadata={"reason": reason or "manual_revoke"},
        )
        return _session_detail(self.requests, session_id)

    def record(self, principal: Principal, session_id: int, data: dict[str, Any]) -> dict[str, Any]:
        principal.require("access_requests.manage")
        now = to_storage(self.clock.now())
        self.requests.expire_sessions(now)
        session = self.requests.get_session(session_id)
        if session["state"] != "active":
            raise ConflictError("会话已过期或已撤销，不能建立查阅记录")
        item = self.requests.item_for_dossier(session["request_id"], data["dossier_id"])
        if item is None:
            raise ValidationError("档案不在本次申请范围内")
        if item["state"] != "approved":
            raise ConflictError("该档案未获批准，不能查阅")
        if data["action"] not in item["actions"]:
            raise ConflictError("该档案未授予此动作", context={"allowed_actions": item["actions"]})
        existing = self.requests.record_by_key(session_id, data["idempotency_key"])
        if existing is not None:
            if existing["dossier_id"] != data["dossier_id"] or existing["action"] != data["action"]:
                raise ConflictError("同一幂等键不能用于不同的查阅记录")
            return {"record": existing, "replayed": True}
        try:
            record = self.requests.add_record(
                session_id, data["dossier_id"], data["action"], principal.user_id, data["idempotency_key"], now
            )
        except sqlite3.IntegrityError:
            concurrent = self.requests.record_by_key(session_id, data["idempotency_key"])
            if concurrent is not None and concurrent["dossier_id"] == data["dossier_id"] and concurrent["action"] == data["action"]:
                return {"record": concurrent, "replayed": True}
            raise ConflictError("同一幂等键不能用于不同的查阅记录")
        self.audit.record(
            principal,
            "access_session.record",
            "access_session",
            str(session_id),
            after=record,
            metadata={"dossier_id": data["dossier_id"], "action": data["action"]},
        )
        return {"record": record, "replayed": False}


class AccessStatisticsService:
    """面向管理员的查阅统计，严格区分申请、批准与实际查阅三类事件。"""

    def __init__(self, connection: sqlite3.Connection, clock: Clock | None = None):
        self.connection = connection
        self.clock = clock or SystemClock()
        self.requests = AccessRequestRepository(connection)

    def overview(self, principal: Principal) -> dict[str, Any]:
        principal.require("access_requests.manage")
        now = to_storage(self.clock.now())
        self.requests.expire_sessions(now)
        request_rows = self.connection.execute(
            "SELECT state,COUNT(*) AS count FROM access_requests GROUP BY state"
        ).fetchall()
        item_rows = self.connection.execute(
            """SELECT COUNT(*) AS total,
                      SUM(CASE WHEN state='pending' THEN 1 ELSE 0 END) AS pending,
                      SUM(CASE WHEN state='approved' THEN 1 ELSE 0 END) AS approved,
                      SUM(CASE WHEN state='rejected' THEN 1 ELSE 0 END) AS rejected,
                      SUM(CASE WHEN requires_approval=0 THEN 1 ELSE 0 END) AS auto_approved,
                      SUM(CASE WHEN decided_by IS NOT NULL THEN 1 ELSE 0 END) AS manual_decisions
               FROM access_request_items"""
        ).fetchone()
        session_rows = self.connection.execute(
            "SELECT state,COUNT(*) AS count FROM access_sessions GROUP BY state"
        ).fetchall()
        renewed = self.connection.execute(
            "SELECT COALESCE(SUM(renewed_count),0) FROM access_sessions"
        ).fetchone()[0]
        record_rows = self.connection.execute(
            "SELECT action,COUNT(*) AS count FROM access_records GROUP BY action"
        ).fetchall()
        requests_by_state = {row["state"]: int(row["count"]) for row in request_rows}
        return {
            "generated_at": now,
            "requests": {
                "total": sum(requests_by_state.values()),
                "by_state": requests_by_state,
                "items_total": int(item_rows["total"] or 0),
            },
            "approvals": {
                "pending_items": int(item_rows["pending"] or 0),
                "approved_items": int(item_rows["approved"] or 0),
                "rejected_items": int(item_rows["rejected"] or 0),
                "auto_approved_items": int(item_rows["auto_approved"] or 0),
                "manual_decisions": int(item_rows["manual_decisions"] or 0),
            },
            "access": {
                "sessions_total": sum(int(row["count"]) for row in session_rows),
                "sessions_by_state": {row["state"]: int(row["count"]) for row in session_rows},
                "renewals_total": int(renewed),
                "records_total": sum(int(row["count"]) for row in record_rows),
                "records_by_action": {row["action"]: int(row["count"]) for row in record_rows},
            },
        }

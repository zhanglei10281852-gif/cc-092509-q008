from __future__ import annotations

import threading
from datetime import UTC, datetime

import pytest

from app.core.clock import FrozenClock
from app.core.errors import ConflictError
from app.core.security import Principal


def _create_dossier(client, admin, code, secrecy_level, batch=None):
    if batch is None:
        batch = client.post(
            "/api/dossiers/batches",
            headers=admin["headers"],
            json={"intake_code": f"BATCH-{code}", "project_code": "P-EXT", "expected_count": 1},
        ).json()
    response = client.post(
        "/api/dossiers",
        headers=admin["headers"],
        json={
            "dossier_code": code,
            "intake_id": batch["id"],
            "asset_type": "工艺技术文档",
            "secrecy_level": secrecy_level,
            "quantity": 1,
            "unit": "份",
        },
    )
    assert response.status_code == 201, response.text
    assert response.json()["secrecy_level"] == secrecy_level
    return response.json()


def _create_approver(client, admin):
    created = client.post(
        "/api/users",
        headers=admin["headers"],
        json={
            "username": "approver1",
            "password": "Approver!234",
            "display_name": "保密办审批员",
            "role_codes": ["approver"],
        },
    )
    assert created.status_code == 201, created.text
    login = client.post(
        "/api/auth/login",
        json={"username": "approver1", "password": "Approver!234", "client_label": "tests"},
    )
    assert login.status_code == 200, login.text
    return {"headers": {"Authorization": f"Bearer {login.json()['token']}"}}


def _request_payload(items, key="req-0001", needed_until="2027-01-15T00:00:00+00:00"):
    return {
        "consultant_name": "王顾问",
        "consultant_organization": "华信资产评估事务所",
        "reason": "尽职调查需要查阅相关技术秘密",
        "needed_until": needed_until,
        "idempotency_key": key,
        "items": items,
    }


def _create_request(client, admin, items, key="req-0001"):
    response = client.post(
        "/api/access-requests",
        headers=admin["headers"],
        json=_request_payload(items, key=key),
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_secrecy_level_decides_whether_approval_is_needed(client, admin):
    low = _create_dossier(client, admin, "EXT-LOW", "confidential")
    high = _create_dossier(client, admin, "EXT-HIGH", "top_secret")
    body = _create_request(
        client,
        admin,
        [
            {"dossier_id": low["id"], "purpose": "核对工艺参数", "actions": ["view"]},
            {"dossier_id": high["id"], "purpose": "评估核心配方价值", "actions": ["view", "download"]},
        ],
    )
    assert body["state"] == "pending"
    assert body["replayed"] is False
    items = {item["dossier_id"]: item for item in body["items"]}
    assert items[low["id"]]["state"] == "approved"
    assert items[low["id"]]["requires_approval"] is False
    assert items[high["id"]]["state"] == "pending"
    assert items[high["id"]]["requires_approval"] is True


def test_identical_concurrent_creation_returns_same_request(client, admin):
    dossier = _create_dossier(client, admin, "EXT-IDEM", "internal")
    payload = _request_payload(
        [{"dossier_id": dossier["id"], "purpose": "核对工艺参数", "actions": ["view"]}],
        key="req-idem",
    )
    first = client.post("/api/access-requests", headers=admin["headers"], json=payload)
    second = client.post("/api/access-requests", headers=admin["headers"], json=payload)
    assert first.status_code == second.status_code == 201
    assert first.json()["id"] == second.json()["id"]
    assert second.json()["replayed"] is True

    changed = {**payload, "reason": "另一份不同的申请说明"}
    conflict = client.post("/api/access-requests", headers=admin["headers"], json=changed)
    assert conflict.status_code == 409


def test_concurrent_threads_create_single_request(client, admin):
    from app.database import transaction
    from app.archives.access_requests import AccessRequestService

    dossier = _create_dossier(client, admin, "EXT-RACE", "internal")
    payload = _request_payload(
        [{"dossier_id": dossier["id"], "purpose": "核对工艺参数", "actions": ["view"]}],
        key="req-race",
    )
    principal = Principal(
        user_id=admin["body"]["user"]["id"],
        username="admin",
        display_name="档案平台主管",
        department_id=None,
        permissions=frozenset({"*"}),
        session_id=admin["body"]["user"]["id"],
    )
    barrier = threading.Barrier(2)
    results = []

    def worker():
        barrier.wait()
        with transaction(immediate=True) as connection:
            results.append(AccessRequestService(connection).create(principal, payload))

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(results) == 2
    assert results[0]["id"] == results[1]["id"]
    assert sorted(result["replayed"] for result in results) == [False, True]


def test_partial_approval_and_full_session_lifecycle(client, admin):
    approver = _create_approver(client, admin)
    open_item = _create_dossier(client, admin, "EXT-OPEN", "internal")
    grant_item = _create_dossier(client, admin, "EXT-GRANT", "restricted")
    deny_item = _create_dossier(client, admin, "EXT-DENY", "restricted")
    body = _create_request(
        client,
        admin,
        [
            {"dossier_id": open_item["id"], "purpose": "核对公开工艺", "actions": ["view", "download"]},
            {"dossier_id": grant_item["id"], "purpose": "评估机密配方", "actions": ["view"]},
            {"dossier_id": deny_item["id"], "purpose": "评估另一配方", "actions": ["view", "download"]},
        ],
    )
    pending_items = {item["dossier_id"]: item for item in body["items"] if item["state"] == "pending"}
    decision = client.post(
        f"/api/access-requests/{body['id']}/decisions",
        headers=approver["headers"],
        json={
            "decisions": [
                {"item_id": pending_items[grant_item["id"]]["id"], "decision": "approve", "comment": "仅限现场查看"},
                {"item_id": pending_items[deny_item["id"]]["id"], "decision": "reject", "comment": "超出尽调范围"},
            ]
        },
    )
    assert decision.status_code == 200, decision.text
    decided = decision.json()
    assert decided["state"] == "partially_approved"
    items = {item["dossier_id"]: item for item in decided["items"]}
    assert items[grant_item["id"]]["state"] == "approved"
    assert items[deny_item["id"]]["state"] == "rejected"

    session = client.post(
        f"/api/access-requests/{body['id']}/sessions",
        headers=admin["headers"],
        json={},
    )
    assert session.status_code == 201, session.text
    session = session.json()
    assert session["state"] == "active"
    assert {item["dossier_id"] for item in session["approved_items"]} == {open_item["id"], grant_item["id"]}

    view = client.post(
        f"/api/access-sessions/{session['id']}/records",
        headers=admin["headers"],
        json={"dossier_id": open_item["id"], "action": "view", "idempotency_key": "rec-0001"},
    )
    assert view.status_code == 201, view.text
    download = client.post(
        f"/api/access-sessions/{session['id']}/records",
        headers=admin["headers"],
        json={"dossier_id": open_item["id"], "action": "download", "idempotency_key": "rec-0002"},
    )
    assert download.status_code == 201, download.text

    replay = client.post(
        f"/api/access-sessions/{session['id']}/records",
        headers=admin["headers"],
        json={"dossier_id": open_item["id"], "action": "view", "idempotency_key": "rec-0001"},
    )
    assert replay.status_code == 201
    assert replay.json()["replayed"] is True
    assert replay.json()["record"]["id"] == view.json()["record"]["id"]

    not_granted = client.post(
        f"/api/access-sessions/{session['id']}/records",
        headers=admin["headers"],
        json={"dossier_id": grant_item["id"], "action": "download", "idempotency_key": "rec-0003"},
    )
    assert not_granted.status_code == 409

    rejected_item = client.post(
        f"/api/access-sessions/{session['id']}/records",
        headers=admin["headers"],
        json={"dossier_id": deny_item["id"], "action": "view", "idempotency_key": "rec-0004"},
    )
    assert rejected_item.status_code == 409

    renewed = client.post(
        f"/api/access-sessions/{session['id']}/renew",
        headers=admin["headers"],
        json={"expires_at": "2027-01-10T00:00:00+00:00"},
    )
    assert renewed.status_code == 200, renewed.text
    assert renewed.json()["expires_at"] == "2027-01-10T00:00:00+00:00"
    assert renewed.json()["renewed_count"] == 1

    beyond_window = client.post(
        f"/api/access-sessions/{session['id']}/renew",
        headers=admin["headers"],
        json={"expires_at": "2027-02-01T00:00:00+00:00"},
    )
    assert beyond_window.status_code == 422

    revoked = client.post(
        f"/api/access-sessions/{session['id']}/revoke",
        headers=admin["headers"],
        json={"reason": "顾问提前离场"},
    )
    assert revoked.status_code == 200, revoked.text
    assert revoked.json()["state"] == "revoked"
    assert revoked.json()["revoke_reason"] == "顾问提前离场"

    after_revoke = client.post(
        f"/api/access-sessions/{session['id']}/records",
        headers=admin["headers"],
        json={"dossier_id": open_item["id"], "action": "view", "idempotency_key": "rec-0005"},
    )
    assert after_revoke.status_code == 409

    renew_revoked = client.post(
        f"/api/access-sessions/{session['id']}/renew",
        headers=admin["headers"],
        json={},
    )
    assert renew_revoked.status_code == 409


def test_requester_cannot_approve_own_request(client, admin):
    dossier = _create_dossier(client, admin, "EXT-SELF", "restricted")
    body = _create_request(
        client,
        admin,
        [{"dossier_id": dossier["id"], "purpose": "评估机密配方", "actions": ["view"]}],
    )
    item_id = body["items"][0]["id"]
    own = client.post(
        f"/api/access-requests/{body['id']}/decisions",
        headers=admin["headers"],
        json={"decisions": [{"item_id": item_id, "decision": "approve"}]},
    )
    assert own.status_code == 422


def test_session_requires_approved_request(client, admin):
    dossier = _create_dossier(client, admin, "EXT-PEND", "restricted")
    body = _create_request(
        client,
        admin,
        [{"dossier_id": dossier["id"], "purpose": "评估机密配方", "actions": ["view"]}],
    )
    session = client.post(f"/api/access-requests/{body['id']}/sessions", headers=admin["headers"], json={})
    assert session.status_code == 409


def test_cancel_request_revokes_active_session(client, admin):
    approver = _create_approver(client, admin)
    dossier = _create_dossier(client, admin, "EXT-CANCEL", "restricted")
    body = _create_request(
        client,
        admin,
        [{"dossier_id": dossier["id"], "purpose": "评估机密配方", "actions": ["view"]}],
    )
    decided = client.post(
        f"/api/access-requests/{body['id']}/decisions",
        headers=approver["headers"],
        json={"decisions": [{"item_id": body["items"][0]["id"], "decision": "approve"}]},
    )
    assert decided.json()["state"] == "approved"
    session = client.post(f"/api/access-requests/{body['id']}/sessions", headers=admin["headers"], json={})
    assert session.status_code == 201
    cancelled = client.post(f"/api/access-requests/{body['id']}/cancel", headers=admin["headers"])
    assert cancelled.status_code == 200, cancelled.text
    assert cancelled.json()["state"] == "cancelled"
    assert cancelled.json()["sessions"][0]["state"] == "revoked"
    record = client.post(
        f"/api/access-sessions/{session.json()['id']}/records",
        headers=admin["headers"],
        json={"dossier_id": dossier["id"], "action": "view", "idempotency_key": "rec-cancel"},
    )
    assert record.status_code == 409


def test_expired_session_cannot_record_or_renew(client, admin):
    from app.database import transaction
    from app.archives.access_requests import AccessRequestService, AccessSessionService

    dossier = _create_dossier(client, admin, "EXT-EXPIRE", "internal")
    clock = FrozenClock(datetime(2026, 9, 26, 8, 0, tzinfo=UTC))
    principal = Principal(
        user_id=admin["body"]["user"]["id"],
        username="admin",
        display_name="档案平台主管",
        department_id=None,
        permissions=frozenset({"*"}),
        session_id=admin["body"]["user"]["id"],
    )
    payload = _request_payload(
        [{"dossier_id": dossier["id"], "purpose": "核对工艺参数", "actions": ["view"]}],
        key="req-expire",
        needed_until="2026-10-10T08:00:00+00:00",
    )
    with transaction(immediate=True) as connection:
        requests = AccessRequestService(connection, clock)
        sessions = AccessSessionService(connection, clock)
        body = requests.create(principal, payload)
        session = requests.open_session(principal, body["id"], {})
        record = sessions.record(
            principal,
            session["id"],
            {"dossier_id": dossier["id"], "action": "view", "idempotency_key": "rec-before"},
        )
        assert record["replayed"] is False
        clock.advance(days=15)
        with pytest.raises(ConflictError):
            sessions.record(
                principal,
                session["id"],
                {"dossier_id": dossier["id"], "action": "view", "idempotency_key": "rec-after"},
            )
        with pytest.raises(ConflictError):
            sessions.renew(principal, session["id"], {})
        assert sessions.detail(principal, session["id"])["state"] == "expired"


def test_list_and_detail_endpoints(client, admin):
    dossier = _create_dossier(client, admin, "EXT-LIST", "internal")
    body = _create_request(
        client,
        admin,
        [{"dossier_id": dossier["id"], "purpose": "核对工艺参数", "actions": ["view"]}],
        key="req-list",
    )
    listing = client.get("/api/access-requests", headers=admin["headers"])
    assert listing.status_code == 200
    assert any(item["id"] == body["id"] and item["item_count"] == 1 for item in listing.json())
    approved_only = client.get("/api/access-requests", headers=admin["headers"], params={"state": "approved"})
    assert [item["id"] for item in approved_only.json()] == [body["id"]]
    detail = client.get(f"/api/access-requests/{body['id']}", headers=admin["headers"])
    assert detail.status_code == 200
    assert detail.json()["items"][0]["dossier_code"] == "EXT-LIST"
    session = client.post(f"/api/access-requests/{body['id']}/sessions", headers=admin["headers"], json={})
    session_detail = client.get(f"/api/access-sessions/{session.json()['id']}", headers=admin["headers"])
    assert session_detail.status_code == 200
    assert session_detail.json()["request_id"] == body["id"]
    missing = client.get("/api/access-requests/9999", headers=admin["headers"])
    assert missing.status_code == 404


def test_create_request_validation(client, admin):
    dossier = _create_dossier(client, admin, "EXT-VALID", "internal")
    item = {"dossier_id": dossier["id"], "purpose": "核对工艺参数", "actions": ["view"]}
    past = client.post(
        "/api/access-requests",
        headers=admin["headers"],
        json=_request_payload([item], key="req-past", needed_until="2020-01-01T00:00:00+00:00"),
    )
    assert past.status_code == 422
    duplicated = client.post(
        "/api/access-requests",
        headers=admin["headers"],
        json=_request_payload([item, dict(item)], key="req-dup"),
    )
    assert duplicated.status_code == 422
    missing_dossier = client.post(
        "/api/access-requests",
        headers=admin["headers"],
        json=_request_payload([{"dossier_id": 9999, "purpose": "核对工艺参数", "actions": ["view"]}], key="req-missing"),
    )
    assert missing_dossier.status_code == 404


def test_statistics_distinguish_request_approval_and_access(client, admin):
    approver = _create_approver(client, admin)
    auto = _create_dossier(client, admin, "EXT-STAT-A", "internal")
    manual = _create_dossier(client, admin, "EXT-STAT-B", "restricted")
    denied = _create_dossier(client, admin, "EXT-STAT-C", "top_secret")
    body = _create_request(
        client,
        admin,
        [
            {"dossier_id": auto["id"], "purpose": "核对公开工艺", "actions": ["view", "download"]},
            {"dossier_id": manual["id"], "purpose": "评估机密配方", "actions": ["view"]},
            {"dossier_id": denied["id"], "purpose": "评估绝密材料", "actions": ["view"]},
        ],
        key="req-stats",
    )
    pending = {item["dossier_id"]: item for item in body["items"] if item["state"] == "pending"}
    client.post(
        f"/api/access-requests/{body['id']}/decisions",
        headers=approver["headers"],
        json={
            "decisions": [
                {"item_id": pending[manual["id"]]["id"], "decision": "approve"},
                {"item_id": pending[denied["id"]]["id"], "decision": "reject"},
            ]
        },
    )
    session = client.post(f"/api/access-requests/{body['id']}/sessions", headers=admin["headers"], json={}).json()
    client.post(
        f"/api/access-sessions/{session['id']}/records",
        headers=admin["headers"],
        json={"dossier_id": auto["id"], "action": "view", "idempotency_key": "stat-1"},
    )
    client.post(
        f"/api/access-sessions/{session['id']}/records",
        headers=admin["headers"],
        json={"dossier_id": auto["id"], "action": "download", "idempotency_key": "stat-2"},
    )
    stats = client.get("/api/access-requests/statistics", headers=admin["headers"])
    assert stats.status_code == 200, stats.text
    overview = stats.json()
    assert overview["requests"]["total"] == 1
    assert overview["requests"]["by_state"] == {"partially_approved": 1}
    assert overview["requests"]["items_total"] == 3
    assert overview["approvals"]["auto_approved_items"] == 1
    assert overview["approvals"]["manual_decisions"] == 2
    assert overview["approvals"]["approved_items"] == 2
    assert overview["approvals"]["rejected_items"] == 1
    assert overview["approvals"]["pending_items"] == 0
    assert overview["access"]["sessions_total"] == 1
    assert overview["access"]["sessions_by_state"] == {"active": 1}
    assert overview["access"]["records_total"] == 2
    assert overview["access"]["records_by_action"] == {"view": 1, "download": 1}

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient

from app.core.clock import to_storage
from app.database import get_connection


def _iso(days_from_now: int) -> str:
    return to_storage(datetime.now(UTC) + timedelta(days=days_from_now))


def _make_dossier(client, headers, code, secrecy_level, batch_id):
    response = client.post(
        "/api/dossiers",
        headers=headers,
        json={
            "dossier_code": code,
            "intake_id": batch_id,
            "asset_type": "工艺文档",
            "secrecy_level": secrecy_level,
            "quantity": 1,
            "unit": "份",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _bootstrap_dossiers(client, admin):
    client.post(
        "/api/dossiers/vaults",
        headers=admin["headers"],
        json={
            "code": "REV-01",
            "building": "保密楼",
            "room": "查阅室",
            "cabinet": "专用柜",
            "shelf": "一层",
            "sensitivity": "restricted",
            "capacity_units": 50,
        },
    )
    batch = client.post(
        "/api/dossiers/batches",
        headers=admin["headers"],
        json={"intake_code": "REV-BATCH", "project_code": "REV", "expected_count": 3},
    ).json()
    internal = _make_dossier(client, admin["headers"], "REV-D-INTERNAL", "internal", batch["id"])
    confidential = _make_dossier(client, admin["headers"], "REV-D-CONF", "confidential", batch["id"])
    restricted = _make_dossier(client, admin["headers"], "REV-D-RESTR", "restricted", batch["id"])
    return internal, confidential, restricted


def _make_approver(client, admin, username):
    created = client.post(
        "/api/users",
        headers=admin["headers"],
        json={
            "username": username,
            "password": "Approver!2345",
            "display_name": f"审批人 {username}",
            "role_codes": ["approver"],
        },
    )
    assert created.status_code == 201, created.text
    login = client.post(
        "/api/auth/login",
        json={"username": username, "password": "Approver!2345", "client_label": "tests"},
    )
    assert login.status_code == 200, login.text
    return {"headers": {"Authorization": f"Bearer {login.json()['token']}"}}


def _mixed_payload(internal_id, confidential_id, restricted_id):
    return {
        "idempotency_key": "REV-IDEMP-0001",
        "visitor_name": "外部顾问王工",
        "visitor_organization": "合作律所",
        "note": "专利侵权分析",
        "expires_at": _iso(10),
        "items": [
            {"dossier_id": internal_id, "purpose": "在线核对技术背景", "action": "view"},
            {"dossier_id": confidential_id, "purpose": "下载用于比对分析", "action": "download", "download_limit": 1},
            {"dossier_id": restricted_id, "purpose": "查阅核心工艺", "action": "view"},
        ],
    }


def _scenario_partial_approval(client, admin):
    """创建混合密级申请并完成审批：内部/秘密通过，机密被否决，返回会话与档案 id。"""
    internal, confidential, restricted = _bootstrap_dossiers(client, admin)
    approver_one = _make_approver(client, admin, "approver01")
    approver_two = _make_approver(client, admin, "approver02")

    created = client.post(
        "/api/reviews/requests",
        headers=admin["headers"],
        json=_mixed_payload(internal["id"], confidential["id"], restricted["id"]),
    )
    assert created.status_code == 201, created.text
    request_id = created.json()["id"]
    items = {item["dossier_id"]: item for item in created.json()["items"]}
    assert items[internal["id"]]["state"] == "approved"
    assert items[confidential["id"]]["state"] == "pending"
    assert items[restricted["id"]]["state"] == "pending"
    assert items[confidential["id"]]["required_approvals"] == 1
    assert items[restricted["id"]]["required_approvals"] == 2

    first = client.post(
        f"/api/reviews/requests/{request_id}/decisions",
        headers=approver_one["headers"],
        json={
            "items": [
                {"item_id": items[confidential["id"]]["id"], "decision": "approve"},
                {"item_id": items[restricted["id"]]["id"], "decision": "approve"},
            ]
        },
    )
    assert first.status_code == 200, first.text
    assert first.json()["state"] == "pending"

    second = client.post(
        f"/api/reviews/requests/{request_id}/decisions",
        headers=approver_two["headers"],
        json={"items": [{"item_id": items[restricted["id"]]["id"], "decision": "reject", "comment": "范围过大"}]},
    )
    assert second.status_code == 200, second.text
    body = second.json()
    assert body["state"] == "partially_approved"
    final_items = {item["dossier_id"]: item for item in body["items"]}
    assert final_items[internal["id"]]["state"] == "approved"
    assert final_items[confidential["id"]]["state"] == "approved"
    assert final_items[restricted["id"]]["state"] == "rejected"
    assert len(body["sessions"]) == 1
    session_id = body["sessions"][0]["id"]
    return request_id, session_id, internal["id"], confidential["id"], restricted["id"]


def test_internal_only_request_auto_opens_session(client, admin):
    internal, _, _ = _bootstrap_dossiers(client, admin)
    payload = {
        "idempotency_key": "REV-IDEMP-INTERNAL",
        "visitor_name": "顾问甲",
        "visitor_organization": "咨询公司",
        "expires_at": _iso(7),
        "items": [{"dossier_id": internal["id"], "purpose": "背景资料在线查阅", "action": "view"}],
    }
    response = client.post("/api/reviews/requests", headers=admin["headers"], json=payload)
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["state"] == "approved"
    assert body["items"][0]["state"] == "approved"

    detail = client.get(f"/api/reviews/requests/{body['id']}", headers=admin["headers"]).json()
    assert len(detail["sessions"]) == 1
    assert detail["sessions"][0]["state"] == "active"


def test_concurrent_identical_requests_return_same_result(client, admin):
    internal, _, _ = _bootstrap_dossiers(client, admin)
    payload = {
        "idempotency_key": "REV-IDEMP-CONCURRENT",
        "visitor_name": "顾问乙",
        "visitor_organization": "咨询公司",
        "expires_at": _iso(5),
        "items": [{"dossier_id": internal["id"], "purpose": "并发申请在线查阅", "action": "view"}],
    }

    from app.main import app

    def submit():
        with TestClient(app) as local_client:
            response = local_client.post("/api/reviews/requests", headers=admin["headers"], json=payload)
            return response.status_code, response.json()["id"]

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: submit(), range(2)))
    assert all(status == 201 for status, _ in results)
    assert results[0][1] == results[1][1]

    listed = client.get("/api/reviews/requests", headers=admin["headers"]).json()
    matching = [item for item in listed["data"] if item["idempotency_key"] == "REV-IDEMP-CONCURRENT"]
    assert len(matching) == 1


def test_idempotency_key_rejects_different_payload(client, admin):
    internal, confidential, _ = _bootstrap_dossiers(client, admin)
    base = {
        "idempotency_key": "REV-IDEMP-CONFLICT",
        "visitor_name": "顾问丙",
        "visitor_organization": "咨询公司",
        "expires_at": _iso(5),
        "items": [{"dossier_id": internal["id"], "purpose": "第一次申请在线查阅", "action": "view"}],
    }
    first = client.post("/api/reviews/requests", headers=admin["headers"], json=base)
    assert first.status_code == 201, first.text
    base["items"] = [{"dossier_id": confidential["id"], "purpose": "第二次换档案下载", "action": "download"}]
    second = client.post("/api/reviews/requests", headers=admin["headers"], json=base)
    assert second.status_code == 409


def test_multi_level_approval_and_partial_approval(client, admin):
    request_id, session_id, internal_id, confidential_id, restricted_id = _scenario_partial_approval(client, admin)

    # 申请人不能审批自己的申请
    detail = client.get(f"/api/reviews/requests/{request_id}", headers=admin["headers"]).json()
    restricted_item = next(item for item in detail["items"] if item["dossier_id"] == restricted_id)
    self_decision = client.post(
        f"/api/reviews/requests/{request_id}/decisions",
        headers=admin["headers"],
        json={"items": [{"item_id": restricted_item["id"], "decision": "approve"}]},
    )
    assert self_decision.status_code in {409, 422}

    session = client.get(f"/api/reviews/sessions/{session_id}", headers=admin["headers"]).json()
    assert {grant["dossier_id"] for grant in session["grants"]} == {internal_id, confidential_id}


def test_access_respects_action_limits_and_records(client, admin):
    _, session_id, internal_id, confidential_id, restricted_id = _scenario_partial_approval(client, admin)
    detail = client.get(f"/api/reviews/sessions/{session_id}", headers=admin["headers"]).json()
    code = detail["session_code"]

    viewed = client.post(
        "/api/reviews/accesses",
        headers=admin["headers"],
        json={"session_code": code, "dossier_id": internal_id, "action": "view"},
    )
    assert viewed.status_code == 201, viewed.text

    # 内部档案仅授权 view，下载被拒绝
    download_forbidden = client.post(
        "/api/reviews/accesses",
        headers=admin["headers"],
        json={"session_code": code, "dossier_id": internal_id, "action": "download"},
    )
    assert download_forbidden.status_code == 409

    # 秘密档案允许下载一次
    first_download = client.post(
        "/api/reviews/accesses",
        headers=admin["headers"],
        json={"session_code": code, "dossier_id": confidential_id, "action": "download"},
    )
    assert first_download.status_code == 201, first_download.text
    assert first_download.json()["grant"]["download_count"] == 1

    # 超过下载上限
    second_download = client.post(
        "/api/reviews/accesses",
        headers=admin["headers"],
        json={"session_code": code, "dossier_id": confidential_id, "action": "download"},
    )
    assert second_download.status_code == 409

    # 被否决的机密档案不在授权集合，不能访问
    unauthorized = client.post(
        "/api/reviews/accesses",
        headers=admin["headers"],
        json={"session_code": code, "dossier_id": restricted_id, "action": "view"},
    )
    assert unauthorized.status_code == 409

    records = client.get(f"/api/reviews/sessions/{session_id}/accesses", headers=admin["headers"]).json()
    assert sorted(record["action"] for record in records["data"]) == ["download", "view"]

    # 被拒绝的尝试不产生访问记录，但留下 denied 审计事件
    stats = client.get("/api/reviews/stats/summary", headers=admin["headers"]).json()
    assert "review.access.denied" in stats["events_by_action"]
    assert stats["events_by_action"]["review.access.denied"].get("denied", 0) >= 3


def test_revoked_session_cannot_download(client, admin):
    _, session_id, _, confidential_id, _ = _scenario_partial_approval(client, admin)
    detail = client.get(f"/api/reviews/sessions/{session_id}", headers=admin["headers"]).json()

    revoked = client.post(
        f"/api/reviews/sessions/{session_id}/revoke",
        headers=admin["headers"],
        json={"reason": "顾问提前离场"},
    )
    assert revoked.status_code == 200
    assert revoked.json()["state"] == "revoked"

    denied = client.post(
        "/api/reviews/accesses",
        headers=admin["headers"],
        json={"session_code": detail["session_code"], "dossier_id": confidential_id, "action": "download"},
    )
    assert denied.status_code == 409

    renew = client.post(
        f"/api/reviews/sessions/{session_id}/renew",
        headers=admin["headers"],
        json={"new_expires_at": _iso(20)},
    )
    assert renew.status_code == 409


def test_expired_session_cannot_create_records(client, admin):
    _, session_id, internal_id, _, _ = _scenario_partial_approval(client, admin)
    detail = client.get(f"/api/reviews/sessions/{session_id}", headers=admin["headers"]).json()
    past = to_storage(datetime.now(UTC) - timedelta(minutes=1))
    get_connection().execute("UPDATE review_sessions SET expires_at=? WHERE id=?", (past, session_id))

    denied = client.post(
        "/api/reviews/accesses",
        headers=admin["headers"],
        json={"session_code": detail["session_code"], "dossier_id": internal_id, "action": "view"},
    )
    assert denied.status_code == 409
    refreshed = client.get(f"/api/reviews/sessions/{session_id}", headers=admin["headers"]).json()
    assert refreshed["state"] == "expired"


def test_renew_extends_session_and_grants(client, admin):
    _, session_id, _, _, _ = _scenario_partial_approval(client, admin)
    new_expires = _iso(20)
    renewed = client.post(
        f"/api/reviews/sessions/{session_id}/renew",
        headers=admin["headers"],
        json={"new_expires_at": new_expires, "reason": "项目延期"},
    )
    assert renewed.status_code == 200, renewed.text
    assert renewed.json()["expires_at"] == new_expires
    assert renewed.json()["renew_count"] == 1
    assert all(grant["expires_at"] == new_expires for grant in renewed.json()["grants"])


def test_revoke_single_grant_keeps_other_active(client, admin):
    _, session_id, internal_id, confidential_id, _ = _scenario_partial_approval(client, admin)
    detail = client.get(f"/api/reviews/sessions/{session_id}", headers=admin["headers"]).json()
    grants = {grant["dossier_id"]: grant for grant in detail["grants"]}
    code = detail["session_code"]

    revoked = client.post(
        f"/api/reviews/grants/{grants[confidential_id]['id']}/revoke",
        headers=admin["headers"],
        json={"reason": "下载范围收回"},
    )
    assert revoked.status_code == 200

    denied = client.post(
        "/api/reviews/accesses",
        headers=admin["headers"],
        json={"session_code": code, "dossier_id": confidential_id, "action": "view"},
    )
    assert denied.status_code == 409

    allowed = client.post(
        "/api/reviews/accesses",
        headers=admin["headers"],
        json={"session_code": code, "dossier_id": internal_id, "action": "view"},
    )
    assert allowed.status_code == 201


def test_stats_distinguishes_request_approval_access_events(client, admin):
    _, _, _, _, _ = _scenario_partial_approval(client, admin)
    stats = client.get("/api/reviews/stats/summary", headers=admin["headers"])
    assert stats.status_code == 200, stats.text
    body = stats.json()
    assert body["event_family_counts"]["request"] >= 1
    assert body["event_family_counts"]["approval"] >= 1
    assert body["actual_access"]["download_count"] == 0
    assert body["requests_by_state"].get("partially_approved") == 1
    assert "review.request.submitted" in body["events_by_action"]
    assert "review.request.finalized" in body["events_by_action"]


def test_stats_counts_actual_access_as_third_family(client, admin):
    _, session_id, internal_id, confidential_id, _ = _scenario_partial_approval(client, admin)
    detail = client.get(f"/api/reviews/sessions/{session_id}", headers=admin["headers"]).json()
    code = detail["session_code"]
    assert client.post(
        "/api/reviews/accesses",
        headers=admin["headers"],
        json={"session_code": code, "dossier_id": internal_id, "action": "view"},
    ).status_code == 201
    assert client.post(
        "/api/reviews/accesses",
        headers=admin["headers"],
        json={"session_code": code, "dossier_id": confidential_id, "action": "download"},
    ).status_code == 201

    body = client.get("/api/reviews/stats/summary", headers=admin["headers"]).json()
    families = body["event_family_counts"]
    assert families["request"] >= 1
    assert families["approval"] >= 1
    assert families["access"] >= 2
    assert body["actual_access"]["view_count"] == 1
    assert body["actual_access"]["download_count"] == 1
    assert "review.access.viewed" in body["events_by_action"]
    assert "review.access.downloaded" in body["events_by_action"]

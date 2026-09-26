from __future__ import annotations

import sqlite3
from typing import Any

from app.core.errors import ConflictError, NotFoundError, ValidationError


REVIEW_REQUEST_STATES = ("pending", "approved", "partially_approved", "rejected", "cancelled", "expired")


def _row(row: sqlite3.Row | None, message: str = "查阅记录不存在") -> dict[str, Any]:
    if row is None:
        raise NotFoundError(message)
    return dict(row)


class ReviewRequestRepository:
    def __init__(self, connection: sqlite3.Connection):
        self.connection = connection

    def create_request(self, data: dict[str, Any], request_code: str, now: str) -> dict[str, Any]:
        cursor = self.connection.execute(
            """INSERT INTO review_requests(request_code,requested_by,visitor_name,visitor_organization,
                  idempotency_key,request_hash,note,state,expires_at,access_starts_at,access_expires_at,
                  created_at,updated_at)
               VALUES(?,?,?,?,?,?,?,'pending',?,?,?,?,?)""",
            (
                request_code, data["requested_by"], data["visitor_name"], data["visitor_organization"],
                data["idempotency_key"], data["request_hash"], data["note"],
                data["approval_expires_at"], data["starts_at"], data["expires_at"], now, now,
            ),
        )
        return self.get_request(int(cursor.lastrowid))

    def by_idempotency(self, requested_by: int, key: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM review_requests WHERE requested_by=? AND idempotency_key=?",
            (requested_by, key),
        ).fetchone()
        return dict(row) if row else None

    def get_request(self, request_id: int) -> dict[str, Any]:
        row = _row(
            self.connection.execute("SELECT * FROM review_requests WHERE id=?", (request_id,)).fetchone(),
            "查阅申请不存在",
        )
        row["items"] = self.list_items(request_id)
        return row

    def list_requests(self, *, state: str | None = None, requested_by: int | None = None, limit: int = 100) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if state:
            clauses.append("state=?")
            params.append(state)
        if requested_by is not None:
            clauses.append("requested_by=?")
            params.append(requested_by)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        params.append(limit)
        rows = self.connection.execute(
            "SELECT * FROM review_requests" + where + " ORDER BY id DESC LIMIT ?",
            tuple(params),
        ).fetchall()
        return [dict(row) for row in rows]

    def add_item(self, request_id: int, item: dict[str, Any], required_approvals: int, now: str) -> dict[str, Any]:
        state = "approved" if required_approvals == 0 else "pending"
        cursor = self.connection.execute(
            """INSERT INTO review_request_items(request_id,dossier_id,purpose,action,download_limit,secrecy_level,
                  required_approvals,state,created_at,updated_at)
               VALUES(?,?,?,?,?,?,?,?,?,?)""",
            (
                request_id, item["dossier_id"], item["purpose"], item["action"], item["download_limit"],
                item["secrecy_level"], required_approvals, state, now, now,
            ),
        )
        return self.get_item(int(cursor.lastrowid))

    def get_item(self, item_id: int) -> dict[str, Any]:
        return _row(
            self.connection.execute("SELECT * FROM review_request_items WHERE id=?", (item_id,)).fetchone(),
            "查阅申请条目不存在",
        )

    def list_items(self, request_id: int) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT * FROM review_request_items WHERE request_id=? ORDER BY id",
            (request_id,),
        ).fetchall()
        return [dict(row) for row in rows]

    def decisions_of_item(self, item_id: int) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT * FROM review_item_decisions WHERE item_id=? ORDER BY id",
            (item_id,),
        ).fetchall()
        return [dict(row) for row in rows]

    def add_decision(self, item_id: int, approver_user_id: int, decision: str, comment: str, now: str) -> None:
        self.connection.execute(
            """INSERT INTO review_item_decisions(item_id,approver_user_id,decision,comment,decided_at)
               VALUES(?,?,?,?,?)""",
            (item_id, approver_user_id, decision, comment, now),
        )

    def set_item_state(self, item_id: int, state: str, now: str, *, reject_reason: str | None = None) -> None:
        if reject_reason is None:
            self.connection.execute(
                "UPDATE review_request_items SET state=?,version=version+1,updated_at=? WHERE id=?",
                (state, now, item_id),
            )
        else:
            self.connection.execute(
                "UPDATE review_request_items SET state=?,reject_reason=?,version=version+1,updated_at=? WHERE id=?",
                (state, reject_reason, now, item_id),
            )

    def refresh_request_state(self, request_id: int, now: str) -> dict[str, Any]:
        items = self.list_items(request_id)
        if any(item["state"] == "pending" for item in items):
            return self.get_request(request_id)
        approved = [item for item in items if item["state"] == "approved"]
        if len(approved) == len(items):
            state = "approved"
        elif approved:
            state = "partially_approved"
        else:
            state = "rejected"
        self.connection.execute(
            "UPDATE review_requests SET state=?,decided_at=COALESCE(decided_at,?),version=version+1,updated_at=? WHERE id=?",
            (state, now, now, request_id),
        )
        return self.get_request(request_id)

    def set_request_state(self, request_id: int, state: str, now: str) -> None:
        self.connection.execute(
            "UPDATE review_requests SET state=?,version=version+1,updated_at=? WHERE id=?",
            (state, now, request_id),
        )

    def expire_due_requests(self, now: str) -> list[int]:
        rows = self.connection.execute(
            "SELECT id FROM review_requests WHERE state='pending' AND expires_at<?",
            (now,),
        ).fetchall()
        ids = [int(row[0]) for row in rows]
        if ids:
            self.connection.execute(
                "UPDATE review_requests SET state='expired',version=version+1,updated_at=? WHERE state='pending' AND expires_at<?",
                (now, now),
            )
            self.connection.execute(
                """UPDATE review_request_items SET state='cancelled',version=version+1,updated_at=?
                   WHERE state='pending' AND request_id IN (""" + ",".join("?" for _ in ids) + ")",
                (now, *ids),
            )
        return ids


class ReviewSessionRepository:
    def __init__(self, connection: sqlite3.Connection):
        self.connection = connection

    def create_session(self, request: dict[str, Any], session_code: str, now: str) -> int:
        cursor = self.connection.execute(
            """INSERT INTO review_sessions(session_code,request_id,visitor_name,visitor_organization,
                  starts_at,expires_at,state,created_at,updated_at)
               VALUES(?,?,?,?,?,?,'active',?,?)""",
            (
                session_code, request["id"], request["visitor_name"], request["visitor_organization"],
                request["access_starts_at"], request["access_expires_at"], now, now,
            ),
        )
        return int(cursor.lastrowid)

    def add_grant(self, session_id: int, item: dict[str, Any], expires_at: str, now: str) -> int:
        cursor = self.connection.execute(
            """INSERT INTO review_session_grants(session_id,item_id,dossier_id,purpose,action,download_limit,
                  state,expires_at,created_at,updated_at)
               VALUES(?,?,?,?,?,?,'active',?,?,?)""",
            (
                session_id, item["id"], item["dossier_id"], item["purpose"], item["action"],
                item["download_limit"], expires_at, now, now,
            ),
        )
        return int(cursor.lastrowid)

    def get_session(self, session_id: int) -> dict[str, Any]:
        return _row(
            self.connection.execute("SELECT * FROM review_sessions WHERE id=?", (session_id,)).fetchone(),
            "查阅会话不存在",
        )

    def get_session_by_code(self, session_code: str) -> dict[str, Any] | None:
        row = self.connection.execute("SELECT * FROM review_sessions WHERE session_code=?", (session_code,)).fetchone()
        return dict(row) if row else None

    def list_sessions(self, *, request_id: int | None = None, state: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if request_id is not None:
            clauses.append("request_id=?")
            params.append(request_id)
        if state:
            clauses.append("state=?")
            params.append(state)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        params.append(limit)
        rows = self.connection.execute(
            "SELECT * FROM review_sessions" + where + " ORDER BY id DESC LIMIT ?",
            tuple(params),
        ).fetchall()
        return [dict(row) for row in rows]

    def list_grants(self, session_id: int) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            """SELECT g.*,s.dossier_code,s.secrecy_level
               FROM review_session_grants g JOIN dossiers s ON s.id=g.dossier_id
               WHERE g.session_id=? ORDER BY g.id""",
            (session_id,),
        ).fetchall()
        return [dict(row) for row in rows]

    def get_grant(self, grant_id: int) -> dict[str, Any]:
        return _row(
            self.connection.execute("SELECT * FROM review_session_grants WHERE id=?", (grant_id,)).fetchone(),
            "会话授权不存在",
        )

    def find_grant(self, session_id: int, dossier_id: int) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM review_session_grants WHERE session_id=? AND dossier_id=?",
            (session_id, dossier_id),
        ).fetchone()
        return dict(row) if row else None

    def renew(self, session_id: int, new_expires_at: str, grant_ids: list[int] | None, now: str) -> int:
        result = self.connection.execute(
            "UPDATE review_sessions SET expires_at=?,renew_count=renew_count+1,version=version+1,updated_at=? WHERE id=?",
            (new_expires_at, now, session_id),
        )
        if result.rowcount != 1:
            raise ConflictError("会话续期失败")
        if grant_ids:
            placeholders = ",".join("?" for _ in grant_ids)
            updated = self.connection.execute(
                f"UPDATE review_session_grants SET expires_at=?,updated_at=? "
                f"WHERE session_id=? AND state='active' AND id IN ({placeholders})",
                (new_expires_at, now, session_id, *grant_ids),
            )
            if updated.rowcount != len(set(grant_ids)):
                raise ValidationError("部分授权不存在或已撤销，不能续期")
        else:
            self.connection.execute(
                "UPDATE review_session_grants SET expires_at=?,updated_at=? WHERE session_id=? AND state='active'",
                (new_expires_at, now, session_id),
            )
        return int(self.connection.execute("SELECT renew_count FROM review_sessions WHERE id=?", (session_id,)).fetchone()[0])

    def expire_due_sessions(self, now: str) -> list[int]:
        rows = self.connection.execute(
            "SELECT id FROM review_sessions WHERE state='active' AND expires_at<?",
            (now,),
        ).fetchall()
        ids = [int(row[0]) for row in rows]
        if ids:
            self.connection.execute(
                "UPDATE review_sessions SET state='expired',version=version+1,updated_at=? WHERE state='active' AND expires_at<?",
                (now, now),
            )
            placeholders = ",".join("?" for _ in ids)
            self.connection.execute(
                f"UPDATE review_session_grants SET state='expired',updated_at=? "
                f"WHERE state='active' AND session_id IN ({placeholders})",
                (now, *ids),
            )
        return ids

    def revoke_session(self, session_id: int, reason: str, revoked_by: int, now: str) -> None:
        self.connection.execute(
            "UPDATE review_sessions SET state='revoked',revoke_reason=?,revoked_by=?,revoked_at=?,version=version+1,updated_at=? WHERE id=?",
            (reason, revoked_by, now, now, session_id),
        )
        self.connection.execute(
            "UPDATE review_session_grants SET state='revoked',revoke_reason=?,revoked_by=?,revoked_at=?,updated_at=? "
            "WHERE session_id=? AND state='active'",
            (reason, revoked_by, now, now, session_id),
        )

    def revoke_grant(self, grant_id: int, reason: str, revoked_by: int, now: str) -> None:
        result = self.connection.execute(
            "UPDATE review_session_grants SET state='revoked',revoke_reason=?,revoked_by=?,revoked_at=?,updated_at=? "
            "WHERE id=? AND state='active'",
            (reason, revoked_by, now, now, grant_id),
        )
        if result.rowcount != 1:
            raise ConflictError("授权已经撤销或过期")

    def add_access_record(
        self,
        session_id: int,
        grant_id: int,
        dossier_id: int,
        operator_user_id: int,
        action: str,
        file_ref: str,
        now: str,
    ) -> int:
        cursor = self.connection.execute(
            """INSERT INTO review_access_records(session_id,grant_id,dossier_id,operator_user_id,action,file_ref,occurred_at,created_at)
               VALUES(?,?,?,?,?,?,?,?)""",
            (session_id, grant_id, dossier_id, operator_user_id, action, file_ref, now, now),
        )
        return int(cursor.lastrowid)

    def increment_download(self, grant_id: int, now: str) -> bool:
        result = self.connection.execute(
            """UPDATE review_session_grants SET download_count=download_count+1,updated_at=?
               WHERE id=? AND state='active' AND download_count<download_limit
                 AND EXISTS (
                     SELECT 1 FROM review_sessions s
                     WHERE s.id=review_session_grants.session_id AND s.state='active'
                       AND s.starts_at<=? AND s.expires_at>=?
                 )
                 AND expires_at>=?""",
            (now, grant_id, now, now, now),
        )
        return result.rowcount == 1

    def list_access_records(self, session_id: int) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            """SELECT r.*,u.display_name AS operator_name,s.dossier_code
               FROM review_access_records r
               JOIN users u ON u.id=r.operator_user_id
               JOIN dossiers s ON s.id=r.dossier_id
               WHERE r.session_id=? ORDER BY r.id""",
            (session_id,),
        ).fetchall()
        return [dict(row) for row in rows]

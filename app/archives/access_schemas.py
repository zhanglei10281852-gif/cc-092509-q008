from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class AccessRequestItem(BaseModel):
    dossier_id: int = Field(gt=0)
    purpose: str = Field(min_length=4, max_length=500)
    actions: list[Literal["view", "download"]] = Field(min_length=1, max_length=2)


class AccessRequestCreate(BaseModel):
    request_code: str | None = Field(default=None, max_length=64)
    consultant_name: str = Field(min_length=2, max_length=100)
    consultant_organization: str = Field(min_length=2, max_length=200)
    reason: str = Field(min_length=4, max_length=1000)
    needed_until: str = Field(min_length=10, max_length=40)
    idempotency_key: str = Field(min_length=4, max_length=100)
    items: list[AccessRequestItem] = Field(min_length=1, max_length=50)


class AccessItemDecision(BaseModel):
    item_id: int = Field(gt=0)
    decision: Literal["approve", "reject"]
    comment: str = Field(default="", max_length=500)


class AccessRequestDecide(BaseModel):
    decisions: list[AccessItemDecision] = Field(min_length=1, max_length=50)


class AccessSessionOpen(BaseModel):
    expires_at: str | None = Field(default=None, min_length=10, max_length=40)


class AccessSessionRenew(BaseModel):
    expires_at: str | None = Field(default=None, min_length=10, max_length=40)


class AccessSessionRevoke(BaseModel):
    reason: str = Field(default="", max_length=500)


class AccessRecordCreate(BaseModel):
    dossier_id: int = Field(gt=0)
    action: Literal["view", "download"]
    idempotency_key: str = Field(min_length=4, max_length=100)

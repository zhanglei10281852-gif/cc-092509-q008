from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, model_validator

ReviewAction = Literal["view", "download"]


class ReviewRequestItemInput(BaseModel):
    dossier_id: int = Field(gt=0)
    purpose: str = Field(min_length=4, max_length=500)
    action: ReviewAction
    download_limit: int = Field(default=1, ge=0, le=10_000)


class ReviewRequestCreate(BaseModel):
    idempotency_key: str = Field(min_length=4, max_length=100)
    visitor_name: str = Field(min_length=1, max_length=100)
    visitor_organization: str = Field(min_length=1, max_length=200)
    note: str = Field(default="", max_length=500)
    starts_at: str | None = Field(default=None, min_length=10, max_length=40)
    expires_at: str = Field(min_length=10, max_length=40)
    items: list[ReviewRequestItemInput] = Field(min_length=1, max_length=200)

    @model_validator(mode="after")
    def unique_dossiers(self):
        dossier_ids = [item.dossier_id for item in self.items]
        if len(set(dossier_ids)) != len(dossier_ids):
            raise ValueError("同一申请内档案不能重复")
        return self


class ReviewDecisionItem(BaseModel):
    item_id: int = Field(gt=0)
    decision: Literal["approve", "reject"]
    comment: str = Field(default="", max_length=500)


class ReviewDecisionBatch(BaseModel):
    comment: str = Field(default="", max_length=500)
    items: list[ReviewDecisionItem] = Field(min_length=1, max_length=200)

    @model_validator(mode="after")
    def unique_items(self):
        item_ids = [item.item_id for item in self.items]
        if len(set(item_ids)) != len(item_ids):
            raise ValueError("同一审批内条目不能重复")
        return self


class ReviewSessionRenew(BaseModel):
    new_expires_at: str = Field(min_length=10, max_length=40)
    grant_ids: list[int] | None = Field(default=None, max_length=200)
    reason: str = Field(default="", max_length=500)


class ReviewSessionRevoke(BaseModel):
    reason: str = Field(default="", max_length=500)


class ReviewGrantRevoke(BaseModel):
    reason: str = Field(default="", max_length=500)


class ReviewAccessCreate(BaseModel):
    session_code: str = Field(min_length=3, max_length=64)
    dossier_id: int = Field(gt=0)
    action: ReviewAction
    file_ref: str = Field(default="", max_length=300)

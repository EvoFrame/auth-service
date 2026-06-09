"""Schemas for ABAC management and evaluation endpoints."""

import uuid
from datetime import datetime

from pydantic import BaseModel

# ---------------------------------------------------------------------------
# User attributes
# ---------------------------------------------------------------------------


class UserAttributeUpsertRequest(BaseModel):
    value: str


class UserAttributeResponse(BaseModel):
    user_id: uuid.UUID
    key: str
    value: str
    created_at: datetime


# ---------------------------------------------------------------------------
# Policy conditions
# ---------------------------------------------------------------------------


class PolicyConditionCreateRequest(BaseModel):
    attribute_source: str  # "subject" | "resource" | "environment"
    attribute_key: str
    operator: str  # eq | neq | in | not_in | contains | gt | lt | gte | lte
    value: str = ""
    value_ref_source: str | None = None  # set to compare against another attribute
    value_ref_key: str | None = None     # attribute key in value_ref_source bag


class PolicyConditionResponse(BaseModel):
    id: uuid.UUID
    policy_id: uuid.UUID
    attribute_source: str
    attribute_key: str
    operator: str
    value: str
    value_ref_source: str | None
    value_ref_key: str | None


# ---------------------------------------------------------------------------
# Policies
# ---------------------------------------------------------------------------


class PolicyCreateRequest(BaseModel):
    name: str
    description: str | None = None
    effect: str  # "allow" | "deny"
    priority: int = 0
    is_active: bool = True
    scope_resource_type: str | None = None  # NULL = all resource types
    scope_action: str | None = None         # NULL = all actions


class PolicyUpdateRequest(BaseModel):
    name: str | None = None
    description: str | None = None
    effect: str | None = None
    priority: int | None = None
    is_active: bool | None = None
    scope_resource_type: str | None = None
    scope_action: str | None = None


class PolicyResponse(BaseModel):
    id: uuid.UUID
    name: str
    description: str | None
    effect: str
    priority: int
    is_active: bool
    scope_resource_type: str | None
    scope_action: str | None
    created_at: datetime


class PolicyDetailResponse(PolicyResponse):
    conditions: list[PolicyConditionResponse]


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------


class EvaluationRequest(BaseModel):
    user_id: uuid.UUID
    action: str
    resource_type: str
    resource_attributes: dict[str, str] = {}
    environment_attributes: dict[str, str] = {}


class EvaluationResponse(BaseModel):
    decision: str  # "allow" | "deny"
    matched_policy_id: uuid.UUID | None = None
    matched_policy_name: str | None = None
    reason: str

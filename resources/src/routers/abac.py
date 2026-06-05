"""ABAC management and evaluation router."""

import uuid

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession

from src.controllers import abac as abac_ctrl
from src.db.session import get_session
from src.libs.auth_deps import require_permission
from src.libs.pagination import PagedResponse
from src.schemas.abac import (
    EvaluationRequest,
    EvaluationResponse,
    PolicyConditionCreateRequest,
    PolicyCreateRequest,
    PolicyDetailResponse,
    PolicyResponse,
    PolicyUpdateRequest,
    UserAttributeResponse,
    UserAttributeUpsertRequest,
)

_read = Depends(require_permission("abac:read"))
_write = Depends(require_permission("abac:write"))
_evaluate = Depends(require_permission("abac:evaluate"))

router = APIRouter(prefix="/abac", tags=["ABAC"])


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------


@router.post("/evaluate", response_model=EvaluationResponse, dependencies=[_evaluate])
async def evaluate(
    body: EvaluationRequest,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> EvaluationResponse:
    caller_service: str = getattr(request.state, "caller_service", "test-client")
    return await abac_ctrl.evaluate_access(body, caller_service, session)


# ---------------------------------------------------------------------------
# User attributes
# ---------------------------------------------------------------------------


@router.get("/users/{user_id}/attributes", response_model=list[UserAttributeResponse], dependencies=[_read])
async def list_user_attributes(
    user_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
) -> list[UserAttributeResponse]:
    return await abac_ctrl.list_user_attributes(user_id, session)


@router.put(
    "/users/{user_id}/attributes/{key}",
    response_model=UserAttributeResponse,
    dependencies=[_write],
)
async def upsert_user_attribute(
    user_id: uuid.UUID,
    key: str,
    body: UserAttributeUpsertRequest,
    session: AsyncSession = Depends(get_session),
) -> UserAttributeResponse:
    return await abac_ctrl.upsert_user_attribute(user_id, key, body, session)


@router.delete("/users/{user_id}/attributes/{key}", status_code=204, dependencies=[_write])
async def delete_user_attribute(
    user_id: uuid.UUID,
    key: str,
    session: AsyncSession = Depends(get_session),
) -> None:
    await abac_ctrl.delete_user_attribute(user_id, key, session)


# ---------------------------------------------------------------------------
# Policies
# ---------------------------------------------------------------------------


@router.get("/policies", response_model=PagedResponse[PolicyResponse], dependencies=[_read])
async def list_policies(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    session: AsyncSession = Depends(get_session),
) -> PagedResponse[PolicyResponse]:
    return await abac_ctrl.list_policies(session, page=page, page_size=page_size)


@router.post("/policies", response_model=PolicyDetailResponse, status_code=201, dependencies=[_write])
async def create_policy(
    body: PolicyCreateRequest,
    session: AsyncSession = Depends(get_session),
) -> PolicyDetailResponse:
    policy = await abac_ctrl.create_policy(body, session)
    return await abac_ctrl.get_policy(policy.id, session)


@router.get("/policies/{policy_id}", response_model=PolicyDetailResponse, dependencies=[_read])
async def get_policy(
    policy_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
) -> PolicyDetailResponse:
    return await abac_ctrl.get_policy(policy_id, session)


@router.patch("/policies/{policy_id}", response_model=PolicyResponse, dependencies=[_write])
async def update_policy(
    policy_id: uuid.UUID,
    body: PolicyUpdateRequest,
    session: AsyncSession = Depends(get_session),
) -> PolicyResponse:
    return await abac_ctrl.update_policy(policy_id, body, session)


@router.delete("/policies/{policy_id}", status_code=204, dependencies=[_write])
async def delete_policy(
    policy_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
) -> None:
    await abac_ctrl.delete_policy(policy_id, session)


# ---------------------------------------------------------------------------
# Policy conditions
# ---------------------------------------------------------------------------


@router.post(
    "/policies/{policy_id}/conditions",
    response_model=PolicyDetailResponse,
    status_code=201,
    dependencies=[_write],
)
async def add_condition(
    policy_id: uuid.UUID,
    body: PolicyConditionCreateRequest,
    session: AsyncSession = Depends(get_session),
) -> PolicyDetailResponse:
    return await abac_ctrl.add_condition(policy_id, body, session)


@router.delete("/conditions/{condition_id}", status_code=204, dependencies=[_write])
async def remove_condition(
    condition_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
) -> None:
    await abac_ctrl.remove_condition(condition_id, session)

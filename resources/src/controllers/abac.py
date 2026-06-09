"""ABAC management and evaluation controller."""

import uuid

import structlog
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.libs.abac_engine import ConditionSpec, EvaluationContext, PolicySpec, evaluate
from src.libs.errors import AppError
from src.libs.pagination import PagedResponse, paginate
from src.models.abac import Policy, PolicyCondition, UserAttribute
from src.models.rbac import Permission, Role, RolePermission, UserRole
from src.models.user import User
from src.schemas.abac import (
    EvaluationRequest,
    EvaluationResponse,
    PolicyConditionCreateRequest,
    PolicyConditionResponse,
    PolicyCreateRequest,
    PolicyDetailResponse,
    PolicyResponse,
    PolicyUpdateRequest,
    UserAttributeResponse,
    UserAttributeUpsertRequest,
)

logger = structlog.get_logger()


# ---------------------------------------------------------------------------
# User attributes
# ---------------------------------------------------------------------------


async def list_user_attributes(user_id: uuid.UUID, session: AsyncSession) -> list[UserAttributeResponse]:
    result = await session.execute(
        select(UserAttribute).where(UserAttribute.user_id == user_id).order_by(UserAttribute.key)
    )
    return [UserAttributeResponse.model_validate(a, from_attributes=True) for a in result.scalars().all()]


async def upsert_user_attribute(
    user_id: uuid.UUID, key: str, data: UserAttributeUpsertRequest, session: AsyncSession
) -> UserAttributeResponse:
    existing = await session.get(UserAttribute, {"user_id": user_id, "key": key})
    if existing:
        existing.value = data.value
        session.add(existing)
    else:
        existing = UserAttribute(user_id=user_id, key=key, value=data.value)
        session.add(existing)

    await session.commit()
    await session.refresh(existing)
    logger.info("abac.user_attribute_upserted", user_id=str(user_id), key=key)
    return UserAttributeResponse.model_validate(existing, from_attributes=True)


async def delete_user_attribute(user_id: uuid.UUID, key: str, session: AsyncSession) -> None:
    attr = await session.get(UserAttribute, {"user_id": user_id, "key": key})
    if not attr:
        raise AppError("NOT_FOUND", "Attribute not found.", status_code=404)
    await session.delete(attr)
    await session.commit()
    logger.info("abac.user_attribute_deleted", user_id=str(user_id), key=key)


# ---------------------------------------------------------------------------
# Policies
# ---------------------------------------------------------------------------


async def list_policies(session: AsyncSession, page: int = 1, page_size: int = 50) -> PagedResponse[PolicyResponse]:
    from sqlalchemy import func

    total = (await session.execute(select(func.count()).select_from(Policy))).scalar_one()
    rows = (
        (
            await session.execute(
                select(Policy)
                .order_by(Policy.priority.desc(), Policy.name)
                .offset((page - 1) * page_size)
                .limit(page_size)
            )
        )
        .scalars()
        .all()
    )
    return paginate([PolicyResponse.model_validate(p, from_attributes=True) for p in rows], total, page, page_size)


async def create_policy(data: PolicyCreateRequest, session: AsyncSession) -> PolicyResponse:
    _validate_effect(data.effect)
    existing = await session.execute(select(Policy).where(Policy.name == data.name))
    if existing.scalar_one_or_none():
        raise AppError("CONFLICT", f"Policy '{data.name}' already exists.", status_code=409)

    policy = Policy(
        name=data.name,
        description=data.description,
        effect=data.effect,
        priority=data.priority,
        is_active=data.is_active,
        scope_resource_type=data.scope_resource_type,
        scope_action=data.scope_action,
    )
    session.add(policy)
    await session.commit()
    await session.refresh(policy)
    logger.info("abac.policy_created", policy_id=str(policy.id), name=policy.name)
    return PolicyResponse.model_validate(policy, from_attributes=True)


async def get_policy(policy_id: uuid.UUID, session: AsyncSession) -> PolicyDetailResponse:
    policy = await session.get(Policy, policy_id)
    if not policy:
        raise AppError("NOT_FOUND", "Policy not found.", status_code=404)
    return await _build_policy_detail(policy, session)


async def update_policy(policy_id: uuid.UUID, data: PolicyUpdateRequest, session: AsyncSession) -> PolicyResponse:
    policy = await session.get(Policy, policy_id)
    if not policy:
        raise AppError("NOT_FOUND", "Policy not found.", status_code=404)

    if data.effect is not None:
        _validate_effect(data.effect)
        policy.effect = data.effect
    if data.name is not None and data.name != policy.name:
        conflict = await session.execute(select(Policy).where(Policy.name == data.name))
        if conflict.scalar_one_or_none():
            raise AppError("CONFLICT", f"Policy '{data.name}' already exists.", status_code=409)
        policy.name = data.name
    if data.description is not None:
        policy.description = data.description
    if data.priority is not None:
        policy.priority = data.priority
    if data.is_active is not None:
        policy.is_active = data.is_active
    # Scope fields use explicit sentinel: pass None to clear, omit field means "don't touch".
    # Since PolicyUpdateRequest defaults both to None, we use a sentinel pattern via model_fields_set.
    if "scope_resource_type" in data.model_fields_set:
        policy.scope_resource_type = data.scope_resource_type
    if "scope_action" in data.model_fields_set:
        policy.scope_action = data.scope_action

    session.add(policy)
    await session.commit()
    await session.refresh(policy)
    logger.info("abac.policy_updated", policy_id=str(policy_id))
    return PolicyResponse.model_validate(policy, from_attributes=True)


async def delete_policy(policy_id: uuid.UUID, session: AsyncSession) -> None:
    policy = await session.get(Policy, policy_id)
    if not policy:
        raise AppError("NOT_FOUND", "Policy not found.", status_code=404)

    await session.execute(PolicyCondition.__table__.delete().where(PolicyCondition.policy_id == policy_id))
    await session.delete(policy)
    await session.commit()
    logger.info("abac.policy_deleted", policy_id=str(policy_id))


# ---------------------------------------------------------------------------
# Policy conditions
# ---------------------------------------------------------------------------


async def add_condition(
    policy_id: uuid.UUID, data: PolicyConditionCreateRequest, session: AsyncSession
) -> PolicyDetailResponse:
    policy = await session.get(Policy, policy_id)
    if not policy:
        raise AppError("NOT_FOUND", "Policy not found.", status_code=404)

    _validate_source(data.attribute_source)
    _validate_operator(data.operator)
    _validate_value_ref(data.value_ref_source, data.value_ref_key)

    cond = PolicyCondition(
        policy_id=policy_id,
        attribute_source=data.attribute_source,
        attribute_key=data.attribute_key,
        operator=data.operator,
        value=data.value,
        value_ref_source=data.value_ref_source,
        value_ref_key=data.value_ref_key,
    )
    session.add(cond)
    await session.commit()
    logger.info("abac.condition_added", policy_id=str(policy_id), key=data.attribute_key)
    return await _build_policy_detail(policy, session)


async def remove_condition(condition_id: uuid.UUID, session: AsyncSession) -> None:
    cond = await session.get(PolicyCondition, condition_id)
    if not cond:
        raise AppError("NOT_FOUND", "Condition not found.", status_code=404)
    await session.delete(cond)
    await session.commit()
    logger.info("abac.condition_removed", condition_id=str(condition_id))


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------


async def evaluate_access(
    request: EvaluationRequest,
    caller_service: str,
    session: AsyncSession,
) -> EvaluationResponse:
    # 1. Load user
    user = await session.get(User, request.user_id)
    if not user or user.deleted_at is not None:
        raise AppError("NOT_FOUND", "User not found.", status_code=404)

    # 2. Load user attributes
    attr_rows = await session.execute(select(UserAttribute).where(UserAttribute.user_id == request.user_id))
    subject: dict[str, str] = {a.key: a.value for a in attr_rows.scalars().all()}

    # 3. Inject derived subject fields
    subject["is_active"] = str(user.is_active).lower()
    subject["is_verified"] = str(user.is_verified).lower()
    subject["mfa_enabled"] = str(user.mfa_enabled).lower()

    # 4. Inject roles and permissions as JSON-encoded lists
    roles_result = await session.execute(
        select(Role.name).join(UserRole, Role.id == UserRole.role_id).where(UserRole.user_id == user.id)
    )
    import json

    subject["roles"] = json.dumps(sorted(r for (r,) in roles_result.all()))

    perms_result = await session.execute(
        select(Permission.name)
        .join(RolePermission, Permission.id == RolePermission.permission_id)
        .join(Role, Role.id == RolePermission.role_id)
        .join(UserRole, UserRole.role_id == Role.id)
        .where(UserRole.user_id == user.id)
        .distinct()
    )
    subject["permissions"] = json.dumps(sorted(p for (p,) in perms_result.all()))

    # 5. Build environment — caller_service is always injected server-side
    environment = dict(request.environment_attributes)
    environment["caller_service"] = caller_service
    environment["action"] = request.action
    environment["resource_type"] = request.resource_type

    # 6. Load active policies pre-filtered by scope — NULL scope columns match any value (wildcard)
    policy_rows = (
        (
            await session.execute(
                select(Policy).where(
                    Policy.is_active.is_(True),
                    or_(Policy.scope_resource_type.is_(None), Policy.scope_resource_type == request.resource_type),
                    or_(Policy.scope_action.is_(None), Policy.scope_action == request.action),
                )
            )
        )
        .scalars()
        .all()
    )
    policy_ids = [p.id for p in policy_rows]

    conditions_by_policy: dict[uuid.UUID, list[PolicyCondition]] = {pid: [] for pid in policy_ids}
    if policy_ids:
        cond_rows = (
            (await session.execute(select(PolicyCondition).where(PolicyCondition.policy_id.in_(policy_ids))))
            .scalars()
            .all()
        )
        for c in cond_rows:
            conditions_by_policy[c.policy_id].append(c)

    specs = [
        PolicySpec(
            id=p.id,
            name=p.name,
            effect=p.effect,
            priority=p.priority,
            conditions=[
                ConditionSpec(
                    attribute_source=c.attribute_source,
                    attribute_key=c.attribute_key,
                    operator=c.operator,
                    value=c.value,
                    value_ref_source=c.value_ref_source,
                    value_ref_key=c.value_ref_key,
                )
                for c in conditions_by_policy[p.id]
            ],
        )
        for p in policy_rows
    ]

    # 7. Evaluate
    ctx = EvaluationContext(
        subject=subject,
        resource=dict(request.resource_attributes),
        environment=environment,
    )
    result = evaluate(specs, ctx)

    logger.info(
        "abac.evaluate",
        user_id=str(request.user_id),
        action=request.action,
        resource_type=request.resource_type,
        caller_service=caller_service,
        decision=result.decision,
        matched_policy=result.matched_policy_name,
    )

    return EvaluationResponse(
        decision=result.decision,
        matched_policy_id=result.matched_policy_id,
        matched_policy_name=result.matched_policy_name,
        reason=result.reason,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _validate_effect(effect: str) -> None:
    if effect not in ("allow", "deny"):
        raise AppError("VALIDATION_ERROR", "Effect must be 'allow' or 'deny'.", status_code=422)


def _validate_source(source: str) -> None:
    if source not in ("subject", "resource", "environment"):
        raise AppError(
            "VALIDATION_ERROR",
            "attribute_source must be 'subject', 'resource', or 'environment'.",
            status_code=422,
        )


def _validate_operator(operator: str) -> None:
    valid = {"eq", "neq", "in", "not_in", "contains", "gt", "lt", "gte", "lte"}
    if operator not in valid:
        raise AppError("VALIDATION_ERROR", f"Operator must be one of: {', '.join(sorted(valid))}.", status_code=422)


def _validate_value_ref(value_ref_source: str | None, value_ref_key: str | None) -> None:
    if bool(value_ref_source) != bool(value_ref_key):
        raise AppError(
            "VALIDATION_ERROR",
            "value_ref_source and value_ref_key must both be set or both be absent.",
            status_code=422,
        )
    if value_ref_source:
        _validate_source(value_ref_source)


async def _build_policy_detail(policy: Policy, session: AsyncSession) -> PolicyDetailResponse:
    cond_rows = (
        (
            await session.execute(
                select(PolicyCondition)
                .where(PolicyCondition.policy_id == policy.id)
                .order_by(PolicyCondition.attribute_key)
            )
        )
        .scalars()
        .all()
    )
    return PolicyDetailResponse(
        id=policy.id,
        name=policy.name,
        description=policy.description,
        effect=policy.effect,
        priority=policy.priority,
        is_active=policy.is_active,
        scope_resource_type=policy.scope_resource_type,
        scope_action=policy.scope_action,
        created_at=policy.created_at,
        conditions=[PolicyConditionResponse.model_validate(c, from_attributes=True) for c in cond_rows],
    )

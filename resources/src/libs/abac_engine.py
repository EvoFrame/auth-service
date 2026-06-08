"""Pure ABAC policy evaluation engine — no I/O, fully testable in isolation."""

import json
import uuid
from dataclasses import dataclass, field


@dataclass
class EvaluationContext:
    """Holds all attribute bags used during policy evaluation.

    Attributes:
        subject: User-level attributes (DB user_attributes + derived fields such as
                 ``is_active``, ``is_verified``, ``mfa_enabled``, ``roles``,
                 ``permissions``).  Values are always strings; lists are
                 JSON-encoded.
        resource: Attributes describing the resource being accessed, supplied by
                  the calling service.
        environment: Ambient attributes such as ``caller_service``, ``action``,
                     ``resource_type``, and any extras the calling service adds.
                     ``caller_service`` is always injected server-side and cannot
                     be overridden by callers.
    """

    subject: dict[str, str] = field(default_factory=dict)
    resource: dict[str, str] = field(default_factory=dict)
    environment: dict[str, str] = field(default_factory=dict)


@dataclass
class ConditionSpec:
    """Lightweight representation of a single policy condition."""

    attribute_source: str  # "subject" | "resource" | "environment"
    attribute_key: str
    operator: str
    value: str                           # literal value (used when value_ref_source is None)
    value_ref_source: str | None = None  # "subject" | "resource" | "environment"
    value_ref_key: str | None = None     # attribute key to resolve from that bag


@dataclass
class PolicySpec:
    """Lightweight representation of a policy and its conditions."""

    id: uuid.UUID
    name: str
    effect: str  # "allow" | "deny"
    priority: int
    conditions: list[ConditionSpec]


@dataclass
class EvaluationResult:
    """Outcome of a policy evaluation.

    Attributes:
        decision: ``"allow"`` or ``"deny"``.
        matched_policy_id: UUID of the first policy that determined the outcome,
                           or ``None`` when the default-deny applies.
        matched_policy_name: Human-readable name of the matched policy, or
                             ``"default-deny"`` when no policy fired.
        reason: Short human-readable explanation of the decision.
    """

    decision: str
    matched_policy_id: uuid.UUID | None = None
    matched_policy_name: str | None = None
    reason: str = ""


# ---------------------------------------------------------------------------
# Operator implementations
# ---------------------------------------------------------------------------


def _coerce_float(v: str) -> float:
    try:
        return float(v)
    except ValueError:
        raise ValueError(f"Cannot compare non-numeric value '{v}'")


def _match_operator(operator: str, actual: str | None, condition_value: str) -> bool:
    """Evaluate a single condition operator.

    Args:
        operator: One of eq, neq, in, not_in, contains, gt, lt, gte, lte.
        actual: The attribute value from the context (``None`` if key is absent).
        condition_value: The value stored in the condition.

    Returns:
        ``True`` if the condition is satisfied.
    """
    if actual is None:
        return False

    match operator:
        case "eq":
            return actual == condition_value
        case "neq":
            return actual != condition_value
        case "in":
            candidates = json.loads(condition_value)
            return actual in candidates
        case "not_in":
            candidates = json.loads(condition_value)
            return actual not in candidates
        case "contains":
            return condition_value in actual
        case "gt":
            return _coerce_float(actual) > _coerce_float(condition_value)
        case "lt":
            return _coerce_float(actual) < _coerce_float(condition_value)
        case "gte":
            return _coerce_float(actual) >= _coerce_float(condition_value)
        case "lte":
            return _coerce_float(actual) <= _coerce_float(condition_value)
        case _:
            return False


# ---------------------------------------------------------------------------
# Policy evaluation
# ---------------------------------------------------------------------------


def _source_bag(ctx: EvaluationContext, source: str) -> dict[str, str]:
    match source:
        case "subject":
            return ctx.subject
        case "resource":
            return ctx.resource
        case "environment":
            return ctx.environment
        case _:
            return {}


def _resolve_rhs(cond: ConditionSpec, ctx: EvaluationContext) -> str | None:
    """Return the right-hand side value for the condition.

    If ``value_ref_source`` and ``value_ref_key`` are set, resolve the value
    dynamically from the appropriate context bag.  If the referenced key is
    absent the condition will not match (returns ``None``).

    Otherwise return the stored literal value.
    """
    if cond.value_ref_source and cond.value_ref_key:
        bag = _source_bag(ctx, cond.value_ref_source)
        return bag.get(cond.value_ref_key)
    return cond.value


def _policy_fires(policy: PolicySpec, ctx: EvaluationContext) -> bool:
    """Return True only when the policy has at least one condition and ALL conditions match the context."""
    if not policy.conditions:
        return False
    for cond in policy.conditions:
        bag = _source_bag(ctx, cond.attribute_source)
        actual = bag.get(cond.attribute_key)
        rhs = _resolve_rhs(cond, ctx)
        if rhs is None or not _match_operator(cond.operator, actual, rhs):
            return False
    return True


def evaluate(policies: list[PolicySpec], ctx: EvaluationContext) -> EvaluationResult:
    """Evaluate an access request against the supplied policies.

    **Algorithm**:

    1. Filter to active policies (callers should only pass active ones, but the
       engine does not re-filter — that is the controller's responsibility).
    2. Sort by ``priority`` descending (higher priority evaluated first).
    3. Collect all policies whose conditions fully match the context.
    4. If any fired policy has ``effect="deny"`` → **DENY** (explicit deny wins).
    5. If any fired policy has ``effect="allow"`` → **ALLOW**.
    6. If no policy fires → **DENY** (default, fail-closed).

    Args:
        policies: List of :class:`PolicySpec` objects to evaluate against.
        ctx: The :class:`EvaluationContext` containing subject, resource, and
             environment attributes.

    Returns:
        An :class:`EvaluationResult` with ``decision``, ``matched_policy_id``,
        ``matched_policy_name``, and a human-readable ``reason``.
    """
    sorted_policies = sorted(policies, key=lambda p: p.priority, reverse=True)

    fired_deny: PolicySpec | None = None
    fired_allow: PolicySpec | None = None

    for policy in sorted_policies:
        if not _policy_fires(policy, ctx):
            continue
        if policy.effect == "deny" and fired_deny is None:
            fired_deny = policy
        elif policy.effect == "allow" and fired_allow is None:
            fired_allow = policy

    if fired_deny is not None:
        return EvaluationResult(
            decision="deny",
            matched_policy_id=fired_deny.id,
            matched_policy_name=fired_deny.name,
            reason=f"Denied by policy '{fired_deny.name}'.",
        )

    if fired_allow is not None:
        return EvaluationResult(
            decision="allow",
            matched_policy_id=fired_allow.id,
            matched_policy_name=fired_allow.name,
            reason=f"Allowed by policy '{fired_allow.name}'.",
        )

    return EvaluationResult(
        decision="deny",
        matched_policy_id=None,
        matched_policy_name="default-deny",
        reason="No matching allow policy found.",
    )

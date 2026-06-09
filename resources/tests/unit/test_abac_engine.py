"""Unit tests: ABAC policy evaluator engine (pure, no I/O)."""

import json
import uuid

from src.libs.abac_engine import (
    ConditionSpec,
    EvaluationContext,
    PolicySpec,
    evaluate,
)


def _policy(effect: str, conditions: list[ConditionSpec], priority: int = 0) -> PolicySpec:
    return PolicySpec(
        id=uuid.uuid4(),
        name=f"{effect}-policy-{uuid.uuid4().hex[:6]}",
        effect=effect,
        priority=priority,
        conditions=conditions,
    )


def _ctx(
    subject: dict | None = None,
    resource: dict | None = None,
    environment: dict | None = None,
) -> EvaluationContext:
    return EvaluationContext(
        subject=subject or {},
        resource=resource or {},
        environment=environment or {},
    )


def _cond(source: str, key: str, operator: str, value: str) -> ConditionSpec:
    return ConditionSpec(attribute_source=source, attribute_key=key, operator=operator, value=value)


# ---------------------------------------------------------------------------
# Default deny
# ---------------------------------------------------------------------------


def test_default_deny_no_policies():
    result = evaluate([], _ctx())
    assert result.decision == "deny"
    assert result.matched_policy_name == "default-deny"


def test_default_deny_no_matching_policy():
    p = _policy("allow", [_cond("subject", "department", "eq", "engineering")])
    result = evaluate([p], _ctx(subject={"department": "finance"}))
    assert result.decision == "deny"


# ---------------------------------------------------------------------------
# Allow
# ---------------------------------------------------------------------------


def test_allow_fires_on_eq_match():
    p = _policy("allow", [_cond("subject", "department", "eq", "engineering")])
    result = evaluate([p], _ctx(subject={"department": "engineering"}))
    assert result.decision == "allow"
    assert result.matched_policy_id == p.id


def test_allow_all_conditions_must_match():
    p = _policy(
        "allow",
        [
            _cond("subject", "department", "eq", "engineering"),
            _cond("environment", "caller_service", "eq", "api-gateway"),
        ],
    )
    # Only first condition matches
    result = evaluate(
        [p],
        _ctx(
            subject={"department": "engineering"},
            environment={"caller_service": "other-service"},
        ),
    )
    assert result.decision == "deny"


def test_allow_all_conditions_match():
    p = _policy(
        "allow",
        [
            _cond("subject", "department", "eq", "engineering"),
            _cond("environment", "caller_service", "eq", "api-gateway"),
        ],
    )
    result = evaluate(
        [p],
        _ctx(
            subject={"department": "engineering"},
            environment={"caller_service": "api-gateway"},
        ),
    )
    assert result.decision == "allow"


# ---------------------------------------------------------------------------
# Deny overrides allow
# ---------------------------------------------------------------------------


def test_deny_overrides_allow():
    allow_p = _policy("allow", [_cond("subject", "is_active", "eq", "true")], priority=0)
    deny_p = _policy("deny", [_cond("subject", "department", "eq", "blocked")], priority=5)
    result = evaluate([allow_p, deny_p], _ctx(subject={"is_active": "true", "department": "blocked"}))
    assert result.decision == "deny"
    assert result.matched_policy_id == deny_p.id


def test_deny_without_allow_still_denies():
    p = _policy("deny", [_cond("subject", "clearance", "eq", "none")])
    result = evaluate([p], _ctx(subject={"clearance": "none"}))
    assert result.decision == "deny"
    assert result.matched_policy_id == p.id


# ---------------------------------------------------------------------------
# Missing attribute
# ---------------------------------------------------------------------------


def test_missing_attribute_does_not_match():
    p = _policy("allow", [_cond("subject", "nonexistent_key", "eq", "value")])
    result = evaluate([p], _ctx(subject={}))
    assert result.decision == "deny"


# ---------------------------------------------------------------------------
# Operators
# ---------------------------------------------------------------------------


def test_operator_neq():
    p = _policy("allow", [_cond("subject", "status", "neq", "suspended")])
    assert evaluate([p], _ctx(subject={"status": "active"})).decision == "allow"
    assert evaluate([p], _ctx(subject={"status": "suspended"})).decision == "deny"


def test_operator_in():
    p = _policy("allow", [_cond("subject", "role", "in", json.dumps(["admin", "editor"]))])
    assert evaluate([p], _ctx(subject={"role": "admin"})).decision == "allow"
    assert evaluate([p], _ctx(subject={"role": "viewer"})).decision == "deny"


def test_operator_not_in():
    p = _policy("allow", [_cond("subject", "role", "not_in", json.dumps(["banned", "suspended"]))])
    assert evaluate([p], _ctx(subject={"role": "editor"})).decision == "allow"
    assert evaluate([p], _ctx(subject={"role": "banned"})).decision == "deny"


def test_operator_contains():
    p = _policy("allow", [_cond("subject", "email", "contains", "@company.com")])
    assert evaluate([p], _ctx(subject={"email": "alice@company.com"})).decision == "allow"
    assert evaluate([p], _ctx(subject={"email": "alice@other.com"})).decision == "deny"


def test_operator_gt():
    p = _policy("allow", [_cond("subject", "clearance_level", "gt", "2")])
    assert evaluate([p], _ctx(subject={"clearance_level": "3"})).decision == "allow"
    assert evaluate([p], _ctx(subject={"clearance_level": "2"})).decision == "deny"


def test_operator_lt():
    p = _policy("deny", [_cond("subject", "failed_attempts", "gte", "5")])
    assert evaluate([p], _ctx(subject={"failed_attempts": "5"})).decision == "deny"
    assert evaluate([p], _ctx(subject={"failed_attempts": "4"})).decision == "deny"  # default deny


def test_operator_gte():
    p = _policy("allow", [_cond("resource", "min_clearance", "lte", "3")])
    assert evaluate([p], _ctx(resource={"min_clearance": "2"})).decision == "allow"
    assert evaluate([p], _ctx(resource={"min_clearance": "4"})).decision == "deny"


# ---------------------------------------------------------------------------
# Priority ordering
# ---------------------------------------------------------------------------


def test_priority_higher_evaluated_first():
    low_deny = _policy("deny", [_cond("subject", "is_active", "eq", "true")], priority=1)
    high_allow = _policy("allow", [_cond("subject", "is_active", "eq", "true")], priority=10)
    # deny should still win regardless of priority
    result = evaluate([low_deny, high_allow], _ctx(subject={"is_active": "true"}))
    assert result.decision == "deny"


def test_resource_and_environment_attributes():
    p = _policy(
        "allow",
        [
            _cond("resource", "owner_id", "eq", "user-123"),
            _cond("environment", "action", "eq", "read"),
        ],
    )
    result = evaluate(
        [p],
        _ctx(
            resource={"owner_id": "user-123"},
            environment={"action": "read"},
        ),
    )
    assert result.decision == "allow"


# ---------------------------------------------------------------------------
# Cross-attribute comparison
# ---------------------------------------------------------------------------


def _ref_cond(source: str, key: str, operator: str, ref_source: str, ref_key: str) -> ConditionSpec:
    return ConditionSpec(
        attribute_source=source,
        attribute_key=key,
        operator=operator,
        value="",
        value_ref_source=ref_source,
        value_ref_key=ref_key,
    )


def test_cross_attr_eq_allow():
    """subject.user_id eq resource.owner_id → allow when equal."""
    p = _policy("allow", [_ref_cond("subject", "user_id", "eq", "resource", "owner_id")])
    user_id = "abc-123"
    result = evaluate([p], _ctx(subject={"user_id": user_id}, resource={"owner_id": user_id}))
    assert result.decision == "allow"


def test_cross_attr_eq_deny_when_different():
    """subject.user_id eq resource.owner_id → deny when different."""
    p = _policy("allow", [_ref_cond("subject", "user_id", "eq", "resource", "owner_id")])
    result = evaluate([p], _ctx(subject={"user_id": "user-a"}, resource={"owner_id": "user-b"}))
    assert result.decision == "deny"


def test_cross_attr_ref_missing_from_bag():
    """Referenced key absent from bag → condition does not match."""
    p = _policy("allow", [_ref_cond("subject", "user_id", "eq", "resource", "owner_id")])
    result = evaluate([p], _ctx(subject={"user_id": "user-a"}, resource={}))
    assert result.decision == "deny"


def test_cross_attr_mixed_literal_and_ref():
    """Policy with one literal condition and one ref condition — both must match."""
    p = _policy(
        "allow",
        [
            _cond("environment", "action", "eq", "read"),
            _ref_cond("subject", "user_id", "eq", "resource", "owner_id"),
        ],
    )
    user_id = "user-x"
    assert (
        evaluate(
            [p],
            _ctx(
                subject={"user_id": user_id},
                resource={"owner_id": user_id},
                environment={"action": "read"},
            ),
        ).decision
        == "allow"
    )
    assert (
        evaluate(
            [p],
            _ctx(
                subject={"user_id": user_id},
                resource={"owner_id": user_id},
                environment={"action": "write"},
            ),
        ).decision
        == "deny"
    )

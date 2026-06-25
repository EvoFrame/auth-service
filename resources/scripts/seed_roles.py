"""Dev seed script — creates default roles and permissions.

Idempotent: safe to run multiple times; existing records are skipped.

Usage:
    uv run python resources/scripts/seed_roles.py

Or via task:
    task db:seed
"""

import asyncio
import sys
from pathlib import Path

# Make `src.*` importable when running from the repo root.
sys.path.insert(0, str(Path(__file__).parent.parent))

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from src.config.settings import settings
from src.models.rbac import Permission, Role, RolePermission

# ---------------------------------------------------------------------------
# Seed data
# ---------------------------------------------------------------------------

PERMISSIONS: list[tuple[str, str]] = [
    # (name, description)
    ("users:read", "View user profiles and listings"),
    ("users:write", "Create and update users"),
    ("users:delete", "Soft-delete users"),
    ("roles:read", "View roles and permissions"),
    ("roles:write", "Create, update, and delete roles and permissions"),
    ("roles:assign", "Assign and revoke roles on users"),
    ("policies:read", "View ABAC policies"),
    ("policies:write", "Create, update, and delete ABAC policies"),
    ("service_clients:read", "View service client registrations"),
    ("service_clients:write", "Create, update, and delete service clients"),
]

ROLES: list[tuple[str, str, list[str]]] = [
    # (name, description, [permission names])
    (
        "admin",
        "Full administrative access — all permissions granted",
        [p[0] for p in PERMISSIONS],
    ),
    (
        "user",
        "Standard authenticated user — read-only access to own profile",
        ["users:read"],
    ),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _upsert_permission(session: AsyncSession, name: str, description: str) -> Permission:
    result = await session.execute(select(Permission).where(Permission.name == name))
    perm = result.scalar_one_or_none()
    if perm is None:
        perm = Permission(name=name, description=description)
        session.add(perm)
        await session.flush()
        print(f"  ✔ created permission  {name!r}")
    else:
        print(f"  · skipped permission  {name!r}  (already exists)")
    return perm


async def _upsert_role(session: AsyncSession, name: str, description: str) -> Role:
    result = await session.execute(select(Role).where(Role.name == name))
    role = result.scalar_one_or_none()
    if role is None:
        role = Role(name=name, description=description)
        session.add(role)
        await session.flush()
        print(f"  ✔ created role        {name!r}")
    else:
        print(f"  · skipped role        {name!r}  (already exists)")
    return role


async def _assign_permission(session: AsyncSession, role: Role, perm: Permission) -> None:
    existing = await session.get(RolePermission, {"role_id": role.id, "permission_id": perm.id})
    if existing is None:
        session.add(RolePermission(role_id=role.id, permission_id=perm.id))
        print(f"    ✔ assigned  {perm.name!r}  →  {role.name!r}")
    else:
        print(f"    · skipped  {perm.name!r}  →  {role.name!r}  (already assigned)")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


async def seed() -> None:
    engine = create_async_engine(settings.DATABASE_URL, echo=False)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    async with session_factory() as session:
        print("\n── Permissions ──────────────────────────────────────────────")
        perm_map: dict[str, Permission] = {}
        for name, description in PERMISSIONS:
            perm_map[name] = await _upsert_permission(session, name, description)

        print("\n── Roles & assignments ──────────────────────────────────────")
        for role_name, role_desc, perm_names in ROLES:
            role = await _upsert_role(session, role_name, role_desc)
            for perm_name in perm_names:
                await _assign_permission(session, role, perm_map[perm_name])

        await session.commit()

    await engine.dispose()
    print("\n✅  Seed complete.\n")


if __name__ == "__main__":
    asyncio.run(seed())

from fastapi import APIRouter

from src.routers.abac import router as abac_router
from src.routers.rbac import router as rbac_router
from src.routers.service_clients import router as service_clients_router
from src.routers.users import router as users_router

router = APIRouter()
router.include_router(users_router)
router.include_router(service_clients_router)
router.include_router(rbac_router)
router.include_router(abac_router)

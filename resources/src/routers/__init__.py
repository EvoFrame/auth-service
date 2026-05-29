from fastapi import APIRouter

from src.routers.service_clients import router as service_clients_router
from src.routers.users import router as users_router

router = APIRouter()
router.include_router(users_router)
router.include_router(service_clients_router)

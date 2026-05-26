from pydantic import BaseModel


class PermissionsResponse(BaseModel):
    user_id: str
    roles: list[str]
    permissions: list[str]

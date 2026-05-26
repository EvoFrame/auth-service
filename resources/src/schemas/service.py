from pydantic import BaseModel


class ServiceTokenRequest(BaseModel):
    service_id: str
    service_secret: str


class ServiceTokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class ServiceIntrospectRequest(BaseModel):
    token: str


class ServiceIntrospectResponse(BaseModel):
    sub: str
    iss: str
    type: str
    scope: str
    jti: str
    exp: int
    iat: int

from pydantic import BaseModel


class MFAEnableResponse(BaseModel):
    totp_uri: str
    secret: str


class MFAVerifyRequest(BaseModel):
    code: str


class MFADisableRequest(BaseModel):
    code: str

from pydantic import BaseModel, Field, field_validator
from typing import Optional
import re


class ChatRequest(BaseModel):
    message: str = Field(
        ...,
        min_length=1,
        max_length=2000,
        description="User message - max 2000 chars to prevent abuse"
    )
    session_id: Optional[str] = Field(
        default=None,
        max_length=64,
        pattern=r'^[a-zA-Z0-9_-]+$'
    )
    context: Optional[str] = Field(
        default=None,
        max_length=500
    )

    @field_validator('session_id')
    @classmethod
    def validate_session_id(cls, v):
        if v and not re.match(r'^[a-zA-Z0-9_-]+$', v):
            raise ValueError('session_id contains invalid characters')
        return v

    @field_validator('message')
    @classmethod
    def message_not_empty(cls, v):
        if not v.strip():
            raise ValueError('message cannot be blank')
        return v.strip()


class ChatResponse(BaseModel):
    response: str
    request_id: str
    session_id: Optional[str] = None
    model: str = "gpt-4o-mini"


class HealthResponse(BaseModel):
    status: str
    version: str


class ValidationResult(BaseModel):
    is_valid: bool
    sanitized_message: str = ""
    reason: Optional[str] = None
"""
STRIDE Control: Spoofing
API key authentication using secure comparison.

Attack paths mitigated:
- ATK-005: Unauthenticated API access
- ATK-006: Timing-based key enumeration
"""

import os
import hmac
import hashlib
import logging
from fastapi import HTTPException, Security
from fastapi.security import APIKeyHeader

logger = logging.getLogger(__name__)

API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)

# In production: load from secrets manager (AWS Secrets Manager, Vault, etc.)
# NEVER hardcode keys - this reads from environment variable
_RAW_KEY = os.getenv("API_KEY", "dev-insecure-key-replace-in-production")
_HASHED_KEY = hashlib.sha256(_RAW_KEY.encode()).hexdigest()


async def verify_api_key(api_key: str = Security(API_KEY_HEADER)) -> str:
    """
    Verify API key using constant-time comparison to prevent timing attacks.

    STRIDE - Spoofing: Ensures requests are from authenticated clients.
    STRIDE - Information Disclosure: Uses hmac.compare_digest (constant-time).
    """
    if not api_key:
        logger.warning("Request received with no API key")
        raise HTTPException(
            status_code=401,
            detail="Authentication required",
            headers={"WWW-Authenticate": "ApiKey"}
        )

    # Hash the provided key before comparison (don't compare raw keys)
    provided_hash = hashlib.sha256(api_key.encode()).hexdigest()

    # Constant-time comparison - prevents timing oracle attacks (ATK-006)
    if not hmac.compare_digest(provided_hash, _HASHED_KEY):
        logger.warning(f"Invalid API key attempt - key prefix: {api_key[:4]}****")
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired API key"
        )

    return api_key

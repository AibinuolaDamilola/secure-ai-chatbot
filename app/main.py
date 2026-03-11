"""
Secure AI Chatbot API
STRIDE Threat Model Applied - See /docs/STRIDE_THREAT_MODEL.md
"""

from fastapi import FastAPI, HTTPException, Depends, Request, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
import time
import logging
import uvicorn

from app.models import ChatRequest, ChatResponse, HealthResponse
from app.security.auth import verify_api_key
from app.security.rate_limiter import RateLimiter
from app.security.input_validator import InputValidator
from app.security.output_sanitizer import OutputSanitizer
from app.security.audit_logger import AuditLogger
from app.chat_handler import ChatHandler

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format='{"time": "%(asctime)s", "level": "%(levelname)s", "logger": "%(name)s", "message": "%(message)s"}'
)
logger = logging.getLogger(__name__)

# Initialize security components
rate_limiter = RateLimiter(max_requests=20, window_seconds=60)
input_validator = InputValidator()
output_sanitizer = OutputSanitizer()
audit_logger = AuditLogger()
chat_handler = ChatHandler()


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Secure AI Chatbot API starting up")
    yield
    logger.info("Secure AI Chatbot API shutting down")


app = FastAPI(
    title="Secure AI Chatbot API",
    description="AI chatbot with STRIDE threat modeling and security controls applied",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    lifespan=lifespan
)

# STRIDE Control: Spoofing - CORS restricted to known origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "https://yourdomain.com"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
)


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    """
    STRIDE Controls Applied:
    - Spoofing: Request ID tracking
    - Denial of Service: Rate limiting check
    - Information Disclosure: Sanitize error responses
    """
    start_time = time.time()
    request_id = request.headers.get("X-Request-ID", f"req_{int(time.time() * 1000)}")

    # Rate limiting - DoS protection
    client_ip = request.client.host
    if not rate_limiter.is_allowed(client_ip):
        audit_logger.log_security_event(
            event_type="RATE_LIMIT_EXCEEDED",
            client_ip=client_ip,
            request_id=request_id,
            details="Too many requests"
        )
        return JSONResponse(
            status_code=429,
            content={"error": "Rate limit exceeded. Try again later.", "request_id": request_id}
        )

    response = await call_next(request)

    # Add security headers - Information Disclosure mitigation
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["X-Request-ID"] = request_id
    response.headers["Cache-Control"] = "no-store"
    # Remove server fingerprint
    response.headers.pop("server", None)

    duration = time.time() - start_time
    logger.info(f"Request {request_id} - {request.method} {request.url.path} - {response.status_code} - {duration:.3f}s")

    return response


@app.get("/health", response_model=HealthResponse, tags=["System"])
async def health_check():
    """Health check endpoint - minimal information disclosure."""
    return HealthResponse(status="healthy", version="1.0.0")


@app.post("/api/v1/chat", response_model=ChatResponse, tags=["Chat"])
async def chat(
    request: ChatRequest,
    req: Request,
    api_key: str = Depends(verify_api_key),
    x_request_id: str = Header(default=None)
):
    """
    Secure chat endpoint with all STRIDE controls applied.

    Security controls:
    - Authentication required (Spoofing)
    - Input validation + prompt injection detection (Tampering)
    - Audit logging (Repudiation)
    - Output sanitization (Information Disclosure)
    - Rate limiting via middleware (DoS)
    - Role-based system prompt isolation (Elevation of Privilege)
    """
    client_ip = req.client.host
    request_id = x_request_id or f"req_{int(time.time() * 1000)}"

    # STRIDE: Tampering - Validate and sanitize input
    validation_result = input_validator.validate(request.message)
    if not validation_result.is_valid:
        audit_logger.log_security_event(
            event_type="INPUT_VALIDATION_FAILED",
            client_ip=client_ip,
            request_id=request_id,
            details=f"Reason: {validation_result.reason}"
        )
        raise HTTPException(
            status_code=400,
            detail={"error": "Invalid input detected", "reason": validation_result.reason}
        )

    # STRIDE: Repudiation - Log all interactions
    audit_logger.log_chat_request(
        request_id=request_id,
        client_ip=client_ip,
        message_length=len(request.message),
        session_id=request.session_id
    )

    try:
        # STRIDE: Elevation of Privilege - Enforce system prompt, don't let user override it
        response_text = await chat_handler.process(
            message=validation_result.sanitized_message,
            session_id=request.session_id,
            context=request.context
        )

        # STRIDE: Information Disclosure - Sanitize output
        safe_response = output_sanitizer.sanitize(response_text)

        audit_logger.log_chat_response(
            request_id=request_id,
            response_length=len(safe_response),
            was_sanitized=safe_response != response_text
        )

        return ChatResponse(
            response=safe_response,
            request_id=request_id,
            session_id=request.session_id
        )

    except Exception as e:
        # STRIDE: Information Disclosure - Never leak internal errors
        logger.error(f"Chat processing error for request {request_id}: {str(e)}")
        audit_logger.log_security_event(
            event_type="PROCESSING_ERROR",
            client_ip=client_ip,
            request_id=request_id,
            details="Internal processing error"
        )
        raise HTTPException(
            status_code=500,
            detail={"error": "An error occurred processing your request", "request_id": request_id}
        )


@app.get("/api/v1/audit/events", tags=["Security"])
async def get_audit_events(
    api_key: str = Depends(verify_api_key),
    limit: int = 50
):
    """
    Retrieve recent security audit events.
    Requires authentication - for security monitoring only.
    """
    return {"events": audit_logger.get_recent_events(limit=min(limit, 100))}


if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        ssl_keyfile="certs/key.pem",     # STRIDE: Information Disclosure - TLS required
        ssl_certfile="certs/cert.pem",
        reload=False                       # Never reload in production
    )

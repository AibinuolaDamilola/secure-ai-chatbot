"""
STRIDE Control: Tampering
Input validation and prompt injection detection.

Attack paths mitigated:
- ATK-001: Direct prompt injection
- ATK-002: Indirect prompt injection via context
- ATK-003: Jailbreak attempts
- ATK-004: Malicious payload injection
"""

import re
import html
import logging
from app.models import ValidationResult

logger = logging.getLogger(__name__)


class InputValidator:
    """
    Validates and sanitizes user input against known attack patterns.
    Implements defense-in-depth: pattern matching + length limits + encoding.
    """

    # Prompt injection patterns - ordered by severity
    PROMPT_INJECTION_PATTERNS = [
        # Direct instruction override attempts
        r'ignore\s+(all\s+)?(previous|prior|above|system)\s+(instructions?|prompts?|context)',
        r'forget\s+(everything|all|your\s+instructions)',
        r'you\s+are\s+now\s+(a\s+)?(?!an?\s+AI)',
        r'new\s+instructions?:\s*',
        r'system\s+prompt\s*:',
        r'<\s*system\s*>',
        r'\[SYSTEM\]',
        r'###\s*(instruction|system|prompt)',

        # Role escalation / jailbreak
        r'(act|pretend|roleplay|simulate|imagine)\s+(as|you\'re|you\s+are)\s+(a\s+)?(hacker|criminal|evil|unrestricted|unfiltered)',
        r'DAN\s+(mode|prompt)',
        r'developer\s+mode',
        r'jailbreak',
        r'bypass\s+(safety|filter|restriction|guideline)',

        # Data extraction attempts
        r'(print|show|reveal|output|display|repeat|echo)\s+(your\s+)?(system\s+prompt|instructions?|training data)',
        r'what\s+(is|are)\s+your\s+(system\s+prompt|instructions?)',
        r'tell\s+me\s+your\s+(hidden|secret|system)\s+(prompt|instructions?)',
        r'(your\s+)?(hidden|secret)\s+instructions?',
    ]

    # Potentially dangerous content patterns
    DANGEROUS_CONTENT_PATTERNS = [
        r'<script[^>]*>',
        r'javascript\s*:',
        r'on\w+\s*=\s*["\']',   # HTML event handlers
        r'\{\{.*\}\}',           # Template injection
        r'\$\{.*\}',             # JS template literals in input
        r'eval\s*\(',
        r'exec\s*\(',
    ]

    COMPILED_INJECTION = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in PROMPT_INJECTION_PATTERNS]
    COMPILED_DANGEROUS = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in DANGEROUS_CONTENT_PATTERNS]

    def validate(self, message: str) -> ValidationResult:
        """
        Validate input message. Returns ValidationResult with sanitized message
        or rejection reason.
        """
        # Step 1: Basic length check (enforced at model level too, but defense in depth)
        if len(message) > 2000:
            return ValidationResult(is_valid=False, reason="Message exceeds maximum length")

        if not message.strip():
            return ValidationResult(is_valid=False, reason="Message is empty")

        # Step 2: Check for prompt injection attempts
        for pattern in self.COMPILED_INJECTION:
            if pattern.search(message):
                logger.warning(f"Prompt injection attempt detected: pattern={pattern.pattern[:50]}")
                return ValidationResult(
                    is_valid=False,
                    reason="Input contains patterns associated with prompt injection"
                )

        # Step 3: Check for dangerous content
        for pattern in self.COMPILED_DANGEROUS:
            if pattern.search(message):
                logger.warning(f"Dangerous content pattern detected")
                return ValidationResult(
                    is_valid=False,
                    reason="Input contains potentially dangerous content"
                )

        # Step 4: Sanitize - encode HTML entities, strip null bytes
        sanitized = self._sanitize(message)

        return ValidationResult(
            is_valid=True,
            sanitized_message=sanitized
        )

    def _sanitize(self, message: str) -> str:
        """Apply sanitization to clean message."""
        # Remove null bytes
        sanitized = message.replace('\x00', '')
        # Encode HTML entities to prevent XSS if output is rendered
        sanitized = html.escape(sanitized, quote=True)
        # Normalize whitespace
        sanitized = ' '.join(sanitized.split())
        return sanitized

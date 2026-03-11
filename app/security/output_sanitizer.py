"""
STRIDE Control: Information Disclosure
Sanitizes LLM output to prevent data leakage.

Attack paths mitigated:
- ATK-010: PII leakage in responses
- ATK-011: System prompt extraction via response
- ATK-012: Credential/secret leakage
"""

import re
import logging

logger = logging.getLogger(__name__)


class OutputSanitizer:
    """
    Scans and redacts sensitive information from LLM responses
    before returning to clients.
    """

    # Patterns for sensitive data that should never appear in responses
    SENSITIVE_PATTERNS = [
        # Credentials and tokens
        (r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\']?[\w\-]{20,}["\']?', '[API_KEY_REDACTED]'),
        (r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']?\S+["\']?', '[PASSWORD_REDACTED]'),
        (r'(?i)(secret|token|bearer)\s*[:=]\s*["\']?[\w\-\.]{10,}["\']?', '[SECRET_REDACTED]'),
        (r'sk-[a-zA-Z0-9-]{20,}', '[OPENAI_KEY_REDACTED]'),  # OpenAI key pattern — covers sk-, sk-proj-, sk-org- variants
        (r'(?i)Authorization:\s*Bearer\s+[\w\-\.]+', '[AUTH_HEADER_REDACTED]'),

        # PII patterns
        (r'\b\d{3}-\d{2}-\d{4}\b', '[SSN_REDACTED]'),                    # SSN
        (r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b', '[CC_REDACTED]'),  # Credit card
        (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[EMAIL_REDACTED]'),

        # Internal system info
        (r'(?i)(system prompt|system message)\s*[:=]\s*.+', '[SYSTEM_INFO_REDACTED]'),
        (r'(?i)my instructions (are|include|say)', '[INSTRUCTION_DISCLOSURE_BLOCKED]'),
    ]

    COMPILED_PATTERNS = [
        (re.compile(pattern, re.IGNORECASE), replacement)
        for pattern, replacement in SENSITIVE_PATTERNS
    ]

    def sanitize(self, response: str) -> str:
        """
        Scan LLM output for sensitive data and redact before returning to client.
        Logs any redactions for security monitoring.
        """
        sanitized = response
        redactions = []

        for pattern, replacement in self.COMPILED_PATTERNS:
            new_text = pattern.sub(replacement, sanitized)
            if new_text != sanitized:
                redactions.append(replacement)
                sanitized = new_text

        if redactions:
            logger.warning(f"Output sanitizer redacted sensitive data: {redactions}")

        return sanitized

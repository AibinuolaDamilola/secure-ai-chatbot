"""
STRIDE Control: Repudiation
Structured audit logging for all security-relevant events.

Attack paths mitigated:
- ATK-008: Brute force (detectable via audit trail)
- Provides non-repudiation for all interactions
"""

import logging
import json
import time
from datetime import datetime, timezone
from collections import deque
from threading import Lock

logger = logging.getLogger("audit")


class AuditLogger:
    """
    Immutable audit trail for security events and chat interactions.
    In production: ship to SIEM (Splunk, Datadog, CloudWatch).
    """

    def __init__(self, max_memory_events: int = 1000):
        self._events = deque(maxlen=max_memory_events)
        self._lock = Lock()

    def log_security_event(
        self,
        event_type: str,
        client_ip: str,
        request_id: str,
        details: str = ""
    ):
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_class": "SECURITY",
            "event_type": event_type,
            "client_ip": self._mask_ip(client_ip),
            "request_id": request_id,
            "details": details
        }
        self._store(event)
        logger.warning(json.dumps(event))

    def log_chat_request(
        self,
        request_id: str,
        client_ip: str,
        message_length: int,
        session_id: str = None
    ):
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_class": "CHAT_REQUEST",
            "request_id": request_id,
            "client_ip": self._mask_ip(client_ip),
            "message_length": message_length,
            "session_id": session_id
        }
        self._store(event)
        logger.info(json.dumps(event))

    def log_chat_response(
        self,
        request_id: str,
        response_length: int,
        was_sanitized: bool
    ):
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_class": "CHAT_RESPONSE",
            "request_id": request_id,
            "response_length": response_length,
            "output_sanitized": was_sanitized
        }
        self._store(event)
        logger.info(json.dumps(event))

    def get_recent_events(self, limit: int = 50):
        with self._lock:
            events = list(self._events)
        return events[-limit:]

    def _store(self, event: dict):
        with self._lock:
            self._events.append(event)

    @staticmethod
    def _mask_ip(ip: str) -> str:
        parts = ip.split('.')
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.{parts[2]}.xxx"
        return "masked"

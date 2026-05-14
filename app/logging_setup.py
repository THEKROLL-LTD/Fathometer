"""Structlog-Konfiguration mit Redaction-Filter.

Sensible Felder, deren Name die Muster `password|key|token|hash` enthaelt
(case-insensitive), werden vor dem Rendern als `***REDACTED***` ersetzt.
Renderer ist JSON — siehe ARCHITECTURE.md §10.
"""

from __future__ import annotations

import logging
import re
from typing import Any

import structlog
from structlog.types import EventDict, Processor

# Felder mit diesen Substrings (case-insensitive) werden geredacted.
_REDACT_PATTERN = re.compile(r"(password|key|token|hash)", re.IGNORECASE)
_REDACTED = "***REDACTED***"


def _redact_sensitive(_logger: object, _method_name: str, event_dict: EventDict) -> EventDict:
    """Ueberschreibt sensible Felder im Event-Dict.

    Greift rekursiv in verschachtelte Dicts hinein, damit z.B.
    `request={"headers": {"authorization": "..."}}` ebenfalls geredacted wird.
    """

    def _scrub(value: Any) -> Any:
        if isinstance(value, dict):
            return {
                k: (_REDACTED if _REDACT_PATTERN.search(str(k)) else _scrub(v))
                for k, v in value.items()
            }
        if isinstance(value, list):
            return [_scrub(v) for v in value]
        return value

    return {
        k: (_REDACTED if _REDACT_PATTERN.search(str(k)) else _scrub(v))
        for k, v in event_dict.items()
    }


def configure_logging(level: str = "INFO") -> None:
    """Konfiguriert structlog mit JSON-Output und Redaction.

    Wird einmalig in der App-Factory aufgerufen.
    """
    numeric_level = getattr(logging, level.upper(), logging.INFO)

    logging.basicConfig(
        format="%(message)s",
        level=numeric_level,
    )

    processors: list[Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        _redact_sensitive,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.JSONRenderer(),
    ]

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(numeric_level),
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

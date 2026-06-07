"""
Probe: testet welche response_format-Variante DeepInfra mit openai/gpt-oss-120b
akzeptiert. Spiegelt den exakten Call-Shape des Worker-Helpers `chat_completion_json`
(app/services/llm_risk_reviewer.py) bzw. der funktionierenden probe_gpt_oss.py.

Ziel: den 400-Status aus dem Worker-Log
    "HTTP/1.1 400 Bad Request"
mit dem konkreten DeepInfra-Error-Body korrelieren.

Vier Varianten werden gegen denselben minimalen Pass-2-Prompt geschickt:
  (A) {"type": "json_schema", "json_schema": {... strict: False ...}}  ← aktueller Worker
  (B) {"type": "json_schema", "json_schema": {... strict: True ...}}
  (C) {"type": "json_object"}                                          ← Spec / probe_gpt_oss
  (D) ohne response_format                                             ← Vergleichs-Baseline

Pro Variante:
  - HTTP-Status
  - DeepInfra-Error-Body (komplette JSON-Response oder Text)
  - bei 200: erste 200 Zeichen der Antwort

Requires: pip install openai httpx
Usage:    DEEPINFRA_API_KEY=... python probe_response_format.py
"""

from __future__ import annotations

import json
import os
import sys
import time

import httpx
from openai import APIStatusError, OpenAI

API_KEY = os.environ.get("DEEPINFRA_API_KEY")
if not API_KEY:
    print("ERROR: DEEPINFRA_API_KEY environment variable not set.", file=sys.stderr)
    sys.exit(2)

MODEL = "openai/gpt-oss-120b"
BASE_URL = "https://api.deepinfra.com/v1/openai"

SYSTEM_PROMPT = (
    "You are an experienced IT security analyst. Return only valid JSON "
    "matching the schema below. No prose, no markdown.\n\n"
    'Schema: {"evaluations": [{"group_label": "string", "risk_band": "string"}]}'
)

USER_PROMPT = (
    "Host: Ubuntu 22.04, listener tcp 0.0.0.0:22 sshd.\n"
    "Group: openssh-server. Findings: CVE-2024-6387 CVSS 8.1 KEV yes has_fix=yes."
)

# Minimal-Schema entsprechend Pass-2-Schema, gekürzt.
SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["evaluations"],
    "properties": {
        "evaluations": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["group_label", "risk_band"],
                "properties": {
                    "group_label": {"type": "string"},
                    "risk_band": {
                        "type": "string",
                        "enum": ["escalate", "act", "monitor", "noise"],
                    },
                },
            },
        }
    },
}

VARIANTS: list[tuple[str, dict | None]] = [
    (
        "A: json_schema, strict=False (current worker)",
        {
            "type": "json_schema",
            "json_schema": {
                "name": "fathometer_risk_review",
                "schema": SCHEMA,
                "strict": False,
            },
        },
    ),
    (
        "B: json_schema, strict=True",
        {
            "type": "json_schema",
            "json_schema": {
                "name": "fathometer_risk_review",
                "schema": SCHEMA,
                "strict": True,
            },
        },
    ),
    (
        "C: json_object (spec / working probe)",
        {"type": "json_object"},
    ),
    (
        "D: no response_format",
        None,
    ),
]


def call(client: OpenAI, response_format: dict | None) -> dict:
    """Returns dict with status, body, headers (truncated), or content on success."""
    kwargs = dict(
        model=MODEL,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": USER_PROMPT},
        ],
        stream=False,
        max_tokens=512,
        temperature=0,
    )
    if response_format is not None:
        kwargs["response_format"] = response_format

    t0 = time.monotonic()
    try:
        resp = client.chat.completions.create(**kwargs)
        elapsed_ms = int((time.monotonic() - t0) * 1000)
        return {
            "ok": True,
            "status": 200,
            "elapsed_ms": elapsed_ms,
            "content": (resp.choices[0].message.content or "")[:200],
            "model": resp.model,
            "usage": {
                "prompt": resp.usage.prompt_tokens,
                "completion": resp.usage.completion_tokens,
            },
        }
    except APIStatusError as exc:
        elapsed_ms = int((time.monotonic() - t0) * 1000)
        body: object
        try:
            body = exc.response.json()
        except Exception:
            body = exc.response.text
        return {
            "ok": False,
            "status": exc.status_code,
            "elapsed_ms": elapsed_ms,
            "body": body,
            "headers": {
                k: v
                for k, v in dict(exc.response.headers).items()
                if k.lower() in ("content-type", "x-request-id", "deepinfra-request-id")
            },
        }
    except httpx.HTTPError as exc:
        return {"ok": False, "status": None, "transport_error": str(exc)}
    except Exception as exc:
        return {"ok": False, "status": None, "unexpected": f"{type(exc).__name__}: {exc}"}


def main() -> int:
    client = OpenAI(api_key=API_KEY, base_url=BASE_URL, timeout=60.0)
    print(f"=== Probe response_format variants against {MODEL} ===\n")
    summary: list[tuple[str, str]] = []
    for label, fmt in VARIANTS:
        print(f"--- {label} ---")
        result = call(client, fmt)
        print(json.dumps(result, indent=2, default=str)[:2000])
        print()
        if result.get("ok"):
            summary.append((label, "200 OK"))
        else:
            summary.append((label, f"{result.get('status')} — see body above"))
    print("=== Summary ===")
    for label, status in summary:
        print(f"  {status:>40s}  |  {label}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

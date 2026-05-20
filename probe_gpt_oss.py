"""
Probe DeepInfra response shape for openai/gpt-oss-120b with Pass-2 prompt.
Pure inspection — no parsing, no validation, just print what comes back.

Requires: pip install openai
Usage:    DEEPINFRA_API_KEY=... python probe_gpt_oss.py
"""

import json
import os
from openai import OpenAI

API_KEY = os.environ["DEEPINFRA_API_KEY"]
MODEL = "openai/gpt-oss-120b"

SYSTEM_PROMPT = """You are an experienced IT security analyst. Your task: evaluate each application group's risk on this specific Linux host and assign one of four risk bands plus one of four action types.

Exposure is determined ONLY from listener addresses:
  - 0.0.0.0 or :: → public / internet-facing
  - 127.0.0.1 or ::1 → loopback only
  - private IPv4 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) → internal network only

For EACH group, return ONE risk_band (escalate, act, monitor, noise) and ONE action_type (patch, mitigate, watch, none).

Allowed (risk_band, action_type) combinations:
  (escalate, patch), (escalate, mitigate), (act, patch), (monitor, watch), (noise, none)

Return only valid JSON matching this schema:
{
  "evaluations": [
    {"group_label": "string", "risk_band": "string", "action_type": "string",
     "worst_finding_id": number, "reason": "string (max 200 chars)"}
  ]
}
No prose, no markdown, no explanation outside the JSON.
"""

USER_PROMPT = """Host context:
  os: Ubuntu 22.04 LTS
  listeners: tcp 0.0.0.0:22 sshd; tcp 0.0.0.0:443 nginx
  active services: sshd, nginx
  kernel modules: ext4, nf_conntrack (NO bluetooth modules)

Groups to evaluate:

Group A: openssh-server
  Findings (1): CVE-2024-6387 CVSS 8.1 KEV yes EPSS 0.88 has_fix=yes
  finding_ids: [1001]

Group B: nginx
  Findings (1): CVE-2024-7347 CVSS 9.8 KEV yes EPSS 0.72 has_fix=yes
  finding_ids: [2001]

Group C: linux-firmware-bluetooth
  Findings (1): CVE-2024-24859 CVSS 9.8 KEV no EPSS 0.02 has_fix=yes
  finding_ids: [3001]
"""

client = OpenAI(
    api_key=API_KEY,
    base_url="https://api.deepinfra.com/v1/openai",
)

print(f"=== Calling {MODEL} via DeepInfra ===\n")

response = client.chat.completions.create(
    model=MODEL,
    messages=[
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": USER_PROMPT},
    ],
    stream=False,
    max_tokens=4096,
    temperature=0,
    response_format={"type": "json_object"},
)

print("=== Raw response object ===")
print(f"type: {type(response).__name__}")
print(f"model: {response.model}")
print(f"id: {response.id}\n")

print("=== Usage ===")
print(f"prompt_tokens:     {response.usage.prompt_tokens}")
print(f"completion_tokens: {response.usage.completion_tokens}")
print(f"total_tokens:      {response.usage.total_tokens}")
# Manche Provider liefern Reasoning-Tokens separat:
for extra_attr in ("reasoning_tokens", "completion_tokens_details", "prompt_tokens_details"):
    if hasattr(response.usage, extra_attr):
        val = getattr(response.usage, extra_attr)
        if val is not None:
            print(f"{extra_attr}: {val}")
print()

print("=== choices[0].message ===")
msg = response.choices[0].message
print(f"role: {msg.role}")
print(f"type of content: {type(msg.content).__name__}")
print(f"len of content: {len(msg.content) if msg.content else 0} chars\n")

print("=== ALL attributes on message ===")
# Zeigt ob es message.reasoning, message.reasoning_content, message.thinking etc. gibt
for attr in dir(msg):
    if attr.startswith("_"):
        continue
    val = getattr(msg, attr, None)
    if callable(val):
        continue
    if val is None or val == "":
        continue
    val_repr = repr(val)
    if len(val_repr) > 200:
        val_repr = val_repr[:200] + "... (truncated)"
    print(f"  msg.{attr} = {val_repr}")
print()

print("=== Raw content (full, character-by-character to see invisible) ===")
print("--- BEGIN content ---")
print(msg.content)
print("--- END content ---\n")

print("=== Hex-dump of first 200 chars (to catch invisible markers) ===")
if msg.content:
    for i, c in enumerate(msg.content[:200]):
        if ord(c) < 0x20 or ord(c) > 0x7e:
            print(f"  [{i}] {ord(c):#04x}  {repr(c)}")
print()

print("=== Try plain json.loads ===")
try:
    parsed = json.loads(msg.content)
    print("✓ json.loads succeeded directly!")
    print(json.dumps(parsed, indent=2)[:500])
except json.JSONDecodeError as e:
    print(f"✗ json.loads failed: {e}")
    print("  → strip logic needed")
print()

print("=== Search for known reasoning patterns ===")
patterns = [
    ("Harmony channel", "<|channel|>"),
    ("Think tag", "<think>"),
    ("Reasoning block", "[REASONING]"),
    ("Markdown json fence", "```json"),
    ("Markdown plain fence", "```"),
    ("Analysis keyword", "analysis"),
]
for name, marker in patterns:
    if msg.content and marker.lower() in msg.content.lower():
        idx = msg.content.lower().find(marker.lower())
        print(f"  FOUND '{name}' ({marker!r}) at offset {idx}")
        snippet = msg.content[max(0, idx-20):idx+100]
        print(f"    context: ...{snippet!r}...")
    else:
        print(f"  not found: {name} ({marker!r})")

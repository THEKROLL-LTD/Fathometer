"""Standalone-Worker fuer secscan (kein Flask-App-Context).

Enthaelt aktuell nur :mod:`app.workers.llm_worker` (Block P, ADR-0023) —
LLM-Risk-Reviewer-Job-Loop mit Pickup, Stale-Reaper, Token-Budget und
Heartbeat.
"""

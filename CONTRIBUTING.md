# Contributing to Fathometer

Thanks for considering a contribution! Fathometer is maintained by THEKROLL LTD
and licensed under the [Apache License 2.0](LICENSE).

## Contributor License Agreement (required)

Before your first pull request can be merged, you must sign our
[Contributor License Agreement](CLA.md). This is automated:

1. Open your pull request as usual.
2. The **CLA Assistant** check will comment if a signature is needed.
3. Reply on the PR with the exact text:
   `I have read the CLA Document and I hereby sign the CLA`
4. The check turns green and stays valid for all your future PRs.

Contributing on behalf of a company? Mention the entity's name in that comment,
and make sure you're authorized to sign on its behalf.

## Development setup

```bash
python3.13 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
docker compose up -d db          # PostgreSQL 17
alembic upgrade head
```

See [`README.md`](README.md) for running the app and
[`ARCHITECTURE.md`](ARCHITECTURE.md) for the design.

## Code quality gates

Pull requests must pass:

```bash
ruff check . && ruff format --check .
mypy app/
pytest
```

- **Ruff** for lint and formatting.
- **mypy --strict** on `app/` — no type errors.
- **pytest** default selection (pure unit tests).

New source files in `app/` should carry the SPDX header:

```python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 THEKROLL LTD
```

## Scope and decisions

Fathometer has a deliberately bounded scope. Before proposing a feature, check
the out-of-scope list and the architecture decision records under
[`docs/decisions/`](docs/decisions/). Scope-expanding changes need a new ADR
first.

## Reporting security issues

Please do **not** open public issues for security vulnerabilities. Contact
THEKROLL LTD privately so the issue can be addressed before disclosure.

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

Requires [uv](https://docs.astral.sh/uv/). `make install` installs Python 3.14
and exactly the dependencies pinned in `uv.lock`.

```bash
make install
docker compose up -d db          # PostgreSQL 17
uv run alembic upgrade head
```

See [`README.md`](README.md) for running the app and
[`ARCHITECTURE.md`](ARCHITECTURE.md) for the design.

## Code quality gates

Pull requests must pass:

```bash
make lint        # ruff check, ruff format --check, shellcheck agent/*.sh
make typecheck   # mypy --strict on app/
make test        # pytest default selection with the coverage gate
```

CI runs exactly these targets.

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

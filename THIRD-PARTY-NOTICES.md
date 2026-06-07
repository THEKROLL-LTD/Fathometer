# Third-Party Notices

Fathometer is licensed under the Apache License, Version 2.0 (see [`LICENSE`](LICENSE)).
It bundles and depends on third-party components that are distributed under their
own licenses. The notices below are provided to satisfy the attribution and
source-availability obligations of those licenses.

## LGPL-3.0 components — psycopg

Fathometer distributes (e.g. in its Docker image) the following components under
the **GNU Lesser General Public License, version 3.0 only (LGPL-3.0-only)**:

| Component       | Version | License        | Project / Source                          |
|-----------------|---------|----------------|-------------------------------------------|
| `psycopg`       | 3.3.x   | LGPL-3.0-only  | https://psycopg.org/ · https://github.com/psycopg/psycopg |
| `psycopg-binary`| 3.3.x   | LGPL-3.0-only  | https://psycopg.org/ · https://github.com/psycopg/psycopg |

Compliance statement:

- psycopg is used **as a separate, dynamically imported Python library**. It is
  not statically combined with, or built into, Fathometer's own source code.
  Fathometer's own code remains licensed under Apache-2.0; only psycopg and
  `psycopg-binary` are covered by the LGPL-3.0.
- The complete corresponding **source code** of psycopg is publicly available at
  https://github.com/psycopg/psycopg and on PyPI (https://pypi.org/project/psycopg/).
- The full **LGPL-3.0 license text** is available at
  https://www.gnu.org/licenses/lgpl-3.0.txt (the LGPL-3.0 consists of the
  GPL-3.0, https://www.gnu.org/licenses/gpl-3.0.txt, plus the additional
  permissions of the LGPL). A copy of each package's license is also shipped
  inside the installed package's `*.dist-info` directory in any distribution
  that includes it.
- Because psycopg is installed as a standard, replaceable Python package
  (`pip install psycopg[binary]`), a recipient may modify or substitute their
  own version of psycopg, as required by the LGPL-3.0.

To obtain a distribution **without** the bundled binary build, install plain
`psycopg` (linked against a system libpq) instead of `psycopg[binary]`; the
license is identical (LGPL-3.0-only) in either case.

## MPL-2.0 components

The following transitively included components are licensed under the
**Mozilla Public License 2.0 (MPL-2.0)**. MPL-2.0 is file-level weak copyleft;
their source is available from the projects below and is unmodified by Fathometer:

| Component  | License  | Source                                        |
|------------|----------|-----------------------------------------------|
| `certifi`  | MPL-2.0  | https://github.com/certifi/python-certifi     |

## Permissively licensed runtime dependencies

The remaining direct runtime dependencies are distributed under permissive
licenses (Apache-2.0, BSD, MIT). Each retains its own copyright and license
notice within its distributed package:

| Component          | License                    |
|--------------------|----------------------------|
| Flask              | BSD-3-Clause               |
| Werkzeug / Jinja2  | BSD-3-Clause               |
| SQLAlchemy         | MIT                        |
| alembic            | MIT                        |
| pydantic           | MIT                        |
| pydantic-settings  | MIT                        |
| Flask-Login        | MIT                        |
| Flask-Limiter      | MIT                        |
| Flask-WTF / WTForms| BSD-3-Clause               |
| structlog          | MIT OR Apache-2.0          |
| argon2-cffi        | MIT                        |
| cryptography       | Apache-2.0 OR BSD-3-Clause |
| openai             | Apache-2.0                 |
| nh3                | MIT                        |
| httpx              | BSD-3-Clause               |
| gunicorn           | MIT                        |
| packaging          | Apache-2.0 OR BSD-2-Clause |

This list reflects the direct runtime dependencies declared in
[`pyproject.toml`](pyproject.toml). Transitive dependencies carry their own
license notices within their respective packages.

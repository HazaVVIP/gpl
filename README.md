# gpl

GPL (GraphQL Probe & Loader) is a Python CLI for GraphQL schema introspection and guided data extraction.

## vNext Scope

- **Product type:** CLI-first Python tool
- **Primary users:** Developers, security testers, API integrators
- **Core use cases:**
  1. List available queries and mutations
  2. Enumerate schema types
  3. Run guided data-dump exploration for target entities
  4. Export query results to JSON

### MVP boundaries

- Include: introspection-driven discovery, interactive dump workflow, JSON export
- Exclude (for now): hosted service, database persistence, remote orchestration

## Install

### Local development

```bash
pip install -e .[dev]
```

### Run

```bash
python main.py --help
# or (after install)
gpl --help
# or
python -m gpl --help
```

## Usage

```bash
gpl --url https://target.com/graphql -q
gpl --url https://target.com/graphql -m
gpl --url https://target.com/graphql -t
gpl --url https://target.com/graphql --dbs --concurrency 16 --output dump.json
```

## Project structure

```text
.
├── src/gpl/
│   ├── __init__.py
│   ├── __main__.py
│   └── cli.py
├── tests/
├── .github/workflows/
├── main.py
├── pyproject.toml
└── README.md
```

## Testing & quality gates

```bash
python -m compileall -q src tests main.py
pytest
```

- CI runs compile + tests on Python 3.10/3.11/3.12.
- Coverage threshold is enforced at 10% for the initial baseline and will be raised in upcoming releases.

## Update plan (implemented in this version)

- Migrated from flat script setup to package layout under `src/`.
- Added modern project metadata and dependency management via `pyproject.toml`.
- Added baseline tests and CI checks.
- Added governance and contribution docs.

## Upgrade plan (ongoing)

- Monthly dependency review and updates.
- Track new Python releases and deprecation windows.
- Document compatibility and migration notes per release.
- Keep security workflows active and triage findings quickly.

## Roadmap

- **v0.1.0:** project scaffolding, baseline docs, tests, CI ✅
- **v0.2.0:** richer dump filters, better output selectors, stronger test depth
- **v1.0.0:** stable CLI contract, migration guidance, production-ready release process

## Responsible use

Use only on systems and GraphQL endpoints you are authorized to test.

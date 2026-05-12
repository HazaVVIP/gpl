# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog and this project uses Semantic Versioning.

## [Unreleased]

### Added
- Enterprise scan mode (`--scan`) with initial pentest checks and policy gating (`--fail-on`)
- Modular scan foundation: transport, schema analysis, findings model, checks, engine, reporting
- JSON and SARIF report export for scan results (`--report-json`, `--report-sarif`)
- CLI auth and transport options for scan mode (`--api-key`, `--api-key-header`, `--cookie`, `--ca-file`, `--insecure`, `--retries`)
- New tests for scan engine, reporting, and policy-exit behavior

## [0.1.0] - 2026-05-12

### Added
- Python project packaging via `pyproject.toml`
- `src/gpl` package layout and module entrypoint
- Backward-compatible `main.py` shim entrypoint
- Initial unit/integration smoke tests
- CI and security workflows
- Contribution and governance templates
- Expanded project documentation and release policy

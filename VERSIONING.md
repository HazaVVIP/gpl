# Versioning & Upgrade Policy

## Versioning model

GPL follows Semantic Versioning (`MAJOR.MINOR.PATCH`).

- **MAJOR**: breaking CLI contract changes.
- **MINOR**: backward-compatible feature additions.
- **PATCH**: bug fixes and non-breaking improvements.

## Upgrade cadence

- Dependencies: review at least monthly.
- Python runtime: add support for new stable releases quickly; deprecate old versions with one minor-release notice.

## Backward compatibility

- During `0.x`, small breaking changes may occur but must be documented in `CHANGELOG.md`.
- From `1.0.0`, breaking changes require major version bumps and migration notes.

## Security response

- Triage reported vulnerabilities quickly.
- Patch and release as soon as practical.
- Document impact, fixed versions, and mitigation in release notes.

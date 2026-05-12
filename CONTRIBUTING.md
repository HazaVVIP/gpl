# Contributing to GPL

## Development setup

1. Use Python 3.10+.
2. Create a virtual environment.
3. Install project with dev extras:

```bash
pip install -e .[dev]
```

## Local quality checks

```bash
python -m compileall -q src tests main.py
pytest
```

## Contribution rules

- Keep changes focused and small.
- Add/adjust tests for behavior changes.
- Update `README.md` and `CHANGELOG.md` when user-facing behavior changes.
- Never commit credentials, tokens, or endpoint secrets.

## Pull requests

- Open PRs against the default branch.
- Fill the PR template completely.
- Ensure CI is green before requesting review.

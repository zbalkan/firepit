# Installation

Firepit 3 supports CPython 3.11, 3.12, 3.13, and 3.14.

## Development install

```bash
python -m pip install -e ".[test]"
python -m pytest
```

The GitHub Actions matrix runs the supported Python versions on Linux, macOS, and Windows.

## Build a distribution

```bash
python -m pip install build
python -m build
```

All package metadata and dependencies live in `pyproject.toml`. The repository no longer carries `setup.py`, `setup.cfg`, requirements files, `tox.ini`, a project Makefile, or Pylint-specific configuration.

## Dependencies

The core runtime dependency set is intentionally one package:

```text
duckdb
```

Testing adds `pytest` and `pytest-cov`. Release tooling is optional.

## Database compatibility

Firepit 3 does not reinterpret older Firepit databases. A session without the current native-model metadata, or with another native model version, is rejected. Re-ingest source STIX 2.1 into a new database/session.

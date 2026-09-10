# Installation

Firepit 3 supports CPython 3.11, 3.12, 3.13, and 3.14.

## Query-only installation

The public query interface has one runtime dependency: DuckDB.

```bash
python -m pip install -e .
```

## Acquisition integration

Applications using Firepit's private ingestion path install the optional ingestion extra:

```bash
python -m pip install -e ".[ingest]"
```

This adds OASIS `cti-python-stix2` for standard STIX 2.1 object handling and `stix2-patterns` for authoritative STIX 2.1 Indicator pattern inspection. The public query path imports neither dependency.

## Development install

```bash
python -m pip install -e ".[test]"
python -m pytest
```

The test extra includes the ingestion dependencies because the suite covers both the private acquisition boundary and the public query contract.

CI is configured for Python 3.11 through 3.14 on Linux, macOS, and Windows.

## Build a distribution

```bash
python -m pip install build
python -m build
```

Package metadata and dependencies are defined in `pyproject.toml`. The repository does not use `setup.py`, `setup.cfg`, requirements files, tox, a project Makefile, Pylint configuration, or Sphinx/RST documentation.

## Database compatibility

The current private storage model is version 9 and public view definitions are versioned separately. Earlier Firepit database layouts are not migrated implicitly. Re-ingest source STIX 2.1 into a new database/session when crossing an incompatible model boundary.

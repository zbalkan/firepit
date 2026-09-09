# Installation

Firepit supports CPython 3.11, 3.12, 3.13, and 3.14.

## Editable development install

```bash
python -m pip install -e .
```

Install test dependencies with:

```bash
python -m pip install -e ".[test]"
```

Run tests:

```bash
python -m pytest
```

Run the configured Python-version matrix:

```bash
tox
```

## Build a distribution

```bash
python -m pip install build
python -m build
```

The package metadata and dependencies are defined only in `pyproject.toml`. There is no `setup.py`, `setup.cfg`, or requirements file compatibility layer.

## Runtime dependency policy

DuckDB is the permanent storage dependency. Other dependencies are transitional and should disappear as the corresponding compatibility layers are removed. See the dependency burn-down in [MODERNIZATION_ROADMAP.md](../MODERNIZATION_ROADMAP.md).

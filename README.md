# Firepit

Firepit is a small DuckDB-native storage layer for STIX 2.1 data.

The architecture is intentionally narrow:

```text
remote source
    |
    v
Python acquisition/orchestration
    - credentials
    - STIX-Shifter
    - query execution / polling / paging
    |
    | raw STIX 2.1 JSON
    v
Firepit + DuckDB
    - immutable raw-bundle provenance
    - typed STIX tables
    - LIST / MAP / STRUCT
    - explicit reference views
    |
    v
DuckDB SQL / DuckDB UI
```

Firepit does not target SQLite or PostgreSQL and does not preserve the original Kestrel 1 storage/runtime contract. DuckDB is the storage and analytical engine. Firepit does not provide a second query AST, local STIX-pattern compiler, automatic graph dereferencing layer, dataframe ingestion path, or interactive shell.

## Data model

Known STIX structure is represented with native DuckDB types:

- known scalar properties use scalar columns;
- known nested objects use `STRUCT`;
- repeated values use `LIST`;
- homogeneous dictionaries use `MAP`;
- JSON is reserved for immutable raw provenance, unknown/custom properties, and genuinely heterogeneous fields.

Unknown properties remain recoverable without causing dynamic schema growth.

## Requirements

- CPython 3.11, 3.12, 3.13, or 3.14
- DuckDB

DuckDB is the only core runtime dependency.

## Installation

```bash
python -m pip install -e .
```

For development and tests:

```bash
python -m pip install -e ".[test]"
python -m pytest
```

See [docs/INSTALLATION.md](docs/INSTALLATION.md) for packaging details.

## Ingestion

```python
from firepit import get_storage

store = get_storage("observations.duckdb", "hunt")
store.cache("query-1", "bundle.json")
store.close()
```

The input bundle must use the STIX 2.1 object model. Deprecated embedded `observed-data.objects` is not upgraded; acquisition should supply `observed-data.object_refs`.

## Analysis

Use DuckDB directly for analytical queries:

```bash
duckdb observations.duckdb -ui
```

Firepit installs typed STIX tables plus a small set of explicit enrichment/reference views. New analytical behavior should normally be SQL rather than another Firepit abstraction.

## Documentation

- [Installation](docs/INSTALLATION.md)
- [Usage](docs/USAGE.md)
- [Database model](docs/DATABASE.md)
- [Modernization roadmap](MODERNIZATION_ROADMAP.md)
- [Contributing](CONTRIBUTING.md)

## License

Apache License 2.0. See [LICENSE](LICENSE).

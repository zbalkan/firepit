# Firepit

Firepit is being modernized into a small DuckDB-native storage layer for STIX 2.1 data.

The current direction is intentionally narrow:

```text
remote source
    |
    v
Python acquisition/orchestration
    - credentials
    - STIX-Shifter
    - query execution / polling / paging
    |
    | STIX 2.1 JSON
    v
Firepit + DuckDB
    - raw JSON provenance
    - typed STIX tables
    - LIST / MAP / STRUCT
    - explicit reference views
    |
    v
DuckDB SQL / DuckDB UI
```

Firepit no longer targets SQLite or PostgreSQL, and it is not intended to remain a compatibility runtime for the original Kestrel 1 storage contract. DuckDB is the storage and analytical engine; Python is used only where orchestration or STIX input handling requires it.

## Status

The branch `claude/firepit-duckdb-modernize-9tj618` is an active modernization branch. The native STIX model exists, but some compatibility APIs are still being removed phase by phase.

The target data-model rules are:

- known scalar STIX properties use native scalar columns;
- known nested objects use `STRUCT`;
- known repeated values use `LIST`;
- homogeneous dictionaries use `MAP`;
- JSON is reserved for raw provenance, custom fields, and genuinely heterogeneous structures.

Unknown properties must remain recoverable without causing dynamic schema growth.

## Requirements

- CPython 3.11, 3.12, 3.13, or 3.14
- DuckDB

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

## Basic usage

```python
from firepit import get_storage

store = get_storage("observations.duckdb", "hunt")
store.cache("query-1", "bundle.json")
```

The storage API is still being reduced. New analytical code should prefer DuckDB SQL directly instead of adding new Firepit query abstractions.

## Documentation

- [Installation](docs/INSTALLATION.md)
- [Usage](docs/USAGE.md)
- [Database model](docs/DATABASE.md)
- [Modernization roadmap](MODERNIZATION_ROADMAP.md)
- [Contributing](CONTRIBUTING.md)

## License

Apache License 2.0. See [LICENSE](LICENSE).

# Firepit

Firepit is a small DuckDB-native storage layer for STIX 2.1 data.

Version 3 removes the historical multi-backend and Kestrel-oriented runtime surface. Firepit now has one responsibility: accept raw STIX 2.1 JSON, preserve acquisition provenance, project known STIX fields into DuckDB-native types, and leave analysis to DuckDB.

```text
remote source
    |
    v
Python acquisition/orchestration
    - credentials
    - STIX-Shifter
    - native query execution
    - polling / paging / retry
    |
    | raw STIX 2.1 JSON
    v
Firepit + DuckDB
    - strict typed projection
    - immutable raw bundle provenance
    - scalar / LIST / MAP / STRUCT
    - explicit reference and enrichment views
    |
    v
DuckDB SQL / DuckDB UI / DuckDB clients
```

## Requirements

- CPython 3.11, 3.12, 3.13, or 3.14
- DuckDB

DuckDB is the only runtime dependency.

## Installation

```bash
python -m pip install -e .
```

For tests:

```bash
python -m pip install -e ".[test]"
python -m pytest
```

## Ingestion

```python
from firepit import get_storage

store = get_storage("observations.duckdb", "hunt")
store.cache(
    "query-1",
    "bundle.json",
    source="qradar",
    stix_pattern="[network-traffic:dst_port = 443]",
    native_query="...",
)
store.close()
```

Input must use the STIX 2.1 object model. Firepit does not upgrade STIX 2.0 embedded `observed-data.objects`. Acquisition should request/produce STIX 2.1 and use `observed-data.object_refs`.

Known fields are cast to their declared DuckDB types. A malformed known field fails the ingestion transaction instead of silently becoming `NULL`. Unknown/custom fields remain available in `_raw` and `raw_bundle`.

## Analysis

Firepit deliberately does not expose a parallel query language. Use DuckDB directly:

```python
store = get_storage("observations.duckdb", "hunt")

rows = store.connection.execute("""
    SELECT id, pid, command_line
    FROM process
    WHERE command_line IS NOT NULL
""").fetchall()
```

Or use DuckDB UI:

```bash
duckdb observations.duckdb -ui
```

Useful installed views include:

- `observation_ref` — expands `observed-data.object_refs`;
- `observation_summary` — exposes `observation_records`, `observation_count`, and first/last observation times per object;
- `stixv_process` — explicit process parent/user/image enrichment;
- `stixv_network_traffic` — explicit IPv4/IPv6 source/destination enrichment.

## Database compatibility

Version 3 uses native storage model version 6. Pre-native Firepit databases and older native model versions are rejected explicitly. Create a new database/session and re-ingest STIX 2.1 source bundles rather than relying on implicit migration.

## Documentation

- [Installation](docs/INSTALLATION.md)
- [Usage](docs/USAGE.md)
- [Database model](docs/DATABASE.md)
- [Completed modernization roadmap](MODERNIZATION_ROADMAP.md)
- [Contributing](CONTRIBUTING.md)
- [History](HISTORY.md)

## License

Apache License 2.0. See [LICENSE](LICENSE).

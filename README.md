# Firepit

Firepit is a small query-only STIX 2.1 threat-intelligence layer backed by DuckDB.

Version 3 removes the historical multi-backend and Kestrel-oriented runtime surface. Acquisition remains private, standard STIX validation is delegated to OASIS `cti-python-stix2`, and analysts query a small public view surface through Firepit's read-only API.

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
private Firepit ingestion
    - OASIS STIX validation
    - canonical object/version handling
    - acquisition provenance
    |
    v
internal DuckDB tables
    |
    v
public views
    - ThreatIntelIndicators
    - ThreatIntelObjects
    - ThreatIntelObservedObjects
    - ThreatIntelObservationSummary
    - ThreatIntelValueCounts
    - ThreatIntelRelationships
    |
    v
Firepit query-only API
```

## Requirements

- CPython 3.11, 3.12, 3.13, or 3.14
- DuckDB

DuckDB is the only query-time runtime dependency. The optional ingestion extra adds `cti-python-stix2`.

## Installation

```bash
python -m pip install -e .
```

For ingestion and tests:

```bash
python -m pip install -e ".[ingest,test]"
python -m pytest
```

## Querying

```python
from firepit import get_storage

with get_storage("intel.duckdb", "hunt") as store:
    rows = store.query("""
        SELECT Id, Confidence, Pattern
        FROM ThreatIntelIndicators
        WHERE Confidence >= ?
    """, (70,))
```

The public object does not expose a DuckDB connection or write API. Queries must be a single `SELECT`, the database is opened read-only, external access is disabled, and Firepit verifies that the public schema contains views only.

## Public views

The two Sentinel-inspired main views are:

- `ThreatIntelIndicators` — STIX indicators with Sentinel-compatible convenience columns and complete STIX in `Data`;
- `ThreatIntelObjects` — every non-indicator STIX object, including SCOs, relationships, observed-data, and threat actors.

Four derived views reproduce the useful historical Firepit hunting semantics without restoring its old query engine:

- `ThreatIntelObservedObjects` — expands `observed-data.object_refs`, replacing the old timestamped/observed-data attribute queries;
- `ThreatIntelObservationSummary` — first/last observation time, observation-record count, and summed `number_observed` per object;
- `ThreatIntelValueCounts` — value-count and observation-count aggregation over scalar STIX properties;
- `ThreatIntelRelationships` — relationship source/target expansion with common name/value dereferencing.

All derived views are defined only in terms of `ThreatIntelIndicators` and `ThreatIntelObjects`.

## Ingestion boundary

Acquisition code should use the private ingestion path indirectly from the STIX-Shifter/orchestration layer. Standard STIX 2.1 objects are validated by OASIS `cti-python-stix2`; custom objects retain their raw JSON after envelope validation.

Firepit does not support STIX 2.0 embedded `observed-data.objects`.

## Database compatibility

Version 3 uses the private model version 7. Older Firepit database layouts are rejected explicitly. Re-ingest STIX 2.1 source data into a new database/session rather than relying on implicit migration.

## Documentation

- [Installation](docs/INSTALLATION.md)
- [Usage](docs/USAGE.md)
- [Database model](docs/DATABASE.md)
- [Completed modernization roadmap](MODERNIZATION_ROADMAP.md)
- [Contributing](CONTRIBUTING.md)
- [History](HISTORY.md)

## License

Apache License 2.0. See [LICENSE](LICENSE).

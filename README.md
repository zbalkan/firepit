# Firepit

Firepit is a query-only threat-intelligence interface backed by DuckDB and STIX 2.1.

Version 3 deliberately separates acquisition/storage internals from the analyst surface. Physical tables and provenance live in a private DuckDB schema. The public session schema contains exactly two read-only views, modeled on Microsoft Sentinel's current threat-intelligence tables:

- `ThreatIntelIndicators`
- `ThreatIntelObjects`

Users query those views through Firepit's read-only API. Firepit does not expose a DuckDB connection, cursor, arbitrary execution handle, insert/update/delete methods, or physical-table API.

```text
remote source
    |
    v
acquisition/orchestration
    - STIX-Shifter
    - paging / polling / retry
    - cti-python-stix2 validation
    |
    | STIX 2.1 bundles
    v
private Firepit writer
    |
    v
__firepit_<session>
    - runs
    - bundles
    - canonical STIX objects
    - run/object provenance
    |
    +-----------------------------+
                                  |
                     public <session> schema
                     - ThreatIntelIndicators
                     - ThreatIntelObjects
                                  |
                                  v
                         Firepit query API
```

## Requirements

Firepit supports CPython 3.11, 3.12, 3.13, and 3.14. Query-only installations depend only on DuckDB.

```bash
python -m pip install -e .
```

Applications which use Firepit's private acquisition integration also install the ingestion extra:

```bash
python -m pip install -e ".[ingest]"
```

That extra provides OASIS `cti-python-stix2`, which is used as the authoritative STIX 2.1 validator for standard objects. It is not imported by the public query path.

## Querying

```python
from firepit import get_storage

with get_storage("intel.duckdb", "hunt") as store:
    rows = store.query(
        """
        SELECT Id, Confidence, Pattern
        FROM ThreatIntelIndicators
        WHERE Confidence >= ?
        """,
        (70,),
    )
```

Convenience methods are available for the two public views:

```python
indicators = store.indicators("Confidence >= ?", (70,), limit=100)
relationships = store.objects("StixType = ?", ("relationship",))
```

`query()`, `query_one()`, and `query_value()` accept exactly one `SELECT` statement. DDL, DML, `PRAGMA`, `ATTACH`, multiple statements, Firepit's internal schema, and DuckDB/catalog relations are rejected. The underlying connection is opened read-only and external access is disabled.

## Public data model

`ThreatIntelIndicators` contains STIX Indicator objects. `ThreatIntelObjects` contains all other stored STIX objects. Both expose the complete canonical STIX object in `Data` as JSON alongside Sentinel-inspired convenience columns.

Azure-specific columns are present for schema familiarity but are `NULL` when Firepit has no equivalent value. `ObservableKey` and `ObservableValue` are currently nullable; Firepit does not reintroduce a local STIX-pattern compiler merely to populate them.

## Internal storage

The physical schema is intentionally not part of the public API. It may change between model versions. Applications must not query or mutate `__firepit_<session>` directly.

The query API enforces this boundary, but a process with direct writable filesystem access to the DuckDB database can bypass any Python API. Use operating-system file permissions if the database file itself must be protected from modification.

## Documentation

- [Installation](docs/INSTALLATION.md)
- [Usage](docs/USAGE.md)
- [Database model](docs/DATABASE.md)
- [Completed modernization roadmap](MODERNIZATION_ROADMAP.md)
- [Contributing](CONTRIBUTING.md)
- [History](HISTORY.md)

## License

Apache License 2.0. See [LICENSE](LICENSE).

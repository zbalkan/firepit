# Firepit

Firepit is a small query-only STIX 2.1 threat-intelligence layer backed by DuckDB.

Version 3 removes the historical multi-backend and Kestrel-oriented runtime surface. Acquisition remains private, standard STIX validation is delegated to OASIS `cti-python-stix2`, and analysts query a public view family through Firepit's read-only API.

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
    - OASIS STIX validation / pattern inspection
    - DuckDB JSON transformation
    - canonical object/version handling
    - acquisition-run provenance
    |
    v
internal DuckDB tables
    |
    v
public views
    - Sentinel-compatible base views
    - Firepit semantic Ex views
    - Firepit wide W views
    |
    v
Firepit query-only API
```

## Requirements

- CPython 3.11, 3.12, 3.13, or 3.14
- DuckDB

DuckDB is the only query-time runtime dependency. The optional ingestion extra adds OASIS `cti-python-stix2` and `stix2-patterns`.

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

The public object does not expose a DuckDB connection or write API. Queries must be a single `SELECT`, the database is opened read-only, external access is disabled, and Firepit verifies the public view contract before accepting queries.

## JSON and schema handling

`Data` is the canonical STIX object. Firepit does not maintain a parallel hand-written STIX schema. OASIS validates standard STIX objects at ingestion, while DuckDB performs JSON mapping and type normalization with `json_transform`/`json_transform_strict` for analyst-facing projections and the internal version envelope.

Known homogeneous fields become DuckDB scalar, `LIST`, `MAP`, and `STRUCT` values. Fields not part of a projection remain available unchanged in `Data`.

## View convention

Firepit uses three public view tiers.

### Base views

The two Sentinel-inspired schema contracts are:

- `ThreatIntelIndicators`
- `ThreatIntelObjects`

Firepit-specific convenience columns are not added to these schemas. For a STIX Indicator containing exactly one unqualified equality comparison, OASIS `stix2-patterns` supplies `ObservableKey` and `ObservableValue`. More complex patterns leave those columns `NULL`; `Pattern` remains authoritative.

### Extended views: `Ex`

`ThreatIntel<Semantic>Ex` means a Firepit semantic/enrichment view. These views may change row grain because their purpose is to eliminate recurring joins, reference traversal, expansion, or aggregation.

- `ThreatIntelRelationshipsEx` — relationship edges with source/target enrichment.
- `ThreatIntelActorRelationsEx` — threat-actor relationships normalized in both directions.
- `ThreatIntelObservationsEx` — one row per `observed-data.object_refs` membership.
- `ThreatIntelObservationSummaryEx` — first/last observation and record/occurrence counts per object.
- `ThreatIntelObservablesEx` — common SCO values and hashes expressed as STIX paths.
- `ThreatIntelObservableStatsEx` — value and observation aggregation.

These retain the useful semantics of the old Firepit `timestamped`, `summary`, `number_observed`, `value_counts`, and dereference helpers without restoring a separate query engine.

### Wide views: `W`

`W` means a wide, denormalized search view. A `W` view preserves the row grain of its corresponding base view and appends computed columns.

- `ThreatIntelIndicatorsW`
- `ThreatIntelObjectsW`

`ThreatIntelIndicatorsW` exposes common indicator fields, safely derived single-equality observables, and related threat-actor lists. `ThreatIntelObjectsW` exposes common STIX fields plus relationship, actor, observation, process, network, file, account, and registry search columns.

## Why the derived views exist

An indicator-to-threat-actor lookup can use the wide view directly:

```sql
SELECT NetworkIP, ThreatActorNames
FROM ThreatIntelIndicatorsW
WHERE NetworkIP = '192.0.2.1';
```

Actor-centric relationship hunting does not need separate source and target joins:

```sql
SELECT ThreatActorName, RelatedStixType, RelatedName, RelatedValue,
       RelatedPattern, RelationshipType
FROM ThreatIntelActorRelationsEx
WHERE ThreatActorName = 'Sangria Tempest';
```

All `Ex` and `W` views are derived from `ThreatIntelIndicators` and `ThreatIntelObjects`. Internal physical tables are not part of the analyst contract.

## Ingestion boundary

Acquisition code uses the private ingestion path from the STIX-Shifter/orchestration layer. Its identifier is an acquisition `run_id`, not a persistent query identity. Standard STIX 2.1 objects are validated by OASIS `cti-python-stix2`; custom objects retain their raw JSON after envelope validation.

Firepit does not support STIX 2.0 embedded `observed-data.objects`.

## Database compatibility

Version 3 uses private model version 9. Public view definitions have a separate version so opening a writer does not rebuild unchanged views. Older Firepit database layouts are rejected explicitly; re-ingest STIX 2.1 source data rather than relying on implicit migration.

## Documentation

- [Installation](docs/INSTALLATION.md)
- [Usage](docs/USAGE.md)
- [Database model](docs/DATABASE.md)
- [Completed modernization roadmap](MODERNIZATION_ROADMAP.md)
- [Contributing](CONTRIBUTING.md)
- [History](HISTORY.md)

## License

Apache License 2.0. See [LICENSE](LICENSE).

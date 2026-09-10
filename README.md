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
    - OASIS STIX validation
    - DuckDB JSON transformation
    - canonical object/version handling
    - acquisition provenance
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

## JSON and schema handling

`Data` is the canonical STIX object. Firepit does not maintain a parallel hand-written STIX storage schema. OASIS validates standard STIX objects at ingestion, then DuckDB performs JSON mapping and type normalization with `json_transform`/`json_transform_strict` when building analyst views and the internal version envelope.

Known homogeneous fields become DuckDB scalar, `LIST`, `MAP`, and `STRUCT` values. Standard shapes use strict transformation where appropriate; heterogeneous `ThreatIntelObjectsW` projections use tolerant transformation so a custom object cannot invalidate the entire view. Fields not part of a projection remain available unchanged in `Data`.

## View convention

Firepit uses three public view tiers.

### Base views

The two Sentinel-inspired contracts remain unchanged:

- `ThreatIntelIndicators`
- `ThreatIntelObjects`

These are the compatibility foundation. New Firepit-specific convenience columns do not get added to them.

### Extended views: `Ex`

`ThreatIntel<Semantic>Ex` means a Firepit semantic/enrichment view. These views may change row grain because their purpose is to eliminate recurring joins, reference traversal, expansion, or aggregation.

- `ThreatIntelRelationshipsEx` — relationship edges with source/target type, name, value, pattern, and raw endpoint data.
- `ThreatIntelActorRelationsEx` — threat-actor relationships normalized in both directions so actor-centric hunting needs no source/target union.
- `ThreatIntelObservationsEx` — one row per `observed-data.object_refs` membership.
- `ThreatIntelObservationSummaryEx` — first/last observation, record count, and summed `number_observed` per object.
- `ThreatIntelObservablesEx` — common searchable SCO values and hashes expressed as STIX paths.
- `ThreatIntelObservableStatsEx` — value-count and observation-count aggregation for those observables.

These replace the useful parts of the old Firepit `timestamped`, `summary`, `number_observed`, `value_counts`, and dereference/query-helper behavior without restoring a query engine.

### Wide views: `W`

`W` means a wide, denormalized search view. Unlike `Ex`, a `W` view preserves the row grain of its corresponding base view and appends many computed columns.

- `ThreatIntelIndicatorsW`
- `ThreatIntelObjectsW`

`ThreatIntelIndicatorsW` exposes common indicator/STIX fields, common equality-pattern observables such as IP/domain/email/URL/file-hash/X.509 values, and related threat-actor lists. `ThreatIntelObjectsW` exposes common STIX fields plus relationship, threat-actor, observed-data, process, network, file, account, and registry search columns.

The `W` pattern-derived observable columns are intentionally best-effort convenience fields for common equality predicates. `Pattern` remains authoritative for complex STIX patterns.

## Why the derived views exist

Queries similar to the Microsoft Sentinel examples become much smaller. For example, an indicator-to-threat-actor lookup can use the wide view directly:

```sql
SELECT NetworkIP, ThreatActorNames
FROM ThreatIntelIndicatorsW
WHERE NetworkIP = '192.0.2.1';
```

Actor-centric relationship hunting no longer needs separate source and target joins:

```sql
SELECT
    ThreatActorName,
    RelatedStixType,
    RelatedName,
    RelatedValue,
    RelatedPattern,
    RelationshipType
FROM ThreatIntelActorRelationsEx
WHERE ThreatActorName = 'Sangria Tempest';
```

All `Ex` and `W` views are derived from `ThreatIntelIndicators` and `ThreatIntelObjects`. Internal physical tables are not part of the analyst contract.

## Ingestion boundary

Acquisition code should use the private ingestion path indirectly from the STIX-Shifter/orchestration layer. Standard STIX 2.1 objects are validated by OASIS `cti-python-stix2`; custom objects retain their raw JSON after envelope validation.

Firepit does not support STIX 2.0 embedded `observed-data.objects`.

## Database compatibility

Version 3 uses the private model version 8. Older Firepit database layouts are rejected explicitly. Re-ingest STIX 2.1 source data into a new database/session rather than relying on implicit migration.

## Documentation

- [Installation](docs/INSTALLATION.md)
- [Usage](docs/USAGE.md)
- [Database model](docs/DATABASE.md)
- [Completed modernization roadmap](MODERNIZATION_ROADMAP.md)
- [Contributing](CONTRIBUTING.md)
- [History](HISTORY.md)

## License

Apache License 2.0. See [LICENSE](LICENSE).

# Usage

Firepit exposes a query-only threat-intelligence surface backed by DuckDB. Acquisition stays above Firepit; analysts query public views only.

## Open a session

```python
from firepit import get_storage

store = get_storage("intel.duckdb", "hunt")
```

A session is a public DuckDB schema containing views only. Physical tables live in a private Firepit schema and are not part of the user contract.

## Main views

`ThreatIntelIndicators` and `ThreatIntelObjects` are the two Sentinel-inspired main views.

```python
rows = store.query("""
    SELECT Id, Confidence, Pattern
    FROM ThreatIntelIndicators
    WHERE Confidence >= ?
""", (70,))
```

The complete STIX object remains available in the `Data` JSON column.

## Derived hunting views

The old Firepit storage API contained several fixed analytical query patterns. Version 3 exposes the useful ones as views rather than Python methods or mutable variables.

### ThreatIntelObservedObjects

Expands STIX 2.1 `observed-data.object_refs` and associates each referenced object with the observation timestamps and `number_observed` value.

```sql
SELECT
    ObservationId,
    ObjectId,
    StixType,
    FirstObserved,
    LastObserved,
    NumberObserved,
    Data
FROM ThreatIntelObservedObjects;
```

This replaces the historical `timestamped()` and observed-data attribute extraction patterns.

### ThreatIntelObservationSummary

Aggregates observation history per referenced object:

```sql
SELECT
    ObjectId,
    StixType,
    ObservationRecords,
    ObservationCount,
    FirstObserved,
    LastObserved
FROM ThreatIntelObservationSummary;
```

`ObservationRecords` counts object/observation associations. `ObservationCount` sums STIX `number_observed`. This replaces the old `summary()` and `number_observed()` helpers while keeping the two quantities explicit.

### ThreatIntelValueCounts

Flattens scalar properties from observed SCO JSON and aggregates their observation frequency:

```sql
SELECT
    StixPath,
    Value,
    ObservationRecords,
    ObservationCount
FROM ThreatIntelValueCounts
WHERE StixType = 'ipv4-addr'
ORDER BY ObservationCount DESC;
```

Array indexes are normalized to `[*]`, giving paths such as `file:hashes.SHA-256` or repeated-property paths with wildcard indexes. This replaces the old path-oriented `value_counts()` behavior.

### ThreatIntelRelationships

Expands relationship source and target references and resolves common `name` and `value` properties from the two main views:

```sql
SELECT
    RelationshipType,
    SourceStixType,
    SourceName,
    SourceValue,
    TargetStixType,
    TargetName,
    TargetValue
FROM ThreatIntelRelationships;
```

This covers the most common historical `join()` and reference-dereference use cases without reintroducing recursive auto-dereferencing.

## Query-only boundary

The public object exposes `query()`, `query_one()`, `query_value()`, `indicators()`, and `objects()`. It does not expose a DuckDB connection, cursor, DDL/DML execution, ingestion, or deletion APIs.

Queries must contain exactly one `SELECT` statement. The database is opened read-only and external access is disabled.

## Close

```python
store.close()
```

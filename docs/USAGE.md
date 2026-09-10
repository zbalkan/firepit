# Usage

Firepit exposes a read-only SQL surface over public DuckDB views. Acquisition stays above Firepit; internal physical tables are not part of the analyst contract.

## Open a session

```python
from firepit import get_storage

store = get_storage("observations.duckdb", "hunt")
```

A session is a DuckDB schema containing public views only.

## Query tiers

### Base views

Use the Sentinel-compatible base views when portability and schema stability matter most:

```sql
SELECT Id, Confidence, Pattern
FROM ThreatIntelIndicators
WHERE Confidence >= 70;
```

The base contracts are `ThreatIntelIndicators` and `ThreatIntelObjects` and are intentionally kept unchanged.

### Extended `Ex` views

Use `ThreatIntel<Semantic>Ex` when the query would otherwise require repeated relationship traversal, observation expansion, or aggregation.

Threat actors related to any intelligence object:

```sql
SELECT
    ThreatActorName,
    RelationshipType,
    RelatedStixType,
    RelatedName,
    RelatedValue,
    RelatedPattern
FROM ThreatIntelActorRelationsEx
WHERE ThreatActorName = 'Sangria Tempest';
```

The view already normalizes both relationship directions. There is no need to build separate source/target branches and `UNION` them.

Observation history for an object:

```sql
SELECT
    ObjectId,
    StixType,
    ObservationRecords,
    ObservationCount,
    FirstObserved,
    LastObserved
FROM ThreatIntelObservationSummaryEx
WHERE ObjectId = ?;
```

Common observable/value counts:

```sql
SELECT
    ObservableKey,
    ObservableValue,
    ObjectCount,
    ObservationRecords,
    ObservationCount,
    FirstObserved,
    LastObserved
FROM ThreatIntelObservableStatsEx
WHERE ObservableValue = '192.0.2.1';
```

`ObservationRecords` counts linked `observed-data` SDOs. `ObservationCount` sums their `number_observed` values.

### Wide `W` views

Use the `W` views for interactive search and hunting when repeatedly extracting fields from `Data` would add noise.

```sql
SELECT
    NetworkIP,
    DomainName,
    FileHashType,
    FileHashValue,
    ThreatActorNames,
    Confidence,
    Pattern
FROM ThreatIntelIndicatorsW
WHERE NetworkIP = '192.0.2.1';
```

The equivalent actor correlation in raw Sentinel-style queries requires relationship extraction, source/target joins, and a union. `ThreatIntelIndicatorsW` precomputes the common actor linkage.

For general STIX objects:

```sql
SELECT
    StixType,
    Name,
    Value,
    RelationshipType,
    SourceName,
    TargetName,
    Pid,
    CommandLine,
    SrcPort,
    DstPort
FROM ThreatIntelObjectsW
WHERE StixType IN ('relationship', 'process', 'network-traffic');
```

The `W` views preserve one output row per base-view row. They add search columns but do not explode arrays or relationships.

## Pattern-derived wide columns

`ThreatIntelIndicatorsW` extracts common equality-pattern values for IPv4, IPv6, domain, email, URL, network source/destination IP, file hashes, and X.509 fields. These columns are convenience projections, not a replacement STIX pattern engine.

Complex patterns using boolean combinations, `IN`, comparison operators, qualifiers, or unsupported object paths must still be evaluated from the original `Pattern` value. The raw STIX `Data` and `Pattern` remain authoritative.

## Read-only contract

Firepit accepts one `SELECT` statement per query. The public object does not expose a DuckDB connection, cursor, DDL, or DML operation. External access and direct access to Firepit's internal schemas/catalog surfaces are blocked by the query wrapper.

```python
rows = store.query(
    "SELECT Id, Name FROM ThreatIntelIndicatorsW WHERE Confidence >= ?",
    (70,),
)
```

Convenience methods `indicators()` and `objects()` continue to target the two base views.

## Close

```python
store.close()
```

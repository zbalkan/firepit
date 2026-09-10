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
SELECT Id, Confidence, ObservableKey, ObservableValue, Pattern
FROM ThreatIntelIndicators
WHERE Confidence >= 70;
```

The base schema contracts are `ThreatIntelIndicators` and `ThreatIntelObjects`. For a STIX Indicator with exactly one unqualified equality comparison, `ObservableKey` and `ObservableValue` are populated from OASIS `stix2-patterns` inspection. Otherwise they are `NULL`, and `Pattern` remains the authoritative expression.

### Extended `Ex` views

Use `ThreatIntel<Semantic>Ex` when the query would otherwise require repeated relationship traversal, observation expansion, or aggregation.

```sql
SELECT ThreatActorName, RelationshipType, RelatedStixType,
       RelatedName, RelatedValue, RelatedPattern
FROM ThreatIntelActorRelationsEx
WHERE ThreatActorName = 'Sangria Tempest';
```

The view normalizes both relationship directions; separate source/target branches and a `UNION` are unnecessary.

Observation history:

```sql
SELECT ObjectId, StixType, ObservationRecords, ObservationCount,
       FirstObserved, LastObserved
FROM ThreatIntelObservationSummaryEx
WHERE ObjectId = ?;
```

Observable statistics:

```sql
SELECT ObservableKey, ObservableValue, ObjectCount,
       ObservationRecords, ObservationCount, FirstObserved, LastObserved
FROM ThreatIntelObservableStatsEx
WHERE ObservableValue = '192.0.2.1';
```

`ObservationRecords` counts linked `observed-data` SDOs. `ObservationCount` sums their `number_observed` values.

### Wide `W` views

Use the W views for interactive hunting when repeated projection from `Data` or relationship correlation would add noise.

```sql
SELECT NetworkIP, DomainName, FileHashType, FileHashValue,
       ThreatActorNames, Confidence, Pattern
FROM ThreatIntelIndicatorsW
WHERE NetworkIP = '192.0.2.1';
```

For general STIX objects:

```sql
SELECT StixType, Name, Value, RelationshipType,
       SourceName, TargetName, Pid, CommandLine, SrcPort, DstPort
FROM ThreatIntelObjectsW
WHERE StixType IN ('relationship', 'process', 'network-traffic');
```

W views preserve one output row per base-view row. They add nullable search columns but do not explode arrays or relationships.

## Indicator observables

Firepit does not use regular expressions as a partial STIX-pattern parser. During ingestion, the OASIS STIX 2.1 pattern parser inspects the pattern. Firepit exposes a convenience observable only when the pattern contains one unqualified equality comparison, for example:

```text
[ipv4-addr:value = '192.0.2.1']
```

which yields:

```text
ObservableKey   = ipv4-addr:value
ObservableValue = 192.0.2.1
```

Compound expressions, qualifiers, non-equality operators, or patterns which cannot be represented by one key/value pair leave the convenience fields `NULL`. The original `Pattern` and `Data` are retained unchanged.

## Read-only contract

Firepit accepts one `SELECT` statement per query. The public object does not expose a DuckDB connection, cursor, DDL, or DML operation. External access and direct access to Firepit's internal schemas/catalog surfaces are blocked by the query wrapper.

```python
rows = store.query(
    "SELECT Id, Name FROM ThreatIntelIndicatorsW WHERE Confidence >= ?",
    (70,),
)
```

Convenience methods `indicators()` and `objects()` target the two base views.

## Acquisition runs

The private writer identifies each acquisition execution by `run_id`. This is provenance for one execution, not the identity of a reusable query. The original STIX pattern and native query can be recorded as run metadata when the orchestration layer has them.

## Close

```python
store.close()
```

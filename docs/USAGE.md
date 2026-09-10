# Usage

Firepit exposes a query-only interface over two public threat-intelligence views. The underlying DuckDB database and physical Firepit tables are implementation details.

## Open a session

```python
from firepit import get_storage

store = get_storage("intel.duckdb", "hunt")
```

The session name selects the public schema. That schema must contain exactly:

- `ThreatIntelIndicators`
- `ThreatIntelObjects`

and no base tables. If the public schema has been altered out of band, Firepit refuses to open it.

## Query indicators

```python
rows = store.query(
    """
    SELECT Id, Confidence, Pattern, ValidFrom, ValidUntil
    FROM ThreatIntelIndicators
    WHERE Confidence >= ?
    ORDER BY Confidence DESC
    """,
    (70,),
)
```

Rows are returned as dictionaries keyed by the selected column names.

For common cases:

```python
rows = store.indicators("Confidence >= ?", (70,), limit=100)
```

## Query other STIX objects

```python
actors = store.objects("StixType = ?", ("threat-actor",))

relationship = store.query_one(
    """
    SELECT Id, Data
    FROM ThreatIntelObjects
    WHERE StixType = 'relationship'
    LIMIT 1
    """
)
```

The full canonical STIX object is available in `Data` as JSON, so normal DuckDB JSON expressions can be used inside a permitted `SELECT`:

```python
rows = store.query(
    """
    SELECT
        Id,
        json_extract_string(Data, '$.name') AS Name
    FROM ThreatIntelObjects
    WHERE StixType = 'threat-actor'
    """
)
```

## Scalar queries

```python
count = store.query_value(
    "SELECT count(*) FROM ThreatIntelIndicators"
)
```

`query_one()` returns the first row as a dictionary or `None`. `query_value()` returns the first column of the first row or `None`.

## Query restrictions

Firepit accepts exactly one `SELECT` statement. The public API rejects:

- `INSERT`, `UPDATE`, `DELETE`, `MERGE`, and other DML;
- `CREATE`, `DROP`, `ALTER`, and other DDL;
- `PRAGMA` and `ATTACH`;
- multiple SQL statements;
- direct references to `__firepit_*` schemas;
- DuckDB, `information_schema`, PostgreSQL-compatibility, and SQLite-compatibility catalog relations;
- external file access such as `read_csv_auto()`.

The DuckDB connection is not exposed by the public object.

## Acquisition

Acquisition is intentionally separate from the public query API. Firepit's private writer is used by acquisition/orchestration code, not by analyst-facing callers. Standard STIX 2.1 objects are validated with OASIS `cti-python-stix2`; custom object envelopes are preserved without pretending Firepit has an authoritative custom schema.

Users of the query interface do not need the ingestion extra.

## Close

```python
store.close()
```

or use a context manager:

```python
with get_storage("intel.duckdb", "hunt") as store:
    count = store.query_value("SELECT count(*) FROM ThreatIntelObjects")
```

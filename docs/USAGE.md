# Usage

Firepit is a thin STIX 2.1 ingestion and storage component. Acquisition stays above Firepit; analysis uses DuckDB directly.

## Open a session

```python
from firepit import get_storage

store = get_storage("observations.duckdb", "hunt")
```

A session is a DuckDB schema inside the database file.

## Ingest STIX 2.1

```python
store.cache(
    "query-1",
    bundle_json,
    source="source-name",
    stix_pattern="[process:pid = 1234]",
    native_query="vendor native query",
)
```

`bundle_json` may be a Python dictionary, raw JSON text, a file-like object, or a local file path. Firepit performs no HTTP acquisition.

Ingestion is transactional. Known STIX fields are cast to the types declared by `stixschema.py`; incompatible known values fail the run. `raw_query` records `COMPLETED` or `FAILED` state, and successful raw bundles are retained in `raw_bundle`.

## Query with DuckDB

Use the underlying DuckDB connection directly:

```python
rows = store.connection.execute("""
    SELECT
        id,
        pid,
        command_line,
        extensions."windows-process-ext".owner_sid
    FROM process
    WHERE pid IS NOT NULL
""").fetchall()
```

There is no Firepit `lookup()`, `filter()`, `extract()`, query AST, or local STIX-pattern compiler in version 3.

## Observation semantics

STIX observation records and represented event counts are different quantities. Firepit exposes them explicitly:

```sql
SELECT
    object_ref,
    observation_records,
    observation_count,
    first_observed,
    last_observed
FROM observation_summary;
```

`observation_records` counts linked `observed-data` objects. `observation_count` sums their `number_observed` values.

## Reference enrichment

References remain IDs or native lists in base tables. Firepit does not auto-dereference `SELECT *`.

Use explicit views when useful:

```sql
SELECT pid, parent_pid, user_name, image_name
FROM stixv_process;

SELECT src_ipv4, src_ipv6, dst_ipv4, dst_ipv6
FROM stixv_network_traffic;
```

## Close

```python
store.close()
```

For interactive exploration, open the same database in DuckDB UI:

```bash
duckdb observations.duckdb -ui
```

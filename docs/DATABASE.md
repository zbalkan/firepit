# Database model

Firepit stores STIX 2.1 using DuckDB-native types and retains raw provenance.

## Modeling rules

```text
Known scalar field       -> scalar column
Known nested object      -> STRUCT
Known repeated scalar    -> LIST<T>
Known repeated object    -> LIST<STRUCT<...>>
Homogeneous dictionary   -> MAP
Known heterogeneous field-> JSON
Unknown/custom content   -> _raw JSON
Original bundle          -> raw_bundle JSON
```

JSON is the exception for analytical data, not the default representation.

## Typed STIX tables

Each encountered STIX object type receives one typed table. Known schema comes from `firepit/stixschema.py`; ingestion does not infer types or execute `ALTER TABLE ADD COLUMN` for new custom fields.

Example:

```sql
SELECT
    id,
    pid,
    command_line,
    environment_variables,
    extensions."windows-process-ext".owner_sid
FROM process;
```

Unknown or future properties remain in `_raw`:

```sql
SELECT json_extract(_raw, '$.x_vendor_context')
FROM process;
```

## Strict projection

DuckDB performs JSON iteration, extraction, and casting. Known nested and scalar values are cast to the declared type. A conversion failure aborts the ingestion transaction and records the acquisition run as failed.

## References

Scalar references such as `parent_ref`, `src_ref`, and `dst_ref` remain IDs. Repeated references such as `object_refs`, `contains_refs`, and `opened_connection_refs` remain `VARCHAR[]`.

`observation_ref` expands only observation membership:

```sql
SELECT observed_data_id, object_ref, number_observed
FROM observation_ref;
```

`observation_summary` makes the two observation quantities explicit:

```sql
SELECT
    object_ref,
    observation_records,
    observation_count,
    first_observed,
    last_observed
FROM observation_summary;
```

Common process and network enrichment is exposed through explicit `stixv_process` and `stixv_network_traffic` views rather than recursive auto-dereference.

## Provenance

Provenance is independent of stable SCO identity:

- `raw_query` stores acquisition-run metadata and status;
- `raw_bundle` stores successful original STIX bundles;
- `raw_run_object` associates a run with object IDs.

The same SCO can therefore appear in multiple acquisition runs without duplicating its typed row or losing run provenance.

## Idempotence

Object IDs are the typed-table conflict key. Re-ingesting the same object ID does not add `number_observed` again. Multiple distinct `observed-data` objects that reference the same SCO remain distinct and are aggregated only in analytical views.

## Schema version

Firepit 3 uses native model version 6. Older/pre-native database sessions are rejected explicitly; there is no implicit conversion from the legacy SQLite/PostgreSQL-era model.

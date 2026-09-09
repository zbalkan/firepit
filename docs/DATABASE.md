# Database model

Firepit's target database model follows STIX semantics while using DuckDB-native types.

## Modeling rules

```text
Known scalar field       -> scalar column
Known nested object      -> STRUCT
Known repeated scalar    -> LIST<T>
Known repeated object    -> LIST<STRUCT<...>>
Homogeneous dictionary   -> MAP
Unknown/custom content   -> JSON fallback
Raw source preservation  -> JSON provenance
```

JSON is an exception, not the default analytical representation.

## Example

A process can expose standard nested fields without flattening them into dotted SQL column names:

```sql
SELECT
    id,
    pid,
    command_line,
    environment_variables,
    extensions."windows-process-ext".owner_sid
FROM process;
```

`opened_connection_refs` and other repeated STIX references remain native lists instead of being decomposed into a mandatory physical relationship table.

## Schema evolution

A new or custom STIX field does not immediately change a table with `ALTER TABLE`. Unknown content remains available in the raw object. A field should be promoted into the native schema only when its STIX shape is known and its analytical value justifies a first-class typed representation.

## Reference handling

Scalar references such as `parent_ref`, `src_ref`, and `dst_ref` remain IDs. List references such as `object_refs`, `contains_refs`, and `opened_connection_refs` remain lists.

Relational expansion is derived when required:

```sql
SELECT id, unnest(object_refs) AS object_ref
FROM "observed-data";
```

Common enriched relationships should be exposed through explicit, inspectable views instead of implicit `SELECT *` auto-dereferencing.

## Provenance

Stable SCO identity and acquisition provenance are separate concerns. The target model records acquisition runs/bundles independently from SCO rows so the same SCO can participate in multiple runs without overwriting provenance.

See [MODERNIZATION_ROADMAP.md](../MODERNIZATION_ROADMAP.md) for the staged transition from the legacy metadata and compatibility tables.

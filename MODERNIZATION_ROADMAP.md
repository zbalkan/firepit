# Firepit DuckDB Modernization and Code-Reduction Roadmap

## Goal

Turn Firepit from a multi-backend, Kestrel-oriented STIX relationalization layer into a small DuckDB-native STIX storage component.

The target boundary is intentionally narrow:

```text
remote source
    |
    v
Python acquisition/orchestration
    - credentials
    - STIX-Shifter
    - native query execution
    - polling / paging / retry
    - STIX 2.1 result production
    |
    | raw STIX 2.1 JSON
    v
DuckDB / Firepit
    - JSON ingestion
    - typed STIX storage
    - LIST / MAP / STRUCT
    - reference views
    - SQL / PRQL
    - provenance
    |
    v
DuckDB UI / other DuckDB clients
```

Firepit should not remain a compatibility runtime for Kestrel 1, a second STIX-Shifter translation path, a dataframe transformation layer, or a generic SQL abstraction library.

Kestrel 2 itself has moved toward a redesigned runtime with lazy/JIT execution, data-lakehouse optimization, deeply nested queries, and representations beyond STIX. Preserving the Kestrel 1 storage contract therefore carries substantial complexity without aligning Firepit with the current direction of Kestrel. See <https://github.com/opencybersecurityalliance/kestrel-lang>.

## Current modernization baseline

Already completed on `claude/firepit-duckdb-modernize-9tj618`:

- DuckDB is the only database backend.
- Backend dialect branching has been removed.
- Windows and POSIX DuckDB paths are handled directly.
- A DuckDB-native STIX schema exists for core STIX 2.1 objects.
- Standard nested STIX structures use DuckDB `LIST`, `MAP`, and `STRUCT` types.
- `NativeDuckDBStorage` exists as an opt-in implementation.
- Complete objects remain available in `_raw JSON` for provenance and unknown/custom properties.
- Packaging is moving to `pyproject.toml` with CPython 3.11-3.14 as the explicit support window.

The major remaining problem is that the public API and several internal modules still model the old Firepit/Kestrel architecture.

## Removal criteria

A component should be removed when all three statements are true:

1. DuckDB or the Python acquisition layer already provides the capability more directly.
2. The component exists primarily to preserve an old backend, flattened schema, Kestrel contract, or Firepit-specific query abstraction.
3. Removing it does not destroy STIX semantics, acquisition provenance, or a capability that cannot be expressed cleanly in DuckDB.

The objective is not code golf. Code is retained when it protects an actual semantic boundary.

## High-confidence deletion inventory

| Component | Why it exists | Replacement | Dependency removed |
| --- | --- | --- | --- |
| `firepit/aio/ingest.py` | Experimental dataframe-based STIX-Shifter fast translation | Python acquisition layer produces STIX 2.1 JSON | `pandas` |
| `firepit/aio/asyncstorage.py` | Generic async storage abstraction and dataframe writer | Synchronous DuckDB API; async orchestration belongs above storage | `pandas` |
| `firepit/aio/asyncwrapper.py` | Wraps synchronous storage methods in `async def` | Direct synchronous storage calls | `pandas`, async compatibility code |
| `firepit/splint.py` | Standalone STIX/log manipulation utility | Separate tool/repository if still useful | part of `typer`, `python-dateutil` usage |
| `firepit/woodchipper.py` | Security-dataset/Zeek/log-to-STIX conversion used by `splint` | Acquisition/ETL tooling outside Firepit | `python-dateutil` and substantial conversion code |
| HTTP branch in `raft.get_objects()` | Firepit fetches remote JSON itself | Python acquisition layer | `requests` |
| `firepit/deref.py` | Generic auto-dereference over flattened reference columns | explicit `stixv.*` views and native refs | `anytree` |
| `firepit/splitter.py` | Dynamic schema inference and `ALTER TABLE` for row-oriented backends | explicit native STIX schemas plus `_raw` | dynamic DDL machinery |
| `__columns` | Maps flattened STIX paths to shortened dynamic columns | native schema/catalog | shortening and schema-learning metadata |
| `__reflist` | Emulates list references in relational backends | native `VARCHAR[]` references + `unnest()` | compatibility edge table |
| `__contains` | Emulates `observed-data.object_refs` | native `object_refs VARCHAR[]`, optionally an edge view | compatibility edge table |
| `__symtable` + appdata | Named-variable metadata for the old external runtime contract | DuckDB catalog plus explicit provenance tables | Kestrel-style view state |
| `firepit/query.py` | Database-independent relational AST | DuckDB SQL and optional PRQL | custom query rendering layer |
| `firepit/stix20.py` + `paramstix.lark` | Local STIX-pattern-to-SQL compiler | STIX-Shifter for remote acquisition; SQL/PRQL locally | `lark` |
| legacy `SqlStorage` abstraction | Shared SQLite/PostgreSQL behavior | one DuckDB-native storage implementation | generic backend abstraction |
| `firepit/cli.py` | Test/experimentation CLI over Firepit API | DuckDB UI/CLI and SQL/PRQL | `tabulate`, remaining `typer` usage |

Some removals are blocked by the native-storage cutover and must not be done out of order.

---

## Phase 1 - Remove parallel/experimental execution paths

### 1.1 Delete the AIO dataframe stack

Delete:

- `firepit/aio/ingest.py`
- `firepit/aio/asyncstorage.py`
- `firepit/aio/asyncwrapper.py`
- `firepit/aio/__init__.py`
- `tests/test_asyncingest.py`
- `tests/test_asyncstorage.py`

Rationale:

`aio/ingest.py` is explicitly an experimental "fast translation" path using STIX-Shifter mappings and pandas. It performs work that belongs in the acquisition layer and duplicates the chosen STIX-Shifter -> STIX 2.1 JSON boundary.

`SyncWrapper` does not make DuckDB asynchronous. It exposes synchronous storage operations through coroutine-shaped methods. Keeping this layer creates two APIs and forces pandas into testing for no storage-engine benefit.

After deletion:

- remove the `aio` optional dependency group;
- remove `pandas` from test dependencies;
- remove `pytest-asyncio` if no other async tests remain.

Acceptance criteria:

- no import under `firepit` requires pandas;
- no STIX-Shifter native-result mapping code exists in Firepit;
- all remaining ingestion accepts STIX rather than vendor-native result frames.

### 1.2 Remove Firepit-side HTTP acquisition

Remove the URL-fetch branch from `raft.get_objects()` and stop importing `requests`.

Firepit should receive local data, file-like data, or preferably raw JSON directly from the Python orchestration layer. Authentication, remote status, paging, timeout, retry, and transport errors must stay above the storage boundary.

Acceptance criteria:

- `requests` disappears from `pyproject.toml`;
- storage tests use in-memory STIX or local fixtures only;
- no network access is performed by Firepit ingestion.

### 1.3 Remove `splint` and `woodchipper`

These utilities are useful in isolation but are not storage-engine responsibilities. `woodchipper.py` contains log-format conversion, reference guessing, registry normalization, Zeek/security-dataset handling, and STIX generation. `splint.py` exposes that functionality as a second CLI.

Delete or move to a separate repository/package:

- `firepit/splint.py`
- `firepit/woodchipper.py`
- splint-specific tests and fixtures
- the `splint` console entry point

Then check whether `firepit/timestamp.py` still has consumers. If not, delete it and remove `python-dateutil`.

Acceptance criteria:

- Firepit does not convert arbitrary log formats into STIX;
- only STIX ingestion remains;
- `python-dateutil` is absent unless a remaining storage function genuinely needs it.

---

## Phase 2 - Make native STIX storage authoritative

The native model must become the default before deleting the legacy schema pipeline.

### 2.1 Switch `get_storage()` to `NativeDuckDBStorage`

Requirements before cutover:

- validate core STIX 2.1 object schemas against representative STIX-Shifter output;
- verify `TIMESTAMPTZ`, unsigned integer, `LIST`, `MAP`, and `STRUCT` conversions on Python 3.11-3.14;
- verify extension projection and `_raw` retention;
- define database version/migration behavior explicitly.

Do not silently reinterpret existing compatibility databases. A breaking native schema should either require a new database/session or have an explicit one-way migration.

### 2.2 Stop flattening STIX on ingest

Once native storage is the default, delete the old path that:

- recursively flattens dictionaries into dotted column names;
- removes `*_refs` and writes `__reflist` rows;
- removes `object_refs` and writes `__contains` rows;
- shortens extension column names;
- dynamically infers SQL types;
- dynamically alters tables when unseen properties arrive.

Unknown/custom fields remain in `_raw JSON`. Standard fields are promoted only by the explicit schema contract.

### 2.3 Delete `splitter.py`

Delete:

- `SqlWriter`
- `SplitWriter`
- `RecordList`
- `JsonWriter` unless an independently justified caller exists
- `shorten_extension_name`

Acceptance criteria:

- ingesting a new custom STIX property never executes `ALTER TABLE ADD COLUMN`;
- standard nested data remains native nested data;
- unknown data is recoverable from `_raw`;
- no normal ingest path calls `infer_type()`.

Dependency impact:

- begin removing broad `ujson` use where it only supported the legacy writer.

---

## Phase 3 - Remove Kestrel-era state and variable semantics

This is the main Kestrel-specific cut.

### 3.1 Remove `__symtable`

`__symtable` duplicates information DuckDB already has in its catalog and adds Firepit-specific state for named variables/views.

Delete:

- `_new_name()`
- `_drop_name()`
- `table_type()` logic that depends on `__symtable`
- `get_view_data()`
- `set_appdata()`
- `get_appdata()`
- CLI commands `viewdata`, `set-appdata`, and `get-appdata`

If a semantic type needs to be associated with a durable analytic view, use a small explicit metadata table with a narrow documented purpose rather than a generic application-data field.

### 3.2 Remove variable-mutation APIs

Review and normally delete:

- `assign()`
- `assign_query()`
- `reassign()`
- `rename_view()`
- `remove_view()` wrappers
- view-swapping/rewrite code used to preserve mutable Kestrel variables

Equivalent analyst operations are ordinary DuckDB statements:

```sql
CREATE VIEW ... AS SELECT ...;
CREATE OR REPLACE VIEW ... AS SELECT ...;
CREATE TABLE ... AS SELECT ...;
DROP VIEW ...;
```

PRQL can be an optional front-end for relational pipelines; it should not require a second internal query object model.

Acceptance criteria:

- no Firepit API models a mutable Kestrel hunt variable;
- named analytical state is a normal DuckDB table/view;
- `__symtable` no longer exists in new databases.

### 3.3 Replace `__queries` with real provenance

`__queries(sco_id, query_id)` mixes source-query provenance with deduplicated SCO identity. The same SCO may appear in multiple observed-data records and acquisition runs.

Replace it with explicit acquisition provenance, for example:

```text
raw.query
    query_id
    source
    connector
    stix_pattern
    native_query
    started_at
    completed_at
    status
    result_count
    error

raw.bundle
    query_id
    received_at
    bundle JSON
```

If object/run membership is required, use a separate relation such as `raw.run_object(query_id, object_id)`.

Acceptance criteria:

- provenance is independent of stable SCO identity;
- one SCO can be associated with multiple runs without modifying the SCO row;
- no filtering API depends on `__queries`.

---

## Phase 4 - Replace compatibility relationships and auto-dereference

### 4.1 Remove `__reflist`

Keep STIX list references as native lists:

```sql
opened_connection_refs VARCHAR[]
object_refs            VARCHAR[]
contains_refs          VARCHAR[]
```

Use `unnest()` when a relational expansion is needed.

If repeated graph traversal becomes important, expose a normalized edge **view** or table with explicit semantics:

```text
stix.object_ref
    source_id
    source_type
    property
    ordinal
    target_id
    target_type
```

Do not make the edge representation the canonical storage format for list properties.

### 4.2 Remove `__contains`

`observed-data.object_refs` is already a list in STIX 2.1. Preserve it as such. Derive containment relationships when needed.

This also removes the old distinction where `value_counts()` counted observed-data links while `number_observed()` summed `number_observed`. Replace ambiguous APIs with clearly named analytical queries/macros such as:

- `observation_records`
- `observation_count`

### 4.3 Delete `deref.py`

Generic recursive auto-dereference creates unpredictable joins and was necessary mainly because the old relational representation split every reference into separate tables/columns.

Replace it with explicit enriched views for common entities, for example:

```sql
CREATE VIEW stixv.network_traffic AS
SELECT
    nt.*,
    src4.value AS src_ipv4,
    src6.value AS src_ipv6,
    dst4.value AS dst_ipv4,
    dst6.value AS dst_ipv6
FROM stix.network_traffic nt
LEFT JOIN stix.ipv4_addr src4 ON nt.src_ref = src4.id
LEFT JOIN stix.ipv6_addr src6 ON nt.src_ref = src6.id
LEFT JOIN stix.ipv4_addr dst4 ON nt.dst_ref = dst4.id
LEFT JOIN stix.ipv6_addr dst6 ON nt.dst_ref = dst6.id;
```

Delete `anytree` after `deref.py` is gone.

Acceptance criteria:

- `lookup('*')` does not trigger graph traversal;
- common enriched views are explicit and inspectable;
- arbitrary references remain IDs/lists until the query explicitly follows them.

---

## Phase 5 - Remove the database-independent query language

### 5.1 Delete `query.py`

The `Query`, `Filter`, `Projection`, `Join`, `Aggregation`, `Group`, `Order`, `Limit`, `Offset`, `BinnedColumn`, and related renderer classes were useful when Firepit targeted multiple SQL dialects.

With DuckDB as the only backend they are an extra relational AST between the caller and DuckDB.

Replace with:

- DuckDB SQL for canonical operations;
- PRQL as an optional analyst-facing pipeline language;
- small SQL helpers/macros only where repeated semantics warrant them.

### 5.2 Remove heuristic aggregation behavior

Delete the `props.py` rules that automatically choose `AVG`, `COUNT(DISTINCT)`, `MIN`, or `MAX` based on column names/types.

Examples such as "all integer columns -> AVG" are not semantic guarantees and can produce meaningless results for categorical numeric fields.

Use explicit analytical views/macros instead.

### 5.3 Collapse remaining property metadata into `stixschema.py`

Retain only information that is part of the STIX model or genuinely needed to compile reference paths. Move that information into the native schema module.

Then delete obsolete parts of `props.py`, including:

- `KNOWN_PROPS` duplicates covered by the native schema;
- auto-aggregation helpers;
- legacy primary-property heuristics;
- path helpers that only support flattened columns.

Acceptance criteria:

- no public operation requires construction of a Firepit query AST;
- DuckDB receives SQL/PRQL directly;
- schema semantics have a single source of truth.

---

## Phase 6 - Retire local STIX-pattern SQL compilation

This phase should happen after Kestrel-style `extract()` / `filter()` APIs are gone.

### 6.1 Delete the custom Lark parser

Delete:

- `firepit/stix20.py`
- `firepit/paramstix.lark`
- STIX-pattern SQL rendering tests that only exercise the Firepit compiler

Remove `lark` from dependencies.

Rationale:

There are two distinct query contexts:

1. Remote acquisition: the Python orchestration layer gives the STIX pattern to STIX-Shifter, which translates it for the source.
2. Local analysis: the analyst uses DuckDB SQL or PRQL.

A third translation path from STIX pattern to Firepit SQL is unnecessary once Firepit is no longer serving Kestrel's local variable/filter contract.

If local STIX-pattern querying remains a hard requirement, implement it as an optional adapter with a narrow STIX-path-to-DuckDB-expression compiler. Do not preserve the current general query AST merely for that feature.

Acceptance criteria:

- `lark` is absent from core dependencies;
- no STIX pattern parser runs in the storage engine;
- remote STIX patterns are handled only by STIX-Shifter.

---

## Phase 7 - Reduce ingestion to STIX 2.1 JSON

### 7.1 Drop STIX 2.0 compatibility

The acquisition boundary should request STIX 2.1 from STIX-Shifter. Once representative connectors are validated, delete support for embedded STIX 2.0 `observed-data.objects`.

Delete or simplify:

- `raft.upgrade_2021()`
- numeric-reference rewriting
- legacy 2.0 flattening/ranking code
- STIX 2.0-specific fixtures/tests

This is a breaking change and should coincide with a major version boundary.

### 7.2 Let DuckDB parse JSON

Longer term, remove most or all of `raft.py` and pass raw JSON directly into DuckDB.

Avoid this pipeline:

```text
JSON -> Python dictionaries -> Python normalization -> SQL rows
```

Prefer:

```text
STIX 2.1 JSON -> DuckDB JSON -> typed relations/views
```

At that point remove:

- `ijson`;
- remaining parser-side `ujson` use that has no other purpose;
- Python flattening helpers.

Acceptance criteria:

- the handoff from acquisition to storage is raw STIX 2.1 JSON;
- Python does not relationalize STIX;
- DuckDB performs JSON projection/casting.

---

## Phase 8 - Remove the Firepit CLI

`firepit/cli.py` describes itself as a testing/experimentation CLI. Most commands mirror methods that will have been removed in the earlier phases.

After DuckDB UI/CLI is the supported interactive surface, delete:

- `firepit/cli.py`;
- the `firepit` console entry point;
- CLI-specific tests;
- `tabulate`;
- `typer` once `splint` is also gone.

If a bootstrap command is still valuable, keep only a tiny command for database initialization or one-shot STIX ingestion. It should call the same narrow storage API and must not recreate the old Firepit command surface.

Acceptance criteria:

- interactive query/documentation examples use DuckDB SQL/PRQL;
- there is no duplicate Firepit shell for catalog/query operations.

---

## Phase 9 - Collapse the storage classes

Once the native writer is default and legacy query/view semantics are gone, merge the useful DuckDB pieces into one implementation.

Delete the inheritance split between generic `SqlStorage` and DuckDB storage. Keep only abstractions that separate actual concerns, not historical backends.

Likely survivors:

```text
firepit/
    __init__.py
    storage.py          # DuckDB connection, provenance, ingest entry point
    stixschema.py       # STIX -> DuckDB native type contract
    views.py            # explicit enriched views/macros, if Python-managed
    exceptions.py
    validate.py         # only if public identifier/path validation remains
```

Possible even smaller endpoint if views are installed as SQL resources:

```text
firepit/
    __init__.py
    storage.py
    stixschema.py
    sql/
        schema.sql
        views.sql
```

Do not merge classes merely to reduce file count before the semantics are simplified. The correct time is after the compatibility APIs are gone.

---

## Dependency burn-down

Current/near-current dependency | Removal trigger
--- | ---
`pandas` | delete `aio/*`
`pytest-asyncio` | delete async compatibility tests
`requests` | delete HTTP acquisition from `raft`
`python-dateutil` | delete `splint`/`woodchipper`/unused timestamp helpers
`anytree` | delete generic auto-dereference
`lark` | delete local STIX-pattern compiler
`tabulate` | delete Firepit CLI
`typer` | delete both CLIs
`ijson` | move JSON parsing into DuckDB
`ujson` | delete legacy Python relationalization/serialization path
`duckdb` | retained

The desired core runtime dependency set is eventually:

```text
duckdb
```

STIX-Shifter belongs to the acquisition application/package, not the Firepit storage package.

## Recommended commit sequence

Keep each deletion independently reviewable:

1. `packaging: migrate to pyproject.toml and Python 3.11-3.14`
2. `aio: remove experimental dataframe ingestion and sync async-wrapper`
3. `splint: move standalone STIX/log conversion out of firepit`
4. `ingest: remove HTTP acquisition from storage`
5. `native: make DuckDB-native STIX storage the default`
6. `ingest: remove SplitWriter and dynamic schema mutation`
7. `kestrel: remove symtable appdata and mutable variable APIs`
8. `provenance: replace __queries with acquisition-run metadata`
9. `refs: replace __contains/__reflist with native list relationships`
10. `deref: replace auto-deref with explicit enriched views`
11. `query: remove generic relational AST and auto-aggregation`
12. `pattern: remove local STIX-pattern compiler`
13. `stix: require STIX 2.1 at the storage boundary`
14. `ingest: move JSON projection into DuckDB`
15. `cli: remove Firepit experimental CLI`
16. `storage: collapse legacy SqlStorage/DuckDBStorage split`
17. `docs: remove Kestrel/SQLite/PostgreSQL-era documentation and examples`

## Gates before a major deletion

Before deleting a compatibility layer, require tests for the behavior that replaces it rather than tests for the implementation being removed.

Minimum gates:

- representative STIX-Shifter STIX 2.1 bundles from several connectors;
- mixed IPv4/IPv6 reference resolution;
- repeated SCO identity across multiple observed-data records and acquisition runs;
- `number_observed > 1` semantics;
- list references and nested standard extensions;
- custom extension/property retention in `_raw`;
- schema evolution without dynamic `ALTER TABLE`;
- Python 3.11, 3.12, 3.13, and 3.14 CI;
- reopen/persistence tests for the DuckDB file;
- explicit migration/rejection behavior for pre-native databases.

## End state

Firepit should no longer be "a relational emulation of STIX for Kestrel over whichever SQL backend happens to be configured."

It should be:

> a small DuckDB-native STIX 2.1 storage layer that accepts raw STIX JSON, preserves provenance and STIX semantics, exposes predictable typed relations/views, and leaves acquisition to STIX-Shifter/Python and analysis to DuckDB SQL/PRQL.

That endpoint removes the historical reasons for most of the current codebase rather than carrying them forward behind a DuckDB adapter.

# Firepit DuckDB Modernization Roadmap — Completed

## Status

The modernization roadmap is complete on `claude/firepit-duckdb-modernize-9tj618`.

Firepit has moved from a multi-backend, Kestrel-oriented relationalization layer to a small DuckDB-native STIX 2.1 storage component.

## Final boundary

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
Firepit / DuckDB
    - strict typed projection
    - raw acquisition provenance
    - scalar / LIST / MAP / STRUCT
    - explicit analytical views
    |
    v
DuckDB SQL / UI / clients
```

## Completed phases

### Phase 1 — Remove parallel execution paths

Complete.

Removed the AIO/Pandas ingestion stack, Firepit-side HTTP acquisition, `splint.py`, `woodchipper.py`, and their supporting dependencies. Acquisition and STIX-Shifter orchestration now live above Firepit.

### Phase 2 — Make native STIX storage authoritative

Complete.

DuckDB-native storage is the only implementation. STIX is no longer flattened into dotted scalar columns. `splitter.py`, dynamic type inference, and dynamic schema growth are gone. Known nested data uses native DuckDB types; unknown/custom data remains in `_raw`.

### Phase 3 — Remove Kestrel-era state

Complete.

Removed `__symtable`, appdata, mutable variable/view assignment APIs, and `__queries`. Provenance now uses `raw_query`, `raw_bundle`, and `raw_run_object`.

### Phase 4 — Replace relationship emulation and auto-dereference

Complete.

Removed `__reflist`, `__contains`, `deref.py`, `anytree`, and implicit recursive dereferencing. Native `*_refs` and `object_refs` remain lists. `observation_ref`, `observation_summary`, `stixv_process`, and `stixv_network_traffic` provide explicit relational views.

`observation_summary` distinguishes:

- `observation_records`: number of linked `observed-data` objects;
- `observation_count`: sum of `number_observed`.

### Phase 5 — Remove the generic query language

Complete.

Removed `query.py`, the database-independent relational AST, heuristic aggregation, and legacy query metadata. DuckDB SQL is the analytical query language. `stixschema.py` is the schema source of truth.

### Phase 6 — Retire local STIX-pattern compilation

Complete.

Removed `stix20.py`, `paramstix.lark`, `lark`, and local `extract()`/`filter()` STIX-pattern execution. Remote patterns belong to STIX-Shifter; local analysis belongs to DuckDB SQL.

### Phase 7 — Reduce ingestion to STIX 2.1 JSON

Complete.

STIX 2.0 and embedded `observed-data.objects` are rejected. DuckDB JSON functions perform object iteration and projection. Python flattening, ID synthesis, `raft.py`, `stix21.py`, `ijson`, and `ujson` are gone. Known-field casts are strict, failed ingestion is recorded in `raw_query`, and re-ingesting the same object ID is idempotent.

### Phase 8 — Remove the Firepit CLI

Complete.

The Firepit interactive shell, `typer`, and `tabulate` are gone. DuckDB UI/CLI is the supported interactive surface.

### Phase 9 — Collapse storage classes

Complete.

The historical `SqlStorage`/backend inheritance hierarchy is gone. The surviving package is centered on:

```text
firepit/
    __init__.py
    storage.py
    stixschema.py
    storageurl.py
    views.py
    validate.py
    exceptions.py
```

## Repository cleanup

Complete.

Removed obsolete project scaffolding and migration-era fixtures, including `setup.py`, `setup.cfg`, requirements files, RST/Sphinx documentation, `tox.ini`, the project `Makefile`, `.pylintrc`, old STIX 2.0/conversion fixtures, and unused test helpers. Final compatibility-only storage remnants (`batchsize`/catch-all cache arguments and the unused session-existence helper) were removed as well. `pyproject.toml` is authoritative.

## Dependency burn-down

Final core runtime dependency:

```text
duckdb
```

Removed from the historical/transition stack:

```text
pandas
pytest-asyncio
requests
python-dateutil
anytree
lark
tabulate
typer
ijson
ujson
psycopg2
asyncpg
```

## Acceptance gates

Covered by the current test suite and CI configuration:

- native `STRUCT`, `LIST`, and `MAP` projection;
- strict known-field conversion failures;
- custom property retention in `_raw`;
- standard nested extensions;
- native list references;
- mixed IPv4/IPv6 explicit enrichment;
- repeated SCO identity across acquisition runs;
- multiple observation records and `number_observed > 1`;
- explicit `observation_records` versus `observation_count`;
- idempotent re-ingestion;
- raw bundle provenance;
- persistence/reopen behavior;
- STIX 2.0 rejection;
- pre-native database rejection;
- representative STIX-Shifter 2.1 bundle shapes;
- CPython 3.11, 3.12, 3.13, and 3.14 CI on Linux, macOS, and Windows.

## End state

Firepit is now:

> a small DuckDB-native STIX 2.1 storage layer that accepts raw STIX JSON, preserves acquisition provenance, exposes predictable native relations and explicit views, and leaves acquisition to STIX-Shifter/Python and analysis to DuckDB.

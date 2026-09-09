# History

## 3.0.0

Firepit 3 is a breaking architectural reduction centered on DuckDB and STIX 2.1.

Major changes:

- DuckDB is the sole database backend.
- CPython 3.11-3.14 is supported.
- Packaging is defined in `pyproject.toml`.
- STIX 2.0 embedded-object compatibility was removed.
- Raw STIX 2.1 JSON is parsed and projected by DuckDB.
- Known STIX fields use scalar, `LIST`, `MAP`, and `STRUCT` types.
- Unknown/custom content is preserved in `_raw` and immutable raw-bundle provenance.
- Dynamic schema inference/`ALTER TABLE` ingestion was removed.
- SQLite/PostgreSQL dialect abstractions were removed.
- Kestrel-era `__symtable`, appdata, mutable hunt variables, and `__queries` semantics were removed.
- Provenance now uses `raw_query`, `raw_bundle`, and `raw_run_object`.
- `__contains`, `__reflist`, and recursive auto-dereference were removed.
- The generic query AST, heuristic aggregation, and local STIX-pattern compiler were removed.
- AIO/Pandas ingestion, HTTP acquisition, `splint`, `woodchipper`, and the Firepit CLI were removed.
- Observation record count and `number_observed` sum are exposed explicitly through `observation_summary`.
- Known-field type mismatches fail ingestion instead of silently becoming null.
- Pre-native/older native databases are rejected explicitly.
- Runtime dependencies were reduced to `duckdb`.

The implementation history is recorded in [MODERNIZATION_ROADMAP.md](MODERNIZATION_ROADMAP.md).

## 2.x and earlier

Earlier releases relationalized STIX over SQLite and PostgreSQL and primarily served the Kestrel 1 storage contract. Refer to Git history and published releases for detailed historical changes.

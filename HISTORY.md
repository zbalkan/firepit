# History

## 2.3.35 modernization branch

The `claude/firepit-duckdb-modernize-9tj618` branch starts a breaking modernization of Firepit rather than extending the historical multi-backend design.

Major changes underway:

- DuckDB replaces SQLite and PostgreSQL as the sole storage engine.
- SQL dialect branching is being removed.
- CPython 3.11-3.14 is the supported range.
- Packaging uses `pyproject.toml`.
- A native STIX 2.1 schema maps known data to DuckDB scalar, `LIST`, `MAP`, and `STRUCT` types.
- Unknown and custom fields remain available through raw JSON provenance instead of triggering dynamic `ALTER TABLE` growth.
- Kestrel-era state, generic query abstraction, async/dataframe ingestion, STIX 2.0 compatibility, and utility CLIs are scheduled for staged removal.

The detailed sequence and acceptance criteria are tracked in [MODERNIZATION_ROADMAP.md](MODERNIZATION_ROADMAP.md).

## Earlier releases

Earlier releases provided relationalized STIX storage over SQLite and PostgreSQL and were primarily designed around the Kestrel 1 storage contract. Refer to Git history and published releases for the exact historical changelog.

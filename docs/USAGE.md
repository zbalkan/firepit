# Usage

Firepit is a thin STIX 2.1-to-DuckDB storage component. Acquisition stays outside Firepit and analysis uses DuckDB directly.

## Storage

```python
from firepit import get_storage

store = get_storage("observations.duckdb", "hunt")
store.cache("query-1", "bundle.json")
```

The storage boundary accepts STIX 2.1 bundles. Remote credentials, connector execution, polling, paging, retries, and vendor-native translation belong in the acquisition layer.

## Recommended analytical workflow

Use DuckDB SQL against typed STIX tables and explicit enriched views.

```sql
SELECT
    id,
    pid,
    command_line,
    extensions."windows-process-ext".owner_sid
FROM process
WHERE command_line IS NOT NULL;
```

Known nested fields are native DuckDB `STRUCT`, `LIST`, or `MAP` values, which keeps their schema visible to DuckDB tooling and autocomplete.

## Acquisition boundary

```text
STIX pattern
    |
    v
Python + STIX-Shifter
    |
    | raw STIX 2.1 JSON
    v
Firepit / DuckDB
```

Firepit does not own credentials, remote HTTP, connector polling, pagination, or vendor-native result translation.

## Interactive analysis

A Firepit database is an ordinary DuckDB database. Use DuckDB directly:

```bash
duckdb observations.duckdb -ui
```

There is no parallel Firepit shell. DuckDB SQL/UI is the interactive query surface.

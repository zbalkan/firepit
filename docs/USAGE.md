# Usage

Firepit is becoming a thin STIX-to-DuckDB storage component. New integrations should keep acquisition outside Firepit and use DuckDB directly for analysis.

## Storage

```python
from firepit import get_storage

store = get_storage("observations.duckdb", "hunt")
store.cache("query-1", "bundle.json")
```

The modernization branch still contains compatibility methods that will be removed. Do not build new code around mutable Firepit hunt variables, appdata, database-independent query objects, or automatic graph dereferencing.

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

Remote access should look like:

```text
STIX pattern
    |
    v
Python + STIX-Shifter
    |
    | STIX 2.1 JSON
    v
Firepit / DuckDB
```

Firepit should not own credentials, remote HTTP, connector polling, pagination, or vendor-native result translation.

## DuckDB UI

A Firepit database is an ordinary DuckDB database. For interactive analysis:

```bash
duckdb observations.duckdb -ui
```

The long-term interactive surface is DuckDB SQL/UI rather than a parallel Firepit shell.

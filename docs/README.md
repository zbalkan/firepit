# Documentation

Firepit 3 is a query-only STIX 2.1 threat-intelligence interface backed by DuckDB.

- [Installation](INSTALLATION.md)
- [Usage](USAGE.md)
- [Database model](DATABASE.md)
- [Completed modernization roadmap](../MODERNIZATION_ROADMAP.md)

The public contract consists of two Sentinel-inspired views queried through Firepit's read-only API. Physical DuckDB tables and acquisition provenance are private implementation details.

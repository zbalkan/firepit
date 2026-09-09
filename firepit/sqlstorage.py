"""Temporary compatibility shim for the retired generic SQL storage layer."""

from firepit.storage import DuckDBStorage as SqlStorage

DB_VERSION = "3-native"


def infer_type(key, value):
    if key == "id":
        return "VARCHAR"
    if isinstance(value, bool):
        return "BOOLEAN"
    if isinstance(value, int):
        return "BIGINT"
    if isinstance(value, float):
        return "DOUBLE"
    if isinstance(value, (list, dict)):
        return "JSON"
    return "VARCHAR"


def get_path_joins(*_args, **_kwargs):
    raise NotImplementedError(
        "implicit flattened-path joins are not part of native storage"
    )


__all__ = ["DB_VERSION", "SqlStorage", "infer_type", "get_path_joins"]

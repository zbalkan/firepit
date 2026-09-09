"""Validation for SQL identifiers accepted by Firepit."""

import re

from firepit.exceptions import InvalidViewname

_NAME_RE = re.compile(r"^[\w-]+$")


def validate_name(name):
    """Require a simple identifier before interpolating it into DuckDB SQL."""
    if not isinstance(name, str) or _NAME_RE.fullmatch(name) is None:
        raise InvalidViewname(name)

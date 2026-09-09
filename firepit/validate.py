"""Validation for Firepit session names."""

import re

from firepit.exceptions import InvalidSession

_NAME_RE = re.compile(r"^[\w-]+$", re.ASCII)


def validate_name(name):
    """Require a simple schema identifier."""
    if not isinstance(name, str) or _NAME_RE.fullmatch(name) is None:
        raise InvalidSession(name)

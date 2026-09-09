import uuid

import pytest

from firepit.exceptions import InvalidViewname
from firepit.validate import validate_name


@pytest.mark.parametrize(
    "name, expected",
    [
        ("foo", True),
        ("[*]", False),
        ("__tmp_6668fcc6300f40e39c255c6573d79180", True),
        ("__tmp_" + uuid.uuid4().hex, True),
        ("foo;", False),
        ("foo; --", False),
        ("network-traffic", True),
        ("x509-certificate", True),
        ("admin'--", False),
        ('admin"--', False),
        ('foo OR "1" = "1', False),
        ('ipv4-addr" union select * from "user-account', False),
        ('foo; select value from "ipv4-addr', False),
    ],
)
def test_validate_name(name, expected):
    if expected:
        validate_name(name)
    else:
        with pytest.raises(InvalidViewname):
            validate_name(name)

import json
import os

from typer.testing import CliRunner

from firepit.cli import app


runner = CliRunner()


def test_cli_cache_and_lookup(tmpdir):
    dbname = str(tmpdir.join("cli.duckdb"))
    bundle = os.path.join(os.path.dirname(__file__), "spec_2_1_bundle.json")

    result = runner.invoke(
        app,
        ["--dbname", dbname, "cache", "test-id", bundle],
    )
    assert result.exit_code == 0, result.stdout

    result = runner.invoke(
        app,
        [
            "--dbname",
            dbname,
            "lookup",
            "ipv4-addr",
            "--output",
            "json",
            "--columns",
            "value",
            "--limit",
            "2",
        ],
    )
    assert result.exit_code == 0, result.stdout
    output = json.loads(result.stdout)
    assert len(output) == 1
    assert set(output[0]) == {"value"}

import json

from typer.testing import CliRunner

from firepit.cli import app


runner = CliRunner()


def test_cli_cache_and_lookup(fake_bundle_file, tmpdir):
    dbname = str(tmpdir.join("cli.duckdb"))

    result = runner.invoke(
        app,
        ["--dbname", dbname, "cache", "test-id", fake_bundle_file],
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
    assert len(output) == 2
    assert set(output[0]) == {"value"}

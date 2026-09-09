# type: ignore[attr-defined]

"""Temporary Firepit CLI retained until Phase 8."""

import csv
import json
import os
from typing import List

import typer
from tabulate import tabulate

from firepit import get_storage

app = typer.Typer(
    name="firepit",
    help="DuckDB-native STIX storage utilities",
    add_completion=False,
)

state = {
    "dbname": os.getenv("FIREPITDB", "stix.db"),
    "session": os.getenv("FIREPITID", "main"),
}


def _store():
    return get_storage(state["dbname"], state["session"])


def _print_rows(rows, output="table"):
    if output == "json":
        print(json.dumps(rows, ensure_ascii=False, default=str))
    elif output == "csv":
        for row in rows:
            print(",".join(json.dumps(value, ensure_ascii=False, default=str)
                           for value in row.values()))
    else:
        print(tabulate(rows, headers="keys"))


@app.callback()
def main(
    dbname: str = typer.Option(None, help="Path/name of DuckDB database"),
    session: str = typer.Option(state["session"], help="DuckDB schema/session"),
):
    if dbname:
        state["dbname"] = dbname
    if session:
        state["session"] = session


@app.command()
def cache(
    query_id: str,
    filenames: List[str],
    batchsize: int = typer.Option(2000),
):
    """Ingest local STIX bundles and associate them with an acquisition run."""
    store = _store()
    try:
        store.cache(query_id, filenames, batchsize=batchsize)
    finally:
        store.close()


@app.command()
def lookup(
    name: str,
    limit: int = typer.Option(None),
    offset: int = typer.Option(0),
    output: str = typer.Option("table", help="table, json or csv"),
    columns: str = typer.Option(None),
):
    store = _store()
    try:
        rows = store.lookup(
            name,
            cols=columns or "*",
            limit=limit,
            offset=offset,
        )
        _print_rows(rows, output)
    finally:
        store.close()


@app.command()
def values(path: str, name: str):
    store = _store()
    try:
        for value in store.values(path, name):
            print(value)
    finally:
        store.close()


@app.command()
def tables():
    store = _store()
    try:
        for name in store.tables():
            print(name)
    finally:
        store.close()


@app.command()
def views():
    store = _store()
    try:
        for name in store.views():
            print(name)
    finally:
        store.close()


@app.command("type")
def object_type(name: str):
    store = _store()
    try:
        print(store.table_type(name))
    finally:
        store.close()


@app.command()
def columns(name: str):
    store = _store()
    try:
        for column in store.columns(name):
            print(column)
    finally:
        store.close()


@app.command()
def schema(name: str = typer.Argument(None)):
    store = _store()
    try:
        _print_rows(store.schema(name))
    finally:
        store.close()


@app.command()
def count(name: str):
    store = _store()
    try:
        print(store.count(name))
    finally:
        store.close()


@app.command()
def provenance(query_id: str = typer.Argument(None)):
    store = _store()
    try:
        result = store.provenance(query_id)
        _print_rows([result] if isinstance(result, dict) else result)
    finally:
        store.close()


@app.command()
def load(
    filename: str,
    sco_type: str = typer.Option(None),
    query_id: str = typer.Option(None),
    preserve_ids: bool = typer.Option(True),
):
    """Ingest object records without creating a Firepit variable/view."""
    store = _store()
    try:
        with open(filename, "r", encoding="utf-8") as fp:
            try:
                data = json.load(fp)
            except ValueError:
                fp.seek(0)
                data = list(csv.DictReader(fp))
        store.load(None, data, sco_type, query_id, preserve_ids)
    finally:
        store.close()


@app.command(name="value-counts")
def value_counts(name: str, path: str, output: str = typer.Option("table")):
    store = _store()
    try:
        _print_rows(store.value_counts(name, path), output)
    finally:
        store.close()


@app.command(name="number-observed")
def number_observed(name: str, path: str, value: str = typer.Option(None)):
    store = _store()
    try:
        print(store.number_observed(name, path, value))
    finally:
        store.close()


@app.command()
def timestamped(
    name: str,
    path: List[str] = typer.Argument(None),
    value: str = typer.Option(None),
    timestamp: str = typer.Option("first_observed"),
    limit: int = typer.Option(None),
    output: str = typer.Option("table"),
):
    store = _store()
    try:
        _print_rows(
            store.timestamped(name, path, value, timestamp, limit),
            output,
        )
    finally:
        store.close()


@app.command()
def summary(
    name: str,
    path: str = typer.Argument(None),
    value: str = typer.Option(None),
    output: str = typer.Option("table"),
):
    store = _store()
    try:
        _print_rows([store.summary(name, path, value)], output)
    finally:
        store.close()


@app.command()
def sql(statement: str):
    """Execute raw DuckDB SQL. Prefer the DuckDB CLI/UI for regular analysis."""
    store = _store()
    try:
        rows = store._query(statement).fetchall()
        if rows:
            _print_rows(rows)
    finally:
        store.close()


@app.command()
def delete():
    store = _store()
    store.delete()


if __name__ == "__main__":
    app()

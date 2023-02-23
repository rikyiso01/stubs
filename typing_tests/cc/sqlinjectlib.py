from __future__ import annotations
from typing import Any, Iterator, TypeAlias
from MySQLdb import connect as mysql_connect, Connection as MySQLConnection
from sqlite3 import connect as sqlite_connect, Connection as SQLiteConnection
from tempfile import NamedTemporaryFile

DB: TypeAlias = "MySQLConnection | SQLiteConnection"


def mysql() -> Iterator[MySQLConnection]:
    with mysql_connect(
        host="db", port=3306, user="root", passwd="example"
    ) as connection:
        yield connection


def sqlite() -> Iterator[SQLiteConnection]:
    with NamedTemporaryFile() as f:
        with sqlite_connect(f.name) as connection:
            yield connection


def exec(db: DB, query: str) -> list[list[Any]]:
    if isinstance(db, SQLiteConnection):
        cursor = db.cursor()
        result = cursor.execute(query).fetchall()
        cursor.close()
    else:
        db.query(query)
        cursor = db.store_result()
        result = cursor.fetch_row()
    return [list(row) for row in result]

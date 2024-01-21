from datetime import date, datetime, time, timedelta
from typing import Callable, Optional, Any, Literal, overload
from sqlalchemy.engine.base import Engine
from sqlalchemy.sql.selectable import Select

def create_engine(
    url: str,
    *,
    echo: bool = ...,
    future: Literal[True],
    connect_args: dict[str, str] = ...,
) -> Engine: ...
def create_mock_engine(url: str, *, executor: Callable[..., Any]) -> Engine: ...

Integer: int

def String(length: int = ...) -> str: ...
def CHAR(length: int = ...) -> str: ...
def Numeric(precision: int = ..., scale: int = ...) -> int: ...

Interval: timedelta
Date: date
DateTime: datetime
Time: time

class ForeignKey:
    @overload
    def __new__(cls, target: str, *, deferrable: bool = ...) -> Any: ...
    @overload
    def __new__[T](cls, target: T, *, deferrable: bool = ...) -> T: ...
    column: Column

class Column:
    @overload
    def __new__[
        T
    ](
        cls,
        type: T,
        /,
        *,
        primary_key: Literal[False] = ...,
        nullable: Literal[True] = ...,
        unique: bool = ...,
        default: Optional[T] = ...,
    ) -> Optional[T]: ...
    @overload
    def __new__[
        T
    ](
        cls,
        type: T,
        /,
        *,
        primary_key: Literal[True],
        unique: bool = ...,
        default: T = ...,
    ) -> T: ...
    @overload
    def __new__[
        T
    ](
        cls,
        type: T,
        /,
        *,
        nullable: Literal[False],
        primary_key: bool = ...,
        unique: bool = ...,
        default: T = ...,
    ) -> T: ...

    primary_key: bool
    nullable: bool
    name: str
    foreign_keys: set[ForeignKey]
    table: Table
    unique: bool

def select(*args: Any) -> Select: ...
def and_(*args: bool) -> bool: ...
def text(text: str) -> Select: ...

class Table:
    name: str
    columns: list[Column]

class CheckConstraint:
    def __init__(self, check: str) -> None:
        pass

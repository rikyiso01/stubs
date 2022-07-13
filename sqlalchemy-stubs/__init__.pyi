from datetime import date, datetime, time, timedelta
from typing import Callable, Optional, TypeVar, Any, Literal, overload
from .engine.base import Engine
from .sql.selectable import Select

_T = TypeVar("_T")

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
    def __new__(cls, target: _T, *, deferrable: bool = ...) -> _T: ...
    column: Column

class Column:
    @overload
    def __new__(
        cls,
        type: _T,
        /,
        *,
        primary_key: Literal[False] = ...,
        nullable: Literal[True] = ...,
        unique: bool = ...,
        default: Optional[_T] = ...,
    ) -> Optional[_T]: ...
    @overload
    def __new__(
        cls,
        type: _T,
        /,
        *,
        primary_key: Literal[True],
        unique: bool = ...,
        default: _T = ...,
    ) -> _T: ...
    @overload
    def __new__(
        cls,
        type: _T,
        /,
        *,
        nullable: Literal[False],
        primary_key: bool = ...,
        unique: bool = ...,
        default: _T = ...,
    ) -> _T: ...

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

from mte.json import JsonType, PythonJsonGeneric, PythonJsonScalar
from typing import Any
from collections.abc import Callable
from datetime import datetime, date, time
from enum import Enum

_DumpType = PythonJsonGeneric[
    PythonJsonScalar | datetime | date | time | Enum, _DumpType
]

def loads(data: bytes | str, /) -> JsonType: ...
def dumps(
    obj: _DumpType,
    /,
    default: Callable[[Any], Any] | None = ...,
    option: int | None = ...,
) -> bytes: ...

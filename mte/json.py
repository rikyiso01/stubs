from __future__ import annotations
from typing_extensions import TypeAlias
from mte.typevar import T, K
from collections.abc import Sequence, Mapping

JsonScalar: TypeAlias = "str|int|float|bool|None"
JsonObject: TypeAlias = "dict[str,JsonType]"
JsonList: TypeAlias = "list[JsonType]"
JsonType: TypeAlias = "JsonScalar|JsonObject|JsonList"


PythonJsonScalar: TypeAlias = "JsonScalar"
PythonJsonGeneric: TypeAlias = "K|Mapping[K,T]|Sequence[T]"
PythonJsonType: TypeAlias = "PythonJsonGeneric[PythonJsonScalar,PythonJsonType]"

from __future__ import annotations
from typing_extensions import TypeAlias
from datetime import date, datetime
from mte.typevar import T, K
from collections.abc import Mapping, Sequence, Set

YamlScalar: TypeAlias = "str|int|float|bool|None|date|datetime|bytes"
YamlCollection: TypeAlias = "dict[YamlScalar,YamlType]|list[tuple[YamlScalar,YamlType]]|list[YamlType]|set[YamlType]"
YamlType: TypeAlias = "YamlScalar|YamlCollection"


PythonYamlScalar: TypeAlias = "YamlScalar"
PythonYamlGeneric: TypeAlias = "K|Mapping[K,T]|Sequence[T]|Set[T]"
PythonYamlType: TypeAlias = "PythonYamlGeneric[PythonYamlScalar,PythonYamlType]"

from __future__ import annotations
from typing_extensions import TypeAlias
from datetime import time, date, datetime

TomlScalar: TypeAlias = "str|int|float|bool|date|time|datetime"
TomlArray: TypeAlias = "list[TomlGeneric]"
TomlTable: TypeAlias = "dict[str,TomlGeneric]"
TomlGeneric: TypeAlias = "TomlScalar|TomlArray|TomlTable"
TomlType: TypeAlias = "TomlTable"

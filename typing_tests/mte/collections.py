from mte.collections import (
    BaseSequence,
    Sequence,
    BaseMutableSequence,
    MutableSequence,
    ByteString,
    Set,
    MutableSet,
    BaseMapping,
    MappingView,
    KeysView,
    ValuesView,
    ItemsView,
    Mapping,
    BaseMutableMapping,
    MutableMapping,
    IO,
    TextIO,
    BinaryIO,
)
from sys import stdin, stdout


a: BaseSequence[int] = [1, 2, 3]
aa: BaseSequence[float] = a
b: Sequence[int] = [1, 2, 3]
bb: Sequence[float] = b
bb2: Sequence[int | tuple[int, ...]] = [1, 2, (1, 2)]
c: BaseMutableSequence[int] = [1, 2, 3]
d: MutableSequence[int] = [1, 2, 3]
e: ByteString = b"123"
f: Set[int] = {1, 2, 3}
ff: Set[float] = f
ff2: Set[float | tuple[int, ...]] = {1, 2, 3}
g: MutableSet[int] = {1, 2, 3}
h: BaseMapping[str, int] = {"1": 2, "3": 4}
hh: BaseMapping[str, float] = h
hh2: BaseMapping[str, Sequence[int] | None] = {"a": [1, 2, 3], "b": None}
i: MappingView = {1: 1}.keys()
j: KeysView[int | tuple[int, ...]] = {1: 1}.keys()
k: ValuesView[int] = {1: 1}.values()
l: ItemsView[str, int] = {"1": 1}.items()
m: Mapping[int, int] = {1: 1}
mm: Mapping[str, int] = {"a": 1}
mm2: Mapping[str, Sequence[int] | None] = {"a": [1, 2, 3], "b": None}
mm3: Mapping[str | int, list[int] | tuple[int, ...]] = {"a": [1, 2, 3], "b": (1, 2, 3)}
n: BaseMutableMapping[int, int] = {1: 1}
o: MutableMapping[int, int] = {1: 1}
p: IO[str] = stdin
p: IO[str] = stdout
q: IO[bytes] = stdin.buffer
q: IO[bytes] = stdout.buffer
r: TextIO = stdin
r: TextIO = stdout
s: BinaryIO = stdin.buffer
s: BinaryIO = stdout.buffer

from collections.abc import Mapping
from typing import KeysView


class A(Mapping[int | tuple[int, ...], int]):
    def keys(self) -> KeysView[int | tuple[int, ...]]:
        return super().keys()

from __future__ import annotations
from typing import runtime_checkable, Protocol, overload, AnyStr, Any
from typing_extensions import Self
from collections.abc import Iterable, Reversible, Sized, Set as AbstractSet, Iterator
from mte.typevar import V_co, T, T_co, V, T2, T_con
from mte.protocols import SupportsGetItem


@runtime_checkable
class Container(Protocol):
    def __contains__(self, other: Any, /) -> bool:
        ...


@runtime_checkable
class Collection(Iterable[V_co], Sized, Container, Protocol[V_co]):
    ...


@runtime_checkable
class BaseSequence(
    Reversible[V_co], Collection[V_co], SupportsGetItem[int, V_co], Protocol[V_co]
):
    ...


@runtime_checkable
class Sequence(BaseSequence[V_co], Protocol[V_co]):
    def index(self, elem: Any, start: int = ..., end: int = ..., /) -> int:
        ...

    def count(self, elem: Any, /) -> int:
        ...


@runtime_checkable
class BaseMutableSequence(BaseSequence[T], Protocol[T]):
    @overload
    def __setitem__(self, index: int, value: T, /) -> None:
        ...

    @overload
    def __setitem__(self, index: slice, value: Iterable[T], /) -> None:
        ...

    @overload
    def __delitem__(self, index: int, /) -> None:
        ...

    @overload
    def __delitem__(self, index: slice, /) -> None:
        ...


@runtime_checkable
class MutableSequence(BaseMutableSequence[T], Sequence[T], Protocol[T]):
    def insert(self, index: int, value: T, /) -> None:
        ...

    def append(self, value: T, /) -> None:
        ...

    def reverse(self) -> None:
        ...

    def pop(self, index: int = ...) -> T:
        ...

    def extend(self, values: Iterable[T], /) -> None:
        ...

    def remove(self, value: T, /) -> None:
        ...

    def __iadd__(self, values: Iterable[T], /) -> Self:
        ...


@runtime_checkable
class ByteString(Sequence[int], Protocol):
    ...


@runtime_checkable
class Set(Collection[V_co], Protocol[V_co]):
    def __lt__(self, other: AbstractSet[object], /) -> bool:
        ...

    def __gt__(self, other: AbstractSet[object], /) -> bool:
        ...

    def __ge__(self, other: AbstractSet[object], /) -> bool:
        ...

    def __le__(self, other: AbstractSet[object], /) -> bool:
        ...

    def __and__(self, other: AbstractSet[object], /) -> Set[V_co]:
        ...

    def __or__(self, other: AbstractSet[T], /) -> AbstractSet[V_co | T]:
        ...

    def __sub__(self, other: AbstractSet[Any], /) -> Set[V_co]:
        ...

    def __xor__(self, other: AbstractSet[T], /) -> AbstractSet[V_co | T]:
        ...

    def isdisjoint(self, other: Iterable[object], /) -> bool:
        ...


@runtime_checkable
class MutableSet(Set[T], Protocol[T]):
    def add(self, value: T, /) -> None:
        ...

    def discard(self, value: T, /) -> None:
        ...

    def clear(self) -> None:
        ...

    def pop(self) -> T:
        ...

    def remove(self, value: T, /) -> None:
        ...

    def __ior__(self, value: AbstractSet[T], /) -> Self:
        ...

    def __iand__(self, value: AbstractSet[object], /) -> Self:
        ...

    def __ixor__(self, value: AbstractSet[T], /) -> Self:
        ...

    def __isub__(self, value: AbstractSet[object], /) -> Self:
        ...


@runtime_checkable
class BaseMapping(Collection[T], Protocol[T, V_co]):
    def __getitem__(self, key: T, /) -> V_co:
        ...


@runtime_checkable
class MappingView(Sized, Protocol):
    ...


@runtime_checkable
class KeysView(Set[V_co], Protocol[V_co]):
    ...


@runtime_checkable
class ValuesView(Collection[V_co], Protocol[V_co]):
    ...


@runtime_checkable
class ItemsView(Set[tuple[T_co, V_co]], Protocol[T_co, V_co]):
    ...


@runtime_checkable
class Mapping(BaseMapping[T, V_co], Protocol[T, V_co]):
    def items(self) -> ItemsView[T, V_co]:
        ...

    def values(self) -> ValuesView[V_co]:
        ...

    def keys(self) -> Iterable[T]:
        ...

    # @overload
    # def get(self, item: T, /) -> V_co | None:
    #     ...

    # @overload
    # def get(self, item: T, default: V, /) -> V | V_co:
    #     ...


@runtime_checkable
class BaseMutableMapping(BaseMapping[T, V], Protocol[T, V]):
    def __setitem__(self, key: T, value: V, /) -> None:
        ...

    def __delitem__(self, key: T, /) -> None:
        ...


@runtime_checkable
class SupportsKeysAndGetItem(SupportsGetItem[T_con, V_co], Protocol[T_con, V_co]):
    def keys(self) -> Iterator[V_co]:
        ...


@runtime_checkable
class MutableMapping(BaseMutableMapping[T, V], Mapping[T, V], Protocol[T, V]):
    @overload
    def pop(self, item: T, /) -> V:
        ...

    @overload
    def pop(self, item: T, default: T2, /) -> V | T2:
        ...

    def popitem(self) -> tuple[T, V]:
        ...

    def clear(self) -> None:
        ...

    @overload
    def update(self, mapping: SupportsKeysAndGetItem[T, V], /) -> None:
        ...

    @overload
    def update(self, mapping: Iterable[tuple[T, V]], /) -> None:
        ...

    @overload
    def update(
        self: MutableMapping[str, V],
        mapping: SupportsKeysAndGetItem[T, V],
        /,
        **kwargs: V,
    ) -> None:
        ...

    @overload
    def update(
        self: MutableMapping[str, V], mapping: Iterable[tuple[T, V]], /, **kwargs: V
    ) -> None:
        ...

    @overload
    def update(self: MutableMapping[str, V], **kwargs: V) -> None:
        ...

    def setdefault(self, key: T, default: V, /) -> V:
        ...


@runtime_checkable
class IO(Protocol[AnyStr]):
    def close(self) -> None:
        ...

    @property
    def closed(self) -> bool:
        ...

    @property
    def mode(self) -> str:
        ...

    @property
    def name(self) -> str:
        ...

    def fileno(self) -> int:
        ...

    def flush(self) -> None:
        ...

    def isatty(self) -> bool:
        ...

    def readable(self) -> bool:
        ...

    def readline(self, size: int = ..., /) -> AnyStr:
        ...

    def readlines(self, hint: int = ..., /) -> Sequence[AnyStr]:
        ...

    def read(self, n: int, /) -> AnyStr:
        ...

    def seek(self, offset: int, whence: int = ..., /) -> int:
        ...

    def seekable(self) -> bool:
        ...

    def tell(self) -> int:
        ...

    def truncate(self, size: int | None = ..., /) -> int:
        ...

    def writelines(self, lines: Iterable[AnyStr], /) -> None:
        ...

    def write(self, data: AnyStr, /) -> int:
        ...


@runtime_checkable
class TextIO(IO[str], Protocol):
    ...


@runtime_checkable
class BinaryIO(IO[bytes], Protocol):
    ...

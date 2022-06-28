from typing import TypeVar, Generic, Type, overload
from numpy.typing import ArrayLike
from collections.abc import Iterable

_K = TypeVar("_K")
_K2 = TypeVar("_K2")
_V = TypeVar("_V")

SeriesLike = dict[_K, _V] | ArrayLike[_V] | Iterable[_V]

class Series(Generic[_K, _V]):
    def __init__(
        self,
        data: SeriesLike[_K, _V] = ...,
        index: ArrayLike[_K] | Iterable[_K] = ...,
        dtype: Type[_V] = ...,
        name: str = ...,
        copy: bool = ...,
    ) -> None: ...
    def __getitem__(self, item: _K, /) -> _V: ...

class DataFrame(Generic[_K, _K2, _V]):
    def __init__(
        self,
        data: SeriesLike[_K, _V] = ...,
        index: ArrayLike[_K2] | Iterable[_K2] = ...,
        columns: ArrayLike[_K] | Iterable[_K] = ...,
        dtype: Type[_V] = ...,
        copy: bool = ...,
    ) -> None: ...
    @overload
    def __getitem__(self, item: _K, /) -> Series[_K2, _V]: ...
    @overload
    def __getitem__(self, item: slice, /) -> DataFrame[_K, _K2, _V]: ...
    @overload
    def __setitem__(self, item: _K2, value: _V, /) -> None: ...
    @overload
    def __setitem__(self, item: slice, value: Iterable[_V], /) -> None: ...

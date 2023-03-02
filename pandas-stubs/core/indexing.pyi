from typing import Generic, TypeVar, overload, Any
from collections.abc import Sequence
from pandas import Series, DataFrame

_K = TypeVar("_K")
_K2 = TypeVar("_K2")
_V = TypeVar("_V")

class LockIndexerDataFrame(Generic[_K, _K2, _V]):
    @overload
    def __getitem__(
        self,
        item: _K2 | tuple[slice, _K] | tuple[_K2, slice],
        /,
    ) -> Series[_K, _V]: ...
    @overload
    def __getitem__(self, item: tuple[_K2, _K], /) -> _V: ...
    @overload
    def __getitem__(
        self,
        item: slice
        | tuple[
            slice | Sequence[bool] | Series[_K2, bool] | Series[Any, _K] | Sequence[_K],
            slice | Sequence[bool] | Series[_K2, bool] | Series[Any, _K] | Sequence[_K],
        ]
        | Sequence[bool]
        | Series[_K2, bool]
        | Series[Any, _K]
        | Sequence[_K],
        /,
    ) -> DataFrame[_K, _K2, _V]: ...
    @overload
    def __setitem__(
        self,
        item: _K2
        | tuple[
            slice | Sequence[bool] | Series[_K2, bool] | Series[Any, _K] | Sequence[_K],
            _K,
        ]
        | tuple[
            _K2,
            slice | Sequence[bool] | Series[_K2, bool] | Series[Any, _K] | Sequence[_K],
        ],
        value: Series[_K, _V],
        /,
    ) -> None: ...
    @overload
    def __setitem__(self, item: tuple[_K2, _K], value: _V, /) -> _V: ...
    @overload
    def __setitem__(
        self, item: slice | tuple[slice, slice], value: DataFrame[_K, _K2, _V], /
    ) -> DataFrame[_K, _K2, _V]: ...

class iLockIndexerDataFrame(Generic[_K, _K2, _V]):
    @overload
    def __getitem__(
        self,
        item: int | tuple[slice, int] | tuple[int, slice],
        /,
    ) -> Series[_K, _V]: ...
    @overload
    def __getitem__(self, item: tuple[int, int], /) -> _V: ...
    @overload
    def __getitem__(
        self, item: slice | tuple[slice, slice], /
    ) -> DataFrame[_K, _K2, _V]: ...
    @overload
    def __setitem__(
        self,
        item: int | tuple[slice, int] | tuple[int, slice],
        value: Series[_K, _V],
        /,
    ) -> None: ...
    @overload
    def __setitem__(self, item: tuple[int, int], value: _V, /) -> None: ...
    @overload
    def __setitem__(
        self, item: slice | tuple[slice, slice], value: DataFrame[_K, _K2, _V], /
    ) -> None: ...

class iLockIndexerSeries(Generic[_K, _V]):
    def __getitem__(self, item: int, /) -> _V: ...

class LockIndexerSeries(Generic[_K, _V]):
    def __getitem__(self, item: _K, /) -> _V: ...

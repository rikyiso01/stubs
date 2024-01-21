from typing import overload, Any
from pandas import Series, DataFrame
from mte.pandas import SeriesCompatible, DataFrameLike, SeriesLike
from collections.abc import Iterator
from numpy.typing import NDArray, ArrayLike

class LockIndexerDataFrame[K, K2, V]:
    @overload
    def __getitem__(
        self,
        item: K2 | tuple[slice | ArrayLike[bool], K] | tuple[K2, slice],
        /,
    ) -> Series[K, V]: ...
    @overload
    def __getitem__(self, item: tuple[K2, K], /) -> V: ...
    @overload
    def __getitem__(
        self,
        item: slice
        | tuple[
            slice | SeriesCompatible[K2, bool] | SeriesCompatible[Any, K],
            slice | SeriesCompatible[K2, bool] | SeriesCompatible[Any, K],
        ]
        | SeriesCompatible[K2, bool]
        | SeriesCompatible[Any, K],
        /,
    ) -> DataFrame[K, K2, V]: ...
    @overload
    def __setitem__(
        self,
        item: K2
        | tuple[
            slice | SeriesCompatible[K2, bool] | SeriesCompatible[Any, K],
            K,
        ]
        | tuple[
            K2,
            slice | SeriesCompatible[K2, bool] | SeriesCompatible[Any, K],
        ],
        value: SeriesCompatible[K, V] | V,
        /,
    ) -> None: ...
    @overload
    def __setitem__(self, item: tuple[K2, K], value: V, /) -> V: ...
    @overload
    def __setitem__(
        self, item: slice | tuple[slice, slice], value: DataFrameLike[K, K2, V], /
    ) -> DataFrame[K, K2, V]: ...

class iLockIndexerDataFrame[K, K2, V]:
    @overload
    def __getitem__(
        self,
        item: int | tuple[slice, int] | tuple[int, slice],
        /,
    ) -> Series[K, V]: ...
    @overload
    def __getitem__(self, item: tuple[int, int], /) -> V: ...
    @overload
    def __getitem__(
        self, item: slice | tuple[slice, slice], /
    ) -> DataFrame[K, K2, V]: ...
    @overload
    def __setitem__(
        self,
        item: int | tuple[slice, int] | tuple[int, slice],
        value: SeriesLike[K, V],
        /,
    ) -> None: ...
    @overload
    def __setitem__(self, item: tuple[int, int], value: V, /) -> None: ...
    @overload
    def __setitem__(
        self, item: slice | tuple[slice, slice], value: DataFrameLike[K, K2, V], /
    ) -> None: ...
    def __iter__(self) -> Iterator[NDArray[V]]: ...

class iLockIndexerSeries[K, V]:
    def __getitem__(self, item: int, /) -> V: ...

class LockIndexerSeries[K, V]:
    def __getitem__(self, item: K, /) -> V: ...
    def __setitem__(
        self, item: K | SeriesCompatible[K, bool], value: SeriesCompatible[K, V] | V, /
    ) -> None: ...

from typing import Any, Literal, Generic, Type, overload
from collections.abc import Iterable, Iterator, Callable,Sequence
from numpy.typing import NDArray
from pandas.core.indexes.base import Index
from pandas.core.groupby.generic import DataFrameGroupBy
from pandas.core.strings.accessor import StringMethods
from pandas.plotting._core import PlotAccessor
from pandas.core.indexing import (
    iLockIndexerDataFrame,
    LockIndexerDataFrame,
    iLockIndexerSeries,
    LockIndexerSeries,
)
from mte.typevar import K, V, K2, I, V2, I2, K3, C, C2
from mte.pandas import SeriesLike, SeriesCompatible, DataFrameLike

def read_csv(
    filepath_or_buffer: str, *, error_bad_lines: bool = ...
) -> DataFrame[str, int, Any]: ...

class Series(Generic[K, V]):
    @overload
    def __new__(
        cls,
        data: SeriesLike[K, V],
        index: Iterable[K] = ...,
        dtype: Type[V] = ...,
        name: str = ...,
        copy: bool = ...,
    ) -> Series[K, V]: ...
    @overload
    def __new__(
        cls,
        data: Iterable[V],
        *,
        dtype: Type[V] = ...,
        name: str = ...,
        copy: bool = ...,
    ) -> Series[int, V]: ...
    @overload
    def __new__(
        cls,
        data: Iterable[V],
        index: Iterable[K],
        dtype: Type[V] = ...,
        name: str = ...,
        copy: bool = ...,
    ) -> Series[K, V]: ...
    @overload
    def __getitem__(self, item: K, /) -> V: ...
    @overload
    def __getitem__(
        self,
        item: slice | SeriesCompatible[K, bool],
        /,
    ) -> Series[K, V]: ...
    @overload
    def __setitem__(self, item: K, value: V, /) -> None: ...
    @overload
    def __setitem__(
        self,
        item: slice | SeriesCompatible[K, bool],
        value: SeriesCompatible[K, V],
        /,
    ) -> None: ...
    def __iter__(self) -> Iterator[V]: ...
    def __len__(self) -> int: ...
    def __contains__(self, item: K, /) -> bool: ...
    def __lt__(self, other: V | SeriesCompatible[K, V], /) -> Series[K, bool]: ...
    __gt__ = __lt__
    __ge__ = __lt__
    __le__ = __lt__
    def __eq__(self, other: Any, /) -> Series[K, bool]: ...
    def __ne__(self, other: Any, /) -> Series[K, bool]: ...
    def __array__(self) -> NDArray[V]: ...
    @property
    def str(self: Series[Any, str]) -> StringMethods[K]: ...
    def value_counts(self, subset: Sequence[K] | None = ...) -> Series[V, int]: ...
    @overload
    def reset_index(self) -> DataFrame[int | str, int, V | K]: ...
    @overload
    def reset_index(self, *, name: K2) -> DataFrame[K2 | str, int, V | K]: ...
    def apply(self, func: Callable[[V], V2]) -> Series[K, V2]: ...
    def mean(self: Series[K, float]) -> float: ...
    def max(self) -> V: ...
    min = max
    def isna(self) -> Series[K, bool]: ...
    isnull = isna
    def any(self) -> bool: ...
    all = any
    def copy(self) -> Series[K, V]: ...
    @property
    def shape(self) -> tuple[int]: ...
    def tolist(self) -> list[V]: ...
    def head(self, n: int = ...) -> Series[K, V]: ...
    def describe(self) -> Series[str, Any]: ...
    @property
    def plot(self) -> PlotAccessor[K]: ...
    def isin(self, values: SeriesCompatible[K, V]) -> Series[K, bool]: ...
    def __and__(
        self: Series[K, I], other: SeriesLike[K, I2]
    ) -> Series[K, I | I2]: ...
    __or__ = __and__
    __xor__ = __or__
    def mode(self) -> Series[int, V]: ...
    @property
    def iloc(self) -> iLockIndexerSeries[K, V]: ...
    @property
    def loc(self) -> LockIndexerSeries[K, V]: ...
    def __add__(
        self: Series[K, C], other: SeriesLike[K, C2]
    ) -> Series[K, C | C2]: ...
    __sub__ = __add__
    __mul__ = __add__

class DataFrame(Generic[K, K2, V]):
    @overload
    def __new__(
        cls, data: Iterable[V], *, dtype: Type[V] = ..., copy: bool = ...
    ) -> DataFrame[int, int, V]: ...
    @overload
    def __new__(
        cls,
        data: Iterable[V],
        index: Iterable[K2],
        *,
        dtype: Type[V] = ...,
        copy: bool = ...,
    ) -> DataFrame[int, K2, V]: ...
    @overload
    def __new__(
        cls,
        data: Iterable[V],
        *,
        columns: Iterable[K],
        dtype: Type[V] = ...,
        copy: bool = ...,
    ) -> DataFrame[K, int, V]: ...
    @overload
    def __new__(
        cls,
        data: Iterable[V],
        index: Iterable[K2],
        columns: Iterable[K],
        dtype: Type[V] = ...,
        copy: bool = ...,
    ) -> DataFrame[K, K2, V]: ...
    @overload
    def __new__(
        cls,
        data: SeriesCompatible[K, V],
        *,
        columns: Iterable[K] = ...,
        dtype: Type[V] = ...,
        copy: bool = ...,
    ) -> DataFrame[K, int, V]: ...
    @overload
    def __new__(
        cls,
        data: SeriesCompatible[K, V],
        index: Iterable[K2],
        columns: Iterable[K] = ...,
        dtype: Type[V] = ...,
        copy: bool = ...,
    ) -> DataFrame[K, K2, V]: ...
    @overload
    def __new__(
        cls,
        data: SeriesCompatible[K, dict[K2, V]],
        index: Iterable[K2] = ...,
        columns: Iterable[K] = ...,
        dtype: Type[V] = ...,
        copy: bool = ...,
    ) -> DataFrame[K, K2, V]: ...
    @overload
    def __getitem__(self, item: K, /) -> Series[K2, V]: ...
    @overload
    def __getitem__(
        self,
        item: slice
        | SeriesCompatible[K2, bool]
        | DataFrame[K, K2, bool]
        | SeriesCompatible[Any, K],
        /,
    ) -> DataFrame[K, K2, V]: ...
    @overload
    def __getitem__(
        self,
        item: DataFrameLike[K, K2, bool],
        /,
    ) -> DataFrame[K, K2, V | float]: ...
    @overload
    def __setitem__(
        self,
        item: slice
        | K
        | SeriesCompatible[K2, bool]
        | DataFrame[K, K2, bool]
        | SeriesCompatible[Any, K],
        value: SeriesCompatible[K2, V],
        /,
    ) -> None: ...
    @overload
    def __setitem__(
        self, item: DataFrameLike[K, K2, bool], value: DataFrameLike[K, K2, V]
    ) -> None: ...
    def __delitem__(
        self,
        item: K2 | slice | SeriesCompatible[K2, bool] | SeriesCompatible[Any, K],
    ) -> None: ...
    def __lt__(
        self, other: V | SeriesCompatible[K, V] | DataFrame[K, K2, V], /
    ) -> DataFrame[K, K2, bool]: ...
    __gt__ = __lt__
    __ge__ = __lt__
    __le__ = __lt__
    def __eq__(self, other: Any, /) -> DataFrame[K, K2, bool]: ...
    def __ne__(self, other: Any, /) -> DataFrame[K, K2, bool]: ...
    @property
    def empty(self) -> bool: ...
    def any(self) -> Series[K, bool]: ...
    all = any
    def __len__(self) -> int: ...
    def __iter__(self) -> Iterator[K]: ...
    def __containes__(self, value: K, /) -> bool: ...
    @property
    def columns(self) -> Index[K]: ...
    @columns.setter
    def columns(self, value: SeriesCompatible[Any, K], /) -> None: ...
    def __array__(self) -> NDArray[V]: ...
    @overload
    def to_dict(self, orient: Literal["records"]) -> list[dict[K, V]]: ...
    @overload
    def to_dict(self, orient: Literal["dict"] = ...) -> dict[K, dict[K2, V]]: ...
    def value_counts(self, subset: Sequence[K] | None = ...) -> Series[V, V]: ...
    def rename(self, *, columns: SeriesLike[K, K3]) -> DataFrame[K | K3, K2, V]: ...
    def sort_values(self, by: K) -> DataFrame[K, K2, V]: ...
    def describe(self) -> DataFrame[K, str, Any]: ...
    def mean(self: DataFrame[K, K2, float]) -> Series[K, float]: ...
    def max(self) -> Series[K, V]: ...
    min = max
    def dropna(
        self, axis: Literal[0, 1, "index", "columns"] = ...
    ) -> DataFrame[K, K2, V]: ...
    def head(self, n: int = ...) -> DataFrame[K, K2, V]: ...
    def drop(
        self,
        labels: Sequence[str] = ...,
        *,
        axis: Literal[0, 1, "index", "columns"] = ...,
        columns: Sequence[str] = ...,
    ) -> DataFrame[K, K2, V]: ...
    def select_dtypes(
        self,
        include: Sequence[Type[Any] | Literal["object"]] | None = ...,
        exclude: Sequence[Type[Any] | Literal["object"]] | None = ...,
    ) -> DataFrame[K, K2, V]: ...
    def copy(self) -> DataFrame[K, K2, V]: ...
    @property
    def shape(self) -> tuple[int, int]: ...
    def isna(self) -> DataFrame[K, K2, bool]: ...
    isnull = isna
    def sum(self) -> Series[K2, int]: ...
    def mode(self) -> DataFrame[K, int, V]: ...
    def groupby(
        self, by: Sequence[K] = ..., *, as_index: Literal[False]
    ) -> DataFrameGroupBy[K, V]: ...
    def isin(self, values: Sequence[V]) -> DataFrame[K, K2, bool]: ...
    @overload
    def reset_index(self) -> DataFrame[K | str, int, V | K2]: ...
    @overload
    def reset_index(self, *, drop: Literal[True] = ...) -> DataFrame[K, K2, V]: ...
    @property
    def loc(self) -> LockIndexerDataFrame[K, K2, V]: ...
    @property
    def iloc(self) -> iLockIndexerDataFrame[K, K2, V]: ...
    @property
    def T(self) -> DataFrame[K2, K, V]: ...
    @property
    def plot(self) -> PlotAccessor[K]: ...
    def __or__(
        self: DataFrameLike[K, K2, I], other: DataFrameLike[K, K2, I2]
    ) -> DataFrame[K, K2, I | I2]: ...
    __and__ = __or__
    __xor__ = __and__
    def __add__(
        self: DataFrame[K, K2, C], other: DataFrameLike[K, K2, C2]
    ) -> DataFrame[K, K2, C | C2]: ...
    __sub__ = __add__
    __mul__ = __add__

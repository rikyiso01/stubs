from typing import Any, Literal, Generic, Type, overload
from typing_extensions import Unpack
from collections.abc import Iterable, Iterator, Callable, Sequence
from numpy.typing import NDArray, ArrayLike
from pandas.core.indexes.base import Index
from pandas.core.indexes.accessors import CombinedDatetimelikeProperties
from pandas.core.groupby.generic import DataFrameGroupBy
from pandas.core.strings.accessor import StringMethods
from pandas.plotting._core import PlotAccessor
from pandas.core.indexing import (
    iLockIndexerDataFrame,
    LockIndexerDataFrame,
    iLockIndexerSeries,
    LockIndexerSeries,
)
from mte.typevar import K, V, K2, I, V2, I2, K3, C, C2, T, TT
from mte.pandas import SeriesLike, SeriesCompatible, DataFrameLike
from datetime import datetime
from pandas.core.arrays.categorical import Categorical
from pandas.io.formats.style import Styler
from pandas.core.indexes.multi import MultiIndex as MultiIndex

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
    def str(self: SeriesLike[Any, str]) -> StringMethods[K]: ...
    def value_counts(
        self, subset: Sequence[K] | None = ..., normalize: bool = ..., sort: bool = ...
    ) -> Series[V, int]: ...
    @overload
    def reset_index(self) -> DataFrame[int | str, int, V | K]: ...
    @overload
    def reset_index(self, *, name: K2) -> DataFrame[K2 | str, int, V | K]: ...
    def apply(self, func: Callable[[V], V2]) -> Series[K, V2]: ...
    def mean(self: SeriesLike[K, float]) -> float: ...
    def var(self: SeriesLike[K, float]) -> float: ...
    def std(self: SeriesLike[K, float]) -> float: ...
    def median(self: SeriesLike[K, float]) -> float: ...
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
        self: SeriesLike[K, I], other: SeriesCompatible[K, I2]
    ) -> Series[K, I | I2]: ...
    __or__ = __and__
    __xor__ = __or__
    def __invert__(self: SeriesLike[K, I]) -> Series[K, I]: ...
    def mode(self) -> Series[int, V]: ...
    @property
    def iloc(self) -> iLockIndexerSeries[K, V]: ...
    @property
    def loc(self) -> LockIndexerSeries[K, V]: ...
    @overload
    def __add__(
        self: SeriesLike[K, C], other: SeriesCompatible[K, C2] | C2
    ) -> Series[K, C | C2]: ...
    @overload
    def __add__(
        self: SeriesLike[K, str], other: SeriesCompatible[K, str] | str
    ) -> Series[K, str]: ...
    def __sub__(
        self: SeriesLike[K, C], other: SeriesCompatible[K, C2] | C2
    ) -> Series[K, C | C2]: ...
    __mul__ = __sub__
    def __truediv__(
        self: SeriesLike[K, C], other: SeriesCompatible[K, C2] | C2
    ) -> Series[K, C | C2 | float]: ...
    def __floordiv__(
        self: SeriesLike[K, I], other: SeriesCompatible[K, I2] | I2
    ) -> Series[K, int]: ...
    def info(self) -> None: ...
    def fillna(self, value: Series[K, V] | V) -> Series[K, V]: ...
    def sum(self: SeriesLike[K, V]) -> int | V: ...
    @property
    def dt(self: SeriesLike[K, datetime]) -> CombinedDatetimelikeProperties[K]: ...
    def astype(self, dtype: Type[T]) -> Series[K, T]: ...
    def dropna(self) -> Series[K, V]: ...
    def sort_values(self) -> Series[K, V]: ...
    def between(
        self,
        left: V,
        right: V,
        inclusive: Literal["both", "neither", "left", "right"] = ...,
    ) -> Series[K, bool]: ...
    def unique(self) -> NDArray[V]: ...
    @overload
    def unstack(
        self: SeriesLike[tuple[K, ...], V]
    ) -> DataFrame[K, tuple[K, ...] | K, V | float]: ...
    @overload
    def unstack(
        self: SeriesLike[tuple[K, ...], V], fill_value: K2
    ) -> DataFrame[K, tuple[K, ...] | K, V | K2]: ...
    def to_numpy(self) -> NDArray[V]: ...
    @property
    def values(self) -> NDArray[V]: ...
    def sort_index(self, *, ascending: bool = ...) -> Series[K, V]: ...
    @property
    def index(self) -> Index[K]: ...
    def reindex(
        self, labels: MultiIndex[Unpack[TT]]
    ) -> Series[tuple[Unpack[TT]], V]: ...
    def notna(self) -> Series[V, bool]: ...
    notnull = notna

class DataFrame(Generic[K, K2, V]):
    @overload
    def __new__(
        cls, data: ArrayLike[V], *, dtype: Type[V] = ..., copy: bool = ...
    ) -> DataFrame[int, int, V]: ...
    @overload
    def __new__(
        cls,
        data: ArrayLike[V],
        index: Iterable[K2],
        *,
        dtype: Type[V] = ...,
        copy: bool = ...,
    ) -> DataFrame[int, K2, V]: ...
    @overload
    def __new__(
        cls,
        data: ArrayLike[V],
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
    def __contains__(self, other: K) -> bool: ...
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
    def value_counts(
        self, subset: Sequence[K] | None = ..., normalize: bool = ..., sort: bool = ...
    ) -> Series[tuple[V, ...], int]: ...
    def rename(
        self, *, columns: SeriesCompatible[K, K3]
    ) -> DataFrame[K | K3, K2, V]: ...
    def sort_values(self, by: K) -> DataFrame[K, K2, V]: ...
    def describe(self) -> DataFrame[K, str, Any]: ...
    def mean(self: DataFrameLike[K, K2, float]) -> Series[K, float]: ...
    def var(self: DataFrameLike[K, K2, float]) -> Series[K, float]: ...
    def std(self: DataFrameLike[K, K2, float]) -> Series[K, float]: ...
    def max(self) -> Series[K, V]: ...
    min = max
    def dropna(
        self,
        *,
        axis: Literal[0, 1, "index", "columns"] = ...,
        subset: K | Sequence[K] = ...,
    ) -> DataFrame[K, K2, V]: ...
    def head(self, n: int = ...) -> DataFrame[K, K2, V]: ...
    @overload
    def drop(
        self, labels: ArrayLike[K], *, axis: Literal[1, "columns"]
    ) -> DataFrame[K, K2, V]: ...
    @overload
    def drop(
        self, labels: ArrayLike[K2], *, axis: Literal[0, "index"] = ...
    ) -> DataFrame[K, K2, V]: ...
    @overload
    def drop(self, *, columns: ArrayLike[K]) -> DataFrame[K, K2, V]: ...
    @overload
    def drop(self, *, index: ArrayLike[K2]) -> DataFrame[K, K2, V]: ...
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
    def sum(self: DataFrameLike[K, K2, V]) -> Series[K2, V | int]: ...
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
    @property
    def style(self) -> Styler: ...
    def __or__(
        self: DataFrameLike[K, K2, I], other: DataFrameLike[K, K2, I2]
    ) -> DataFrame[K, K2, I | I2]: ...
    __and__ = __or__
    __xor__ = __and__
    def __add__(
        self: DataFrameLike[K, K2, C], other: DataFrameLike[K, K2, C2]
    ) -> DataFrame[K, K2, C | C2]: ...
    __sub__ = __add__
    __mul__ = __add__
    def info(self) -> None: ...
    def fillna(
        self, value: DataFrameLike[K, K2, V] | SeriesCompatible[K, V] | V = ...
    ) -> DataFrame[K, K2, V]: ...
    def drop_duplicates(self) -> DataFrame[K, K2, V]: ...
    def astype(self, dtype: Type[T]) -> DataFrame[K, K2, T]: ...
    def boxplot(self, column: str | None = ..., by: str | None = ...) -> None: ...
    def to_numpy(self) -> NDArray[V]: ...
    @property
    def values(self) -> NDArray[V]: ...
    def sort_index(self, *, ascending: bool = ...) -> DataFrame[K, K2, V]: ...
    def corr(self) -> DataFrame[K, K2, float]: ...
    @property
    def index(self) -> Index[K2]: ...
    def apply(
        self,
        func: Callable[[Series[K, V]], V2],
        axis: Literal[0, 1, "index", "columns"] = ...,
    ) -> DataFrame[K, K2, V2]: ...
    def nunique(self) -> Series[K, int]: ...
    def duplicated(
        self, subset: ArrayLike[K] = ..., keep: Literal["first", "last", False] = ...
    ) -> DataFrame[K, K2, bool]: ...
    def notna(self) -> DataFrame[K, K2, bool]: ...
    notnull = notna

@overload
def concat(objs: Iterable[DataFrameLike[K, K2, V]]) -> DataFrame[K, K2, V]: ...
@overload
def concat(objs: Iterable[Series[K, V]]) -> Series[K, V]: ...
def merge(
    left: DataFrame[K, K2, V],
    right: DataFrame[K, K2, V],
    how: Literal["inner", "outer", "left", "right"] = ...,
    on: ArrayLike[K] | None = ...,
    left_on: ArrayLike[K] | None = ...,
    right_on: ArrayLike[K] | None = ...,
) -> DataFrame[K, K2, V]: ...
def to_datetime(arg: Series[K, Any]) -> Series[K, datetime]: ...
def cut(
    x: ArrayLike[V],
    bins: ArrayLike[V],
    *,
    right: bool = ...,
    labels: ArrayLike[V2],
) -> Categorical[V2]: ...

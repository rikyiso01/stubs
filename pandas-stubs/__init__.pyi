from typing import Any, Literal, TypeVar, Generic, Type, overload
from collections.abc import Iterable, Iterator, Sequence, Callable
from pandas.core.indexes.base import Index
from numpy.typing import NDArray
from pandas.core.strings.accessor import StringMethods

_K = TypeVar("_K")
_K_contra = TypeVar("_K_contra", contravariant=True)
_K2 = TypeVar("_K2")
_K3 = TypeVar("_K3")
_V = TypeVar("_V")
_V2 = TypeVar("_V2")
_V_cov = TypeVar("_V_cov", covariant=True)

def read_csv(filepath_or_buffer: str) -> DataFrame[Any, int, Any]: ...

class Series(Generic[_K, _V]):
    @overload
    def __new__(
        cls,
        data: dict[_K, _V],
        index: Iterable[_K] = ...,
        dtype: Type[_V] = ...,
        name: str = ...,
        copy: bool = ...,
    ) -> Series[_K, _V]: ...
    @overload
    def __new__(
        cls,
        data: Iterable[_V],
        *,
        dtype: Type[_V] = ...,
        name: str = ...,
        copy: bool = ...,
    ) -> Series[int, _V]: ...
    @overload
    def __new__(
        cls,
        data: Iterable[_V],
        index: Iterable[_K],
        dtype: Type[_V] = ...,
        name: str = ...,
        copy: bool = ...,
    ) -> Series[_K, _V]: ...
    @overload
    def __getitem__(self, item: _K, /) -> _V: ...
    @overload
    def __getitem__(
        self,
        item: slice | Sequence[bool] | Series[_K, bool],
        /,
    ) -> Series[_K, _V]: ...
    @overload
    def __setitem__(self, item: _K, value: _V, /) -> None: ...
    @overload
    def __setitem__(
        self,
        item: slice | Sequence[bool] | Series[_K, bool],
        value: Sequence[_V] | Series[_K, _V],
        /,
    ) -> None: ...
    def __iter__(self) -> Iterator[_V]: ...
    def __len__(self) -> int: ...
    def __containes(self, item: _K, /) -> bool: ...
    def __lt__(
        self, other: _V | Sequence[_V] | Series[_K, _V], /
    ) -> Series[_K, bool]: ...
    __gt__ = __lt__
    __ge__ = __lt__
    __le__ = __lt__
    def __eq__(self, other: Any, /) -> Series[_K, bool]: ...
    def __ne__(self, other: Any, /) -> Series[_K, bool]: ...
    def __array__(self) -> NDArray[_V]: ...
    @property
    def str(self: Series[Any, str]) -> StringMethods[_K]: ...
    def value_counts(self, subset: Sequence[_K] | None = ...) -> Series[_V, int]: ...
    @overload
    def reset_index(self) -> DataFrame[int | str, int, _V | _K]: ...
    @overload
    def reset_index(self, *, name: _K2) -> DataFrame[_K2 | str, int, _V | _K]: ...
    def apply(self, func: Callable[[_V], _V2]) -> Series[_K, _V2]: ...

class DataFrame(Generic[_K, _K2, _V]):
    @overload
    def __new__(
        cls, data: Iterable[_V], *, dtype: Type[_V] = ..., copy: bool = ...
    ) -> DataFrame[int, int, _V]: ...
    @overload
    def __new__(
        cls,
        data: Iterable[_V],
        index: Iterable[_K2],
        *,
        dtype: Type[_V] = ...,
        copy: bool = ...,
    ) -> DataFrame[int, _K2, _V]: ...
    @overload
    def __new__(
        cls,
        data: Iterable[_V],
        *,
        columns: Iterable[_K],
        dtype: Type[_V] = ...,
        copy: bool = ...,
    ) -> DataFrame[_K, int, _V]: ...
    @overload
    def __new__(
        cls,
        data: Iterable[_V],
        index: Iterable[_K2],
        columns: Iterable[_K],
        dtype: Type[_V] = ...,
        copy: bool = ...,
    ) -> DataFrame[_K, _K2, _V]: ...
    @overload
    def __new__(
        cls,
        data: dict[_K, _V],
        *,
        columns: Iterable[_K] = ...,
        dtype: Type[_V] = ...,
        copy: bool = ...,
    ) -> DataFrame[_K, int, _V]: ...
    @overload
    def __new__(
        cls,
        data: dict[_K, _V],
        index: Iterable[_K2],
        columns: Iterable[_K] = ...,
        dtype: Type[_V] = ...,
        copy: bool = ...,
    ) -> DataFrame[_K, _K2, _V]: ...
    @overload
    def __new__(
        cls,
        data: dict[_K, dict[_K2, _V]],
        index: Iterable[_K2] = ...,
        columns: Iterable[_K] = ...,
        dtype: Type[_V] = ...,
        copy: bool = ...,
    ) -> DataFrame[_K, _K2, _V]: ...
    @overload
    def __getitem__(self, item: _K, /) -> Series[_K2, _V]: ...
    @overload
    def __getitem__(
        self,
        item: slice
        | Sequence[bool]
        | Series[_K2, bool]
        | DataFrame[_K, _K2, bool]
        | Series[Any, _K]
        | Sequence[_K],
        /,
    ) -> DataFrame[_K, _K2, _V]: ...
    @overload
    def __setitem__(
        self,
        item: slice
        | _K
        | Series[_K2, bool]
        | Sequence[bool]
        | DataFrame[_K, _K2, bool]
        | Series[Any, _K],
        value: Series[_K2, _V] | Sequence[_V],
        /,
    ) -> None: ...
    @overload
    def __setitem__(
        self, item: DataFrame[_K, _K2, bool], value: DataFrame[_K, _K2, _V]
    ) -> None: ...
    def __delitem__(
        self,
        item: _K2
        | slice
        | Series[_K2, bool]
        | Sequence[bool]
        | DataFrame[_K, _K2, bool]
        | Series[Any, _K],
    ) -> None: ...
    def __lt__(
        self, other: _V | Sequence[_V] | DataFrame[_K, _K2, _V], /
    ) -> DataFrame[_K, _K2, bool]: ...
    __gt__ = __lt__
    __ge__ = __lt__
    __le__ = __lt__
    def __eq__(self, other: Any, /) -> DataFrame[_K, _K2, bool]: ...
    def __ne__(self, other: Any, /) -> DataFrame[_K, _K2, bool]: ...
    @property
    def empty(self) -> bool: ...
    def any(self) -> Series[_K, bool]: ...
    all = any
    def __len__(self) -> int: ...
    def __iter__(self) -> Iterator[_K]: ...
    def __containes__(self, value: _K, /) -> bool: ...
    @property
    def columns(self) -> Index[_K]: ...
    def __array__(self) -> NDArray[_V]: ...
    @overload
    def to_dict(self, orient: Literal["records"]) -> list[dict[_K, _V]]: ...
    @overload
    def to_dict(self, orient: Literal["dict"] = ...) -> dict[_K, dict[_K2, _V]]: ...
    def value_counts(self, subset: Sequence[_K] | None = ...) -> Series[_V, _V]: ...
    def reset_index(self) -> DataFrame[_K | str, int, _V | _K2]: ...
    def rename(self, *, columns: dict[_K, _K3]) -> DataFrame[_K | _K3, _K2, _V]: ...
    def sort_values(self, by: _K) -> DataFrame[_K, _K2, _V]: ...

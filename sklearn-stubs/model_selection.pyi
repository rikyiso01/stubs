from numpy.typing import ArrayLike
from typing import TypeVar, Any, overload
from mte.pandas import DataFrameLike

T = TypeVar("T", bound=ArrayLike[Any] | DataFrameLike[Any, Any, Any])
V = TypeVar("V", bound=ArrayLike[Any] | DataFrameLike[Any, Any, Any])

@overload
def train_test_split(
    a: T,
    /,
    *,
    random_state: int | None = ...,
    train_size: float | None = ...,
    test_size: float | None = ...,
) -> tuple[T, T]: ...
@overload
def train_test_split(
    a: T,
    b: V,
    /,
    *,
    random_state: int | None = ...,
    train_size: float | None = ...,
    test_size: float | None = ...,
) -> tuple[T, T, V, V]: ...

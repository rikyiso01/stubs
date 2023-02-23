from numpy.typing import ArrayLike
from pandas import DataFrame
from typing import TypeVar, Any, overload

T = TypeVar("T", bound=ArrayLike[Any] | DataFrame[Any, Any, Any])
V = TypeVar("V", bound=ArrayLike[Any] | DataFrame[Any, Any, Any])

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

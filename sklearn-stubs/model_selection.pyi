from numpy.typing import ArrayLike
from typing import Any, overload
from mte.pandas import DataFrameLike

@overload
def train_test_split[
    T: ArrayLike[Any] | DataFrameLike[Any, Any, Any]
](
    a: T,
    /,
    *,
    random_state: int | None = ...,
    train_size: float | None = ...,
    test_size: float | None = ...,
) -> tuple[T, T]: ...
@overload
def train_test_split[
    T: ArrayLike[Any] | DataFrameLike[Any, Any, Any],
    V: ArrayLike[Any] | DataFrameLike[Any, Any, Any],
](
    a: T,
    b: V,
    /,
    *,
    random_state: int | None = ...,
    train_size: float | None = ...,
    test_size: float | None = ...,
) -> tuple[T, T, V, V]: ...

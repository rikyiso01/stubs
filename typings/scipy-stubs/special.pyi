from numpy.typing import ArrayLike, DTypeLike, NDArray
from typing import overload

@overload
def factorial(n: ArrayLike[DTypeLike]) -> NDArray[float]: ...
@overload
def factorial(n: DTypeLike) -> float: ...
@overload
def binom(n: DTypeLike, k: DTypeLike, /) -> float: ...
@overload
def binom(
    n: ArrayLike[DTypeLike] | DTypeLike, k: ArrayLike[DTypeLike], /
) -> NDArray[float]: ...
@overload
def binom(
    n: ArrayLike[DTypeLike], k: ArrayLike[DTypeLike] | DTypeLike, /
) -> NDArray[float]: ...

from .typing import DTypeLike, NDArray, ArrayLike
from typing import TypeVar, overload, BinaryIO, Type, Any
from pathlib import Path
import fft as fft

_T = TypeVar("_T", bound=DTypeLike)
_N = TypeVar("_N", bound=complex)

int_ = int
bool_ = bool
float_ = float
str_ = str
ndarray = NDArray
matrix = NDArray
uint8 = int

@overload
def array(object: range) -> NDArray[int]: ...
@overload
def array(object: ArrayLike[_T]) -> NDArray[_T]: ...
def sum(a: ArrayLike[_T]) -> _T: ...
def min(a: ArrayLike[_T]) -> _T: ...
def max(a: ArrayLike[_T]) -> _T: ...
def mean(a: ArrayLike[_T]) -> float: ...
def average(a: ArrayLike[_T]) -> float: ...
def var(a: ArrayLike[_T], *, ddof: int = ...) -> float: ...
def save(file: str | Path | BinaryIO, arr: ArrayLike[Any]) -> None: ...
@overload
def zeros(shape: int) -> NDArray[float]: ...
@overload
def zeros(shape: int, dtype: Type[_T]) -> NDArray[_T]: ...
@overload
def arange(stop: _T) -> NDArray[_T]: ...
@overload
def arange(start: _T, stop: _T, step: _T = ...) -> NDArray[_T]: ...
def load(file: str | Path | BinaryIO) -> NDArray[Any]: ...
def all(a: ArrayLike[_T]) -> bool: ...
def any(a: ArrayLike[_T]) -> bool: ...
def linspace(
    start: ArrayLike[_T] | _T,
    stop: ArrayLike[_T] | _T,
    num: int = ...,
) -> NDArray[float]: ...
def exp(x: ArrayLike[_T]) -> NDArray[float]: ...
def cumsum(a: ArrayLike[_T] | _T) -> NDArray[_T]: ...
def array_equal(a1: Any, a2: Any, equal_nan: bool = ...) -> bool: ...
@overload
def empty(shape: int | tuple[int, ...]) -> NDArray[float]: ...
@overload
def empty(shape: int | tuple[int, ...], dtype: Type[_T]) -> NDArray[_T]: ...
def bitwise_xor(x1: ArrayLike[int], x2: ArrayLike[int]) -> NDArray[int]: ...
def cos(x: ArrayLike[float], /) -> NDArray[float]: ...
def real(val: ArrayLike[complex]) -> NDArray[float]: ...
def imag(val: ArrayLike[complex]) -> NDArray[float]: ...
def abs(val: ArrayLike[_N]) -> NDArray[_N]: ...

pi: float

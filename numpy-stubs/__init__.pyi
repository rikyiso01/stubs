from numpy.typing import NDArray, ArrayLike, DTypeLike
from typing import (
    overload,
    BinaryIO,
    Type,
    Any,
    SupportsAbs,
    Protocol,
    Callable,
)
from pathlib import Path
from numpy import fft as fft
from numpy import linalg as linalg

int_ = int
bool_ = bool
float_ = float
float32 = float
str_ = str
ndarray = NDArray
matrix = NDArray
uint8 = int
object = Any

nan: float

class _SupportsPositive[T](Protocol):
    def __pos__(self) -> T: ...

class _SupportsNegative[T](Protocol):
    def __neg__(self) -> T: ...

class _SupportsReal[T](Protocol):
    @property
    def real(self) -> T: ...

class _SupportsImag[T](Protocol):
    @property
    def imag(self) -> T: ...

@overload
def array(object: ArrayLike[DTypeLike]) -> NDArray[DTypeLike]: ...
@overload
def array(
    object: ArrayLike[complex | str], dtype: Type[DTypeLike]
) -> NDArray[DTypeLike]: ...

asarray = array
copy = array

def sum[
    C: complex
](
    a: ArrayLike[C], axis: int | tuple[int, ...] | None = ..., dtype: Type[C] = ...
) -> NDArray[C]: ...
def min[
    C: complex
](a: ArrayLike[C], axis: int | tuple[int, ...] | None = ...) -> NDArray[C]: ...
def max[
    C: complex
](a: ArrayLike[C], axis: int | tuple[int, ...] | None = ...) -> NDArray[C]: ...
@overload
def mean[
    C: complex
](a: ArrayLike[C], axis: int | tuple[int, ...] | None = ...) -> NDArray[float | C]: ...
@overload
def mean[
    C: complex
](
    a: ArrayLike[complex], axis: int | tuple[int, ...] | None = ..., *, dtype: Type[C]
) -> NDArray[C]: ...
@overload
def mean[
    C: complex
](a: ArrayLike[complex], axis: int | tuple[int, ...] | None, dtype: Type[C]) -> NDArray[
    C
]: ...
def average[
    C: complex
](
    a: ArrayLike[C],
    axis: int | tuple[int, ...] | None = ...,
    weights: ArrayLike[float] = ...,
) -> NDArray[float | C]: ...
def var(a: ArrayLike[Any], *, ddof: int = ...) -> float: ...
def ravel[T](a: ArrayLike[T]) -> NDArray[T]: ...
def save(file: str | Path | BinaryIO, arr: ArrayLike[Any]) -> None: ...
@overload
def zeros(shape: int | tuple[int, ...]) -> NDArray[float]: ...
@overload
def zeros[T](shape: int | tuple[int, ...], dtype: Type[T]) -> NDArray[T]: ...

ones = zeros

@overload
def arange[T](stop: T) -> NDArray[T]: ...
@overload
def arange[T](start: T, stop: T, step: T = ...) -> NDArray[T]: ...
def load(file: str | Path | BinaryIO) -> NDArray[Any]: ...
def all(a: ArrayLike[Any], axis: int | None = ...) -> NDArray[bool]: ...
def any(a: ArrayLike[Any]) -> NDArray[bool]: ...
def linspace[
    T
](
    start: ArrayLike[T] | T,
    stop: ArrayLike[T] | T,
    num: int = ...,
    endpoint: bool = ...,
) -> NDArray[float]: ...
def exp[C: complex](x: ArrayLike[C]) -> NDArray[C | float]: ...
def cumsum[C: complex](a: ArrayLike[C]) -> NDArray[C]: ...
def array_equal(a1: Any, a2: Any, equal_Can: bool = ...) -> bool: ...
@overload
def empty(shape: int | tuple[int, ...]) -> NDArray[float]: ...
@overload
def empty[T](shape: int | tuple[int, ...], dtype: Type[T]) -> NDArray[T]: ...
def cos[C: complex](x: ArrayLike[C], /) -> NDArray[C | float]: ...
def sin[C](x: ArrayLike[C], /) -> NDArray[C | float]: ...
def argwhere(a: ArrayLike[Any]) -> NDArray[int]: ...
def trapz[C](y: ArrayLike[C]) -> NDArray[float | C]: ...
def convolve[
    C: complex, C2: complex
](a: ArrayLike[C], v: ArrayLike[C2]) -> NDArray[C | C2]: ...
def where(condition: ArrayLike[bool]) -> NDArray[int]: ...
def log10[C: complex](x: ArrayLike[C], /) -> NDArray[float | C]: ...
def zeros_like[T](a: ArrayLike[T]) -> NDArray[T]: ...
def sqrt[C: complex](x: ArrayLike[C], /) -> NDArray[float | C]: ...
def percentile[
    C: complex, F: float
](a: ArrayLike[C], q: ArrayLike[F]) -> NDArray[float | C]: ...
def add[
    C: complex, C2: complex
](x1: ArrayLike[C], x2: ArrayLike[C2], /) -> NDArray[C | C2]: ...
def subtract[
    C: complex, C2: complex
](x1: ArrayLike[C], x2: ArrayLike[C2], /) -> NDArray[C | C2]: ...
def multiply[
    C: complex, C2: complex
](x1: ArrayLike[C], x2: ArrayLike[C2], /) -> NDArray[C | C2]: ...
def divide[
    C: complex, C2: complex
](x1: ArrayLike[C], x2: ArrayLike[C2], /) -> NDArray[C | C2 | float]: ...
def matmul[
    C: complex, C2: complex
](x1: ArrayLike[C], x2: ArrayLike[C2], /) -> NDArray[C | C2]: ...
def floor_divide[
    F: float, F2: float
](x1: ArrayLike[F], x2: ArrayLike[F2], /) -> NDArray[F | F2]: ...
def power[
    C: complex, C2: complex
](x1: ArrayLike[C], x2: ArrayLike[C2], /) -> NDArray[C | C2]: ...
def bitwise_xor[
    I: int, I2: int
](x1: ArrayLike[I], x2: ArrayLike[I2], /) -> NDArray[I | I2]: ...
def dot[
    C: complex, C2: complex
](a: ArrayLike[C], b: ArrayLike[C2]) -> NDArray[C | C2]: ...
def resize[T](a: ArrayLike[T], new_shape: int | tuple[int, ...]) -> NDArray[T]: ...

bitwise_and = bitwise_xor
bitwise_or = bitwise_xor

def divmod[
    F: float, F2: float
](x1: ArrayLike[F], x2: ArrayLike[F2], /) -> tuple[
    NDArray[F | F2], NDArray[F | F2]
]: ...
def mod[
    F: float, F2: float
](x1: ArrayLike[F], x2: ArrayLike[F2], /) -> NDArray[F | F2]: ...
def less(x1: ArrayLike[complex], x2: ArrayLike[complex], /) -> NDArray[bool]: ...
def equal(x1: Any, x2: Any, /) -> NDArray[bool]: ...

not_equal = equal

less_equal = less
greater = less
greater_equal = less

def positive[T](x: ArrayLike[_SupportsPositive[T]], /) -> NDArray[T]: ...
def negative[T](x: ArrayLike[_SupportsNegative[T]], /) -> NDArray[T]: ...
def absolute[C: complex](x: ArrayLike[SupportsAbs[C]], /) -> NDArray[C]: ...

abs = absolute

def invert[I: int](x: ArrayLike[I], /) -> NDArray[I]: ...
def shape(a: ArrayLike[Any]) -> tuple[int, ...]: ...
def size(a: ArrayLike[Any]) -> int: ...
def real[T](val: ArrayLike[_SupportsReal[T]]) -> NDArray[T]: ...
def imag[T](val: ArrayLike[_SupportsImag[T]]) -> NDArray[T]: ...

pi: float

newaxis = None

def apply_along_axis[
    T, *TT, T2
](
    func1d: Callable[[NDArray[T], *TT], ArrayLike[T2]],
    axis: int,
    arr: NDArray[T],
    *args: *TT,
) -> NDArray[T2]: ...
def repeat[
    T
](a: ArrayLike[T], repeats: ArrayLike[int], axis: int | None = ...) -> NDArray[T]: ...
def rint(x: ArrayLike[float], /) -> NDArray[int]: ...
def histogram(
    a: ArrayLike[float], bins: int = ...
) -> tuple[NDArray[int], NDArray[float]]: ...
def reshape[T](a: ArrayLike[T], newshape: tuple[int, ...] | int) -> NDArray[T]: ...
@overload
def logspace(
    start: float, stop: float, num: int = ..., endpoint: bool = ..., base: float = ...
) -> NDArray[float]: ...
@overload
def logspace[
    C: complex
](
    start: float,
    stop: float,
    num: int = ...,
    endpoint: bool = ...,
    base: float = ...,
    *,
    dtype: type[C],
) -> NDArray[C]: ...

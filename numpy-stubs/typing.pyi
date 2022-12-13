from typing import Generic, TypeVar, Protocol, Any, Type
from collections.abc import Iterator, Sequence
from numpy import (
    min as _min,
    max as _max,
    sum as _sum,
    mean as _mean,
    var as _var,
    all as _all,
    any as _any,
    ravel as _ravel,
    cumsum as _cumsum,
    add,
    subtract,
    multiply,
    divide,
    matmul,
    floor_divide,
    mod,
    bitwise_xor,
    bitwise_and,
    bitwise_or,
    divmod,
    less,
    greater,
    less_equal,
    greater_equal,
    positive,
    negative,
    absolute,
    invert,
    power,
    repeat as _repeat,
)

DTypeLike = TypeVar("DTypeLike", bound=complex | str)

_T = TypeVar("_T")
_T2 = TypeVar("_T2")
_T_cov = TypeVar("_T_cov", covariant=True)

class _Array(Protocol[_T_cov]):
    def __array__(self) -> _NDArray[_T_cov]: ...

class _NDArray(Generic[_T_cov]):
    def __array__(self) -> NDArray[_T_cov]: ...

class _SupportsReal(Protocol[_T_cov]):
    @property
    def real(self) -> _T_cov: ...

class _SupportsImag(Protocol[_T_cov]):
    @property
    def imag(self) -> _T_cov: ...

ArrayLike = Sequence[ArrayLike[_T]] | _Array[_T] | _T

class NDArray(Generic[_T], _NDArray[_T]):
    def __array__(self) -> NDArray[_T]: ...
    min = _min
    max = _max
    sum = _sum
    mean = _mean
    var = _var
    all = _all
    any = _any
    ravel = _ravel
    cumsum = _cumsum
    __add__ = add
    __radd__ = add
    __sub__ = subtract
    __rsub__ = subtract
    __mul__ = multiply
    __rmul__ = multiply
    __truediv__ = divide
    __rtruediv__ = divide
    __matmul__ = matmul
    __rmatmul__ = matmul
    __floordiv__ = floor_divide
    __rfloordiv__ = floor_divide
    __mod__ = mod
    __rmod__ = mod
    __pow__ = power
    __rpow__ = power
    __and__ = bitwise_and
    __rand__ = bitwise_and
    __xor__ = bitwise_xor
    __rxor__ = bitwise_xor
    __or__ = bitwise_or
    __ror__ = bitwise_or
    __divmod__ = divmod
    __rdivmod__ = divmod
    __lt__ = less
    __gt__ = greater
    __le__ = less_equal
    __ge__ = greater_equal
    def __eq__(self, other: Any) -> NDArray[bool]: ...
    def __ne__(self, other: Any) -> NDArray[bool]: ...
    __pos__ = positive
    __neg__ = negative
    __abs__ = absolute
    __invert__ = invert
    def __bytes__(self: _NDArray[int]) -> bytes: ...
    def __len__(self) -> int: ...
    def __getitem__(self, key: ArrayLike[int | slice | None], /) -> NDArray[_T]: ...
    def __setitem__(
        self, key: ArrayLike[slice | int | None], value: ArrayLike[_T], /
    ) -> None: ...
    def __iter__(self) -> Iterator[_T]: ...
    def __containes__(self, other: Any) -> bool: ...
    def __bool__(self) -> bool: ...
    def __int__(self: _NDArray[float]) -> int: ...
    def __complex__(self: _NDArray[complex]) -> complex: ...
    def __float__(self: _NDArray[float]) -> float: ...
    def __supportsIndex__(self: _NDArray[int]) -> int: ...
    @property
    def shape(self) -> tuple[int, ...]: ...
    @property
    def size(self) -> int: ...
    def astype(self, dtype: Type[_T2]) -> NDArray[_T2]: ...
    @property
    def real(self: _NDArray[_SupportsReal[_T]]) -> NDArray[_T]: ...
    @property
    def imag(self: _NDArray[_SupportsImag[_T]]) -> NDArray[_T]: ...
    def copy(self) -> NDArray[_T]: ...
    @property
    def T(self) -> NDArray[_T]: ...
    repeat = _repeat

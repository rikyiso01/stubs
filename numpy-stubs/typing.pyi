from typing import Generic, Any, Type, TypeVar
from collections.abc import Iterator
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
    reshape as _reshape,
)
from mte.protocols import SupportsReal, SupportsImag
from mte.typevar import T, T2
from mte.numpy import Array, BaseNDArray, ArrayLike as ArrayLike

DTypeLike = TypeVar("DTypeLike", bound=complex | str)

class NDArray(Generic[T], BaseNDArray[T]):
    def __array__(self) -> NDArray[T]: ...
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
    def __bytes__(self: Array[int]) -> bytes: ...
    def __len__(self) -> int: ...
    def __getitem__(self, key: ArrayLike[int | slice | None], /) -> NDArray[T]: ...
    def __setitem__(
        self, key: ArrayLike[slice | int | None], value: ArrayLike[T], /
    ) -> None: ...
    def __iter__(self) -> Iterator[NDArray[T]]: ...
    def __containes__(self, other: Any) -> bool: ...
    def __bool__(self) -> bool: ...
    def __int__(self: Array[float]) -> int: ...
    def __complex__(self: Array[complex]) -> complex: ...
    def __float__(self: Array[float]) -> float: ...
    def __supportsIndex__(self: Array[int]) -> int: ...
    @property
    def shape(self) -> tuple[int, ...]: ...
    @property
    def size(self) -> int: ...
    def astype(self, dtype: Type[T2]) -> NDArray[T2]: ...
    @property
    def real(self: Array[SupportsReal[T]]) -> NDArray[T]: ...
    @property
    def imag(self: Array[SupportsImag[T]]) -> NDArray[T]: ...
    def copy(self) -> NDArray[T]: ...
    @property
    def T(self) -> NDArray[T]: ...
    repeat = _repeat
    def tolist(self) -> list[T]: ...
    reshape = _reshape

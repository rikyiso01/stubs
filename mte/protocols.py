from __future__ import annotations
from typing import runtime_checkable, Protocol, Type
from typing_extensions import Self, TypeAlias
from types import TracebackType


@runtime_checkable
class SupportsLt[T](Protocol):
    def __lt__(self, other: T, /) -> bool:
        ...


@runtime_checkable
class SupportsLe[T](Protocol):
    def __le__(self, other: T, /) -> bool:
        ...


@runtime_checkable
class SupportsGe[T](Protocol):
    def __ge__(self, other: T, /) -> bool:
        ...


@runtime_checkable
class SupportsGt[T](Protocol):
    def __gt__(self, other: T, /) -> bool:
        ...


@runtime_checkable
class OrderedLt(Protocol):
    def __lt__(self, other: Self, /) -> bool:
        ...


@runtime_checkable
class OrderedLe(Protocol):
    def __le__(self, other: Self, /) -> bool:
        ...


@runtime_checkable
class OrderedGt(Protocol):
    def __gt__(self, other: Self, /) -> bool:
        ...


@runtime_checkable
class OrderedGe(Protocol):
    def __ge__(self, other: Self, /) -> bool:
        ...


SupportsRichComparison: TypeAlias = "OrderedLt | OrderedGt"


@runtime_checkable
class SupportsGetAttr[T](Protocol):
    def __getattr__(self, name: str, /) -> T:
        ...


@runtime_checkable
class SupportsGetItem[T, V](Protocol):
    def __getitem__(self, item: T, /) -> V:
        ...


@runtime_checkable
class SupportsSetItem[T, V](Protocol):
    def __setitem__(self, item: T, /) -> V:
        ...


@runtime_checkable
class SupportsDelItem[T, V](Protocol):
    def __delitem__(self, item: T, /) -> V:
        ...


@runtime_checkable
class SupportsAdd[T, V](Protocol):
    def __add__(self, other: T, /) -> V:
        ...


@runtime_checkable
class SupportsSub[T, V](Protocol):
    def __sub__(self, other: T, /) -> V:
        ...


@runtime_checkable
class SupportsMul[T, V](Protocol):
    def __mul__(self, other: T, /) -> V:
        ...


@runtime_checkable
class SupportsMatMul[T, V](Protocol):
    def __matmul__(self, other: T, /) -> V:
        ...


@runtime_checkable
class SupportsTrueDiv[T, V](Protocol):
    def __truediv__(self, other: T, /) -> V:
        ...


@runtime_checkable
class SupportsFloorDiv[T, V](Protocol):
    def __floordiv__(self, other: T, /) -> V:
        ...


@runtime_checkable
class SupportsMod[T, V](Protocol):
    def __mod__(self, other: T, /) -> V:
        ...


@runtime_checkable
class SupportsDivMod[T, V](Protocol):
    def __divmod__(self, other: T, /) -> V:
        ...


@runtime_checkable
class SupportsPow[T, T2, V](Protocol):
    def __pow__(self, other: T, modulo: T2, /) -> V:
        ...


@runtime_checkable
class SupportsRshift[T, V](Protocol):
    def __rshift__(self, other: T, /) -> V:
        ...


@runtime_checkable
class SupportsLshift[T, V](Protocol):
    def __lshift__(self, other: T, /) -> V:
        ...


@runtime_checkable
class SupportsAnd[T, V](Protocol):
    def __and__(self, other: T, /) -> V:
        ...


@runtime_checkable
class SupportsOr[T, V](Protocol):
    def __or__(self, other: T, /) -> V:
        ...


@runtime_checkable
class SupportsXor[T, V](Protocol):
    def __xor__(self, other: T, /) -> V:
        ...


@runtime_checkable
class SupportsRAdd[T, V](Protocol):
    def __radd__(self, other: T, /) -> V:
        ...


@runtime_checkable
class SupportsRSub[T, V](Protocol):
    def __rsub__(self, other: T, /) -> V:
        ...


@runtime_checkable
class SupportsRMul[T, V](Protocol):
    def __rmul__(self, other: T, /) -> V:
        ...


@runtime_checkable
class SupportsRMatMul[T, V](Protocol):
    def __rmatmul__(self, other: T, /) -> V:
        ...


@runtime_checkable
class SupportsRTrueDiv[T, V](Protocol):
    def __rtruediv__(self, other: T, /) -> V:
        ...


@runtime_checkable
class SupportsRFloorDiv[T, V](Protocol):
    def __rfloordiv__(self, other: T, /) -> V:
        ...


@runtime_checkable
class SupportsRMod[T, V](Protocol):
    def __rmod__(self, other: T, /) -> V:
        ...


@runtime_checkable
class SupportsRDivMod[T, V](Protocol):
    def __rdivmod__(self, other: T, /) -> V:
        ...


@runtime_checkable
class SupportsRPow[T, T2, V](Protocol):
    def __rpow__(self, other: T, modulo: T2, /) -> V:
        ...


@runtime_checkable
class SupportsRRshift[T, V](Protocol):
    def __rrshift__(self, other: T, /) -> V:
        ...


@runtime_checkable
class SupportsRLshift[T, V](Protocol):
    def __rlshift__(self, other: T, /) -> V:
        ...


@runtime_checkable
class SupportsRAnd[T, V](Protocol):
    def __rand__(self, other: T, /) -> V:
        ...


@runtime_checkable
class SupportsROr[T, V](Protocol):
    def __ror__(self, other: T, /) -> V:
        ...


@runtime_checkable
class SupportsRXor[T, V](Protocol):
    def __rxor__(self, other: T, /) -> V:
        ...


@runtime_checkable
class SupportsIAdd[T](Protocol):
    def __iadd__(self, other: T, /) -> Self:
        ...


@runtime_checkable
class SupportsISub[T](Protocol):
    def __isub__(self, other: T, /) -> Self:
        ...


@runtime_checkable
class SupportsIMul[T](Protocol):
    def __imul__(self, other: T, /) -> Self:
        ...


@runtime_checkable
class SupportsIMatMul[T](Protocol):
    def __imatmul__(self, other: T, /) -> Self:
        ...


@runtime_checkable
class SupportsITrueDiv[T](Protocol):
    def __itruediv__(self, other: T, /) -> Self:
        ...


@runtime_checkable
class SupportsIFloorDiv[T](Protocol):
    def __ifloordiv__(self, other: T, /) -> Self:
        ...


@runtime_checkable
class SupportsIMod[T](Protocol):
    def __rmod__(self, other: T, /) -> Self:
        ...


@runtime_checkable
class SupportsIDivMod[T](Protocol):
    def __rdivmod__(self, other: T, /) -> Self:
        ...


@runtime_checkable
class SupportsIPow[T, T2](Protocol):
    def __rpow__(self, other: T, modulo: T2, /) -> Self:
        ...


@runtime_checkable
class SupportsIRshift[T](Protocol):
    def __irshift__(self, other: T, /) -> Self:
        ...


@runtime_checkable
class SupportsILshift[T](Protocol):
    def __ilshift__(self, other: T, /) -> Self:
        ...


@runtime_checkable
class SupportsIAnd[T](Protocol):
    def __iand__(self, other: T, /) -> Self:
        ...


@runtime_checkable
class SupportsIOr[T](Protocol):
    def __ior__(self, other: T, /) -> Self:
        ...


@runtime_checkable
class SupportsIXor[T](Protocol):
    def __ixor__(self, other: T, /) -> Self:
        ...


@runtime_checkable
class SupportsNeg[T](Protocol):
    def __neg__(self) -> T:
        ...


@runtime_checkable
class SupportsPos[T](Protocol):
    def __pos__(self) -> T:
        ...


@runtime_checkable
class SupportsInvert[T](Protocol):
    def __invert__(self) -> T:
        ...


@runtime_checkable
class SupportsTrunc[T](Protocol):
    def __trunc__(self) -> T:
        ...


@runtime_checkable
class SupportsFloor[T](Protocol):
    def __floor__(self) -> T:
        ...


@runtime_checkable
class SupportsCeil[T](Protocol):
    def __ceil__(self) -> T:
        ...


@runtime_checkable
class SupportsEnter[T](Protocol):
    def __enter__(self) -> T:
        ...


@runtime_checkable
class SupportsExit(Protocol):
    def __exit__(
        self,
        exc_type: Type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
        /,
    ) -> bool | None:
        ...


@runtime_checkable
class ContextManager[T](SupportsEnter[T], SupportsExit, Protocol):
    ...


@runtime_checkable
class SupportsAEnter[T](Protocol):
    async def __aenter__(self) -> T:
        ...


@runtime_checkable
class SupportsAExit(Protocol):
    async def __aexit__(
        self,
        exc_type: Type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
        /,
    ) -> bool | None:
        ...


@runtime_checkable
class AsyncContextManager[T](SupportsAEnter[T], SupportsAExit, Protocol):
    ...


class SupportsReal[T](Protocol):
    @property
    def real(self) -> T:
        ...


class SupportsImag[T](Protocol):
    @property
    def imag(self) -> T:
        ...

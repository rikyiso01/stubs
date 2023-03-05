from __future__ import annotations
from typing import runtime_checkable, Protocol, Type
from typing_extensions import Self, TypeAlias
from mte.typevar import T_con, V_co, T_co, T2_con
from types import TracebackType


@runtime_checkable
class SupportsLt(Protocol[T_con]):
    def __lt__(self, other: T_con, /) -> bool:
        ...


@runtime_checkable
class SupportsLe(Protocol[T_con]):
    def __le__(self, other: T_con, /) -> bool:
        ...


@runtime_checkable
class SupportsGe(Protocol[T_con]):
    def __ge__(self, other: T_con, /) -> bool:
        ...


@runtime_checkable
class SupportsGt(Protocol[T_con]):
    def __gt__(self, other: T_con, /) -> bool:
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
class SupportsGetAttr(Protocol[T_co]):
    def __getattr__(self, name: str, /) -> T_co:
        ...


@runtime_checkable
class SupportsGetItem(Protocol[T_con, V_co]):
    def __getitem__(self, item: T_con, /) -> V_co:
        ...


@runtime_checkable
class SupportsSetItem(Protocol[T_con, V_co]):
    def __setitem__(self, item: T_con, /) -> V_co:
        ...


@runtime_checkable
class SupportsDelItem(Protocol[T_con, V_co]):
    def __delitem__(self, item: T_con, /) -> V_co:
        ...


@runtime_checkable
class SupportsAdd(Protocol[T_con, V_co]):
    def __add__(self, other: T_con, /) -> V_co:
        ...


@runtime_checkable
class SupportsSub(Protocol[T_con, V_co]):
    def __sub__(self, other: T_con, /) -> V_co:
        ...


@runtime_checkable
class SupportsMul(Protocol[T_con, V_co]):
    def __mul__(self, other: T_con, /) -> V_co:
        ...


@runtime_checkable
class SupportsMatMul(Protocol[T_con, V_co]):
    def __matmul__(self, other: T_con, /) -> V_co:
        ...


@runtime_checkable
class SupportsTrueDiv(Protocol[T_con, V_co]):
    def __truediv__(self, other: T_con, /) -> V_co:
        ...


@runtime_checkable
class SupportsFloorDiv(Protocol[T_con, V_co]):
    def __floordiv__(self, other: T_con, /) -> V_co:
        ...


@runtime_checkable
class SupportsMod(Protocol[T_con, V_co]):
    def __mod__(self, other: T_con, /) -> V_co:
        ...


@runtime_checkable
class SupportsDivMod(Protocol[T_con, V_co]):
    def __divmod__(self, other: T_con, /) -> V_co:
        ...


@runtime_checkable
class SupportsPow(Protocol[T_con, T2_con, V_co]):
    def __pow__(self, other: T_con, modulo: T2_con, /) -> V_co:
        ...


@runtime_checkable
class SupportsRshift(Protocol[T_con, V_co]):
    def __rshift__(self, other: T_con, /) -> V_co:
        ...


@runtime_checkable
class SupportsLshift(Protocol[T_con, V_co]):
    def __lshift__(self, other: T_con, /) -> V_co:
        ...


@runtime_checkable
class SupportsAnd(Protocol[T_con, V_co]):
    def __and__(self, other: T_con, /) -> V_co:
        ...


@runtime_checkable
class SupportsOr(Protocol[T_con, V_co]):
    def __or__(self, other: T_con, /) -> V_co:
        ...


@runtime_checkable
class SupportsXor(Protocol[T_con, V_co]):
    def __xor__(self, other: T_con, /) -> V_co:
        ...


@runtime_checkable
class SupportsRAdd(Protocol[T_con, V_co]):
    def __radd__(self, other: T_con, /) -> V_co:
        ...


@runtime_checkable
class SupportsRSub(Protocol[T_con, V_co]):
    def __rsub__(self, other: T_con, /) -> V_co:
        ...


@runtime_checkable
class SupportsRMul(Protocol[T_con, V_co]):
    def __rmul__(self, other: T_con, /) -> V_co:
        ...


@runtime_checkable
class SupportsRMatMul(Protocol[T_con, V_co]):
    def __rmatmul__(self, other: T_con, /) -> V_co:
        ...


@runtime_checkable
class SupportsRTrueDiv(Protocol[T_con, V_co]):
    def __rtruediv__(self, other: T_con, /) -> V_co:
        ...


@runtime_checkable
class SupportsRFloorDiv(Protocol[T_con, V_co]):
    def __rfloordiv__(self, other: T_con, /) -> V_co:
        ...


@runtime_checkable
class SupportsRMod(Protocol[T_con, V_co]):
    def __rmod__(self, other: T_con, /) -> V_co:
        ...


@runtime_checkable
class SupportsRDivMod(Protocol[T_con, V_co]):
    def __rdivmod__(self, other: T_con, /) -> V_co:
        ...


@runtime_checkable
class SupportsRPow(Protocol[T_con, T2_con, V_co]):
    def __rpow__(self, other: T_con, modulo: T2_con, /) -> V_co:
        ...


@runtime_checkable
class SupportsRRshift(Protocol[T_con, V_co]):
    def __rrshift__(self, other: T_con, /) -> V_co:
        ...


@runtime_checkable
class SupportsRLshift(Protocol[T_con, V_co]):
    def __rlshift__(self, other: T_con, /) -> V_co:
        ...


@runtime_checkable
class SupportsRAnd(Protocol[T_con, V_co]):
    def __rand__(self, other: T_con, /) -> V_co:
        ...


@runtime_checkable
class SupportsROr(Protocol[T_con, V_co]):
    def __ror__(self, other: T_con, /) -> V_co:
        ...


@runtime_checkable
class SupportsRXor(Protocol[T_con, V_co]):
    def __rxor__(self, other: T_con, /) -> V_co:
        ...


@runtime_checkable
class SupportsIAdd(Protocol[T_con]):
    def __iadd__(self, other: T_con, /) -> Self:
        ...


@runtime_checkable
class SupportsISub(Protocol[T_con]):
    def __isub__(self, other: T_con, /) -> Self:
        ...


@runtime_checkable
class SupportsIMul(Protocol[T_con]):
    def __imul__(self, other: T_con, /) -> Self:
        ...


@runtime_checkable
class SupportsIMatMul(Protocol[T_con]):
    def __imatmul__(self, other: T_con, /) -> Self:
        ...


@runtime_checkable
class SupportsITrueDiv(Protocol[T_con]):
    def __itruediv__(self, other: T_con, /) -> Self:
        ...


@runtime_checkable
class SupportsIFloorDiv(Protocol[T_con]):
    def __ifloordiv__(self, other: T_con, /) -> Self:
        ...


@runtime_checkable
class SupportsIMod(Protocol[T_con]):
    def __rmod__(self, other: T_con, /) -> Self:
        ...


@runtime_checkable
class SupportsIDivMod(Protocol[T_con]):
    def __rdivmod__(self, other: T_con, /) -> Self:
        ...


@runtime_checkable
class SupportsIPow(Protocol[T_con, T2_con]):
    def __rpow__(self, other: T_con, modulo: T2_con, /) -> Self:
        ...


@runtime_checkable
class SupportsIRshift(Protocol[T_con]):
    def __irshift__(self, other: T_con, /) -> Self:
        ...


@runtime_checkable
class SupportsILshift(Protocol[T_con, V_co]):
    def __ilshift__(self, other: T_con, /) -> Self:
        ...


@runtime_checkable
class SupportsIAnd(Protocol[T_con, V_co]):
    def __iand__(self, other: T_con, /) -> Self:
        ...


@runtime_checkable
class SupportsIOr(Protocol[T_con, V_co]):
    def __ior__(self, other: T_con, /) -> Self:
        ...


@runtime_checkable
class SupportsIXor(Protocol[T_con, V_co]):
    def __ixor__(self, other: T_con, /) -> Self:
        ...


@runtime_checkable
class SupportsNeg(Protocol[T_co]):
    def __neg__(self) -> T_co:
        ...


@runtime_checkable
class SupportsPos(Protocol[T_co]):
    def __pos__(self) -> T_co:
        ...


@runtime_checkable
class SupportsInvert(Protocol[T_co]):
    def __invert__(self) -> T_co:
        ...


@runtime_checkable
class SupportsTrunc(Protocol[T_co]):
    def __trunc__(self) -> T_co:
        ...


@runtime_checkable
class SupportsFloor(Protocol[T_co]):
    def __floor__(self) -> T_co:
        ...


@runtime_checkable
class SupportsCeil(Protocol[T_co]):
    def __ceil__(self) -> T_co:
        ...


@runtime_checkable
class SupportsEnter(Protocol[T_co]):
    def __enter__(self) -> T_co:
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
class ContextManager(SupportsEnter[T_co], SupportsExit, Protocol[T_co]):
    ...


@runtime_checkable
class SupportsAEnter(Protocol[T_co]):
    async def __aenter__(self) -> T_co:
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
class AsyncContextManager(SupportsAEnter[T_co], SupportsAExit, Protocol[T_co]):
    ...


class SupportsReal(Protocol[T_co]):
    @property
    def real(self) -> T_co:
        ...


class SupportsImag(Protocol[T_co]):
    @property
    def imag(self) -> T_co:
        ...

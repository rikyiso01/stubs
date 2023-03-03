from __future__ import annotations
from typing import runtime_checkable, Protocol
from typing_extensions import Self, Unpack
from mte.typevar import T_con, V_co, TT, T_co, V


@runtime_checkable
class SupportsLt(Protocol[T_con]):
    def __lt__(self, other: T_con, /) -> bool:
        ...


@runtime_checkable
class SupportsGe(Protocol[T_con]):
    def __get__(self, other: T_con, /) -> bool:
        ...


@runtime_checkable
class OrderedLt(Protocol):
    def __lt__(self, other: Self, /) -> bool:
        ...


@runtime_checkable
class OrderedGt(Protocol):
    def __gt__(self, other: Self, /) -> bool:
        ...


SupportsRichComparison = OrderedLt | OrderedGt


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
class SupportsLen(Protocol):
    def __len__(self) -> int:
        ...


@runtime_checkable
class Sized(SupportsLen, Protocol):
    ...


@runtime_checkable
class SupportsCall(Protocol[Unpack[TT], V_co]):
    def __call__(self, *args: Unpack[TT]) -> V_co:
        ...


@runtime_checkable
class SupportsGetItem(Protocol[T_con, V_co]):
    def __getitem__(self, item: T_con, /) -> V_co:
        ...


class SupportsReal(Protocol[T_co]):
    @property
    def real(self) -> T_co:
        ...


class SupportsImag(Protocol[T_co]):
    @property
    def imag(self) -> T_co:
        ...


class Function(Protocol[Unpack[TT]]):
    def __call__(self: Function[Unpack[TT], V], *args: Unpack[TT]) -> V:
        ...

from __future__ import annotations
from typing import (
    runtime_checkable,
    Protocol,
    SupportsFloat,
    SupportsInt,
    overload,
    Self,
)


@runtime_checkable
class Number(Protocol):
    def __add__(self: Self, other: Self, /) -> Self:
        ...

    def __sub__(self: Self, other: Self, /) -> Self:
        ...

    def __mul__(self: Self, other: Self, /) -> Self:
        ...

    def __neg__(self: Self) -> Self:
        ...

    def __truediv__(self: Self, other: Self, /) -> Self | Real:
        ...

    def __pow__(self: Self, other: Self, /) -> Self | Real:
        ...


@runtime_checkable
class Complex(Number, Protocol):
    def conjugate(self) -> Complex:
        ...

    @property
    def real(self) -> Real:
        ...

    @property
    def imag(self) -> Real:
        ...


@runtime_checkable
class Real(Complex, SupportsFloat, Protocol):
    def __lt__(self: Self, other: Self, /) -> bool:
        ...

    def __le__(self: Self, other: Self, /) -> bool:
        ...

    def __gt__(self: Self, other: Self, /) -> bool:
        ...

    def __ge__(self: Self, other: Self, /) -> bool:
        ...

    def __abs__(self: Self) -> Self:
        ...

    def __round__(self) -> Integer:
        ...

    def __trunc__(self) -> Integer:
        ...

    def __floor__(self) -> Integer:
        ...

    def __ceil__(self) -> Integer:
        ...


@runtime_checkable
class Rational(Real, Protocol):
    @property
    def numerator(self) -> int:
        ...

    @property
    def denominator(self) -> int:
        ...


@runtime_checkable
class Integer(Rational, SupportsInt, Protocol):
    def __floordiv__(self: Self, other: Self, /) -> Self:
        ...

    def __mod__(self: Self, other: Self, /) -> Self:
        ...

    def __divmod__(self: Self, other: Self, /) -> tuple[Self, Self]:
        ...

    @overload
    def __pow__(self: Self, other: Self, modulus: Self, /) -> Self | Real:
        ...

    @overload
    def __pow__(self: Self, other: Self, /) -> Self | Real:
        ...

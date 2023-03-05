from __future__ import annotations
from typing import runtime_checkable, Protocol, SupportsFloat, SupportsInt, overload
from mte.typevar import T


@runtime_checkable
class Number(Protocol):
    def __add__(self: T, other: T, /) -> T:
        ...

    def __sub__(self: T, other: T, /) -> T:
        ...

    def __mul__(self: T, other: T, /) -> T:
        ...

    def __neg__(self: T) -> T:
        ...

    def __truediv__(self: T, other: T, /) -> T | Real:
        ...

    def __pow__(self: T, other: T, /) -> T | Real:
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
    def __lt__(self: T, other: T, /) -> bool:
        ...

    def __le__(self: T, other: T, /) -> bool:
        ...

    def __gt__(self: T, other: T, /) -> bool:
        ...

    def __ge__(self: T, other: T, /) -> bool:
        ...

    def __abs__(self: T) -> T:
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
    def __floordiv__(self: T, other: T, /) -> T:
        ...

    def __mod__(self: T, other: T, /) -> T:
        ...

    def __divmod__(self: T, other: T, /) -> tuple[T, T]:
        ...

    @overload
    def __pow__(self: T, other: T, modulus: T, /) -> T | Real:
        ...

    @overload
    def __pow__(self: T, other: T, /) -> T | Real:
        ...

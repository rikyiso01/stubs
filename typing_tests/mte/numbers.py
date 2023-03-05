from typing import cast
from typing_extensions import assert_type
from mte.numbers import Number, Rational, Real, Integer, Complex

n: Number = 5j
n: Number = 5.0
n: Number = 5
c: Complex = 5j
c: Complex = 5.0
c: Complex = 5
r: Real = 5.0
r: Real = 5
ra: Rational = 5
i: Integer = 5

n = cast(Number, n)
c = cast(Complex, c)
r = cast(Real, r)
ra = cast(Rational, ra)
i = cast(Integer, i)

assert_type(n + c, Number)
assert_type(c + r, Complex)
assert_type(r + ra, Real)
assert_type(ra + i, Rational)

assert_type(n + n, Number)
assert_type(c + c, Complex)
assert_type(r + r, Real)
assert_type(ra + ra, Rational)
assert_type(i + i, Integer)

assert_type(n + r, Number)
assert_type(c + ra, Complex)
assert_type(r + i, Real)

assert_type(n + ra, Number)
assert_type(c + i, Complex)

assert_type(n + i, Number)

print(isinstance("lol", Number))

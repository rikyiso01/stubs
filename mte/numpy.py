from __future__ import annotations
from typing import Protocol
from collections.abc import Sequence


class Array[T](Protocol):
    def __array__(self) -> BaseNDArray[T]:
        ...


class BaseNDArray[T]:
    def __array__(self) -> BaseNDArray[T]:
        ...


type ArrayLike[T] = Sequence[ArrayLike[T]] | Array[T] | T

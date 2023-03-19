from __future__ import annotations
from typing import Protocol, Generic
from typing_extensions import TypeAlias
from collections.abc import Sequence
from mte.typevar import T_co, T


class Array(Protocol[T_co]):
    def __array__(self) -> BaseNDArray[T_co]:
        ...


class BaseNDArray(Generic[T_co]):
    def __array__(self) -> BaseNDArray[T_co]:
        ...


ArrayLike: TypeAlias = "Sequence[ArrayLike[T]] | Array[T] | T"

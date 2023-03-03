from __future__ import annotations
from typing import Protocol, Generic
from mte.typevar import T_co


class Array(Protocol[T_co]):
    def __array__(self) -> BaseNDArray[T_co]:
        ...


class BaseNDArray(Generic[T_co]):
    def __array__(self) -> BaseNDArray[T_co]:
        ...

from pandas import Series
from typing import Generic
from mte.typevar import T

class StringMethods(Generic[T]):
    def contains(self, pat: str) -> Series[T, bool]: ...
    def split(self, pat: str = ...) -> Series[T, list[str]]: ...

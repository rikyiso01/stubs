from pandas import Series
from typing import Generic, TypeVar

_T = TypeVar("_T")

class StringMethods(Generic[_T]):
    def contains(self, pat: str) -> Series[_T, bool]: ...
    def split(self, pat: str = ...) -> Series[_T, list[str]]: ...

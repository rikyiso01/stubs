from typing import overload
from numpy.typing import ArrayLike

class MultiIndex[*TT]:
    @overload
    @staticmethod
    def from_product[
        T, T2
    ](iterables: tuple[ArrayLike[T], ArrayLike[T2]]) -> MultiIndex[T, T2]: ...
    @overload
    @staticmethod
    def from_product[
        T, T2, T3
    ](iterables: tuple[ArrayLike[T], ArrayLike[T2], ArrayLike[T3]]) -> MultiIndex[
        T, T2, T3
    ]: ...

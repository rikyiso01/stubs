from typing import Generic, overload
from typing_extensions import Unpack
from mte.typevar import TT, T, T2, T3
from numpy.typing import ArrayLike

class MultiIndex(Generic[Unpack[TT]]):
    @overload
    @staticmethod
    def from_product(
        iterables: tuple[ArrayLike[T], ArrayLike[T2]]
    ) -> MultiIndex[T, T2]: ...
    @overload
    @staticmethod
    def from_product(
        iterables: tuple[ArrayLike[T], ArrayLike[T2], ArrayLike[T3]]
    ) -> MultiIndex[T, T2, T3]: ...

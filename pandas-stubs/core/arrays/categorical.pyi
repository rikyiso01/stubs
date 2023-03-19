from numpy.typing import NDArray
from typing import Generic
from mte.typevar import T_co
from mte.pandas import SeriesLike

class Categorical(Generic[T_co], SeriesLike[int, T_co]):
    def __array__(self) -> NDArray[T_co]: ...
    def __getitem__(self, item: int) -> T_co: ...
    def __contains__(self, item: int, /) -> bool: ...
    def __len__(self) -> int: ...

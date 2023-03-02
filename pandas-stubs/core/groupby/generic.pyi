from typing import Generic, TypeVar
from pandas import DataFrame

_K = TypeVar("_K")
_V = TypeVar("_V")
_N = TypeVar("_N", bound=float)

class DataFrameGroupBy(Generic[_K, _V]):
    def sum(self: DataFrameGroupBy[_K, _N]) -> DataFrame[_K, int, _V]: ...

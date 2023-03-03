from typing import Generic
from pandas import DataFrame
from mte.typevar import K, V, F

class DataFrameGroupBy(Generic[K, V]):
    def sum(self: DataFrameGroupBy[K, F]) -> DataFrame[K, int, V]: ...

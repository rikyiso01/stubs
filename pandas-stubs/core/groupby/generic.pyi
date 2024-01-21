from pandas import DataFrame

class DataFrameGroupBy[K, V]:
    def sum[F: float](self: DataFrameGroupBy[K, F]) -> DataFrame[K, int, V]: ...

from typing import Any
from numpy.typing import NDArray, ArrayLike
from mte.pandas import DataFrameLike

class SimpleImputer:
    def fit_transform[
        F: float
    ](self, X: ArrayLike[F] | DataFrameLike[Any, Any, F]) -> NDArray[F]: ...
    def transform[
        F: float
    ](self, X: ArrayLike[F] | DataFrameLike[Any, Any, F]) -> NDArray[F]: ...

from typing import Any
from numpy.typing import NDArray, ArrayLike
from mte.typevar import F
from mte.pandas import DataFrameLike

class SimpleImputer:
    def fit_transform(
        self, X: ArrayLike[F] | DataFrameLike[Any, Any, F]
    ) -> NDArray[F]: ...
    def transform(self, X: ArrayLike[F] | DataFrameLike[Any, Any, F]) -> NDArray[F]: ...

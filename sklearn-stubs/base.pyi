from numpy.typing import ArrayLike, NDArray
from typing import Any
from typing_extensions import Self
from mte.pandas import DataFrameLike

class BaseEstimator:
    def fit[
        F: float
    ](
        self, X: ArrayLike[float] | DataFrameLike[Any, Any, F], y: ArrayLike[float]
    ) -> Self: ...
    def predict[
        F: float
    ](self, X: ArrayLike[float] | DataFrameLike[Any, Any, F]) -> NDArray[float]: ...
    def score(self, X: ArrayLike[float], y: ArrayLike[float]) -> float: ...

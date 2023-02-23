from numpy.typing import ArrayLike, NDArray
from pandas import DataFrame
from typing import TypeVar, Any
from typing_extensions import Self

_N = TypeVar("_N", bound=float)

class BaseEstimator:
    def fit(
        self, X: ArrayLike[float] | DataFrame[Any, Any, _N], y: ArrayLike[float]
    ) -> Self: ...
    def predict(
        self, X: ArrayLike[float] | DataFrame[Any, Any, _N]
    ) -> NDArray[float]: ...

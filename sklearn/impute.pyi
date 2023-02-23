from typing import TypeVar, Any
from numpy.typing import NDArray, ArrayLike
from pandas import DataFrame

_N = TypeVar("_N", bound=float)

class SimpleImputer:
    def fit_transform(
        self, X: ArrayLike[_N] | DataFrame[Any, Any, _N]
    ) -> NDArray[_N]: ...
    def transform(self, X: ArrayLike[_N] | DataFrame[Any, Any, _N]) -> NDArray[_N]: ...

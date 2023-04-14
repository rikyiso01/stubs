from numpy.typing import NDArray
from sklearn.base import BaseEstimator

class LinearRegression(BaseEstimator):
    intercept_: float
    coef_: NDArray[float]

class LogisticRegression(BaseEstimator):
    pass

from numpy.typing import NDArray
from typing import TypeVar

_T = TypeVar("_T")

def convolve1d(input: NDArray[_T], weights: NDArray[_T]) -> NDArray[_T]: ...

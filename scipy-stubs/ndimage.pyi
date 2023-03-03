from numpy.typing import NDArray
from mte.typevar import T
from mte.numpy import BaseNDArray

def convolve1d(input: BaseNDArray[T], weights: BaseNDArray[T]) -> NDArray[T]: ...

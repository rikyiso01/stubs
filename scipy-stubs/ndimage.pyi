from numpy.typing import NDArray
from mte.numpy import BaseNDArray

def convolve1d[T](input: BaseNDArray[T], weights: BaseNDArray[T]) -> NDArray[T]: ...

from scipy.signal import windows as windows
from typing import Literal, overload
from numpy.typing import ArrayLike, NDArray
from mte.numpy import BaseNDArray

def medfilt(
    volume: BaseNDArray[float], kernel_size: BaseNDArray[float] | None = ...
) -> NDArray[float]: ...
@overload
def butter(
    N: int,
    Wn: float,
    btype: Literal["lowpass", "highpass", "low", "high"] = ...,
    analog: bool = ...,
) -> tuple[NDArray[float], NDArray[float]]: ...
@overload
def butter(
    N: int,
    Wn: tuple[float, float],
    btype: Literal["bandpass", "bandstop", "band"],
    analog: bool = ...,
) -> tuple[NDArray[float], NDArray[float]]: ...
def lfilter(
    b: ArrayLike[float], a: ArrayLike[float], x: ArrayLike[float]
) -> NDArray[float]: ...
def find_peaks(x: ArrayLike[float], height: int = ...) -> tuple[NDArray[int], None]: ...
def filtfilt(
    b: ArrayLike[float], a: ArrayLike[float], x: ArrayLike[float]
) -> NDArray[float]: ...
def convolve(
    in1: ArrayLike[float],
    in2: ArrayLike[float],
    mode: Literal["full", "valid", "same"] = ...,
) -> NDArray[float]: ...
def convolve2d(
    in1: ArrayLike[float],
    in2: ArrayLike[float],
    mode: Literal["full", "valid", "same"] = ...,
) -> NDArray[float]: ...

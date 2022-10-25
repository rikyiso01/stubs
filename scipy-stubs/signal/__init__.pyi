from scipy.signal import windows as windows

from numpy.typing import NDArray

def medfilt(
    volume: NDArray[float], kernel_size: NDArray[float] | None = ...
) -> NDArray[float]: ...

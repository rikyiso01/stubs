from numpy.typing import NDArray, ArrayLike

def cumulative_distribution(
    image: ArrayLike[int], nbins: int = ...
) -> tuple[NDArray[int], NDArray[int]]: ...
def rescale_intensity(
    image: ArrayLike[int], in_range: tuple[float, float] = ...
) -> NDArray[int]: ...
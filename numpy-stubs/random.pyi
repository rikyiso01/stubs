from numpy.typing import NDArray

def randint(
    low: int, high: int = ..., size: int | tuple[int, ...] = ...
) -> NDArray[int]: ...
def uniform(
    low: float = ..., high: float = ..., size: int | tuple[int, ...] = ...
) -> NDArray[float]: ...

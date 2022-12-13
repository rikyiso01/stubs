from numpy.typing import NDArray
from typing import TypeVar
from skimage.measure._measure import RegionProperties

_T = TypeVar("_T", bound=float)

def label(label_image: NDArray[_T]) -> NDArray[int]: ...
def regionprops(label_image: NDArray[int]) -> list[RegionProperties]: ...

from numpy.typing import NDArray
from skimage.measure._measure import RegionProperties
from mte.typevar import F
from mte.numpy import BaseNDArray

def label(label_image: BaseNDArray[F]) -> NDArray[int]: ...
def regionprops(label_image: BaseNDArray[int]) -> list[RegionProperties]: ...

from numpy.typing import NDArray, ArrayLike

def img_as_float(image: ArrayLike[float]) -> NDArray[float]: ...
def img_as_ubyte(image: ArrayLike[float]) -> NDArray[int]: ...
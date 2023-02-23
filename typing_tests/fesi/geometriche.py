import numpy as np
import matplotlib.pyplot as plt

from skimage import data, color


# t array 2D
def translate(image: np.ndarray[float], t: tuple[float, float]):
    width, height = image.shape[:2]
    dst = np.zeros((width, height, 3), dtype=np.uint8)
    # INVERSE MAPPING Loop over the destination, not the source, to ensure that you cover
    # every destination pixel exactly 1 time.
    for u in range(width):
        for v in range(height):
            x = u - t[0]
            y = v - t[1]
            intx, inty = int(x), int(y)
            # bilinear interpolation
            fracx, fracy = x % 1, y % 1
            # interp = fracx*fracy + (1-fracx)*fracy + fracx*(1-fracy) + (1-fracx)*(1-fracy)
            if 0 < x < width - 1 and 0 < y < height - 1:
                # dst[u, v] = image[intx, inty] # qui tronco
                dst[u, v] = (
                    fracx * fracy * image[intx, inty]
                    + (1 - fracx) * fracy * image[intx + 1, inty]
                    + fracx * (1 - fracy) * image[intx, inty + 1]
                    + (1 - fracx) * (1 - fracy) * image[intx + 1, inty + 1]
                ).astype(np.uint8)
    return dst


# TEST TRANSLATION
rgb_img = data.moon()
img = color.rgb2gray(rgb_img)
t = (-45.3, -4.6)
print(t)
I_t = translate(img, t)
plt.imshow(I_t, cmap=plt.cm.gray)


def rotation(image: np.ndarray[int], angle: float):
    width, height = image.shape[:2]
    dst = np.zeros((width, height, 3), dtype=np.uint8)
    # INVERSE MAPPING Loop over the destination, not the source, to ensure that you cover
    # every destination pixel exactly 1 time.
    for u in range(width):
        for v in range(height):
            x = u * np.cos(-angle) + v * np.sin(-angle)
            y = -u * np.sin(-angle) + v * np.cos(-angle)
            intx, inty = int(x), int(y)
            # bilinear interpolation
            fracx, fracy = x % 1, y % 1
            if 0 < x < width - 1 and 0 < y < height - 1:
                # dst[u, v] = image[intx, inty] # qui tronco
                dst[u, v] = (
                    fracx * fracy * image[intx, inty]
                    + (1 - fracx) * fracy * image[intx + 1, inty]
                    + fracx * (1 - fracy) * image[intx, inty + 1]
                    + (1 - fracx) * (1 - fracy) * image[intx + 1, inty + 1]
                ).astype(np.uint8)
    return dst


# TEST ROTATION
rgb_img = data.moon()
img = color.rgb2gray(rgb_img)
angle = 0.1
print(angle)
I_rot = rotation(img.astype(np.uint8), angle)
plt.imshow(I_rot, cmap=plt.cm.gray)

[R, C] = np.shape(img)
t = (R // 2, C // 2)
angle = 0.05
I_t = translate(img, t)  # traslo portando l'origine al centro dell'immagine
I_rt = rotation(I_t, angle)  # ruoto
I_final = translate(I_rt.astype(np.float_), -1 * t)  # traslazione contraria
plt.imshow(I_final, cmap=plt.cm.gray)

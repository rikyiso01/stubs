import numpy as np
import matplotlib.pyplot as plt
from skimage import data, io

img1 = (
    data.astronaut()
)  # scikit-image comes already with some images (try to use the <TAB> key on data.)
img2 = io.imread(
    "images/parrot_small.jpg"
)  # or you can load a custom one (see the folder 'images')

plt.subplot(1, 2, 1)
plt.imshow(img1)

plt.subplot(1, 2, 2)
plt.imshow(img2)

print("image data type is: {}".format(type(img1)))
print("image shape is: {}".format(img1.shape))

R = img1[:, :, 0]
G = img1[:, :, 1]
B = img1[:, :, 2]
print("R shape is: {}".format(R.shape))
print("G shape is: {}".format(G.shape))
print("B shape is: {}".format(B.shape))

print(R[:3, :5])

print("Max value for the red channel: {}".format(np.max(R)))
print("Min value for the red channel: {}".format(np.min(R)))

plt.figure(figsize=(15, 5))

plt.subplot(1, 3, 1)
plt.imshow((R), cmap="Reds")
# cmap='Reds' <-- falsi colori
plt.colorbar(orientation="vertical")
plt.title("R")

plt.subplot(1, 3, 2)
plt.imshow((G), cmap="Greens")
plt.title("G")
plt.colorbar(orientation="vertical")

plt.subplot(1, 3, 3)
plt.imshow((B), cmap="Blues")
plt.title("B")
plt.colorbar(orientation="vertical")

plt.tight_layout()  # a handy command that increases spacing between subplots


def my_rgb2gray(img: np.ndarray[int]):
    return 0.2125 * (img[:, :, 0]) + 0.7154 * (img[:, :, 1]) + 0.0721 * (img[:, :, 2])


##Code here
plt.imshow(my_rgb2gray(img1), cmap="gray")
# nota la mappa di colori scelta qui

R = img2[:, :, 0]  # type: ignore
G = img2[:, :, 1]  # type: ignore
B = img2[:, :, 2]  # type: ignore

plt.figure(figsize=(15, 5))

plt.subplot(1, 3, 1)
plt.imshow((R), cmap="Reds")
# cmap='Reds' <-- falsi colori
plt.colorbar(orientation="vertical")
plt.title("R")

plt.subplot(1, 3, 2)
plt.imshow((G), cmap="Greens")
plt.title("G")
plt.colorbar(orientation="vertical")

plt.subplot(1, 3, 3)
plt.imshow((B), cmap="Blues")
plt.title("B")
plt.colorbar(orientation="vertical")

plt.tight_layout()  # a handy command that increases spacing between subplots

mask = B > 100
plt.imshow(mask, cmap="gray")

mask3 = np.copy(img2)
mask3[:, :, 0] = mask
mask3[:, :, 1] = mask
plt.imshow(mask3, cmap="gray")

from skimage.color import rgb2hsv

hsv_img = rgb2hsv(img2)
H = hsv_img[:, :, 0]
S = hsv_img[:, :, 1]
V = hsv_img[:, :, 2]

plt.figure(figsize=(15, 5))

plt.subplot(1, 4, 1)
plt.imshow(img2)
# plt.colorbar(orientation='vertical')
plt.title("Image")

plt.subplot(1, 4, 2)
plt.imshow((H), cmap="hsv")
plt.colorbar(orientation="vertical")
plt.title("Hue")

plt.subplot(1, 4, 3)
plt.imshow(S, cmap="gray")
plt.title("Saturation")
plt.colorbar(orientation="vertical")

plt.subplot(1, 4, 4)
plt.imshow(V, cmap="gray")
plt.title("Value")
plt.colorbar(orientation="vertical")

plt.tight_layout()

mask_brown1 = H < 0.12
mask_brown2 = H > 0.05
mask_brown = mask_brown1 & mask_brown2

plt.imshow(mask_brown, cmap="gray")

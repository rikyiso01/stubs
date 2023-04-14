import numpy as np
import matplotlib.pyplot as plt
from skimage import exposure, img_as_ubyte
from skimage import data, color

astro = data.astronaut()
g_astro = img_as_ubyte(color.rgb2gray(astro))

plt.subplot(1, 2, 1)
plt.imshow(astro)

plt.subplot(1, 2, 2)
plt.imshow(g_astro, cmap="gray")

plt.hist


# density controls normalization (try out density False)
# bins the number of bins
plt.hist(g_astro.ravel(), bins=128, density=True, color="r")


R = astro[:, :, 0]
G = astro[:, :, 1]
B = astro[:, :, 2]

plt.figure(figsize=(8, 3))

plt.subplot(1, 3, 1)
plt.hist(R.ravel(), density=True, color="r")
# density controls normalization (try out density False)
plt.ylim((0, 0.03))


plt.subplot(1, 3, 2)
plt.hist(G.ravel(), density=True, color="g")
plt.ylim((0, 0.03))

plt.subplot(1, 3, 3)
plt.ylim((0, 0.03))
plt.hist(B.ravel(), density=True, color="b")

plt.tight_layout()  # a handy command that increases spacing between subplots

mask = np.multiply((R > 140), (G > 150))
plt.imshow(mask, cmap="gray")

# ogni punto rappresenta la coppia (R,G) dei pixel dell'immagine
plt.plot(R.ravel(), G.ravel(), ".")
plt.xlabel("R")
plt.xlabel("G")

from matplotlib.axes import Axes


def plot_img_and_hist(
    img: np.ndarray[int],
    axes: tuple[Axes, Axes],
    bins: int = 256,
):
    """Plot an image along with its histogram and cumulative histogram."""
    # img = img_as_float(img) ##Convert our input greyscale image to float
    ax_img, ax_hist = axes
    ax_cdf = ax_hist.twinx()

    # Display image
    ax_img.imshow(img, cmap=plt.cm.gray)
    ax_img.set_axis_off()

    # Display histogram
    ax_hist.hist(img.ravel(), bins=bins, histtype="step", color="black")
    ax_hist.ticklabel_format(axis="y", style="scientific", scilimits=(0, 0))
    ax_hist.set_xlabel("Pixel intensity")
    ax_hist.set_xlim(0, 255)
    ax_hist.set_yticks([])

    # Display cumulative distribution
    img_cdf, bins2 = exposure.cumulative_distribution(img, bins)
    ax_cdf.plot(bins2, img_cdf, "r")
    ax_cdf.set_yticks([])

    return ax_img, ax_hist, ax_cdf


# Test the function plot_img_and_hist using a sample image
img = data.chelsea()
img = img_as_ubyte(color.rgb2gray(img))

fig, axes2 = plt.subplots(ncols=2)
fig.set_figheight(7)
fig.set_figwidth(9)
ax_img, ax_hist, ax_cdf = plot_img_and_hist(img, axes2, 30)


def my_contrast_stretch(img: np.ndarray[int]):
    M = np.max(img)
    m = np.min(img)
    return np.multiply(np.divide((img - m), (M - m)), 255).astype(np.uint8)


# Load an example image
rgb_img = data.text()

# rgb_img = data.logo()
img = img_as_ubyte(color.rgb2gray(rgb_img))

my_img_rescale = my_contrast_stretch(img)


fig = plt.figure(figsize=(8, 4))
plt.subplot(1, 2, 1)
plt.hist((img).ravel(), bins=30)
# color='black' , histtype='step' );
plt.subplot(1, 2, 2)
plt.hist((my_img_rescale).ravel(), bins=1000)
# color='black' , histtype='step' );

# Contrast stretching
p2, p98 = np.percentile(img, (2, 98))
img_rescale = exposure.rescale_intensity(img, in_range=(float(p2), float(p98)))
my_img_rescale = my_contrast_stretch(img)

# Display results
fig = plt.figure(figsize=(8, 5))
axes: dict[tuple[int, int], Axes] = {}
axes[0, 0] = fig.add_subplot(2, 3, 1)
for i in range(1, 3):
    axes[0, i] = fig.add_subplot(2, 3, 1 + i, sharex=axes[0, 0], sharey=axes[0, 0])
for i in range(0, 3):
    axes[1, i] = fig.add_subplot(2, 3, 4 + i)

ax_img, ax_hist, ax_cdf = plot_img_and_hist(img, (axes[0, 0], axes[1, 0]))
ax_img.set_title("Low contrast image")

y_min, y_max = ax_hist.get_ylim()
ax_hist.set_ylabel("Number of pixels")
ax_hist.set_yticks(np.linspace(0, y_max, 5))

ax_img, ax_hist, ax_cdf = plot_img_and_hist(img_rescale, (axes[0, 1], axes[1, 1]))
ax_img.set_title("Contrast stretching")

ax_img, ax_hist, ax_cdf = plot_img_and_hist(my_img_rescale, (axes[0, 2], axes[1, 2]))
ax_img.set_title("My Contrast stretching")

ax_cdf.set_ylabel("Fraction of total intensity")
ax_cdf.set_yticks(np.linspace(0, 1, 5))

# prevent overlap of y-axis labels
fig.tight_layout()
plt.show()

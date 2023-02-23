import numpy as np
import numpy.fft as fft

import matplotlib.pyplot as plt
# import skimage.filters as flt

# LOAD IMAGE (you may also try others)
img = plt.imread("images/einstein.jpg")

plt.imshow(img, cmap="gray")
plt.axis("off")
plt.title("Image")
plt.colorbar()

# BUILD A 1D GAUSSIAN FILTER

# First a 1-D  Gaussian in space
t = np.linspace(-10, 10, img.shape[0])
sigma = 0.1
bump = np.exp(-(t**2) / (2.0 * sigma**2))
bump /= np.trapz(bump)  # normalize the integral to 1
plt.plot(t, bump)

# BUILD A 2D GAUSSIAN FILTER
# E' costruita con uno shift implicito
gauss = bump[:, np.newaxis] * bump[np.newaxis, :]
plt.imshow(gauss)

# Filter Fourier Transform
gauss_F = fft.fft2(gauss)


# plot output (shift e aumento contrasto per capire meglio)
plt.figure()
plt.imshow((np.abs(fft.fftshift(gauss_F))), cmap="gray")

# FFT
Img = fft.fft2(img)
plt.imshow(np.log10(np.abs(fft.fftshift(Img))), cmap="gray")
plt.title("FFT")
plt.colorbar()

# FILTER
G = np.multiply(gauss_F, Img)

# INVERSE
im_rec = np.real(fft.ifftshift(fft.ifft2(G)))
im_rec= np.real((fft.ifft2(G)))
plt.imshow(im_rec, cmap="gray")
plt.colorbar()

from scipy import signal
from matplotlib import cm

# Partial derivatives kernel
k = np.array([-0.5, 0, 0.5])

# Compute first derivative along x
Ix = np.zeros_like(im_rec)
for i, r in enumerate(im_rec):
    Ix[i, :] = signal.convolve(r, k, mode="same")

# Compute first derivative along y
Iy = np.zeros_like(im_rec)
for i, c in enumerate(im_rec.T):
    Iy[:, i] = signal.convolve(c, k, mode="same")

# Compute the mangnitude of the gradient
G = np.sqrt(Ix**2 + Iy**2) # type: ignore

plt.figure(figsize=(12, 6))
plt.subplot(131)
plt.imshow(Ix, cmap=cm.gist_gray)
plt.title(r"$I_x$")
plt.subplot(132)
plt.imshow(Iy, cmap=cm.gist_gray)
plt.title(r"$I_y$")
plt.subplot(133)
plt.imshow(G, cmap=cm.gist_gray)
plt.title(r"$G = \sqrt{I_x^2+I_y^2}$")
plt.tight_layout

# Partial derivatives kernel
k = np.array([[-1, -2, -1], [0, 0, 0], [1, 2, 1]])

Ix = signal.convolve2d(im_rec, k.T)
Iy = signal.convolve2d(im_rec, k)

# Compute the mangnitude of the gradient
G = np.sqrt(Ix**2 + Iy**2) # type: ignore

plt.figure(figsize=(12, 6))
plt.subplot(131)
plt.imshow(Ix, cmap=cm.gist_gray)
plt.title(r"$I_x$")
plt.subplot(132)
plt.imshow(Iy, cmap=cm.gist_gray)
plt.title(r"$I_y$")
plt.subplot(133)
plt.imshow(G, cmap=cm.gist_gray)
plt.title(r"$G = \sqrt{I_x^2+I_y^2}$")
plt.tight_layout

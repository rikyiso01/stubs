import numpy as np
import matplotlib.pyplot as plt

delta_s = 1.0 / 100
# sampling interval
f_s = 1.0 / delta_s
# sampling frequency
print("Sampling interval", delta_s)
print("Sampling frequency", f_s)

f = 1.0  # Hz # sinusoidal signal frequency
T = 3.0
time = np.arange(0.0, T, delta_s)  # sampling points at f_s frequency
N = time.size
# HERE IS TO BUILD AN ODD FUNCTION
# y =  5*np.sin(2 * np.pi * f * time) + 1* np.sin(4 * 2 * np.pi * f * time)

# HERE IS TO BUILD AN EVEN FUNCTION
y = (
    5 * np.cos(2 * np.pi * f * time)
    + 1 * np.cos(10 * 2 * np.pi * f * time)
    + 1 * np.cos(3 * 2 * np.pi * f * time)
)
print("Array size", N)

plt.plot(time, y)
plt.xlabel("Time (sec)")
plt.ylabel("y")
# print(y)

fft_y = np.fft.fft(y)
n = len(fft_y)
print(n)
freq = np.fft.fftfreq(n, 1 / f_s)

# 0 frequency term
print("F[0]=", fft_y[0])

# IT'S JUST A "VISUAL ILLUSION"!
# NOTICE THE DIFFERENCE IN THE PLOT IF I

plt.figure(figsize=(10, 4))
plt.subplot(1, 2, 1)
plt.plot(freq, np.abs(fft_y))
plt.xlabel("frequency")
plt.title("I plot ind var")
plt.subplot(1, 2, 2)
plt.plot(np.abs(fft_y))
plt.xlabel("array indeces")
plt.title("I don t")

# but fft_y does not change
print(fft_y[0])

# real component
R = np.real(fft_y)
plt.xlabel("n")
plt.ylabel("real(DFT)")
plt.plot(freq, R)

# imag component
Im = np.imag(fft_y)
plt.xlabel("n")
plt.ylabel("imm(DFT)")
plt.plot(freq, Im)

fft_y_shifted = np.fft.fftshift(fft_y)
freq_shifted = np.fft.fftshift(freq)

plt.figure(figsize=(10, 4))
plt.subplot(1, 2, 1)
plt.plot(freq_shifted, np.real(fft_y_shifted))  # it does not change
plt.xlabel("Frequency ")
plt.title("Real part")
plt.subplot(1, 2, 2)
plt.plot(freq_shifted, np.imag(fft_y_shifted))  # it does not change
plt.xlabel("Frequency ")
plt.title("Imaginary part")

# inverse DFT
fft_y_shifted_back = np.fft.ifftshift(fft_y_shifted)

y_rec = np.fft.ifft(fft_y_shifted_back)
plt.plot(time, y_rec.real)  # real part of inverse FFT
plt.plot(time, y)  # original signal
plt.xlabel("Time (sec)")
plt.ylabel("y")

f_s = 512.0  # Hz
T = 1.0  # type: ignore

time = np.arange(
    0, T, 1 / f_s
)  # sampling at f_s frequency starting from 0 (shifted signal)

N = time.size  # type: ignore
# sampling points
y = np.zeros(time.size)
y[int(N / 4) : int(N / 2)] = 4 * time[int(N / 4) : int(N / 2)] - 1
y[int(N / 2) : 3 * int(N / 4)] = -4 * time[int(N / 2) : 3 * int(N / 4)] + 3

plt.plot(time, y)
plt.xlabel("Time (sec)")
plt.ylabel("y")

# DFT computation
fft_y = np.fft.fft(y)
freq = np.fft.fftfreq(n, 1 / f_s)

n = len(fft_y)
print(n)

# zero-frequency component
print(fft_y[0])
print(np.sum(y))

plt.plot(np.abs(fft_y))

fft_y_shifted = np.fft.fftshift(fft_y)
freq_shifted = np.fft.fftshift(freq)

plt.figure(figsize=(10, 4))
plt.subplot(1, 2, 1)
plt.plot(freq_shifted, np.real(fft_y_shifted))  # it does not change
plt.xlabel("Frequency ")
plt.title("Real part")
plt.subplot(1, 2, 2)
plt.plot(freq_shifted, np.imag(fft_y_shifted))  # it does not change
plt.xlabel("Frequency ")
plt.title("Imaginary part")


plt.plot(freq_shifted, np.abs(fft_y_shifted))
plt.xlabel("Frequency (Hz)")


y_rec = np.fft.ifft(fft_y)

plt.figure(figsize=(10, 4))
plt.subplot(1, 2, 1)
plt.plot(np.real(fft_y))  # it does not change
plt.xlabel("Frequency ")
plt.title("DFT")
plt.subplot(1, 2, 2)
plt.xlabel("time ")
plt.plot(y_rec.real)  # real part of inverse FFT
plt.title("IDFT")

# BACK FROM THE SHIFTED VERSION

plt.figure(figsize=(10, 4))
plt.subplot(1, 2, 1)
plt.plot(np.real(fft_y_shifted))  # it does not change

plt.title("DFT")
plt.subplot(1, 2, 2)

plt.plot(np.fft.ifft(fft_y_shifted).real)  # real part of inverse FFT
plt.title("IDFT")

# inverse DFT
fft_y_shifted = np.fft.fftshift(fft_y)
y_rec = np.fft.ifft(np.fft.ifftshift(fft_y_shifted))

plt.figure(figsize=(10, 4))
plt.subplot(1, 2, 1)
plt.plot(np.real(fft_y_shifted))  # it does not change
# plt.xlabel("Frequency ")
plt.title("DFT")
plt.subplot(1, 2, 2)
# plt.xlabel("time ")
plt.plot(y_rec.real)  # real part of inverse FFT
plt.title("IDFT")

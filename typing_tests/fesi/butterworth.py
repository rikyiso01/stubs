import numpy as np
import matplotlib.pyplot as plt
import scipy.io.wavfile as wav
import IPython
import warnings

warnings.filterwarnings("ignore")


def segnale_parabolico(tempi: np.ndarray[int], a: int, b: int, c: int):
    segnale = a * tempi**2 + b * tempi + c
    return segnale


t = np.array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
S_t = segnale_parabolico(t, 3, -2, 1)

## stampiamo i valori di S(t) nei vari istanti di tempo usando la funzione print()
print(S_t)


## disegnamo il grafico di S(t)
plt.plot(
    t,
    S_t,
    "-*b",
)
plt.xlabel("t [sec]")
plt.ylabel("S_t")
plt.grid()

wavname_basso = "34090__t-quote-mo__d-minor-string-walking-bass.wav"
IPython.display.Audio(wavname_basso)

f_s, suono_basso = wav.read(
    wavname_basso
)  # Questo comando carica il segnale e restituisce : frequenza_campionamento, segnale

N = len(suono_basso)  ## Completa qui ##
T_s = 1 / f_s  ## Completa qui ##
t = T_s * np.arange(N)  ## Completa qui ##

## calcoliamo la trasformata di Fourier con la funzione np.fft.fft di numpy
f = f_s / N * np.arange(N)
X = np.fft.fft(suono_basso) / N

plt.plot(t, X, "-b", label=r"$x(t)$")
plt.xlabel("t [s]")
plt.legend()
plt.grid()

plt.plot(f[: N // 2], np.abs(X[: N // 2]), "-r", label=r"$X(f)$")
plt.xlabel("f [Hz]")
plt.xlim((0, 5e3))
plt.legend()
plt.tight_layout()
plt.grid()
plt.savefig(wavname_basso + ".png", type=".png")

wavname_voce = "30084__herbertboland__femalephrase1.wav"
IPython.display.Audio(wavname_voce)

f_s, suono_voce = wav.read(
    wavname_voce
)  # This command loads the wavfile as (sample_rate, signal)
N = len(suono_voce)  # type: ignore
t = 1 / f_s * np.arange(N)

f = f_s / N * np.arange(N)
Fourier_voce = np.fft.fft(suono_voce) / N

plt.figure(figsize=(10, 8))
plt.subplot(2, 1, 1)
plt.plot(t, suono_voce, "-b", label=r"$x(t)$")
plt.xlabel("t [s]")
plt.legend()
plt.grid()

plt.subplot(2, 1, 2)
plt.plot(f[: N // 2], np.abs(Fourier_voce[: N // 2]), "-r", label=r"$X(f)$")
plt.xlabel("f [Hz]")
plt.xlim((0, 5e3))
plt.legend()
plt.tight_layout()
plt.grid()
plt.savefig(wavname_voce + ".png", type=".png")

wavname_alto = "235462__jcdecha__triangle-ringing-fast16.wav"
IPython.display.Audio(wavname_alto)

fs, x = wav.read(
    wavname_alto
)  # This command loads the wavfile as (sample_rate, signal)
N = len(x)  # type: ignore

t = 1 / fs * np.arange(N)
f = fs / N * np.arange(N)
X = np.fft.fft(x) / N  # type: ignore

plt.figure(figsize=(10, 8))
plt.subplot(2, 1, 1)
plt.plot(t, x, "-b", label=r"$x(t)$")
plt.xlabel("t [s]")
plt.legend()
plt.grid()

plt.subplot(2, 1, 2)
plt.plot(f[: N // 2], np.abs(X[: N // 2]), "-r", label=r"$X(f)$")
plt.xlabel("f [Hz]")
plt.xlim((0, 5e3))
plt.legend()
plt.tight_layout()
plt.grid()
plt.savefig(wavname_alto + ".png", type=".png")

# np.intersect1d(np.argwhere(f>1800),np.argwhere(f<3000))
# Y = np.zeros(len(X))
# Y[np.intersect1d(np.argwhere(f>1800),np.argwhere(f<3000))] = X[np.intersect1d(np.argwhere(f>1800),np.argwhere(f<3000))]


Y = X

Y[np.argwhere(f < 1800)] = 0
Y[np.argwhere(f > 3000)] = 0

Y[np.argwhere(f<4000)]=0


#
y = np.fft.ifft(Y)

plt.figure(figsize=(10, 8))
plt.subplot(2, 1, 1)
plt.plot(t, y[:N], "-b", label=r"$y(t)$")
plt.xlabel("t [s]")
plt.legend()
plt.grid()

plt.subplot(2, 1, 2)
plt.plot(f[: N // 2], np.abs(Y[: N // 2]), "-r", label=r"$Y(f)$")
plt.xlabel("f [Hz]")
plt.xlim((0, 5e3))
plt.ylim((0, 35))
plt.legend()
plt.grid()


IPython.display.Audio(y, rate=fs)

## Filtri Butterworth passabanda e passabasso

import scipy.signal as signal


def butter_bandpass(lowcut: int, highcut: int, fs: int, order: int = 5):
    nyq = 0.5 * fs
    low = lowcut / nyq
    high = highcut / nyq
    b, a = signal.butter(order, (low, high), btype="band", analog=False)
    return b, a


def butter_lowpass(lowcut: int, fs: int, order: int = 5):
    nyq = 0.5 * fs
    low = lowcut / nyq
    # high = highcut / nyq
    b, a = signal.butter(order, low, btype="low", analog=False)
    return b, a


b, a = butter_bandpass(1800, 3000, fs)
# Signal filtering

y = signal.lfilter(b, a, x)

# Fourier transform
Y = np.fft.fft(y) / N  # type: ignore


plt.figure(figsize=(10, 8))
plt.subplot(2, 1, 1)
plt.plot(t, y[:N], "-b", label=r"$y(t)$")
plt.xlabel("t [s]")
plt.legend()
plt.grid()

plt.subplot(2, 1, 2)
plt.plot(f[: N // 2], np.abs(Y[: N // 2]), "-r", label=r"$Y(f)$")
plt.xlabel("f [Hz]")
plt.xlim((0, 5e3))
plt.ylim((0, 35))
plt.legend()
plt.grid()

IPython.display.Audio(y, rate=fs)

b,a = butter_lowpass(1000, fs)
b, a = butter_bandpass(3000, 4000, fs)
# Signal filtering

y = signal.lfilter(b, a, x)

# Fourier transform
Y = np.fft.fft(y) / N  # type: ignore


plt.figure(figsize=(10, 8))
plt.subplot(2, 1, 1)
plt.plot(t, y[:N], "-b", label=r"$y(t)$")
plt.xlabel("t [s]")
plt.legend()
plt.grid()

plt.subplot(2, 1, 2)
plt.plot(f[: N // 2], np.abs(Y[: N // 2]), "-r", label=r"$Y(f)$")
plt.xlabel("f [Hz]")
plt.xlim((0, 5e3))
plt.legend()
plt.grid()

IPython.display.Audio(y, rate=fs)

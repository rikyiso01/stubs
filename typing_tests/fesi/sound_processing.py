import numpy as np
import matplotlib.pyplot as plt
import scipy.io.wavfile as wav
import IPython
import warnings

warnings.filterwarnings("ignore")

frequenza = 880

fs = 44100  # sampling frequency
T = 2  # seconds
tempi = np.linspace(0, T, int(T * fs), endpoint=False)  # time variable


suono = np.sin(1 * np.pi * frequenza * tempi)

plt.xlim((0, 0.01))
plt.plot(tempi, suono, "-b")

IPython.display.Audio(suono, rate=fs)

wavname_basso = "contrabbasso.wav"
IPython.display.Audio(wavname_basso)

f_s, suono_basso = wav.read(
    wavname_basso
)  # Questo comando carica il segnale e restituisce : frequenza_campionamento, segnale

N = len(suono_basso)
T_s = 1 / f_s
t = T_s * np.arange(N)

## calcoliamo la trasformata di Fourier con la funzione np.fft.fft di numpy
f = f_s / N * np.arange(N)
Fourier_basso = np.fft.fft(suono_basso) / N
freq_basso = np.fft.fftfreq(N, 1 / f_s)

plt.plot(t, suono_basso, "-b", label=r"$x(t)$")
plt.xlabel("t [s]")
plt.legend()
plt.grid()

plt.plot(
    freq_basso, np.abs(Fourier_basso), "-r", label="$X_f(f)$"
)  # tra $ formule matematiche Latex
plt.xlabel("f [Hz]")
plt.legend()
plt.tight_layout()
plt.grid()

wavname_voce = "voce_cantata.wav"
IPython.display.Audio(wavname_voce)

f_s, suono_voce = wav.read(
    wavname_voce
)  # This command loads the wavfile as (sample_rate, signal)
N = len(suono_voce)  # type: ignore
t = 1 / f_s * np.arange(N)


f = f_s / N * np.arange(N)
Fourier_voce = np.fft.fft(suono_voce) / N
freq_voce = np.fft.fftfreq(N, 1 / f_s)


plt.figure(figsize=(10, 8))
plt.subplot(2, 1, 1)
plt.plot(t, suono_voce, "-b", label=r"$x(t)$")
plt.xlabel("t [s]")
plt.legend()
plt.grid()

plt.subplot(2, 1, 2)
plt.plot(freq_voce, np.abs(Fourier_voce), "-r", label=r"$X(f)$")
plt.xlabel("f [Hz]")
plt.xlim((0, 5e3))
plt.legend()
plt.tight_layout()
plt.grid()
plt.savefig(wavname_voce + ".png", type=".png")


wavname_alto = "triangolo16.wav"
IPython.display.Audio(wavname_alto)

f_s, suono_triangolo = wav.read(
    wavname_alto
)  # This command loads the wavfile as (sample_rate, signal)
N = len(suono_triangolo)  # type: ignore
tempi = 1 / f_s * np.arange(N)

f = f_s / N * np.arange(N)
Fourier_triangolo = np.fft.fft(suono_triangolo)
freq_triangolo = np.fft.fftfreq(N, 1 / f_s)

plt.plot(tempi, suono_triangolo, "-b", label=r"$x(t)$")
plt.xlabel("t [s]")
plt.legend()
plt.grid()
plt.xlim((0.18, 0.2))

plt.plot(freq_triangolo, np.abs(Fourier_triangolo), "-r", label=r"$X(f)$")
plt.xlabel("f [Hz]")
plt.xlim((0, 5e3))
plt.legend()
plt.tight_layout()
plt.grid()

Fourier_filtrato = Fourier_triangolo.copy()

indici = np.argwhere(abs(freq_triangolo) < 4000)

Fourier_filtrato[indici] = 0

plt.plot(freq_triangolo, np.abs(Fourier_filtrato), "-r", label=r"$Y(f)$")
plt.xlabel("f [Hz]")
plt.xlim((0, 5e3))
plt.ylim((0, 35))
plt.legend()
plt.grid()

suono_filtrato = np.fft.ifft(Fourier_filtrato)

plt.plot(tempi, suono_filtrato[:N], "-b", label=r"$y(t)$")
plt.xlabel("t [s]")
plt.legend()
plt.grid()

IPython.display.Audio(suono_filtrato, rate=fs)

Fourier_filtrato = Fourier_triangolo.copy()

indici_sotto = np.argwhere(abs(freq_triangolo) < 1800)
indici_sopra = np.argwhere(abs(freq_triangolo) > 3000)

Fourier_filtrato[indici_sotto] = 0
Fourier_filtrato[indici_sopra] = 0

plt.plot(freq_triangolo, np.abs(Fourier_filtrato), "-r", label=r"$Y(f)$")
plt.xlabel("f [Hz]")
plt.xlim((0, 5e3))
plt.ylim((0, 35))
plt.legend()
plt.grid()

suono_filtrato = np.fft.ifft(Fourier_filtrato)

plt.figure(figsize=(10, 8))
plt.subplot(2, 1, 1)
plt.plot(tempi, suono_filtrato, "-b", label=r"$y(t)$")
plt.xlabel("t [s]")
plt.legend()
plt.grid()

IPython.display.Audio(suono_filtrato, rate=fs)

powerSpectrum, freqenciesFound, time, imageAxis = plt.specgram(
    suono_voce, Fs=f_s, NFFT=1024
)

plt.xlabel("Time")

plt.ylabel("Frequency")
plt.colorbar()

plt.specgram

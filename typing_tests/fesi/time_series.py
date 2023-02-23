from scipy.io import loadmat
import numpy as np
import matplotlib.pyplot as plt
from scipy import signal
from scipy.ndimage import convolve1d

# carichiamo i dati
patient = "PT12_40"

data_o = loadmat(patient + "_original.mat")
data_orig = data_o["data_orig"]

# dimensione dei dati (si tratta in effetti di 10 serie temporali)

print(np.shape(data_orig))

# analizziamo una serie alla volta
idx_data = 7  # scegliamo 1 dei 10 segnali
# le serie sono molto lunghe, la mia analisi sarà bastata sulla
# scelta di una   porzione specifica
min = 1000
max = 1400

plt.plot(data_orig[min:max, idx_data])

# Filtraggio nel tempo: Gaussian filter


windowg = signal.windows.gaussian(51, std=3)  # cambiare valori della gaussian
windowg /= sum(windowg)  # A COSA SERVE??
filt = convolve1d(data_orig[:, idx_data], windowg)

sum(windowg)

plt.figure()
plt.subplot(211)
plt.plot(data_orig[min:max, idx_data])
plt.legend(["original"])
plt.subplot(212)
plt.plot(filt[min:max], "r")
plt.legend(["filtered"])
plt.show()

# filtraggio in Fourier

fs = 25
fft_f = np.fft.fft(data_orig[:, idx_data])
n = len(fft_f)
freq = np.fft.fftfreq(n, 1 / fs)

plt.plot(freq, np.abs(fft_f))
plt.ylim((-1, 100000))
         
idx = np.argwhere(np.abs(freq)>1) #change frequency threshold
fft_cut=np.copy(fft_f)
fft_cut[idx]=0

plt.plot(freq,np.abs(fft_cut) )
plt.xlabel('f [Hz]')
plt.ylim((-1,100000))

plt.grid()


f_cut=np.fft.ifft(fft_cut)

plt.figure()
plt.subplot(211)
plt.plot(data_orig[min:max,idx_data])
plt.legend(['original'])
#plt.title('original')
plt.subplot(212)

plt.plot(np.real(f_cut[min:max]),'r')
plt.legend(['filtered'])
plt.show()

filt_med=signal.medfilt(data_orig[:,idx_data], kernel_size=None) 
plt.plot(data_orig[min:max,idx_data])
plt.plot(filt_med[min:max])

# PIPELINE DI FILTRAGGIO

filt_med=signal.medfilt(data_orig[:,idx_data], kernel_size=None) 
windowg = signal.windows.gaussian(51, std=7) #cambiare valori della gaussian
windowg /= sum(windowg)
filt=convolve1d(filt_med,windowg) 


plt.plot(data_orig[min:max,idx_data]) 
plt.plot(filt_med[min:max]) 
plt.plot(filt[min:max]) 
plt.legend(['original','median','lowpass'])


dx = 1   #incremento su var indipendente
cf = np.convolve(filt, [-0.5, 0, 0.5 ]) / dx

filt_plot = filt[min:max]
toll=0.2
plt.plot(filt_plot)
top = np.max(filt_plot)
bottom = np.min(filt_plot)
plt.plot(50*(cf[min:max]>toll),".") #decrescente
plt.plot(100*(cf[min:max]<-toll),".") #crescente
extr =  np.where(abs(cf[min:max])<toll) #estremi
plt.plot(extr[0],filt_plot[extr],"x")

#plt.ylim(10,top+50)
print(np.shape(filt[extr]))
print(np.shape(extr[0]))

from scipy.signal import find_peaks

filt_cut = filt[min:max]
peaks, _ = find_peaks(filt_cut, height=0)
plt.plot(filt_cut)
plt.plot(peaks, filt_cut[peaks], "x")
plt.show()

# Come trovare le valli?

filt_cut = -filt[min:max]
filt_cut += np.max(filt[min:max])
peaks, _ = find_peaks(filt_cut, height=0)
plt.plot(-filt_cut)
plt.plot(peaks, -filt_cut[peaks], "x")
plt.show()
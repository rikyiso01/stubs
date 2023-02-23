from __future__ import annotations
from skimage import color
import numpy as np


def rgb2hsv(image: np.ndarray[int]) -> np.ndarray[int]:
    """Converte un'immagine da rgb ad hsv non utilizzando i float ma gli int

    image: Immagine da convertire in rgb
    returns: Immagine in hsv ad interi che vanno da 0 a 255
    """
    return (color.rgb2hsv(image) * 255).astype(np.uint8)


def hsv2rgb(image: np.ndarray[int]) -> np.ndarray[int]:
    """Converte un'immagine da hsv ad hsv non utilizzando i float ma gli int

    image: Immagine da convertire ad hsv
    returns: Immagine in rgb ad interi
    """
    return (color.hsv2rgb(image) * 255).astype(np.uint8)


def create_mask(
    image: np.ndarray[int],
    lower_bound: tuple[int, int, int],
    upper_bound: tuple[int, int, int],
) -> np.ndarray[bool]:
    """Crea una maschera ad una immagine in hsv usando un range,
    se lo hue del lower_bound è maggiore dello hue dell'upper_bound vengono effettuati gli opportuni calcoli per considerare la ciclicità


    image: Immagine in HSV
    lower_bound: Terna di minimi valore del range
    upper_bound: Terna di massimi valori del range
    returns: Una matrice di booleani
    """
    result = (image >= lower_bound) & (image <= upper_bound)
    if lower_bound[0] > upper_bound[0]:
        # Per considerare il caso ciclico si crea un'altra matrice di booleani
        # unendo i casi in cui la tinta va da 0 a upper bound o da lower bound a 255
        fix = (image[:, :, 0] <= upper_bound[0]) | (image[:, :, 0] >= lower_bound[0])
        result[:, :, 0] |= fix
    return np.all(result, axis=2)


def apply_mask(image: np.ndarray[int], mask: np.ndarray[bool]) -> np.ndarray[int]:
    """Applica una maschera ad un'immagine

    image: Immagine su cui applicare la maschera
    mask: Matrice di booleani
    returns: Immagine dove i pixel non nella maschera vengono rimpiazzati con nero
    """
    return image * mask[:, :, np.newaxis].repeat(3, axis=2)


from skimage.measure import label, regionprops
from skimage.morphology import erosion, dilation, closing, opening, area_closing
from skimage import io
from skimage import data


def noise_reduction(
    mask: np.ndarray[bool], iterations: int, area_threshold: int
) -> np.ndarray[bool]:
    """Algoritmo di riduzione del rumore

    mask: Maschera da modificare
    iterations: Numero di dilatazioni ed erosioni da applicare
    area_threshold: Area massima da chiudere dopo le dilatazioni
    returns: Maschera modificata
    """
    mask2 = mask.copy()

    for _ in range(iterations):
        mask2 = dilation(mask2, np.ones((3, 3)))
    mask2 = area_closing(mask2, area_threshold)
    for _ in range(iterations):
        mask2 = erosion(mask2, np.ones((3, 3)))

    # Estrazione delle regioni
    labels = label(mask2)
    regions = regionprops(labels)

    # Estrazione della regione massima
    max_region = max(regions, key=lambda e: e.area)
    for region in regions:
        if region != max_region:
            mask2[region.slice] = False

    mask = opening(closing(mask))

    # Filtraggio delle regioni che non hanno centro dentro la super maschera
    labels = label(mask)
    regions = regionprops(labels)
    max_region = max(regions, key=lambda e: e.area)
    for region in regions:
        if not mask2[tuple(map(int, region.centroid))]:
            mask[region.slice] = False

    return mask


def shift_hue(image: np.ndarray[int], shift: int) -> np.ndarray[int]:
    """Sposta la tinta di ogni pixel di un valore

    image: Immagine in HSV
    shift: Di quanto spostare la tinta
    returns: Immagine modificata
    """
    result = image.copy()
    # Essendo unsigned int l'overflow gestisce la ciclicità dello hue
    result[result[:, :, 2] > 0] += np.array([shift, 0, 0], dtype=np.uint8)
    return result


def change_hue(image: np.ndarray[int], target: int, shifted: bool) -> np.ndarray[int]:
    """Rimappa la tinta di una immagine ad un nuovo range usando la media delle tinte come riferimento,
    per la media non vengono considerati i pixel con valore uguale a 0

    image: Immagine in HSV
    target: Tinta media obiettivo
    shifted: Se è necessario considerare per la media la tinta del rosso come 128 per problemi di ciclicità
    returns: Immagine modificata
    """
    hues = image[:, :, 0]
    if shifted:
        # Shift del rosso a 128
        hues = (hues + 128) % 255
    # Calcolo della tinta media
    mean_hue = int(np.average(hues, weights=image[:, :, 2] > 0))
    if shifted:
        mean_hue = (mean_hue + 128) % 255
    return shift_hue(image, target - mean_hue)


def change_color_filter(
    image: np.ndarray[int],
    lower_bound: tuple[int, int, int],
    upper_bound: tuple[int, int, int],
    iterations: int,
    area_threshold: int,
    target_hue: int,
) -> np.ndarray[int]:
    """Filtro finale

    lower_bound: Colore minimo nel range da prendere
    upper_bound: Colore massimo nel range da prendere
    iterations: Numero di iterazioni sull'algoritmo di riduzione del rumore
    area_threshold: Dimensione massima dell'area da chiudere nell'algoritmo di riduzione del rumore
    target_color: Tinta a cui rimappare la tinta della regione più grande
    returns: Immagine finale
    """
    mask = noise_reduction(
        create_mask(image, lower_bound, upper_bound), iterations, area_threshold
    )
    return hsv2rgb(
        change_hue(apply_mask(image, mask), target_hue, lower_bound[0] > upper_bound[0])
        + apply_mask(image, ~mask)
    )


import matplotlib.pyplot as plt


def plot_images(row: dict[str, np.ndarray[int]]) -> None:
    plt.figure(figsize=(15, 5))
    for i, (title, image) in enumerate(row.items()):
        plt.subplot(1, len(row), i + 1)
        plt.title(title)
        plt.imshow(image)
        plt.axis("off")
    plt.tight_layout()
    plt.show()


TARGET_HUES = {"rosso": 0, "verde": 85, "blu": 170, "viola": 213}


def show2(
    image: np.ndarray[int],
    lower_bound: tuple[int, int, int],
    upper_bound: tuple[int, int, int],
    iterations: int,
    area_threshold: int,
) -> None:
    image = rgb2hsv(image)
    original_mask = create_mask(image, lower_bound, upper_bound)
    mask = noise_reduction(original_mask, iterations, area_threshold)
    plot_images(
        {
            "Immagine originale": hsv2rgb(image),
            "HSV": image,
            "Maschera": apply_mask(image, original_mask),
            "Maschera modificata": apply_mask(image, mask),
        }
    )
    plot_images(
        {
            f"Maschera {name}": hsv2rgb(
                change_hue(
                    apply_mask(image, mask), hue, lower_bound[0] > upper_bound[0]
                )
            )
            for name, hue in TARGET_HUES.items()
        }
    )
    plot_images(
        {
            f"Risultato {name}": change_color_filter(
                image, lower_bound, upper_bound, iterations, area_threshold, hue
            )
            for name, hue in TARGET_HUES.items()
        }
    )


show2(io.imread("esempio.jpg"), (240, 100, 50), (255, 255, 255), 7, 50000)
show2(io.imread("gabibbo.jpg"), (245, 200, 50), (5, 255, 255), 7, 50000)
show2(data.astronaut(), (24, 50, 45), (35, 255, 255), 7, 50000)


def show3(
    image: np.ndarray[int],
    lower_bound: tuple[int, int, int],
    upper_bound: tuple[int, int, int],
    iterations: int,
    area_threshold: int,
) -> None:
    image = rgb2hsv(image)
    mask = create_mask(image, lower_bound, upper_bound)
    plot_images(
        {
            "Immagine originale": hsv2rgb(image),
            "HSV": image,
            "Maschera": apply_mask(image, mask),
        }
    )
    plot_images(
        {
            f"Maschera {name}": hsv2rgb(
                change_hue(
                    apply_mask(image, mask), hue, lower_bound[0] > upper_bound[0]
                )
            )
            for name, hue in TARGET_HUES.items()
        }
    )
    plot_images(
        {
            f"Risultato {name}": hsv2rgb(
                change_hue(
                    apply_mask(image, mask), hue, lower_bound[0] > upper_bound[0]
                )
                + apply_mask(image, ~mask)
            )
            for name, hue in TARGET_HUES.items()
        }
    )


show3(io.imread("esempio.jpg"), (240, 100, 50), (255, 255, 255), 7, 50000)
show3(io.imread("gabibbo.jpg"), (245, 200, 50), (5, 255, 255), 7, 50000)
show3(data.astronaut(), (24, 50, 45), (35, 255, 255), 7, 50000)


def gaussian(length: int, sigma: float) -> np.ndarray[float]:
    """Crea una gaussiana

    length: Numero di elementi nell'array da produrre
    sigma: Sigma della Gaussiana
    returns: Array di float corrispondente alla gaussiana con il centro a metà dell'array
    """
    t = np.linspace(-10, 10, length)
    bump = np.exp(-(t**2) / (2.0 * sigma**2))
    # Normalizzazione
    bump /= np.trapz(bump)
    return bump


def gaussian2(shape: tuple[int, int], sigma: float) -> np.ndarray[float]:
    """Crea una gaussiana bidimensionale

    shape: Shape della matrice da creare
    sigma: Sigma della Gaussiana
    returns: Matrice contenente la Gaussiana
    """
    gauss = (
        gaussian(shape[0], sigma)[:, np.newaxis]
        * gaussian(shape[1], sigma)[np.newaxis, :]
    )
    return gauss


def blur(image: np.ndarray[int], k: float) -> np.ndarray[int]:
    """Applica un filtro blur all'imm

    image: Immagine RGB da modificare
    k: Sigma della gaussiana
    returns: Immagine modificata
    """
    result = np.zeros(image.shape, dtype=np.uint8)
    filter = np.fft.fft2(gaussian2(image.shape[:2], k))
    # Il blur deve essere applicato ad ogni canale indipendentemente
    for i in range(3):
        # Shift del risultato per centrarlo
        m = np.fft.ifftshift(
            np.fft.ifft2(np.fft.fft2(image[:, :, i]) * filter)
        ).real.astype(np.uint8)
        result[:, :, i] = m
    return result


def close_area(
    mask: np.ndarray[bool], iterations: int, area_threshold: int
) -> np.ndarray[bool]:
    """Chiude un'area di una maschera

    mask: Maschera da modificare
    iterations: Numero di dilatazioni ed erosioni da applicare
    area_threshold: Dimensione massima dell'area da chiudere nell'algoritmo di riduzione del rumore
    """
    for _ in range(iterations):
        mask = dilation(mask, np.ones((3, 3)))
    mask = area_closing(mask, area_threshold)
    for _ in range(iterations):
        mask = erosion(mask, np.ones((3, 3)))

    mask = opening(mask)
    labels = label(mask)
    regions = regionprops(labels)

    # Estrazione della regione più grande
    max_region = max(regions, key=lambda e: e.area)
    for region in regions:
        if region != max_region:
            mask[region.slice] = False

    return mask


def filter(
    image: np.ndarray[int],
    lower_bound: tuple[int, int, int],
    upper_bound: tuple[int, int, int],
    iterations: int,
    area_threshold: int,
    k: float,
) -> np.ndarray[int]:
    """Filtro finale

    lower_bound: Colore minimo nel range da prendere
    upper_bound: Colore massimo nel range da prendere
    iterations: Numero di iterazioni sull'algoritmo di riduzione del rumore
    area_threshold: Dimensione massima dell'area da chiudere nell'algoritmo di riduzione del rumore
    k: Valore che determina il livello di blur, 0 è assenza di blur
    returns: Immagine finale
    """
    original_mask = create_mask(image, lower_bound, upper_bound)
    mask = close_area(original_mask, iterations, area_threshold)
    return hsv2rgb(apply_mask(image, mask)) + apply_mask(blur(hsv2rgb(image), k), ~mask)


def show4(
    image: np.ndarray[int],
    lower_bound: tuple[int, int, int],
    upper_bound: tuple[int, int, int],
    iterations: int,
    area_threshold: int,
    k: float,
) -> None:
    image = rgb2hsv(image)
    original_mask = create_mask(image, lower_bound, upper_bound)
    mask = close_area(original_mask, iterations, area_threshold)
    plot_images(
        {
            "Maschera": apply_mask(image, original_mask),
            "Maschera modificata": apply_mask(image, mask),
            "Risultato": filter(
                image, lower_bound, upper_bound, iterations, area_threshold, k
            ),
        }
    )


show4(io.imread("esempio.jpg"), (240, 100, 50), (2555, 255, 255), 7, 50000, 0.1)
show4(data.astronaut(), (24, 50, 50), (35, 255, 255), 1, 50000, 0.1)
show4(io.imread("gabibbo.jpg"), (245, 200, 50), (5, 255, 255), 7, 50000, 0.1)
show4(data.astronaut(), (14, 50, 50), (35, 255, 255), 1, 50000, 0.1)


def show5(
    image: np.ndarray[int],
    lower_bound: tuple[int, int, int],
    upper_bound: tuple[int, int, int],
    iterations: int,
    area_threshold: int,
    k: float,
) -> None:
    image = rgb2hsv(image)
    mask = create_mask(image, lower_bound, upper_bound)
    plot_images(
        {
            "Maschera": apply_mask(image, mask),
            "Risultato": hsv2rgb(apply_mask(image, mask))
            + apply_mask(blur(hsv2rgb(image), k), ~mask),
        }
    )


show5(io.imread("gabibbo.jpg"), (245, 200, 50), (5, 255, 255), 7, 50000, 0.1)
show5(data.astronaut(), (24, 50, 50), (35, 255, 255), 1, 50000, 0.1)
show5(io.imread("esempio.jpg"), (240, 100, 50), (2555, 255, 255), 7, 50000, 0.1)
show5(data.astronaut(), (14, 50, 50), (35, 255, 255), 1, 50000, 0.1)

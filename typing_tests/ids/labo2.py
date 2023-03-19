from __future__ import annotations
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

dataset = pd.read_csv("integrate_titles2.csv")

dataset.head()

dataset.describe()

dataset.isna().sum()

dataset2 = dataset.copy()
dataset2["imdb_score"] = dataset2["imdb_score"].fillna(dataset2["imdb_score"].mean())

dataset3 = dataset2.copy()
dataset3["tmdb_score"] = dataset3["tmdb_score"].fillna(dataset3["tmdb_score"].mean())


def stats(d: pd.DataFrame[str, int, float]) -> None:
    for column in ["imdb_score", "tmdb_score"]:
        series = d[column]
        print(f"Media {column}:", series.mean())
        print(f"Deviazione standard {column}:", series.std())
        print(f"Varianza {column}:", series.var())
        print(f"Moda {column}:", series.mode()[0])
        print(f"Mediana {column}:", series.median())
        print()


stats(dataset3)

sorted = dataset3["imdb_score"].sort_values().tolist()
print(sorted[len(sorted) // 2])

integrate_titles = pd.read_csv("integrate_titles2.csv")

stats(integrate_titles)

integrate_titles = pd.read_csv("integrate_titles2.csv")
integrate_titles2 = integrate_titles.dropna(axis=0, subset=["imdb_score"])

stats(integrate_titles2)

integrate_titles3 = integrate_titles2.copy()

for quant, (min, max) in {
    "LOW": (0, 4.9),
    "SUFFICIENT": (5, 5.9),
    "GOOD": (6, 6.9),
    "VERY GOOD": (7, 7.9),
    "EXCELLENT": (8, 10),
}.items():
    integrate_titles3.loc[
        integrate_titles3["imdb_score"].between(min, max, "both"), "imdb_score_quant"
    ] = quant

integrate_titles3 = integrate_titles2.copy()
quantize_imdb_score = ["LOW", "SUFFICIENT", "GOOD", "VERY GOOD", "EXCELLENT"]
integrate_titles3["imdb_score_quant"] = pd.cut(
    integrate_titles3["imdb_score"],
    [0, 4.9, 5.9, 6.9, 7.9, 10],
    labels=quantize_imdb_score,
)

integrate_titles3["imdb_score_quant"].head()

quantize_release_year = ["VERY OLD", "OLD", "RECENT", "VERY RECENT"]

integrate_titles4 = integrate_titles3.copy()
integrate_titles4["release_year_quant"] = pd.cut(
    integrate_titles4["release_year"],
    [1900, 1980, 2000, 2015, 2023],
    labels=quantize_release_year,
)

integrate_titles4["release_year_quant"]

integrate_titles4["type"].isnull().sum()

quantize_type = integrate_titles4["type"].unique()
print(quantize_type)


olap = np.zeros(
    (len(quantize_imdb_score), len(quantize_release_year), len(quantize_type))
)
for z in range(0, len(quantize_type)):
    for j in range(0, len(quantize_release_year)):
        for i in range(0, len(quantize_imdb_score)):
            olap[i, j, z] = np.sum(
                (integrate_titles4["type"] == quantize_type[z])
                & (integrate_titles4["release_year_quant"] == quantize_release_year[j])
                & (integrate_titles4["imdb_score_quant"] == quantize_imdb_score[i])
            )

print(olap)

print("MOVIE")
movies = olap[:, :, quantize_type.tolist().index("MOVIE")]
print(movies)

plt.imshow(movies)
plt.title("SLICING BY MOVIE")
plt.xlabel("MOVIE_AGE")
plt.ylabel("MOVIE_SCORE")
plt.colorbar()

print("SHOW")
show = olap[:, :, quantize_type.tolist().index("SHOW")]

plt.imshow(show)
plt.title("SLICING BY SHOW")
plt.xlabel("SHOW_AGE")
plt.ylabel("SHOW_SCORE")
plt.colorbar()

print("VERY OLD")
old = movies[:, quantize_release_year.index("VERY OLD")]
print(old)

plt.plot(old)
plt.title("VERY OLD FILMS")
plt.xlabel("score")
plt.ylabel("count")

print("GOOD and VERY RECENT")
good_recent = olap[
    quantize_imdb_score.index("GOOD"), quantize_release_year.index("VERY RECENT")
]
print(good_recent)

plt.title("GOOD and VERY RECENT")
plt.bar(["MOVIES", "SHOWS"], good_recent)

years = integrate_titles4["release_year"].value_counts()
years.head()

plt.figure(figsize=(20, 6))
plt.title("number of films by release year")
plt.xlabel("year")
plt.ylabel("count")
years.plot(kind="bar")

plt.title("number of films by release year")
plt.xlabel("year")
plt.ylabel("count")
histo = np.histogram(integrate_titles4["release_year"], bins=10)
plt.bar(x=np.asarray(range(10)), height=histo[0])

plt.title("number of films by release year")
plt.xlabel("year")
plt.ylabel("count")
plt.hist(integrate_titles4["release_year"], bins=10)

integrate_titles4.boxplot("release_year", "type")

integrate_titles4.head()

num_film = [np.sum(integrate_titles4["month"] == i + 1) for i in range(12)]

plt.title("numero di film usciti nei vari mesi di ogni anno")
plt.xlabel("mese")
plt.ylabel("count")
plt.bar(range(12), num_film)

plt.title("numero di film usciti nei vari mesi del 2020")
plt.xlabel("mese")
plt.ylabel("count")
num_film = [
    np.sum((integrate_titles4["month"] == i + 1) & (integrate_titles4["year"] == 2020))
    for i in range(12)
]
plt.bar(range(12), num_film)

integrate_titles4.value_counts(
    subset=["imdb_score_quant", "release_year_quant", "type"], sort=False
).unstack(fill_value=0).to_numpy().reshape(
    (len(quantize_imdb_score), len(quantize_release_year), len(quantize_type))
)
num_film = (
    integrate_titles4["month"][integrate_titles4["year"] == 2020]
    .value_counts()
    .sort_index()
    .values
)

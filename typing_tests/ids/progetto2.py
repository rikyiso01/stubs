from __future__ import annotations
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from typing import Any
import scipy.stats as stats
from IPython.display import display

FILM_RATINGS = {"G", "PG", "PG-13", "R", "NC-17"}
TV_GUIDELINES = {"TV-Y", "TV-Y7", "TV-G", "TV-PG", "TV-14", "TV-MA", "TV-Y7-FV"}
MOVIE = "MOVIE"
SHOW = "SHOW"
TYPES = [MOVIE, SHOW]
PLATFORMS = ["netflix", "disney"]
PLATFORM_FILES = ("{}_titles_1.csv", "{}_titles_2.csv")

datasets = {
    platform: [pd.read_csv(file.format(platform)) for file in PLATFORM_FILES]
    for platform in PLATFORMS
}
for platform, (left, right) in datasets.items():
    print(f"{platform} left")
    display(left.head())
    print(f"{platform} right")
    display(right.head())

KEYS = ["title", "type", "release_year"]
COLUMNS_TO_COPY = ["date_added", "country"]

piattaforma_titles_combinata: dict[str, pd.DataFrame[str, int, Any]] = {}
for platform, (left, right) in datasets.items():
    right_tmp = right[KEYS + COLUMNS_TO_COPY].copy()
    right_tmp["type"] = (
        right_tmp["type"].str.replace("Movie", MOVIE).str.replace("TV Show", SHOW)
    )
    join = pd.merge(left.drop_duplicates(), right_tmp, "left", KEYS)
    piattaforma_titles_combinata[platform] = join
    print(platform)
    display(join)

tmp: list[pd.DataFrame[str, int, Any]] = []
for platform, combinata in piattaforma_titles_combinata.items():
    tmpi = combinata.copy()
    tmpi["platform"] = platform
    tmp.append(tmpi)
titles_combinata = pd.concat(tmp)

iso3166 = pd.read_csv("iso3166.csv")
translation_dict = dict(zip(iso3166["name"], iso3166["alpha-2"]))
translation_dict["United States"] = "US"
translation_dict["United Kingdom"] = "GB"
translation_dict["West Germany"] = "DE"
translation_dict["East Germany"] = "DE"
translation_dict["Soviet Union"] = "RU"
translation_dict["Czech Republic"] = "CZ"
translation_dict["Taiwan"] = "TW"
translation_dict["South Korea"] = "KR"
translation_dict["Iran"] = "IR"
translation_dict["Syria"] = "SY"
translation_dict["Russia"] = "RU"
translation_dict["Vietnam"] = "VN"
translation_dict["Venezuela"] = "VE"
translation_dict["Palestine"] = "PS"
translation_dict["Vatican City"] = "VAT"
translation_dict["Tanzania"] = "TZ"


def translate(x: list[str] | float) -> frozenset[str]:
    if not isinstance(x, list):
        return frozenset()
    return frozenset({translation_dict[xi.strip(",")] for xi in x if xi != ""})


titles_combinata2 = titles_combinata.copy()
titles_combinata2["production_countries"] = (
    titles_combinata2["production_countries"]
    .str[2:-2]
    .str.replace("', '", " ")
    .str.split()
    .apply(lambda x: frozenset(x))
)
titles_combinata2["country"] = (
    titles_combinata2["country"].str.split(", ").apply(translate)
)
titles_combinata2 = titles_combinata2[
    titles_combinata2["production_countries"] == titles_combinata2["country"]
]

titles_combinata2.loc[
    titles_combinata2["production_countries"] == set(), "production_countries"
] = np.nan
del titles_combinata2["country"]
display(titles_combinata2)

titles_combinata3 = titles_combinata2.copy()
date_added = pd.to_datetime(titles_combinata3["date_added"])
titles_combinata3["year_added"] = date_added.dt.year
titles_combinata3["month_added"] = date_added.dt.month
del titles_combinata3["date_added"]
titles_combinata3["genres_number"] = titles_combinata3["genres"].str.count("'") // 2
del titles_combinata3["genres"]
display(titles_combinata3)

titles_combinata3.boxplot("imdb_score", "age_certification")

plt.figure(figsize=(15, 3))
titles_combinata3.value_counts("release_year").sort_index(ascending=False).plot.bar()

titles_combinata3.value_counts("year_added").sort_index(ascending=False).plot.bar()

SIGNIFICANCE_LEVEL = 0.05


def ttest_eq(series1: pd.Series[Any, Any], series2: pd.Series[Any, Any]) -> bool | None:
    ttest = stats.ttest_1samp(series1, series2.mean())
    if ttest.pvalue > SIGNIFICANCE_LEVEL:
        return True
    if ttest.pvalue < SIGNIFICANCE_LEVEL / 100000:
        return False
    return None


for platform in PLATFORMS:
    platform_filter = titles_combinata3["platform"] == platform
    for type in TYPES:
        type_filter = titles_combinata3["type"] == type
        print(
            platform,
            type,
            ttest_eq(
                titles_combinata3[platform_filter & type_filter]["release_year"],
                titles_combinata3[platform_filter & type_filter]["year_added"],
            ),
        )
    print(
        platform,
        "tutti tipe",
        ttest_eq(
            titles_combinata3[platform_filter]["release_year"],
            titles_combinata3[platform_filter]["year_added"],
        ),
    )

index = pd.MultiIndex.from_product(
    (
        titles_combinata3["year_added"].dropna().sort_values().unique(),
        titles_combinata3["type"].unique(),
        titles_combinata3["production_countries"].unique(),
    )
)

a = (
    titles_combinata3[["year_added", "type", "production_countries"]]
    .value_counts()
    .reindex(index)
    .fillna(0)
    .reset_index()
)

from functools import reduce

years = titles_combinata3["year_added"].sort_values().dropna().unique().tolist()
countries = [
    *reduce(
        lambda x, y: x.union(y),
        titles_combinata3["production_countries"].dropna().unique().tolist(),
    )
]

olap = np.zeros(shape=(len(TYPES), len(years), len(countries)))
for x in range(len(TYPES)):
    xf = titles_combinata3["type"] == TYPES[x]
    for y in range(len(years)):
        yf = (titles_combinata3["year_added"] == years[y]) & xf
        for z in range(len(countries)):
            zf = (
                titles_combinata3["production_countries"].apply(
                    lambda x: z in x if isinstance(x, set) else False
                )
                & yf
            )
            olap[x, y, z] = zf.sum()

a = titles_combinata3.value_counts(
    subset=["year_added", "type", "production_countries"]
).unstack(fill_value=0)
display(a)
b = a.to_numpy()
display(b)
print(
    len({*titles_combinata3["year_added"]}),
    len({*titles_combinata3["type"]}),
    len({*titles_combinata3["production_countries"]}),
)

titles_combinata3.value_counts(
    subset=["year_added", "type", "production_countries"]
).unstack(fill_value=0).to_numpy().reshape(
    len(titles_combinata3["year_added"]),
    len(titles_combinata3["type"]),
    len(titles_combinata3["production_countries"]),
)


olap = (
    titles_combinata2.value_counts(subset=["year_added", "type", "country"])
    .unstack(fill_value=0)
    .to_numpy()
    .reshape(
        (
            len(titles_combinata2["year_added"]),
            len(titles_combinata2["type"]),
            len(titles_combinata2["country"]),
        )
    )
)
print(olap.shape)
print(olap)

print(titles_combinata3["platform"].value_counts())

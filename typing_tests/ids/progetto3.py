from __future__ import annotations
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from typing import Any, Literal
import scipy.stats as stats
from IPython.display import display
from itertools import chain, combinations
from functools import reduce
from sklearn.linear_model import LogisticRegression

PLATFORMS = ["netflix", "disney"]
PLATFORM_FILES = ("{}_titles_1.csv", "{}_titles_2.csv")


def copy_datasets(datasets: dict[str, list[pd.DataFrame[str, int, Any]]]):
    return {key: [elem.copy() for elem in array] for key, array in datasets.items()}


datasets = {
    platform: [pd.read_csv(file.format(platform)) for file in PLATFORM_FILES]
    for platform in PLATFORMS
}
for platform, (left, right) in datasets.items():
    print(f"{platform}_title_1.csv")
    display(left)
    print(f"{platform}_titles_2.csv")
    display(right)

datasets1 = copy_datasets(datasets)

datasets = copy_datasets(datasets1)
for i in [0, 1]:
    first_columns = {*datasets[PLATFORMS[0]][i].columns}
    assert first_columns == {*datasets[PLATFORMS[1]][i].columns}
    print(f"titles_{i+1}.csv:", sorted(first_columns))
COLUMNS = [{*datasets[PLATFORMS[0]][i].columns} for i in [0, 1]]

datasets = copy_datasets(datasets1)

for platform, titles in datasets.items():
    for titlesi in titles:
        titlesi["platform"] = platform

datasets2 = copy_datasets(datasets)


def copy_titles(titles: list[pd.DataFrame[str, int, Any]]):
    return [titlesi.copy() for titlesi in titles]


titles = [
    pd.concat([datasets[platform][i].copy() for platform in PLATFORMS]) for i in [0, 1]
]

for titlesi in titles:
    display(titlesi)

titles1 = copy_titles(titles)


def separate(titles: pd.DataFrame[str, int, Any]):
    return [titles[titles["platform"] == platform] for platform in PLATFORMS]


THRESHOLDS = 30
titles = copy_titles(titles1)

for i, titlesi in enumerate(titles):
    print(f"titles_{i+1}.csv")
    uniques = titlesi.nunique()
    display(uniques)
    for column in uniques.index:
        if uniques[column] <= THRESHOLDS:
            print(f"{column}:", {*titles[i][column].unique()})


MOVIE = "MOVIE"
SHOW = "SHOW"
MOVIE_2 = "Movie"
SHOW_2 = "TV Show"
TYPES = [MOVIE, SHOW]
TYPES2 = [MOVIE_2, SHOW_2]

FILM_RATINGS = {"G", "PG", "PG-13", "R", "NC-17"}

TV_GUIDELINES = {"TV-Y", "TV-Y7", "TV-G", "TV-PG", "TV-14", "TV-MA", "TV-Y7-FV"}

POSSIBLE_KEY_COLUMNS = ["title", "type", "release_year"]

titles = copy_titles(titles1)

for titlesi in titles:
    assert (
        titlesi[POSSIBLE_KEY_COLUMNS].isna().sum() == [0] * len(POSSIBLE_KEY_COLUMNS)
    ).all()

titles = copy_titles(titles1)

left, right = titles

for type1, type2 in zip(TYPES, TYPES2):
    right["type"] = right["type"].str.replace(type2, type1)
right["type"].isin(TYPES).all()

titles2 = copy_titles(titles)

titles = copy_titles(titles2)

for i, titlesi in enumerate(titles):
    for platform, data in zip(PLATFORMS, separate(titlesi)):
        print(
            f"{platform}_titles_{i+1}.csv:",
            data[POSSIBLE_KEY_COLUMNS].duplicated(keep=False).sum(),
        )
    print(
        f"combinata_titles_{i+1}.csv:",
        titlesi[POSSIBLE_KEY_COLUMNS].duplicated(keep=False).sum(),
    )

titles = copy_titles(titles2)

for i, titlesi in enumerate(titles):
    for platform, data in zip(PLATFORMS, separate(titlesi)):
        print(f"{platform}_titles_{i+1}.csv")
        display(data[data[POSSIBLE_KEY_COLUMNS].duplicated(keep=False)])

titles = copy_titles(titles2)

titles = [titlesi.drop_duplicates() for titlesi in titles]

for i, titlesi in enumerate(titles):
    for platform, data in zip(PLATFORMS, separate(titlesi)):
        print(f"{platform}_titles_{i+1}.csv")
        display(data[data[POSSIBLE_KEY_COLUMNS].duplicated(keep=False)])

titles3 = copy_titles(titles)

titles = copy_titles(titles3)

display(titles[1][titles[1]["title"] == "Sergio"])

SERGIO_ID = "tm144835"

titles = copy_titles(titles3)

(index,) = titles[0][titles[0]["id"] == SERGIO_ID].index
titles[0] = titles[0].drop(index)
display(titles[0][titles[0]["title"] == "Sergio"])

titles4 = copy_titles(titles)

POSSIBLE_KEYS: list[list[str]] = [
    *map(
        list,
        chain.from_iterable(
            combinations(POSSIBLE_KEY_COLUMNS, i)
            for i in range(1, len(POSSIBLE_KEY_COLUMNS) + 1)
        ),
    )
]
print(POSSIBLE_KEYS)

titles = copy_titles(titles4)

left, right = titles
for key in POSSIBLE_KEYS:
    print("Using key:", key)
    for platform, lefti, righti in zip(PLATFORMS, separate(left), separate(right)):
        print(
            f"{platform}_titles_1.csv:",
            lefti[key].duplicated(keep=False).sum(),
            end=", ",
        )
        print(
            f"{platform}_titles_2.csv:",
            righti[key].duplicated(keep=False).sum(),
            end=", ",
        )
        print(
            f"Unique joins:",
            len({*zip(*[lefti[k] for k in key])} & {*zip(*[righti[k] for k in key])}),
        )

KEY = POSSIBLE_KEY_COLUMNS

titles = copy_titles(titles4)

for titlesi in titles:
    for data in separate(titlesi):
        assert data[KEY].duplicated(keep=False).sum() == 0

COLUMNS_TO_ADD = ["date_added", "country"]

titles = copy_titles(titles4)

left, right = titles
combinata = pd.merge(
    left, right[KEY + COLUMNS_TO_ADD + ["platform"]], "left", KEY + ["platform"]
)
display(combinata)

assert len(combinata) == len(left)

combinata1 = combinata.copy()

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

combinata = combinata1.copy()

print(combinata["production_countries"].isna().sum())
print((combinata["production_countries"] == "[]").sum())
print(combinata["country"].isna().sum())
print(
    (
        combinata["production_countries"].isna()
        & (combinata["production_countries"] == "[]")
    ).sum()
)

combinata = combinata1.copy()

print(
    sorted(
        reduce(
            lambda x, y: x.union(y),
            combinata["production_countries"]
            .str[2:-2]
            .str.replace("', '", " ")
            .str.split()
            .apply(lambda x: frozenset(x)),
        )
    )
)
print(
    sorted(
        reduce(
            lambda x, y: x.union(y),
            combinata["country"].dropna().str.split(", ").apply(lambda x: frozenset(x)),
        )
    )
)

combinata = combinata1.copy()

for row in combinata["country"].dropna():
    if "" in row.split(", "):
        print(row)
    for s in row.split(", "):
        if "," in s:
            print(row)

combinata = combinata1.copy()

combinata["production_countries"] = (
    combinata["production_countries"]
    .str[2:-2]
    .str.replace("', '", " ")
    .str.split()
    .apply(lambda x: frozenset(x))
)

wrong_begin = combinata["country"].str.startswith(", ").fillna(False)
wrong_end = combinata["country"].str.endswith(",").fillna(False)
combinata.loc[wrong_begin, "country"] = combinata.loc[wrong_begin, "country"].str[2:]
combinata.loc[wrong_end, "country"] = combinata.loc[wrong_end, "country"].str[:-1]
combinata.loc[combinata["country"].notna(), "country"] = (
    combinata["country"]
    .dropna()
    .str.split(", ")
    .apply(lambda x: frozenset([translation_dict[xi] for xi in x]))
)
display(combinata)

combinata2 = combinata.copy()

print(
    (
        (combinata["production_countries"] == combinata["country"])
        | combinata["country"].isna()
    ).sum()
)

combinata = combinata2.copy()

combinata = combinata[
    (combinata["production_countries"] == combinata["country"])
    | combinata["country"].isna()
].copy()
del combinata["country"]
display(combinata)

combinata3 = combinata.copy()

combinata = combinata3.copy()

print(combinata["date_added"].isna().sum())

combinata = combinata3.copy()

date_added = pd.to_datetime(combinata["date_added"])
combinata["year_added"] = date_added.dt.year
combinata["month_added"] = date_added.dt.month
del combinata["date_added"]
display(combinata)

combinata4 = combinata.copy()

combinata = combinata4.copy()

print(combinata4["genres"].isna().sum())

combinata = combinata4.copy()

combinata["genres_number"] = combinata["genres"].str.count("'") // 2
del combinata["genres"]
display(combinata)

combinata5 = combinata.copy()

combinata = combinata5.copy()

print(combinata["imdb_score"].isna().sum())
print(combinata["age_certification"].isna().sum())

combinata = combinata5.copy()

combinata.boxplot("imdb_score", "age_certification")

combinata = combinata5.copy()

print(combinata["release_year"].isna().sum())

combinata = combinata5.copy()

plt.figure(figsize=(15, 3))
combinata.value_counts("release_year").sort_index(ascending=False).plot.bar()

combinata = combinata5.copy()

print(combinata["year_added"].isna().sum())

combinata = combinata5.copy()

combinata.value_counts("year_added").sort_index(ascending=False).plot.bar()

SIGNIFICANCE_LEVEL = 0.05


def ttest(
    series1: pd.Series[Any, Any], series2: pd.Series[Any, Any]
) -> Literal[1, -1, 0] | None:
    def aux(
        series1: pd.Series[Any, Any],
        series2: pd.Series[Any, Any],
        alternative: Literal["two-sided", "less", "greater"],
    ) -> bool | None:
        ttest = stats.ttest_1samp(series1, series2.mean(), alternative=alternative)
        if ttest.pvalue > SIGNIFICANCE_LEVEL:
            return True
        if ttest.pvalue < SIGNIFICANCE_LEVEL / 100000:
            return False
        return None

    result1 = aux(series1, series2, "two-sided")
    result2 = aux(series1, series2, "less")
    result3 = aux(series1, series2, "greater")
    if result1:
        assert not result2
        assert not result3
        return 0
    elif result1 is None:
        return None
    else:
        if result2:
            assert not result3
            return 1
        elif result3:
            assert not result2
            return -1
        else:
            assert False


combinata = combinata5.copy()

print(combinata["release_year"].isna().sum())
print(combinata["year_added"].isna().sum())

combinata = combinata5.copy()

for platform, data in zip(PLATFORMS, separate(combinata)):
    for type in TYPES:
        type_filter = data["type"] == type
        print(
            platform,
            type,
            ttest(
                data.loc[type_filter, "release_year"],
                data.loc[type_filter, "year_added"],
            )
            == 0,
        )
print("tutto", ttest(combinata["release_year"], combinata["year_added"]) == 0)

combinata = combinata5.copy()

print(combinata["year_added"].isna().sum())
print(combinata["type"].isna().sum())
print(combinata["production_countries"].isna().sum())

combinata = combinata5.copy()

COUNTRIES = sorted(reduce(lambda x, y: x.union(y), combinata["production_countries"]))
countries_filter = [
    combinata["production_countries"].apply(lambda x: country in x)
    for country in COUNTRIES
]
print(COUNTRIES)

print(TYPES)
types_filter = [combinata["type"] == type for type in TYPES]

YEARS = sorted(combinata["year_added"].dropna().unique().astype(int).tolist())
years_filter = [combinata["year_added"] == year for year in YEARS]
print(YEARS)

combinata = combinata5.copy()

olap = np.array(
    [
        [
            [
                (countries_filter[x] & types_filter[y] & years_filter[z]).sum()
                for z in range(len(YEARS))
            ]
            for y in range(len(TYPES))
        ]
        for x in range(len(COUNTRIES))
    ]
)


assert (
    olap.sum()
    == combinata.loc[combinata["year_added"].notna(), "production_countries"]
    .apply(len)
    .sum()
)

print(olap)

INPUT_COLUMNS = ["imdb_score", "tmdb_score", "tmdb_popularity", "runtime"]
OUTPUT_COLUMN = "type"

combinata = combinata5.copy()

filter = combinata[OUTPUT_COLUMN].notna()
print(f"{OUTPUT_COLUMN}:", combinata[OUTPUT_COLUMN].isna().sum())
for input_column in INPUT_COLUMNS:
    filter &= combinata[input_column].notna()
    print(f"{input_column}:", combinata[input_column].isna().sum())

combinata = combinata5.copy()

X_train, X_valid = separate(combinata[filter])
y_train = X_train["type"] == MOVIE
y_valid = X_valid["type"] == MOVIE
X_train = X_train[INPUT_COLUMNS]
X_valid = X_valid[INPUT_COLUMNS]

regressor = LogisticRegression()
regressor.fit(X_train, y_train)
print(regressor.score(X_train, y_train))
print(regressor.score(X_valid, y_valid))

combinata = combinata5.copy()

mean_movie = y_valid.mean()
print(max(mean_movie, 1 - mean_movie))

# %% [markdown]
# # Introduzione alla Data Science

# %% [markdown]
# ## Progetto

# %% [markdown]
# Per ogni passaggio, commentare opportunamente e fornire giustificazioni delle scelte operate.

# %%
from __future__ import annotations
import pandas as pd
import matplotlib.pyplot as plt
from typing import Any
import scipy.stats as stats

# %%
FILM_RATINGS = {"G", "PG", "PG-13", "R", "NC-17"}
TV_GUIDELINES = {"TV-Y", "TV-Y7", "TV-G", "TV-PG", "TV-14", "TV-MA", "TV-Y7-FV"}
MOVIE = "MOVIE"
SHOW = "SHOW"
TYPES = [MOVIE, SHOW]
DISNEY = "disney"
NETFLIX = "netflix"
PLATFORMS = [DISNEY, NETFLIX]

netflix_titles_1 = pd.read_csv("netflix_titles_1.csv")
netflix_titles_2 = pd.read_csv("netflix_titles_2.csv")
disney_titles_1 = pd.read_csv("disney_titles_1.csv")
disney_titles_2 = pd.read_csv("disney_titles_2.csv")

netflix_titles_1.info()
netflix_titles_1.head()

netflix_titles_1.isna().sum()

for column in ["type", "age_certification"]:
    print("type:", {*netflix_titles_1[column]})


netflix_titles_2.info()
netflix_titles_2.head()

netflix_titles_2.isna().sum()

for column in ["type", "rating", "duration"]:
    print(column, {*netflix_titles_2[column]})


disney_titles_1.info()
disney_titles_1.head()


disney_titles_1.isna().sum()


for column in ["type", "age_certification"]:
    print("type:", {*disney_titles_1[column]})


disney_titles_2.info()
disney_titles_2.head()


disney_titles_2.isna().sum()


for column in ["type", "rating", "duration"]:
    print("type:", {*disney_titles_2[column]})

JOIN_COLUMNS = ["title", "type", "release_year"]


def fix_type(df: pd.DataFrame[str, int, Any]) -> pd.DataFrame[str, int, Any]:
    result = df.copy()
    result["type"] = (
        result["type"].str.replace("TV Show", "SHOW").str.replace("Movie", "MOVIE")
    )
    return result


assert {*netflix_titles_1["type"]} == {*fix_type(netflix_titles_2)["type"]}
assert {*disney_titles_1["type"]} == {*fix_type(disney_titles_2)["type"]}

a = tuple(netflix_titles_1[JOIN_COLUMNS].iloc)

for i in range(len(JOIN_COLUMNS)):
    keys = JOIN_COLUMNS[: i + 1]
    left = {*(tuple(i) for i in netflix_titles_1[keys].iloc)}
    right = {*(tuple(i) for i in fix_type(netflix_titles_2)[keys].iloc)}
    print(netflix_titles_1.drop_duplicates().shape[0] - len(left))
    print(netflix_titles_2.shape[0] - len(right))
    print(len(right - left))


print(netflix_titles_1.shape, netflix_titles_1.drop_duplicates().shape)
netflix_titles_1.drop_duplicates().value_counts(subset=JOIN_COLUMNS).head()

print(netflix_titles_2.shape, netflix_titles_2.drop_duplicates().shape)
netflix_titles_2.drop_duplicates().value_counts(subset=JOIN_COLUMNS).head()

print(disney_titles_1.shape, disney_titles_1.drop_duplicates().shape)
disney_titles_1.drop_duplicates().value_counts(subset=JOIN_COLUMNS).head()

print(disney_titles_2.shape, disney_titles_2.drop_duplicates().shape)
disney_titles_2.drop_duplicates().value_counts(subset=JOIN_COLUMNS).head()

netflix_titles_1[netflix_titles_1["title"] == "Sergio"]

netflix_titles_2[netflix_titles_2["title"] == "Sergio"]

for i in range(3):
    keys = JOIN_COLUMNS[: i + 1]
    print(JOIN_COLUMNS)
    left = {*fix_type(netflix_titles_2).value_counts(subset=keys).index}
    print(len(left))
    right = {*netflix_titles_1.value_counts(subset=keys).index}
    print(len(right))
    print(len(left | right))
    print("lost:", len(left | right) - max(len(left), len(right)))


netflix_titles_combinata = pd.merge(
    netflix_titles_1.drop_duplicates(),
    fix_type(netflix_titles_2),
    "outer",
    JOIN_COLUMNS,
)
netflix_titles_combinata.info()
netflix_titles_combinata.head()

assert netflix_titles_combinata.shape[0] - 1 == len(
    {*netflix_titles_1.value_counts(subset=JOIN_COLUMNS).index}
    | {*fix_type(netflix_titles_2).value_counts(subset=JOIN_COLUMNS).index}
)

disney_titles_combinata = pd.merge(
    disney_titles_1.drop_duplicates(), fix_type(disney_titles_2), "outer", JOIN_COLUMNS
)
disney_titles_combinata.info()
disney_titles_combinata.head()

assert disney_titles_combinata.shape[0] == len(
    {*disney_titles_1.value_counts(subset=JOIN_COLUMNS).index}
    | {*fix_type(disney_titles_2).value_counts(subset=JOIN_COLUMNS).index}
)

netflix_titles_combinata2 = netflix_titles_combinata.copy()
netflix_titles_combinata2["platform"] = NETFLIX
disney_titles_combinata2 = disney_titles_combinata.copy()
disney_titles_combinata2["platform"] = DISNEY
titles_combinata = pd.concat([netflix_titles_combinata2, disney_titles_combinata2])
titles_combinata.info()
titles_combinata.head()


def fix_production_countries_x(
    countries: pd.Series[int, str]
) -> pd.Series[int, list[str]]:
    return countries.str[2:-2].str.split("', '")


def fix_production_countries_y(
    countries: pd.Series[int, str]
) -> pd.Series[int, list[str]]:
    return countries.str.split(", ")


iso3166 = pd.read_csv("iso3166.csv")
iso3166.info()
iso3166.head()

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


def translate(value: list[str] | float) -> set[str] | None:
    if isinstance(value, list):
        return {translation_dict[v.strip(",")] for v in value if v != ""}
    return None


def conditional_set(value: list[str] | float) -> set[str] | None:
    if isinstance(value, list):
        result = {v for v in value if v != ""}
        return result if result else None
    return None


titles_combinata3 = titles_combinata.copy()
titles_combinata3["production_countries"] = (
    titles_combinata3["production_countries"]
    .str[2:-2]
    .str.split("', '")
    .apply(conditional_set)
)
titles_combinata3["country"] = titles_combinata3["country"].str.split(", ")
titles_combinata3["country"] = titles_combinata3["country"].apply(translate)
titles_combinata3.head()


titles_combinata3["production_countries"].apply(
    lambda x: None if x is None else len(x)
).min()


def conditional_union(row: pd.Series[str, set[str] | None]) -> set[str] | None:
    x, y = row
    if x is None and y is None:
        return None
    if x is None:
        return y
    if y is None:
        return x
    return x | y


titles_combinata3[
    (
        (titles_combinata3["production_countries"] != titles_combinata3["country"])
        & (~titles_combinata3["production_countries"].isna())
        & (~titles_combinata3["country"].isna())
    )
].head()

titles_combinata4 = titles_combinata3.copy()
titles_combinata4[["production_countries", "country"]].apply(conditional_union, axis=1)
titles_combinata4["country"] = titles_combinata4[
    ["production_countries", "country"]
].apply(conditional_union, axis=1)
del titles_combinata4["production_countries"]
titles_combinata4.head()

titles_combinata4[
    (titles_combinata4["age_certification"] != titles_combinata4["rating"])
    & (~titles_combinata4["age_certification"].isna())
    & (~titles_combinata4["rating"].isna())
]

titles_combinata2 = titles_combinata.copy()
date_added = pd.to_datetime(titles_combinata2["date_added"])
titles_combinata2["year_added"] = date_added.dt.year
titles_combinata2["month_added"] = date_added.dt.month
titles_combinata2.info()
titles_combinata2.head()

titles_combinata2.boxplot("imdb_score", "age_certification")

plt.figure(figsize=(15, 3))
titles_combinata2.value_counts("release_year").sort_index(ascending=False).plot.bar()

titles_combinata2.value_counts("year_added").sort_index(ascending=False).plot.bar()

SIGNIFICANCE_LEVEL = 0.05


def ttest_eq(series1: pd.Series[Any, Any], series2: pd.Series[Any, Any]) -> bool | None:
    ttest = stats.ttest_1samp(series1, series2.mean())
    if ttest.pvalue > SIGNIFICANCE_LEVEL:
        return True
    if ttest.pvalue < SIGNIFICANCE_LEVEL / 100:
        return False
    return None


for platform in PLATFORMS:
    platform_filter = titles_combinata2["platform"] == platform
    for type in TYPES:
        type_filter = titles_combinata2["type"] == type
        print(
            platform,
            type,
            ttest_eq(
                titles_combinata2[platform_filter & type_filter]["release_year"],
                titles_combinata2[platform_filter & type_filter]["year_added"],
            ),
        )

titles_combinata2.value_counts(subset=["year_added", "type", "country"]).unstack(
    fill_value=0
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

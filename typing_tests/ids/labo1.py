import pandas as pd


netflix_titles = pd.read_csv("netflix_titles.csv")
netflix_titles.head()
netflix_titles.info()
disney_titles = pd.read_csv("disney_titles.csv")
disney_titles.head()
disney_titles.info()
final_table = pd.concat([netflix_titles, disney_titles])
final_table.shape
final_table.isna().sum()
print(netflix_titles.columns)
print(disney_titles.columns)
print(
    {
        name: ("netflix" if name in netflix_titles.columns else "disney")
        for name in {*netflix_titles.columns} ^ {*disney_titles.columns}
    }
)
netflix_titles2 = netflix_titles.drop(
    ["description", "cast", "listed_in"], axis="columns"
)
disney_titles2 = disney_titles.rename(
    columns={"show_type": "type", "from": "date_added"}
)

final_table = pd.concat([disney_titles2, disney_titles2]).drop(
    columns=["Unnamed: 0", "id"]
)
final_table2 = final_table.copy()
print(final_table.isna().sum(), final_table.shape)
final_table.head()
final_table = pd.concat([netflix_titles, disney_titles])
print(final_table.columns)
final_table["show_type"] = final_table["show_type"].fillna(final_table["type"])
final_table["date_added"] = final_table["date_added"].fillna(final_table["from"])
final_table = final_table.drop(columns=["type", "from"])
final_table.head()
netflix_credits = pd.read_csv("netflix_credits.csv")
disney_credits = pd.read_csv("disney_credits.csv")
netflix_credits.head()
disney_credits.head()
final_credits = pd.concat([netflix_credits, disney_credits])
final_table = pd.merge(
    final_table2, final_credits.rename(columns={"id": "imdb_id"}), "outer", "imdb_id"
)
final_table3 = final_table
final_table.head()
print(final_table2.shape)
print(
    final_credits["id"].value_counts().sum()
    + len(
        pd.concat(
            [final_table2["imdb_id"], final_credits["id"], final_credits["id"]]
        ).drop_duplicates()
    )
)
print(final_table.shape)
final_table.head()
print(final_table.columns)
final_table.isnull().sum()
final_table["date_added"].head()
final_table["date_added"] = pd.to_datetime(final_table3["date_added"])
print(final_table["date_added"])
print(final_table["date_added"].isna().sum())
print(final_table3["date_added"].isna().sum())
final_table["day"] = final_table["date_added"].dt.day
final_table["month"] = final_table["date_added"].dt.month
final_table["year"] = final_table["date_added"].dt.year
final_table.head()
movies = final_table[final_table["type"] == "MOVIE"].copy()
movies = movies[movies["duration"].str.contains(" min")]
movies["duration"] = movies["duration"].str.replace(" min", "")
movies["duration"] = movies["duration"].astype(float) / 60
movies["duration"] = movies["duration"].astype(str) + " hours"
print(movies["duration"])
final_table_clean = final_table.copy()
final_table_clean["release_year_y"] = final_table_clean["release_year"].dropna()
final_table_clean.isnull().sum()
print(final_table_clean["release_year_y"])

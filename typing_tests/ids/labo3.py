import pandas as pd
import numpy as np
import scipy.stats as stats


dataset = pd.read_csv("integrate_titles_3.csv")


dataset.head()


print(dataset.shape)
dataset.describe()


dataset.isna().sum()


dataset2 = dataset.dropna(subset="tmdb_score")


dataset2.boxplot(column="imdb_score", by="type")


dataset2.boxplot(column="tmdb_score", by="type")


print(sum(dataset2["type"] == "MOVIE"))
print(sum(dataset2["type"] == "SHOW"))


result = stats.ttest_1samp(
    dataset2[dataset2["type"] == "MOVIE"]["imdb_score"],
    dataset2[dataset2["type"] == "SHOW"]["imdb_score"].mean(),
)
print(result.statistic)
print(result.pvalue)


stats.ttest_1samp(
    dataset2[dataset2["type"] == "MOVIE"]["imdb_score"],
    dataset2[dataset2["type"] == "SHOW"]["imdb_score"].mean(),
    alternative="greater",
)


stats.ttest_1samp(
    dataset2[dataset2["type"] == "MOVIE"]["imdb_score"],
    dataset2[dataset2["type"] == "SHOW"]["imdb_score"].mean(),
    alternative="less",
)


stats.ttest_1samp(
    dataset2[dataset2["type"] == "MOVIE"]["tmdb_score"],
    dataset2[dataset2["type"] == "SHOW"]["tmdb_score"].mean(),
)


dataset3 = dataset2.copy()
dataset3["old"] = (dataset2["release_year"] < 2010).astype(int)


print(dataset3["old"].tolist()[:50])


dataset3.boxplot("imdb_score", "old")


stats.ttest_1samp(
    dataset3[dataset3["old"] == 0]["imdb_score"],
    dataset3[dataset3["old"] == 1]["imdb_score"].mean(),
)


stats.ttest_1samp(
    dataset3[dataset3["old"] == 1]["imdb_score"],
    dataset3[dataset3["old"] == 0]["imdb_score"].mean(),
)


quantize_imdb_score = ["LOW", "SUFFICIENT", "GOOD", "VERY GOOD", "EXCELLENT"]
quantize_release_year = ["VERY OLD", "OLD", "RECENT", "VERY RECENT"]
quantize_type = ["MOVIE", "SHOW"]
OLAP = np.zeros((5, 4, 2))
for z in range(0, len(quantize_type)):
    Awards_prog_z = dataset3[dataset3["type"] == quantize_type[z]]
    for j in range(0, len(quantize_release_year)):
        for i in range(0, len(quantize_imdb_score)):
            OLAP[i, j, z] = np.sum(
                (Awards_prog_z["imdb_score_quant"] == quantize_imdb_score[i])
                & (Awards_prog_z["release_year_quant"] == quantize_release_year[j])
            )


recent_films = OLAP[
    :, quantize_release_year.index("RECENT"), quantize_type.index("MOVIE")
]
print(recent_films)


imdb_score_altri_servizi = [40, 119, 170, 145, 46]


stats.chisquare(recent_films, imdb_score_altri_servizi)


release_year_altri_servizi_old_movies = [20, 42, 250, 299]


low_films = OLAP[quantize_imdb_score.index("LOW"), :, quantize_type.index("MOVIE")]
print(low_films)
stats.chisquare(low_films, release_year_altri_servizi_old_movies)

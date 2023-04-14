import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from numpy.typing import NDArray, ArrayLike

integrate_titles_3 = pd.read_csv("integrate_titles_3.csv")

print(integrate_titles_3.shape)
print(integrate_titles_3.isna().sum())
integrate_titles = integrate_titles_3.dropna(subset="tmdb_score")
integrate_titles_3.describe()

plt.title("scores")
plt.xlabel("tmdb_score")
plt.ylabel("imdb_score")
plt.scatter(integrate_titles["tmdb_score"], integrate_titles["imdb_score"], alpha=0.2)

corr = integrate_titles[["tmdb_score", "imdb_score"]].corr()

corr.style.background_gradient()

plt.imshow(corr)
plt.colorbar()

from sklearn.model_selection import train_test_split

X_train, X_valid, y_train, y_valid = train_test_split(
    integrate_titles[["tmdb_score"]],
    integrate_titles["imdb_score"],
    test_size=0.2,
    random_state=1,
)

from sklearn.linear_model import LinearRegression

regressor = LinearRegression()

trained = regressor.fit(X_train, y_train)

print("intercept", trained.intercept_)
print("coef", trained.coef_)

y_hat2 = regressor.predict(X_train)

plt.scatter(X_train, y_hat2, label="predicted")
plt.xlabel("tmdb_score")
plt.ylabel("imdb_score")
plt.scatter(X_train, y_train, c="r", alpha=0.2, label="training set")
plt.legend()

y_hat = regressor.predict(X_valid)

print("intercept", regressor.intercept_)
print("coef", regressor.coef_)

plt.scatter(X_valid, y_hat, label="predicted")
plt.scatter(X_valid, y_valid, c="r", alpha=0.2, label="validation set")
plt.xlabel("tmdb_score")
plt.ylabel("imdb_score")
plt.legend()


def MSE(y_pred: NDArray[float], y_true: ArrayLike[float]):
    return np.mean((y_pred - y_true) ** 2)


def MAE(y_pred: NDArray[float], y_true: ArrayLike[float]):
    return np.mean(np.abs(y_pred - y_true))


def RMSE(y_pred: NDArray[float], y_true: ArrayLike[float]):
    return np.sqrt(MSE(y_pred, y_true))


print("MAE", MAE(y_hat, y_valid))

print("MSE", MSE(y_hat, y_valid))

print("RMSE", RMSE(y_hat, y_valid))

import sklearn.metrics as metrics

print("MAE:", metrics.mean_absolute_error(y_valid, y_hat))
print("MSE:", metrics.mean_squared_error(y_valid, y_hat))
print("RMSE:", np.sqrt(metrics.mean_squared_error(y_valid, y_hat)))

mean_imdb_score = y_valid.mean()

null_model_y = [mean_imdb_score] * y_valid.shape[0]

print("MAE:", metrics.mean_absolute_error(y_valid, null_model_y))
print("MSE:", metrics.mean_squared_error(y_valid, null_model_y))
print("RMSE:", np.sqrt(metrics.mean_squared_error(y_valid, null_model_y)))

amazon_titles_csv = pd.read_csv("amazon_titles.csv")
amazon_titles_csv.head()

amazon_titles = amazon_titles_csv.dropna(subset=["imdb_score", "tmdb_score"])
amazon_titles_csv.isna().sum()

X = amazon_titles[["tmdb_score"]]
y = amazon_titles["imdb_score"]
y_pred = regressor.predict(X)

plt.scatter(X, y_pred, label="predicted")
plt.scatter(X, y, alpha=0.2, label="test set")
plt.xlabel("tmdb_score")
plt.ylabel("imdb_score")
plt.legend()

print("MAE:", metrics.mean_absolute_error(y, y_pred))
print("MSE:", metrics.mean_squared_error(y, y_pred))
print("RMSE:", np.sqrt(metrics.mean_squared_error(y, y_pred)))

y_mean = y.mean()
print(y_mean)

null_model_y2 = [y_mean] * len(y)

print("MAE:", metrics.mean_absolute_error(y, null_model_y2))
print("MSE:", metrics.mean_squared_error(y, null_model_y2))
print("RMSE:", np.sqrt(metrics.mean_squared_error(y, null_model_y2)))

integrate_titles2 = integrate_titles.copy()
integrate_titles2["above_average"] = (
    integrate_titles2["imdb_score"] > integrate_titles2["imdb_score"].mean()
).astype(int)
integrate_titles2.head()

from sklearn.linear_model import LogisticRegression

from sklearn.linear_model import LogisticRegression

X_train2, X_valid2, y_train2, y_valid2 = train_test_split(
    integrate_titles2[["tmdb_score"]],
    integrate_titles2["above_average"],
    test_size=0.2,
    random_state=1,
)

logregressor = LogisticRegression()
logregressor.fit(X_train2, y_train2)
print(logregressor.score(X_train2, y_train2))
print(logregressor.score(X_valid2, y_valid2))

mean_above = y_valid2.mean()
max(mean_above, 1 - mean_above)

amazon_titles2 = amazon_titles.copy()
amazon_titles2["above_average"] = (
    amazon_titles2["imdb_score"] > amazon_titles2["imdb_score"].mean()
).astype(int)

X2 = amazon_titles2[["tmdb_score"]]
y2 = amazon_titles2["above_average"]

print("Model score:", logregressor.score(X2, y2))

mean_above2 = y2.mean()
print("Null model score:", max(mean_above2, 1 - mean_above2))

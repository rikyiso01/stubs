from __future__ import annotations
from kaggle.api.kaggle_api_extended import KaggleApi

api = KaggleApi()
api.authenticate()
api.competition_download_file("home-data-for-ml-course", "train.csv", force=True)

import pandas as pd

home_data = pd.read_csv("train.csv")
home_data.columns

y: pd.DataFrame[str, int, float] = home_data["SalePrice"]  # type: ignore
feature_names = [
    "LotArea",
    "YearBuilt",
    "1stFlrSF",
    "2ndFlrSF",
    "FullBath",
    "BedroomAbvGr",
    "TotRmsAbvGrd",
]
X: pd.DataFrame[str, int, float] = home_data[feature_names]  # type: ignore

home_data.describe()
home_data.head()

from sklearn.tree import DecisionTreeRegressor

iowa_model = DecisionTreeRegressor(random_state=1)

iowa_model.fit(X, y)

predictions = iowa_model.predict(X)
print(predictions)

y.head()

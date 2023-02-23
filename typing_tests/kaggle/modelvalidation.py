from __future__ import annotations
import pandas as pd
from kaggle.api.kaggle_api_extended import KaggleApi
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeRegressor
from sklearn.metrics import mean_absolute_error

api = KaggleApi()
api.authenticate()
api.dataset_download_files(
    "dansbecker/melbourne-housing-snapshot", unzip=True, force=True
)

melbourne_data = pd.read_csv("melb_data.csv")
filtered_melbourne_data = melbourne_data.dropna(axis=0)
print(filtered_melbourne_data.head())
y = filtered_melbourne_data["Price"]
melbourne_features = [
    "Rooms",
    "Bathroom",
    "Landsize",
    "BuildingArea",
    "YearBuilt",
    "Lattitude",
    "Longtitude",
]
X = filtered_melbourne_data[melbourne_features]

melbourne_model = DecisionTreeRegressor()
melbourne_model.fit(X, y)

predicted_home_prices = melbourne_model.predict(X)
mean_absolute_error(y, predicted_home_prices)

# split data into training and validation data, for both features and target
# The split is based on a random number generator. Supplying a numeric value to
# the random_state argument guarantees we get the same split every time we
# run this script.
train_X, val_X, train_y, val_y = train_test_split(X, y, random_state=0)
# Define model
melbourne_model = DecisionTreeRegressor()
# Fit model
melbourne_model.fit(train_X, train_y)

# get predicted prices on validation data
val_predictions = melbourne_model.predict(val_X)
print(mean_absolute_error(val_y, val_predictions))

from kaggle.api.kaggle_api_extended import KaggleApi

api = KaggleApi()
api.authenticate()
api.competition_download_file("home-data-for-ml-course", "train.csv", force=True)

import pandas as pd

home_data = pd.read_csv("train.csv")
y = home_data["SalePrice"]
feature_columns = [
    "LotArea",
    "YearBuilt",
    "1stFlrSF",
    "2ndFlrSF",
    "FullBath",
    "BedroomAbvGr",
    "TotRmsAbvGrd",
]
X = home_data[feature_columns]  # type: ignore

from sklearn.tree import DecisionTreeRegressor

iowa_model = DecisionTreeRegressor()
iowa_model.fit(X, y)

print("First in-sample predictions:", iowa_model.predict(X.head()))
print("Actual target values for those homes:", y.head().tolist())

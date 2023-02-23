from __future__ import annotations
from kaggle.api.kaggle_api_extended import KaggleApi

api = KaggleApi()
api.authenticate()
api.dataset_download_files("dansbecker/home-data-for-ml-course", unzip=True)

import pandas as pd

home_data: pd.DataFrame[str, int, float]
home_data = pd.read_csv("train.csv")  # type: ignore


home_data.describe()

avg_lot_size = round(home_data["LotArea"].mean())
print(avg_lot_size)

from datetime import date

newest_home_age = date.today().year - home_data["YearBuilt"].max()
print(newest_home_age)

import pandas as pd

yelp_raw_dati = pd.read_csv("yelp.csv")

yelp_raw_dati.head()

yelp_raw_dati.shape

yelp_raw_dati.isnull().sum()

yelp_raw_dati["business_id"].describe()

yelp_raw_dati["review_id"].describe()

yelp_raw_dati["text"].describe()

duplicate_text: str = yelp_raw_dati["text"].mode().iloc[0]
text_is_the_duplicate = yelp_raw_dati["text"] == duplicate_text
text_is_the_duplicate.head()

sum(text_is_the_duplicate)


filtered_dataframe = yelp_raw_dati[text_is_the_duplicate]

yelp_raw_dati["type"].describe()

yelp_raw_dati["user_id"].describe()

yelp_raw_dati["stars"].describe()

yelp_raw_dati["stars"].value_counts()

rank = yelp_raw_dati["stars"].value_counts()
rank.plot(kind="bar")

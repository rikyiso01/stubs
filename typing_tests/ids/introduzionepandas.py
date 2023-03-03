import matplotlib.pyplot as plt
import pandas as pd

url = "https://raw.githubusercontent.com/CSSEGISandData/COVID-19/master/csse_covid_19_data/csse_covid_19_time_series/time_series_19-covid-Confirmed.csv"
df = pd.read_csv(url, error_bad_lines=False)

print(df)

col = df["Country/Region"]

print(df[df["Lat"] > 51])

cleaned = df.drop(columns=["Province/State", "Lat", "Long"])

grouped = cleaned.groupby(["Country/Region"], as_index=False).sum()


Countries = ["China", "Germany", "Italy", "France", "Sweden"]
temp = grouped[grouped["Country/Region"].isin(Countries)]

print(temp)

dfs = temp.reset_index(drop=True)

print(dfs.loc[:, "3/3/20":])

print(dfs.loc[:2])
print(dfs.iloc[:, 2:10])
print(df.iloc[:3, :4])
k = df["Country/Region"] > "B"
print(df.loc[k, :"Long"])
j=((df["Country/Region"] > "B") & (df["Lat"] > 20))
print(df.loc[j, :"Long"])


copydf = df.copy()
copydf.iloc[0, 0] = "ABCDEFGH"
print(copydf.iloc[:3])
print(df.iloc[:3])
dfs1 = dfs.T
dfs2 = dfs1.reset_index()
n = dfs2.iloc[0].copy()
n["index"] = "Date"
#dfs2.columns = n
dfs3 = dfs2[1:]
dfs4 = dfs3.reset_index(drop=True)
dfs5 = dfs4.plot(kind="line", x="Date", figsize=(10, 6))
plt.gca().legend()
plt.grid()
plt.show()
ax = dfs4.plot.bar(x="Date", y="China", figsize=(10, 6))
plt.show()
ax = dfs4.plot.bar(x="Date", y="Italy", figsize=(10, 6))
plt.show()
ax = dfs4.plot.bar(x="Date", y="Germany", figsize=(10, 6))
plt.show()
ax = dfs4.plot.bar(x="Date", y="Sweden", figsize=(10, 6))
plt.show()

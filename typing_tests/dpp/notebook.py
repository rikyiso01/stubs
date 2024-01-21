from __future__ import annotations
import numpy as np
import matplotlib.pyplot as plt
import networkx as nx

a = np.array([1, 2, 3])


SEED = 42


x = np.logspace(1, 4, num=20)
print(x)


a, b, c = np.linalg.solve(
    [[10**2, 10, 1], [10**4**2, 10**4, 1], [2 * 10, 1, 0]], [1, 1, 0]
)
print(a, b, c)


plt.xlim((10, 10000))
# plt.xscale('log')
# plt.yscale('log')
plt.plot([10, 10000], [1, 1], "k--")
plt.plot(x, a * x**2 + b * x + c, "k--")
plt.xlabel("n")
plt.ylabel("t")
plt.show()


def robustness(G: nx.DiGraph[str]) -> list[float]:
    initial_size = len(max(nx.weakly_connected_components(G), key=len))
    result: list[float] = []
    copy = G.copy()
    for node in copy.nodes():
        result.append(
            len(max(nx.weakly_connected_components(G), key=len)) / initial_size
        )
        G.remove_node(node)
    return result


from generator import profiles_to_graph

data = []
y = robustness(nx.DiGraph(profiles_to_graph(data)))


plt.plot(y)
plt.xlabel("Number of nodes removed")
plt.ylabel("Robustness")
plt.show()


y = robustness(nx.DiGraph(profiles_to_graph(data)))


plt.plot(y)
plt.xlabel("Number of nodes removed")
plt.ylabel("Robustness")
plt.show()


print(nx.diameter(nx.Graph(profiles_to_graph(data))))


print(nx.diameter(nx.Graph(profiles_to_graph(data))))


from generator import profiles_to_graph
from statistics import mean


print(mean(nx.betweenness_centrality(nx.DiGraph(profiles_to_graph(data))).values()))
print(mean(nx.betweenness_centrality(nx.DiGraph(profiles_to_graph(data))).values()))


print(mean(nx.closeness_centrality(nx.DiGraph(profiles_to_graph(data))).values()))

print(mean(nx.closeness_centrality(nx.DiGraph(profiles_to_graph(data))).values()))


G = nx.DiGraph(profiles_to_graph(data))
centrality = [*nx.closeness_centrality(G).values()]

nx.draw(G, node_color=centrality, cmap=plt.cm.Reds)
from typing import assert_type

g2 = nx.MultiDiGraph(G)

assert_type(g2, nx.MultiDiGraph[str])

x = np.logspace(1, 4, num=20, dtype=int)

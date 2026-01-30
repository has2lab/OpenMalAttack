import networkx as nx
import time
import random


def get_start_time():
    print(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))


def get_end_time():
    print(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))


G = nx.Graph()
for i in range(5000):
    G.add_node(i)

for i in range(3000):
    source = random.randint(0, 2999)
    target = random.randint(0, 2999)
    G.add_edge(source, target)

a = G.number_of_nodes()
b = G.number_of_edges()

print(a, b)

"""
get_start_time()
a = nx.betweenness_centrality(G)
get_end_time()
print('betweenness_centrality')
print(a[0])
"""

get_start_time()
a = nx.degree_centrality(G)
get_end_time()
print('yes nx.degree_centrality')
print(a[0])

get_start_time()
a = nx.closeness_centrality(G)
get_end_time()
print('nx.closeness_centrality')
print(a[0])


from attackers import RandomAttacker
from classifiers import MalConv, MalGraph, Magic
from attack_evals import Evaler

random = RandomAttacker()
malconv = MalConv()
malgraph = MalGraph()
magic = Magic()
evaler_random_malconv = Evaler(random, malconv)
evaler_random_malgraph = Evaler(random, malgraph)
evaler_random_magic = Evaler(random, magic)

evaler_random_malconv()
evaler_random_malgraph()
evaler_random_magic()
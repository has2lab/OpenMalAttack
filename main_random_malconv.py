# import os
# import glob
# from attack_evals.base import AttackEval
# from attackers.BAttacks import RandomAttacker
# from datasets import PEDataset
# from classifiers import MalConvPytorch


# malconv = MalConvPytorch()
# random_attacker = RandomAttacker()
# datadir = os.path.expanduser('~/benign_data/origin_less_than_2MB/exe/')  # should be a folder with PE
# datadir = os.path.expanduser('~/mal_data/2019-11-29/Win32_EXE/')
# dataset = PEDataset(datadir)
# evaler = AttackEval(random_attacker, malconv)
# evaler.eval(dataset, 16)






from attack_evals.base import Evaler
from attackers import RandomAttacker
from classifiers import MalConv
import json

attacker = RandomAttacker()
clsf = MalConv()
eval_random_malconv = Evaler(attacker=attacker, clsf=clsf)
eval_random_malconv()

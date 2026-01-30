# from attack_eval.base import AttackEval
# from attackers.MakeOver.makeover import MakeOver
# from classifiers.malconv import MalConvPytorch
# from datasets import PEDataset
# import numpy as np
# import random
# import os

# def set_seed(seed=1):
#     random.seed(seed)
#     os.environ['PYTHONHASHSEED'] = str(seed)
#     np.random.seed(seed)

# set_seed(1)

# Makeover = MakeOver()
# MalConv = MalConvPytorch("models/MalConv-base_model_5838.pt")
# datadir = os.path.expanduser('~/mal_data/2019-11-29/Win32_EXE/')
# dataset = PEDataset(datadir)[10000:16000]
# evaler = AttackEval(Makeover, MalConv)
# evaler.eval(dataset)

from attack_evals.base import Evaler
from attackers import MakeOverAttacker
from classifiers import MalConv


if __name__ == "__main__":
    attacker = MakeOverAttacker()
    clsf = MalConv()
    eval_makeover_malconv = Evaler(attacker=attacker, clsf=clsf)
    eval_makeover_malconv()
from attack_evals.base import Evaler
from attackers import GammaAttacker
from classifiers import MalConv
import json

attacker = GammaAttacker()
clsf = MalConv()
eval_gamma_malconv = Evaler(attacker=attacker, clsf=clsf)
eval_gamma_malconv()
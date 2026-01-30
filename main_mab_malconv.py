from attack_evals.base import RLEvaler
from attackers import MABAttacker
from classifiers import MalConv

attacker = MABAttacker()
clsf = MalConv()
eval_mab_malconv = RLEvaler(attacker=attacker, clsf=clsf)
eval_mab_malconv(env_id="mab-malconv-v0")
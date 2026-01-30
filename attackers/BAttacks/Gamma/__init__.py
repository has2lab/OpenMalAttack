import copy
from operator import index
import os
import random
import datetime
import time
from xmlrpc.client import boolean
import numpy as np
from classifiers.base import Classifier
from attackers.base import Problem_Space
from dataclasses import dataclass
from pathlib import Path
from utils.file_handler import save_evaded_sample, calc_sha256
from utils.padding_injection import IndividualOpt, get_Secpopulation

@dataclass
class GammaAttackerConfig:
    max_query: int = 5 # 10~510 origin:30
    converge_iter: int = 5
    population_size: int = 10
    use_section_num: int = 75
    hard_label: bool = True
    regularization: float = 1e-3
    manipulation: str = "section_injection"  # 'padding'
    goodware_path = Path('dataset/goodware/').expanduser()
    output_path = Path("output/").expanduser()

    def __post_init__(self):
        self.output_path.mkdir(parents=True, exist_ok=True)

class GammaAttacker(Problem_Space):
    def __init__(self, **kwargs):
        """
        max_query: maximum queries for every iteration
        converge_iter: attack converges when 
        """
        super(GammaAttacker, self).__init__()
        self.reset()
        self.__name__ = 'Gamma'

        self.config = GammaAttackerConfig()
        self.config.__dict__.update(kwargs)
        assert self.config.goodware_path is not None
        assert self.config.output_path is not None
        self.Secpopulation = get_Secpopulation(self.config.goodware_path, self.config.use_section_num)
 
    # Attack MalConv, Original size should less than 2MB
    def __call__(self, clsf: Classifier, input_: bytes):
        self._attack_begin()

        _q = 1

        # The algorithm is initialized by randomly generating a matrix(N*k) S
        # which represents the initial population of N candidate manipulation vectors
        S = np.random.rand(self.config.population_size, self.config.use_section_num)

        # Initialize the Operator
        _IndividualOpt = IndividualOpt(bytez=input_, 
                                       inds=S, 
                                       evaluator=clsf, 
                                       hard_label=self.config.hard_label, 
                                       regularization=self.config.regularization, 
                                       action=self.config.manipulation, 
                                       Secpopulation=self.Secpopulation)

        while _q < self.config.max_query:
            # $ Selection
            S_candidate = _IndividualOpt._min_n_cand(self.config.population_size)
            # $ Crossover
            S_candidate = _IndividualOpt.crossover(S_candidate, self.config.use_section_num)
            # $ Mutate
            S_candidate = _IndividualOpt.mutate(S_candidate, self.config.use_section_num)

            # In each iteration, the algorithm performs N new queries to the target model, 
            # to evaluate the objective F on the new candidates in S, 
            _IndividualOpt._add(S_candidate)

            # and then retains the best candidate population S. 
            best_now = _IndividualOpt._sliced_min(len(S_candidate))

            # The corresponding optimal adversarial malware x' can be finally obtained by applying the optimal
            # manipulation vector s to the input sample x through the manipulation operator ⊕ as x' = x ⊕ s.
            modified_bytez = _IndividualOpt.manipulationUtil.manipulate(best_now)

            prediction = clsf(modified_bytez).item()

            # Attack Succeeded
            if prediction is False:
                # print('Total query:', _q)
                self._attack_finish()
                self._succeed()
                return calc_sha256(modified_bytez), True
            _q = _q + 1

        # Attack Failed
        # print('Total query:', _q)
        self._attack_finish()
        return None, False
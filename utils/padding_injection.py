import lief  # pip install https://github.com/lief-project/LIEF/releases/download/0.7.0/linux_lief-0.7.0_py3.6.tar.gz
import json
import os
import array
import random
import copy
import time
import string
import numpy as np
# from secml.array import CArray
# from deap import base, creator, tools, algorithms

INFINIT = float("inf") 

# for every iteration:
#   self.record = select N candidate
#   deepcopy(self.record)
#   do crossover & mutation
#   apply the 'fitness' function for new candidates to original data  (fitness: 1.apply manipulation 2.compute penalty term 3.calculate the score of objective fucntion)

class Individuals(object):
    def __init__(self, inds: np.ndarray, pred: np.ndarray):
        assert pred is not None and inds is not None
        self.individuals = inds
        self.predictions = pred
        self.ind_num = len(self.individuals)

    def _addItems(self, inds: np.ndarray, pred: np.ndarray):
        assert pred is not None and inds is not None
        self.individuals = np.concatenate((self.individuals, inds), axis=0)
        self.predictions = np.concatenate((self.predictions, pred), axis=0)
        self.ind_num = len(self.individuals)

    def __len__(self):
        return self.ind_num

    def __getitem__(self, idx):
        return self.individuals[idx], self.predictions[idx]


class Manipulations(object):
    def __init__(self, section_population, bytez, action):
        self.section_population = section_population
        self._action = action
        self._bytez = bytez
    
    def manipulate(self, manipulation: np.ndarray):
        assert self._action in ['padding', 'section_injection']
        modified_bytez = copy.deepcopy(self._bytez)
        manipulated_malware = self.padding(manipulation, modified_bytez) if self._action == 'padding' else self.SecInject(manipulation, modified_bytez)
        return manipulated_malware

    def padding(self, manipulation, bytez):
        manipulated_bytez = list(copy.deepcopy(bytez))
        for i in range(len(manipulation)):                  
            section_content = self.section_population[i]
            manipulated_bytez += section_content[: int(len(section_content)*manipulation[i])]
        return b''.join([bytes((m,)) for m in manipulated_bytez])

    def SecInject(self, manipulation, bytez):
        manipulated_bytez = list(copy.deepcopy(bytez))
        manipulated_malware = lief.PE.parse(raw=manipulated_bytez)

        # ! Code cited from https://github.com/pralab/secml_malware 
        for i in range(len(manipulation)):
            secName = "".join([random.choice(string.ascii_letters+'.?_') for _ in range(6)])
            new_section = lief.PE.Section(secName)
            new_section.content = self.section_population[i][: int(len(self.section_population[i]) * manipulation[i])]
            new_section.virtual_address = max([sec.virtual_address + sec.size for sec in manipulated_malware.sections])
            manipulated_malware.add_section(new_section,
                                        random.choice([
                                            lief.PE.SECTION_TYPES.BSS,
                                            lief.PE.SECTION_TYPES.DATA,
                                            lief.PE.SECTION_TYPES.EXPORT,
                                            lief.PE.SECTION_TYPES.IDATA,
                                            lief.PE.SECTION_TYPES.RELOCATION,
                                            lief.PE.SECTION_TYPES.RESOURCE,
                                            lief.PE.SECTION_TYPES.TEXT,
                                            lief.PE.SECTION_TYPES.TLS_,
                                            lief.PE.SECTION_TYPES.UNKNOWN,
                                        ]))
        
        builder = lief.PE.Builder(manipulated_malware)
        builder.build()
        return array.array("B", builder.get_build()).tobytes()
        # ! End


class IndividualOpt(object):
    def __init__(self, 
                bytez: bytes,
                evaluator, 
                population_size: int = 10,
                inds: np.ndarray = None, 
                hard_label: bool=True, 
                regularization: float=1e-3, 
                action: str='padding',
                Secpopulation = None):
        self._bytez = bytez
        self._defender = evaluator
        self._hard_label = hard_label
        self._regular = regularization
        self._threshold = evaluator.clsf_threshold
        self._action = action
        self.population_size = population_size
        self.manipulationUtil = Manipulations(Secpopulation, bytez, action)
        self._individual = Individuals(inds, self._predict(inds))


    def _add(self, inds: np.ndarray):
        self._individual._addItems(inds, self._predict(inds))

    def _sliced_min(self, slice: int):
        inds, pred = self._individual[-slice:]
        return inds[np.argmin(pred)]

    def _min_n_cand(self, population_size: int):
        '''
        The selection step uses the objective function to evaluate the candidates in S, 
        and selects the best N candidates between the current population S and
        the population generated at the previous iteration S'.
        '''
        res = []
        for _ in range(population_size):
            cand_indx = np.random.choice(len(self._individual), 10, replace=False)
            inds, pred = self._individual[cand_indx]
            res.append(inds[np.argmin(pred)])
        return np.array(res)

    def _predict(self, inds: np.ndarray):
        mani_bytez = []
        penalty = []
        for i in range(inds.shape[0]):
            tmp = self.manipulationUtil.manipulate(inds[i])
            mani_bytez.append(tmp)
            penalty.append(self._regular * abs(len(tmp) - len(self._bytez)))
        pred = self._defender(mani_bytez).cpu().numpy()
        for i in range(inds.shape[0]):
            if self._hard_label:
                pred[i] = float('inf') if pred[i] > self._threshold else 0
            pred[i] += penalty[i]
        return np.array(pred)

    def crossover(self, manipulations: np.ndarray, use_section_num: int):
        '''
        The crossover function takes the selected candidates as input and returns a novel set of N candidates
        by mixing the values of pairs of randomly-chosen vector candidates. 
        In particular, given a pair of candidate vectors from the previous population, a new candidate is generated
        by cloning the values s1, ... ,sj from the first parent and the remaining values sj+1, ... ,sk from 
        the second parent, being j ∈ {1, . . . , k} an index selected at random.
        '''
        S_candidate = []
        num_mani = len(manipulations)
        for i in range(self.population_size):
            if random.random() < 0.9:
                p1, p2 = random.sample(range(num_mani), 2)
                mani_1, mani_2 = manipulations[p1], manipulations[p2]
                indx = random.randint(0, use_section_num)
                new_cand = np.append(mani_1[:indx], mani_2[indx:])
                assert len(new_cand) == len(mani_2)
                S_candidate.append(new_cand)
            else:
                S_candidate.append(manipulations[i])
        return np.array(S_candidate)

    def mutate(self, manipulations: np.ndarray, use_section_num: int):
        """
         The mutation function changes the elements of each input vector at random, with low probability. 
        """
        p = 0.3
        for i in range(len(manipulations)):
            if random.random() < p:
                manipulations[i] = np.random.uniform(0,1 ,(use_section_num))
        return manipulations
        

def get_Secpopulation(path, use_section_num):
    population = []
    file_list = os.listdir(path)
    for file in file_list:
        if os.path.splitext(file)[-1] != '':
            continue
        benign_path = os.path.join(path, file)
        try:
            pe = lief.PE.parse(benign_path)
            for sec in pe.sections:
                if sec.name == ".data":
                    if len(sec.content) > 0:
                        population.append(sec.content)
        except:
            continue
    return population[:use_section_num]

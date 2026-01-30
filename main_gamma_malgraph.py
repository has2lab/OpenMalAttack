import hashlib
import torch
from attack_evals.base import Evaler
from attackers import GammaAttacker
from classifiers import MalGraph as _MalGraph
from classifiers.base import Classifier


class MalGraphWrapper(Classifier):
    def __init__(self, **kwargs):
        self.inner = _MalGraph(**kwargs)
        self.__name__ = 'MalGraph'
        self.clsf_threshold = self.inner.clsf_threshold
        self.device = self.inner.config.device

    def _score_one(self, bytez: bytes) -> float:
        if not isinstance(bytez, (bytes, bytearray)):
            bytez = bytes(bytez)
        data_hash = hashlib.sha256(bytez).hexdigest()
        try:
            return self.inner.get_score(bytez, data_hash)
        except Exception:
            return 1.0

    def __call__(self, bytez):
        if isinstance(bytez, (list, tuple)):
            scores = [self._score_one(b) for b in bytez]
            bools = [s > self.clsf_threshold for s in scores]
            return torch.tensor(bools, dtype=torch.bool, device=self.device)
        score = self._score_one(bytez)
        return torch.tensor(score > self.clsf_threshold,
                            dtype=torch.bool,
                            device=self.device)


if __name__ == "__main__":
    clsf = MalGraphWrapper()
    attacker = GammaAttacker(max_query=10)
    eval_gamma_malgraph = Evaler(attacker=attacker, clsf=clsf)
    eval_gamma_malgraph()
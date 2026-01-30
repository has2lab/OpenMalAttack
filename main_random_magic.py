from attack_evals.base import Evaler
from attackers import RandomAttacker
from classifiers import Magic as _Magic
import torch
from classifiers.base import Classifier
import hashlib


class MagicWrapper(Classifier):
    """
    适配 MagicClsf 到 MalConv 风格接口，使其可以被 Evaler / RandomAttacker 正常调用。
    - Evaler 这边：只传一个 bytez，返回 bool（是否恶意）。
    - RandomAttacker 那边：传入 bytez，返回 bool。
    """
    def __init__(self, **kwargs):
        # kwargs 可以传 threshold_type='100fpr' / '1000fpr', device 等
        self.inner = _Magic(**kwargs)
        self.__name__ = 'Magic'
        self.clsf_threshold = self.inner.clsf_threshold

    def _score_one(self, bytez: bytes) -> float:
        """
        对单个样本，返回 Magic 的分数（float），用于内部计算。
        """
        if not isinstance(bytez, (bytes, bytearray)):
            bytez = bytes(bytez)
        data_hash = hashlib.sha256(bytez).hexdigest()
        # MagicClsf.get_score 返回 float
        try:
            return self.inner.get_score(bytez, data_hash)
        except FileNotFoundError:
            return 1.0

    def __call__(self, *args, **kwargs):
        """
        兼容两种调用方式：
        - clsf(bytez) - Evaler 调用方式
        - clsf(bytez=bytez) - RandomAttacker 调用方式
        """
        # 从 args 或 kwargs 获取 bytez
        if args:
            bytez = args[0]
        elif 'bytez' in kwargs:
            bytez = kwargs['bytez']
        else:
            raise ValueError("bytez parameter is required")
        
        if not isinstance(bytez, (bytes, bytearray)):
            bytez = bytes(bytez)
        
        score = self._score_one(bytez)
        return torch.tensor(score > self.clsf_threshold, dtype=torch.bool)


attacker = RandomAttacker()
clsf = MagicWrapper()
eval_random_magic = Evaler(attacker=attacker, clsf=clsf)
eval_random_magic()
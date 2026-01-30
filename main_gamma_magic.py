from attack_evals.base import Evaler
from attackers import GammaAttacker
from classifiers import Magic as _Magic
import json, torch
from classifiers.base import Classifier
import hashlib


class MagicWrapper(Classifier):
    """
    适配 MagicClsf 到 MalConv 风格接口，使其可以被 Evaler / GammaAttacker / IndividualOpt 正常调用。
    - Evaler 这边：只传一个 bytez，返回 bool（是否恶意）。
    - Gamma / IndividualOpt 那边：会传入一个 bytez 列表，我们返回一个 bool 向量（tensor），和 MalConv 行为一致。
    同时暴露 clsf_threshold 属性，供 IndividualOpt 使用。
    """
    def __init__(self, **kwargs):
        # kwargs 可以传 threshold_type='100fpr' / '1000fpr', device 等
        self.inner = _Magic(**kwargs)
        self.__name__ = 'Magic'
        # 让 Gamma 的 padding_injection.IndividualOpt 能访问到阈值
        self.clsf_threshold = self.inner.clsf_threshold
        # 顺便保留 device，后面构造 tensor 用
        self.device = self.inner.config.device

    def _score_one(self, bytez: bytes) -> float:
        if not isinstance(bytez, (bytes, bytearray)):
            bytez = bytes(bytez)
        data_hash = hashlib.sha256(bytez).hexdigest()
        try:
            return self.inner.get_score(bytez, data_hash)
        except FileNotFoundError:
            return 1.0

    def __call__(self, bytez):
        """
        兼容两种调用：
        - bytez 是单个样本（bytes）：返回 bool 的 0D tensor（score > threshold），给 Evaler / GammaAttacker 用。
        - bytez 是样本列表：返回 bool 向量 tensor，给 IndividualOpt._predict 用（和 MalConvClsf 行为对齐）。
        """
        # 1. 列表输入：给 IndividualOpt 用
        if isinstance(bytez, (list, tuple)):
            scores = [self._score_one(b) for b in bytez]
            # 将分数转成 bool（是否超过阈值），再转成 tensor
            bools = [s > self.clsf_threshold for s in scores]
            return torch.tensor(bools, dtype=torch.bool, device=self.device)

        # 2. 单样本输入：给 Evaler / GammaAttacker 用
        score = self._score_one(bytez)
        print(score, torch.tensor(score > self.clsf_threshold,
                            dtype=torch.bool,
                            device=self.device))
        return torch.tensor(score > self.clsf_threshold,
                            dtype=torch.bool,
                            device=self.device)


attacker = GammaAttacker()
clsf = MagicWrapper()
eval_gamma_magic = Evaler(attacker=attacker, clsf=clsf)
eval_gamma_magic()

import hashlib
import torch
from attack_evals.base import RLEvaler
from attackers import MABAttacker
from classifiers import MalGraph as _MalGraph
from classifiers.base import Classifier


class MalGraphWrapper(Classifier):
    """
    适配 MalGraphClsf 到 MAB 风格接口，使其可以被 RLEvaler / MABAttacker 正常调用。
    参考 Gamma 的实现，确保异常处理和参数传递的一致性。
    - RLEvaler 这边：通过 env 调用 model.get_score
    - MAB env 那边：会调用 model.get_score(bytez, sha256)
    同时暴露 clsf_threshold 属性，供 MAB env 使用。
    """
    def __init__(self, **kwargs):
        self.inner = _MalGraph(**kwargs)
        self.__name__ = 'MalGraph'
        self.clsf_threshold = self.inner.clsf_threshold
        self.device = self.inner.config.device

    def get_score(self, bytez: bytes, sha256: str) -> float:
        """
        MAB env 会调用这个方法
        参考 Gamma 的实现，确保异常处理一致
        """
        if not isinstance(bytez, (bytes, bytearray)):
            bytez = bytes(bytez)
        try:
            return self.inner.get_score(bytez, sha256)
        except Exception as e:
            # 异常时返回高分（视为恶意），确保程序继续运行
            print(f'[MalGraphWrapper.get_score] Exception: {e}, returning 1.0')
            return 1.0

    def predict_proba(self, *args, **kwargs):
        """
        为了兼容，但MAB env不会调用这个方法
        """
        raise NotImplementedError("MalGraphWrapper should use get_score instead")


if __name__ == "__main__":
    attacker = MABAttacker()
    clsf = MalGraphWrapper()
    eval_mab_malgraph = RLEvaler(attacker=attacker, clsf=clsf)
    eval_mab_malgraph(env_id="mab-malgraph-v0")

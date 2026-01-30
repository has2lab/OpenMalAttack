from attack_evals.base import RLEvaler
from attackers import MABAttacker
from classifiers import Magic as _Magic
import torch
from classifiers.base import Classifier
import hashlib


class MagicWrapper(Classifier):
    """
    适配 MagicClsf 到 MAB 风格接口，使其可以被 RLEvaler / MABAttacker 正常调用。
    参考 Gamma 的实现，确保异常处理和参数传递的一致性。
    - RLEvaler 这边：通过 env 调用 model.get_score
    - MAB env 那边：会调用 model.get_score(bytez, sha256)
    同时暴露 clsf_threshold 属性，供 MAB env 使用。
    """
    def __init__(self, **kwargs):
        # kwargs 可以传 threshold_type='100fpr' / '1000fpr', device 等
        self.inner = _Magic(**kwargs)
        self.__name__ = 'Magic'
        # 让 MAB env 能访问到阈值
        self.clsf_threshold = self.inner.clsf_threshold
        # 顺便保留 device，后面构造 tensor 用
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
        except FileNotFoundError:
            # 文件未找到时返回高分（视为恶意），与 Gamma 实现一致
            return 1.0
        except Exception as e:
            # 其他异常也返回高分，确保程序继续运行
            print(f'[MagicWrapper.get_score] Exception: {e}, returning 1.0')
            return 1.0

    def predict_proba(self, *args, **kwargs):
        """
        为了兼容，但MAB env不会调用这个方法
        """
        raise NotImplementedError("MagicWrapper should use get_score instead")


if __name__ == "__main__":
    attacker = MABAttacker()
    clsf = MagicWrapper()
    eval_mab_magic = RLEvaler(attacker=attacker, clsf=clsf)
    eval_mab_magic(env_id="mab-magic-v0")

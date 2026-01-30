# import numpy as np
# import torch
# import torchvision
# from torchvision import transforms
# import os
# import pandas as pd
# import argparse
# from ThirdParty.FGSM.FGSM import FGSMAttack
# from ThirdParty.CW.l2 import carlini_wagner_l2
# from ThirdParty.CW.linf import carlini_wagner_linf

# from classifiers.base import Classifier
# from attackers.base import Problem_Space
# from dataclasses import dataclass
# import time
# import random
# import PIL


# # 只加入ATMPA的FGSM实现
# class ATMPA_Attacker(Problem_Space):
#     def __init__(self, **kwargs):
#         super(ATMPA_Attacker, self).__init__()
#         self.reset()

#     # Attack inception_v3
#     def __call__(self, clsf: Classifier, input_: bytes):
#         self._attack_begin()
#         self.setup_seed(10086)

#         # 超参数？
#         EPSILON = 0.01
#         THETA = 0.1
#         attack = FGSMAttack(clsf.model, EPSILON)
#         image = np.frombuffer(input_, dtype='>u1')  # 这里注意一下，我的理解bytes就是原始的字节流

#         myTransform = transforms.Compose([
#             transforms.Resize([299, 299]),
#             transforms.Grayscale(1),
#             transforms.ToTensor()
#         ])

#         image = PIL.Image.fromarray(image[None])
#         image = image.convert('L')

#         images = myTransform(image)[None]
#         scores = clsf.predict_proba(images)
#         labels = scores.argmax(dim=1)
#         # labels = np.argmax(scores, axis=1)

#         # 双重验证，即要求是对抗样本，有要求距离足够近
#         adverisalExamples = attack.perturb(images.to("cpu"), labels.to('cpu'))
#         adverisalExamples_labels = clsf(torch.from_numpy(adverisalExamples).to('cpu'))

#         isAdverisalExamples = np.array(adverisalExamples_labels.cpu() != labels)

#         distortions = (torch.from_numpy(adverisalExamples) - images).norm(p=np.inf, dim=(1, 2, 3)).numpy()
#         isSuccessExamples = np.array(distortions <= THETA)

#         isSuccessAdversialExamples = isAdverisalExamples & isSuccessExamples

#         self._attack_finish()

#         if isSuccessAdversialExamples[0]:
#             self._succeed()
#             return None, None, True  # 返回值不是太理解用途，可更改
#         else:
#             return None, None, False

#     def setup_seed(self, seed=0):
#         torch.manual_seed(seed)  # 为CPU设置随机种子
#         np.random.seed(seed)  # Numpy module.
#         random.seed(seed)  # Python random module.
#         if torch.cuda.is_available():
#             # torch.backends.cudnn.benchmark = False
#             torch.backends.cudnn.deterministic = True
#             torch.cuda.manual_seed(seed)  # 为当前GPU设置随机种子
#             torch.cuda.manual_seed_all(seed)  # 为所有GPU设置随机种子
#             # os.environ['PYTHONHASHSEED'] = str(seed)








import numpy as np
import torch
import torchvision
from torchvision import transforms
import os
import pandas as pd
import argparse
from ThirdParty.FGSM.FGSM import FGSMAttack

from classifiers.base import Classifier
from attackers.base import Problem_Space
from dataclasses import dataclass
import time
import random
import PIL
import io


# 只加入ATMPA的FGSM实现
class ATMPA_Attacker(Problem_Space):
    def __init__(self, **kwargs):
        super(ATMPA_Attacker, self).__init__()
        self.__name__ = "ATMPA"
        self.reset()

    # Attack inception_v3
    def __call__(self, clsf: Classifier, input_: bytes):
        self._attack_begin()
        self.setup_seed(10086)

        # 超参数？
        EPSILON = 0.01
        THETA = 0.1
        attack = FGSMAttack(clsf.model, EPSILON)
        myTransform = transforms.Compose([
            transforms.Resize([299, 299]),
            transforms.Grayscale(1),
            transforms.ToTensor()
        ])

        # 优先尝试把 bytes 当作真实图片文件解码；失败再退化为 frombuffer 方式
        try:
            image = PIL.Image.open(io.BytesIO(input_))
        except Exception:
            image_np = np.frombuffer(input_, dtype='>u1')
            image = PIL.Image.fromarray(image_np[None])
        image = image.convert('L')

        # 原始图像张量 [1, 1, 299, 299]，范围 [0, 1]
        images = myTransform(image)[None]

        # 使用分类器给出原始标签（整数类别）
        scores = clsf.predict_proba(images)
        labels = scores.argmax(dim=1)

        # FGSM 接口使用 numpy 数组和 numpy 标签
        images_np = images.detach().cpu().numpy()
        labels_np = labels.detach().cpu().numpy().astype(np.int64)

        # 双重验证，即要求是对抗样本，有要求距离足够近
        adverisalExamples_np = attack.perturb(images_np, labels_np)

        # 转回 torch 张量进行后续计算
        adverisalExamples = torch.from_numpy(adverisalExamples_np).to(images.device)

        adv_scores = clsf.predict_proba(adverisalExamples)
        adv_labels = adv_scores.argmax(dim=1)

        isAdverisalExamples = (adv_labels != labels).detach().cpu().numpy()

        distortions = (adverisalExamples - images).norm(p=np.inf, dim=(1, 2, 3)).detach().cpu().numpy()
        isSuccessExamples = distortions <= THETA

        isSuccessAdversialExamples = isAdverisalExamples & isSuccessExamples

        self._attack_finish()

        success = bool(isSuccessAdversialExamples[0])
        if success:
            self._succeed()
        # 与 GammaAttacker 等保持一致的返回接口：(sha256, label)
        return None, success

    def setup_seed(self, seed=0):
        torch.manual_seed(seed)  # 为CPU设置随机种子
        np.random.seed(seed)  # Numpy module.
        random.seed(seed)  # Python random module.
        if torch.cuda.is_available():
            # torch.backends.cudnn.benchmark = False
            torch.backends.cudnn.deterministic = True
            torch.cuda.manual_seed(seed)  # 为当前GPU设置随机种子
            torch.cuda.manual_seed_all(seed)  # 为所有GPU设置随机种子
            # os.environ['PYTHONHASHSEED'] = str(seed)

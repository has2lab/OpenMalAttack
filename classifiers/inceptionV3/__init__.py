# import torch
# from ThirdParty.inceptionV3 import inception_v3
# from classifiers.base import Classifier


# class InceptionV3(Classifier):
#     def __init__(self, model_file='/OpenMalAttack/models/inceptionV3_FGSM.pth', **kwargs):
#         super(InceptionV3, self).__init__(**kwargs)

#         device = self.select_device()
        
#         self.malicious_threshold = 0.5
#         self.model = inception_v3(pretrained=False)
#         self.model.load_state_dict(torch.load(model_file, map_location='cpu'))
#         self.model.eval()

#     def __call__(self, image) -> bool:
#         score = self.predict_proba(image)
#         return score.argmax(dim=1)
    
#     def predict_proba(self, image) -> float:
#         score = self.model(image)
#         return score

#     def select_device(self):
#         if torch.has_mps:
#             device = torch.device('mps')
#             # print('-------using mps as device-------')
#         elif torch.cuda.is_available():
#             device = torch.device('cuda')
#             # print('-------using cuda as device-------')
#         else:
#             device = torch.device('cpu')
#             # print('-------using cpu as device-------')
#         return device




import torch
from ThirdParty.inceptionV3 import inception_v3
from classifiers.base import Classifier
from dataclasses import dataclass


@dataclass
class configuration:
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    model_file = "/OpenMalAttack/models/inceptionV3_FGSM.pth"
    threshold_type = '100fpr'


class InceptionV3(Classifier):
    """
    简单封装的 InceptionV3 二分类检测器。

    - predict_proba: 返回原始 logits / 概率张量
    - __call__: 返回是否为“恶意”（True/False）的布尔张量，供 Evaler 使用
    """

    def __init__(self, model_file='/OpenMalAttack/models/inceptionV3_FGSM.pth', threshold_type='100fpr', **kwargs):
        super(InceptionV3, self).__init__(**kwargs)

        self.config = configuration()
        self.config.__dict__.update(kwargs)
        if 'model_file' in kwargs:
            self.config.model_file = kwargs['model_file']
        if 'threshold_type' in kwargs:
            self.config.threshold_type = kwargs['threshold_type']

        self.device = self.select_device()

        # 根据 threshold_type 设置阈值
        if self.config.threshold_type == '100fpr':
            self.clsf_threshold = 0.91069
        elif self.config.threshold_type == '1000fpr':
            self.clsf_threshold = 0.40456
        else:
            raise NotImplementedError(f"threshold_type {self.config.threshold_type} not supported")

        self.model = inception_v3(pretrained=False)
        self.model.load_state_dict(torch.load(self.config.model_file, map_location='cpu'))
        self.model.to(self.device)
        self.model.eval()

    def __call__(self, image) -> torch.Tensor:
        """
        返回布尔张量：True 表示“恶意”，False 表示“良性”。
        """
        scores = self.predict_proba(image)
        # 支持 1 维或 2 维输出
        if scores.ndim == 2 and scores.size(1) > 1:
            probs = torch.softmax(scores, dim=1)
            malicious_prob = probs[:, 1]
        else:
            malicious_prob = torch.sigmoid(scores.view(-1))
        return malicious_prob > self.clsf_threshold

    def predict_proba(self, image) -> torch.Tensor:
        image = image.to(self.device)
        score = self.model(image)
        return score

    def select_device(self):
        if getattr(torch, "has_mps", False):
            device = torch.device('mps')
        elif torch.cuda.is_available():
            device = torch.device('cuda')
        else:
            device = torch.device('cpu')
        return device


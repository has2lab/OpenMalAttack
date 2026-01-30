from attack_evals.base import Evaler
from attackers import COPYCAT_Attacker
from classifiers import InceptionV3

import torch
from torchvision import transforms
from io import BytesIO
import PIL
import numpy as np


class InceptionV3BytesWrapper:
    def __init__(self, **kwargs):
        self.inner = InceptionV3(**kwargs)
        self.__name__ = "InceptionV3"
        self.model = self.inner.model
        self.device = self.inner.device

        self.transform = transforms.Compose([
            transforms.Resize([299, 299]),
            transforms.Grayscale(1),
            transforms.ToTensor(),
        ])

    def _bytes_to_tensor(self, b: bytes) -> torch.Tensor:
        try:
            img = PIL.Image.open(BytesIO(b))
        except Exception:
            arr = np.frombuffer(b, dtype=">u1")
            img = PIL.Image.fromarray(arr[None])
        img = img.convert("L")
        return self.transform(img)[None]

    def predict_proba(self, image):
        if isinstance(image, (bytes, bytearray)):
            image = self._bytes_to_tensor(bytes(image))
        return self.inner.predict_proba(image)

    def __call__(self, x):
        if isinstance(x, (bytes, bytearray)):
            x = self._bytes_to_tensor(bytes(x))
        return self.inner(x)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="COPYCAT attack on InceptionV3")
    parser.add_argument("--fpr", type=str, default="100", help="100 or 1000")
    args = parser.parse_args()
    
    fpr_type = "100fpr" if args.fpr == "100" else "1000fpr"
    
    attacker = COPYCAT_Attacker()
    clsf = InceptionV3BytesWrapper(threshold_type=fpr_type)
    eval_copycat_inception = Evaler(attacker=attacker, clsf=clsf)
    eval_copycat_inception()


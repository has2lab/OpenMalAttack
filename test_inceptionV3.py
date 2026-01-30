import argparse
import os
from pathlib import Path
from io import BytesIO

import torch
import numpy as np
from torchvision import transforms
from sklearn.metrics import roc_auc_score, confusion_matrix, balanced_accuracy_score, accuracy_score
import PIL

from classifiers import InceptionV3
from dataset import malware_data, goodware_data


class InceptionV3BytesWrapper:
    """
    让 InceptionV3 支持直接输入 bytes（来自图片文件或任意二进制文件）。
    - __call__(bytes) -> bool tensor (恶意=True)
    - predict_proba(bytes|tensor) -> logits tensor
    """

    def __init__(self, **kwargs):
        self.inner = InceptionV3(**kwargs)
        self.__name__ = "InceptionV3"
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
            # fallback: treat bytes as raw stream, make a 1xN image
            arr = np.frombuffer(b, dtype=">u1")
            img = PIL.Image.fromarray(arr[None])
        img = img.convert("L")
        x = self.transform(img)[None]  # [1,1,299,299]
        return x

    def predict_proba(self, x):
        if isinstance(x, (bytes, bytearray)):
            x = self._bytes_to_tensor(bytes(x))
        return self.inner.predict_proba(x)

    def _get_malicious_prob(self, x):
        """返回恶意概率（标量）"""
        scores = self.predict_proba(x)
        if isinstance(scores, torch.Tensor):
            if scores.ndim == 2 and scores.size(1) > 1:
                probs = torch.softmax(scores, dim=1)
                return float(probs[0, 1].item())
            else:
                return float(torch.sigmoid(scores.view(-1)[0]).item())
        return float(scores)

    def __call__(self, x):
        if isinstance(x, (bytes, bytearray)):
            x = self._bytes_to_tensor(bytes(x))
        return self.inner(x)


def compute_threshold(benign_scores, target_fpr_count):
    """
    计算阈值：使得在良性样本中，有 target_fpr_count 个被误判为恶意。
    
    Args:
        benign_scores: 良性样本的恶意概率列表
        target_fpr_count: 目标误报数量（如 100 或 1000）
    
    Returns:
        threshold: 阈值
    """
    if len(benign_scores) == 0:
        return 0.5
    sorted_scores = sorted(benign_scores)
    # 如果目标数量 >= 样本数，返回最小值（所有都被判为恶意）
    if target_fpr_count >= len(sorted_scores):
        return sorted_scores[0] - 1e-6
    # 取第 target_fpr_count 个（从小到大），使得恰好有 target_fpr_count 个误报
    threshold = sorted_scores[target_fpr_count - 1]
    return threshold


def main():
    parser = argparse.ArgumentParser(description="inceptionV3")
    parser.add_argument("--fpr", type=str, help="100 or 1000")
    parser.add_argument("--gpu", type=int, default=-1, help="gpu id (optional)")
    parser.add_argument("--model_file", type=str, default="/OpenMalAttack/models/inceptionV3_FGSM.pth")
    args = parser.parse_args()

    if args.fpr == "100":
        fpr_type = "100fpr"
        target_fpr_count = 100
    elif args.fpr == "1000":
        fpr_type = "1000fpr"
        target_fpr_count = 1000
    else:
        raise Exception("incorrect fpr, use --fpr 100 or --fpr 1000")

    # 第一步：收集所有样本的 scores（不设阈值）
    clsf_raw = InceptionV3BytesWrapper(model_file=args.model_file, threshold_type=fpr_type)
    
    mal_scores, ben_scores = [], []
    err_mal, err_ben = 0, 0

    print("Collecting scores...")
    for i, item in enumerate(malware_data):
        try:
            b = Path(item).read_bytes()
            score = clsf_raw._get_malicious_prob(b)
            mal_scores.append(score)
            if (i + 1) % 100 == 0:
                print(f"Processed {i+1}/{len(malware_data)} malware samples")
        except Exception as e:
            err_mal += 1
            print(f"[Err] {e}, {item}")

    for i, item in enumerate(goodware_data):
        try:
            b = Path(item).read_bytes()
            score = clsf_raw._get_malicious_prob(b)
            ben_scores.append(score)
            if (i + 1) % 100 == 0:
                print(f"Processed {i+1}/{len(goodware_data)} benign samples")
        except Exception as e:
            err_ben += 1
            print(f"[Err] {e}, {item}")

    # 计算阈值
    threshold = compute_threshold(ben_scores, target_fpr_count)
    print(f"\nComputed threshold for {fpr_type}: {threshold:.5f}")
    
    # 更新分类器的阈值
    clsf_raw.inner.clsf_threshold = threshold

    # 第二步：用计算出的阈值重新评估
    print("\nEvaluating with computed threshold...")
    y_true, y_pred = [], []

    for i, item in enumerate(malware_data):
        try:
            b = Path(item).read_bytes()
            pred = clsf_raw(b).item()
            print(i, str(item), pred, f"(score={mal_scores[i]:.4f})")
            y_true.append(1)
            y_pred.append(int(pred))
        except Exception as e:
            err_mal += 1
            print(f"[Err] {e}, {item}")

    for i, item in enumerate(goodware_data):
        try:
            b = Path(item).read_bytes()
            pred = clsf_raw(b).item()
            print(i, str(item), pred, f"(score={ben_scores[i]:.4f})")
            y_true.append(0)
            y_pred.append(int(pred))
        except Exception as e:
            err_ben += 1
            print(f"[Err] {e}, {item}")

    print(f"\nInceptionV3: [{fpr_type}]")
    print(f"Threshold: {threshold:.5f}")
    print(f"mal_all: {len(malware_data)}, error_mal: {err_mal}")
    print(f"ben_all: {len(goodware_data)}, error_ben: {err_ben}")

    if len(set(y_true)) < 2:
        print("Not enough valid samples to compute metrics.")
        return

    tn, fp, fn, tp = confusion_matrix(y_true=y_true, y_pred=y_pred).ravel()
    tpr = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    acc = accuracy_score(y_true=y_true, y_pred=y_pred)
    balanced_acc = balanced_accuracy_score(y_true=y_true, y_pred=y_pred)
    print(f"TPR: {tpr}, FPR: {fpr}")
    print(f"Acc: {acc}, BAcc: {balanced_acc}")
    print(f"AUC: {roc_auc_score(y_true, y_pred)}")
    
    # 打印阈值供后续使用
    print(f"\n=== Threshold for {fpr_type}: {threshold:.5f} ===")
    print(f"Update InceptionV3.__init__ with: self.clsf_threshold = {threshold:.5f}")


if __name__ == "__main__":
    main()


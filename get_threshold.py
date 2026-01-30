from classifiers.malconv import *
from sklearn.metrics import balanced_accuracy_score, confusion_matrix, roc_auc_score
from typing import Sequence
import datetime
import numpy as np
import torch
from os import PathLike
from pathlib import Path
from torch.utils.data import Dataset
import random
import json
import torch
import torch.nn as nn
import torch.nn.functional as F
from dataset import malware_data, goodware_data
import gc 

def only_get_fpr(y_true: Sequence[bool], y_pred: Sequence[bool]):
    tn, fp, fn, tp = confusion_matrix(y_true=y_true, y_pred=y_pred).ravel()
    return float(fp) / float(fp + tn)

def find_threshold_with_fixed_fpr(y_true: Sequence[bool], y_pred: Sequence[float], fpr_target: float):
    start_time = datetime.datetime.now()
    if not isinstance(y_pred, np.ndarray):
        y_pred = np.array(y_pred)
    threshold = 0.0
    fpr = only_get_fpr(y_true, y_pred > threshold)
    while fpr > fpr_target and threshold <= 1.0:
        threshold += 0.0001
        fpr = only_get_fpr(y_true, y_pred > threshold)

    tn, fp, fn, tp = confusion_matrix(y_true=y_true, y_pred=y_pred > threshold).ravel()
    tpr = tp / (tp + fn)
    fpr = fp / (fp + tn)
    acc = (tp + tn) / (tn + fp + fn + tp)  # equal to accuracy_score(y_true=y_true, y_pred=y_pred > threshold)
    balanced_acc = balanced_accuracy_score(y_true=y_true, y_pred=y_pred > threshold)
    
    _info = "Threshold: {:.6f}, TN: {}, FP: {}, FN: {}, TP: {}, TPR: {:.6f}, FPR: {:.6f}, ACC: {:.6f}, Balanced_ACC: {:.6f}. consume about {} time in find threshold".format(
        threshold, tn, fp, fn, tp, tpr, fpr, acc, balanced_acc, datetime.datetime.now() - start_time)
    return _info

if __name__ == "__main__":
    malconv = MalConvClsf(device=torch.device("cuda:3"))
    
    label = [1]*len(malware_data)+[0]*len(goodware_data)
    predicts = []
    
    for i, item in enumerate(malware_data):
        try:
            bytez = Path(item).read_bytes()
            result = malconv._predict(bytez=bytez)
            print(i, item, result)
            predicts.append(result)
        except Exception as e:
            print(f"[Err] {e}, {item}")
        finally:
            del bytez
            gc.collect()

    for i, item in enumerate(goodware_data):
        try:
            bytez = Path(item).read_bytes()
            result = malconv._predict(bytez=bytez)
            print(i, item, result)
            predicts.append(result)
        except Exception as e:
            print(f"[Err] {e}, {item}")
        finally:
            del bytez
            gc.collect()

    print(find_threshold_with_fixed_fpr(label, predicts, 0.01))
    print(find_threshold_with_fixed_fpr(label, predicts, 0.001))

# fpr: .01 0.7989   fpr: .001 0.9801
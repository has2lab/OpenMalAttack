import os
import torch
import random
from classifiers import MalGraph
from dataset import malware_data, goodware_data
from pathlib import Path
import argparse
import requests
from sklearn.metrics import roc_auc_score, confusion_matrix, balanced_accuracy_score, accuracy_score

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='malgraph')
    parser.add_argument("--fpr", type=str, help="input the path to PE.")
    parser.add_argument("--gpu", type=int, help="input the path to PE.")
    args = parser.parse_args()

    device = torch.device(f"cuda:{args.gpu}")
    mal_cnt, benign_cnt, err_mal, err_benign = 0, 0, 0, 0
    if args.fpr == "100":
        fpr = "100fpr"
    else:
        fpr = "1000fpr"

    y_true, y_pred = [], []
    malgraph = MalGraph(threshold_type=fpr, device=device)
    
    for i, item in enumerate(malware_data):
        try:
            result = malgraph(bytez=Path(item).read_bytes(), data_hash=os.path.basename(item)).item()
            print(i, item, result)
            y_true.append(1)
            y_pred.append(result)
        except Exception as e:
            err_mal += 1
            print(f"[Err] {e}, {item}")

    for i, item in enumerate(goodware_data):
        try:
            result = malgraph(bytez=Path(item).read_bytes(), data_hash=os.path.basename(item)).item()
            print(i, item, result)
            y_true.append(0)
            y_pred.append(result)
        except Exception as e:
            err_benign += 1
            print(f"[Err] {e}, {item}")

    
    # for i, item in enumerate(malware_data):
    #     try:
    #         _input = {'bytez':Path(item).read_bytes(), 'data_hash': os.path.basename(item)}
    #         resp = requests.post(url="http://127.0.0.1:8080/predictions/malgraph", data=_input) 
    #         result = resp.json()
    #         if not isinstance(result, bool):
    #             raise TypeError
    #         print(i, item, result)
    #         y_true.append(1)
    #         y_pred.append(result)
    #     except Exception as e:
    #         err_mal += 1
    #         print(f"[Err] {e}, {item}")

    # for i, item in enumerate(goodware_data):
    #     try:
    #         _input = {'bytez':Path(item).read_bytes(), 'data_hash': os.path.basename(item)}
    #         resp = requests.post(url="http://127.0.0.1:8080/predictions/malgraph", data=_input) 
    #         result = resp.json()
    #         if not isinstance(result, bool):
    #             raise TypeError
    #         print(i, item, result)
    #         y_true.append(0)
    #         y_pred.append(result)
    #     except Exception as e:
    #         err_benign += 1
    #         print(f"[Err] {e}, {item}")

    tn, fp, fn, tp = confusion_matrix(y_true=y_true, y_pred=y_pred).ravel()
    tpr = tp / (tp + fn)
    tnr = tn / (tn + fp) if (tn + fp) > 0 else 0
    fpr = fp / (fp + tn)

    print(f"MalGraph: [{fpr}]") 
    print(f"mal_all: {len(malware_data)}, mal_det: {tp}, error_mal: {err_mal}")
    print(f"bengin_all: {len(goodware_data)}, benign_det: {tn}, error_benign: {err_benign}")

    acc = accuracy_score(y_true=y_true, y_pred=y_pred)
    balanced_acc = balanced_accuracy_score(y_true=y_true, y_pred=y_pred)
    print(f"TPR: {tpr}, FPR: {fpr}, TNR: {tnr}")
    print(f"Acc: {acc}, BAcc: {balanced_acc}")
    print(f"AUC: {roc_auc_score(y_true, y_pred)}")
    

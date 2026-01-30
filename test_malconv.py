import requests
import os
import torch
import random
from classifiers.malconv import *
from dataset import malware_data, goodware_data
from pathlib import Path
import argparse
import torch
import torch.nn as nn

def main():
    parser = argparse.ArgumentParser(description='magic')
    parser.add_argument("--fpr", type=str, help="input the path to PE.")
    parser.add_argument("--gpu", type=int, help="input the path to PE.")
    args = parser.parse_args()

    device = torch.device(f"cuda:{args.gpu}")
    mal_cnt, benign_cnt, err_mal, err_benign = 0, 0, 0, 0
    if args.fpr == "100":
        fpr = "100fpr"
    elif args.fpr == "1000":
        fpr = "1000fpr"
    else:
        raise Exception("incorrect fpr")

    malconv = MalConvClsf(threshold_type=fpr, device=device)

    print(malconv.config.threshold_type)
    for i, item in enumerate(malware_data):
        try:
            result = malconv._predict(bytez=Path(item).read_bytes())
            print(i, item, result)
            if result is not None and result >= malconv.clsf_threshold:
                mal_cnt += 1
        except Exception as e:
            err_mal += 1
            print(f"[Err] {e}, {item}")

    for i, item in enumerate(goodware_data):
        try:
            result = malconv._predict(bytez=Path(item).read_bytes())
            print(i, item, result)
            if result is not None and result < malconv.clsf_threshold:
                benign_cnt += 1
        except Exception as e:
            err_benign += 1
            print(f"[Err] {e}, {item}")

    print(f"[{fpr}]") 
    print(f"mal_all: {len(malware_data)}, mal_det: {mal_cnt}, error_mal: {err_mal}")
    print(f"bengin_all: {len(goodware_data)}, benign_det: {benign_cnt}, error_benign: {err_benign}")
    TPR = mal_cnt/(len(malware_data)-err_mal)
    TNR = benign_cnt/(len(goodware_data)-err_benign)
    print(f"TPR: {TPR}")
    print(f"TNR: {TNR}")
    print(f"Acc: {(benign_cnt+mal_cnt)/(len(malware_data)+len(goodware_data)-err_mal-err_benign)}")
    print(f"Balanced_Acc: {(TPR+TNR)/2}")
    
if __name__ == "__main__":
    main()
    # model = torch.load('/OpenMalAttack/models/malconv/malconv_best.pt')
    # print(model.state_dict())


# malconv
# class MalconvClient(): 
#     def __init__(self, base_url:str, threshold_type:str): 
        
#         if threshold_type=='100fpr':
#             self.clsf_threshold = 0.26796
#         elif threshold_type=='1000fpr':
#             self.clsf_threshold = 0.95666
#         else:
#             raise NotImplementedError
#         self.threshold_type = threshold_type
#         self.base_url = base_url
#         self.name = 'malconv'

#     def get_score(self, bytez, data_hash): 
#         resp = requests.post(url=self.base_url, data={'bytez': bytez})
#         score = resp.json()
#         return score


# malconv = MalconvClient(base_url='http://127.0.0.1:8080/predictions/malconv', threshold_type="100fpr")
# bytez = open('/OpenMalAttack/dataset/malware/28235ba25f82b1ce4d4c85706bea035a7c25897604755012a4e34fe92925bc9f','rb').read()
# score = malconv.get_score(bytez, "28235ba25f82b1ce4d4c85706bea035a7c25897604755012a4e34fe92925bc9f")
# print("malconv", score)

# # malgraph
# bytez = open('/OpenMalAttack/dataset/malware/28235ba25f82b1ce4d4c85706bea035a7c25897604755012a4e34fe92925bc9f','rb').read()
# _input = {'bytez':bytez, 'data_hash': "28235ba25f82b1ce4d4c85706bea035a7c25897604755012a4e34fe92925bc9f"}
# resp = requests.post(url="http://127.0.0.1:8080/predictions/malgraph", data=_input) 
# score = resp.json()
# print("malgraph", score)

# # magic
# bytez = open('/OpenMalAttack/dataset/malware/28235ba25f82b1ce4d4c85706bea035a7c25897604755012a4e34fe92925bc9f','rb').read()
# _input = {'bytez':bytez, 'data_hash': "28235ba25f82b1ce4d4c85706bea035a7c25897604755012a4e34fe92925bc9f"}
# resp = requests.post(url="http://127.0.0.1:8080/predictions/magic", data=_input) 
# score = resp.json()
# print("magic", score)
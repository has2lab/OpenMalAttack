#!/usr/bin/env python
# -*- coding: utf-8 -*-
# ************************************
# @Time     : 2020/12/16 15:24
# @Author   : Xiang Ling
# @File     : RealBatch.py
# @Lab      : nesa.zju.edu.cn
# ************************************

from pprint import pprint

import torch
from torch_geometric.data import Batch
from torch_geometric.data import DataLoader


def create_real_batch_data(one_batch: Batch):
    real = []
    position = [0]
    count = 0
    
    # print("Now, creating a real batch for {}".format(one_batch))
    assert len(one_batch.external_list) == len(one_batch.function_edges) == len(one_batch.local_acfgs) == len(one_batch.hash), "size of each component must be equal to each other"
    
    # pprint(one_batch.external_list, compact=True)
    # pprint(one_batch.function_edges, compact=True)
    # pprint(one_batch.local_acfgs, compact=True)
    # pprint(one_batch.hash, compact=True)
    # double_check_x = 0
    for item in one_batch.local_acfgs:
        # print("\t Local acfgs :", type(item), len(item))
        for acfg in item:
            # double_check_x += acfg.x.size(0)
            real.append(acfg)
        count += len(item)
        position.append(count)
        # print("\t position    :", position)
    
    # print("step 1: create real batch data: ", " real = ", type(real), len(real), len(one_batch.local_acfgs))
    # print("step 2: real [0] type: ", type(real[0]))
    
    if len(one_batch.local_acfgs) == 1 and len(one_batch.local_acfgs[0]) == 0:
        return (None for _ in range(6))
    else:
        real_batch = Batch.from_data_list(real)
        # print("double check the length of total x = ", double_check_x)
        return real_batch, position, one_batch.hash, one_batch.external_list, one_batch.function_edges, one_batch.targets


if __name__ == '__main__':
    saved_ben_train_path = "../processed_dataset/10Result.pt"
    benign = torch.load(saved_ben_train_path)
    pprint(benign)
    print("\n")
    
    test_loader = DataLoader(benign, batch_size=4)
    for idx, data in enumerate(test_loader):
        print("{}\nIn the {}-th batch".format("-" * 100, idx))
        _real_batch, _position_list, _hash_list, _external_list, _edges_list, _classes = create_real_batch_data(one_batch=data)
        
        print("Real batch    = ", _real_batch)
        print("Real position = ", _position_list)
        print("Targets       = ", _classes)
        print("-" * 100 + "\n")

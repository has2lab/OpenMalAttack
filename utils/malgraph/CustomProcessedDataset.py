#!/usr/bin/env python
# -*- coding: utf-8 -*-
# ************************************
# @Time     : 2021/12/26 22:14
# @Author   : Xiang Ling
# @File     : CustomProcessedDataset.py
# @Lab      : nesa.zju.edu.cn
# ************************************

import logging
import os

import torch
from torch_geometric.data import Batch


class CustomProcessedDataset(object):
    def __init__(self, root: str, log: logging.Logger = None):
        # self.benign_DLL_processed_dataset_path = os.path.join(root, "Benign_DLL")
        # self.benign_EXE_processed_dataset_path = os.path.join(root, "Benign_EXE")
        
        self.benign_EXE_indexes = [os.path.join(root, "Ben_EXE_{}.pt".format(i)) for i in range(11689)]
        self.benign_DLL_indexes = [os.path.join(root, "Ben_DLL_{}.pt".format(i)) for i in range(11689, 55214 + 11689)]
        
        self.benign_indexes = self.benign_EXE_indexes + self.benign_DLL_indexes
        
        self.log = log
        print(self.benign_indexes[:100])
    
    def __len__(self):
        return len(self.benign_indexes)
    
    # @property
    # def processed_dll_file_names(self):
    #     _benign_DLL = [os.path.join(self.benign_DLL_processed_dataset_path, 'data_{}.pt'.format(idx)) for idx in self.benign_DLL_indexes]
    #     _benign_EXE = [os.path.join(self.benign_DLL_processed_dataset_path, 'data_{}.pt'.format(idx)) for idx in self.benign_DLL_indexes]
    
    def get_train_batch(self, _batch_size: int):
        import random
        train_benign_indexes = self.benign_indexes
        random.Random(122222).shuffle(train_benign_indexes)
        
        start = 0
        current = 0
        
        while True:
            end = start + _batch_size if start + _batch_size < len(train_benign_indexes) else len(train_benign_indexes)
            
            if current >= len(train_benign_indexes):
                current = 0
                random.Random(123).shuffle(train_benign_indexes)
            rtn = []
            for i in range(start, end):
                rtn.append(torch.load(train_benign_indexes[i]))
            print(rtn)
            yield Batch.from_data_list(rtn)
            start = end if end < len(train_benign_indexes) else 0
            current += _batch_size

# temp = CustomProcessedDataset(root="../processed_dataset_limit_1000_10000/Benign/")
# train_batch = temp.get_train_batch(_batch_size=2)
# for index in range(10):
#     print("\nindex = {}".format(index))
#     x = next(train_batch)
#     print(x)

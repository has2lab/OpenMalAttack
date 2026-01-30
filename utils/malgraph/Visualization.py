#!/usr/bin/env python
# -*- coding: utf-8 -*-
# ************************************
# @Time     : 2020/12/30 20:55
# @Author   : Xiang Ling
# @File     : Visualization.py
# @Lab      : nesa.zju.edu.cn
# ************************************

import torch
from visdom import Visdom


class VisdomLogger:
    def __init__(self, title, total_epochs):
        self.vis = Visdom()
        self.opts = dict(title=title, ylabel='', xlabel="Epoch", legend=['Loss', "Accuracy"])
        
        self.vis_window = None
        self.epochs = torch.arange(1, total_epochs + 1)
        self.vis_plotter = True
    
    def update(self, epoch, values):
        pass


a = torch.IntTensor(100)
print(type(a), a.size())
print(a)

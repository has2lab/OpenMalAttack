import ctypes
import numpy as np
import os
import sys
import torch
import pdb
import random
from torch.autograd import Variable
from torch.nn.parameter import Parameter
import torch.nn as nn
import torch.nn.functional as F
import torch.optim as optim
from tqdm import tqdm
    

def PrepareSparseMatrices(graph_batch):
    total_num_nodes, total_num_edges = 0, 0
    for graph in graph_batch:
        total_num_nodes += graph.num_node
        total_num_edges += graph.num_edge
        
    n2n_idxes = torch.LongTensor(2, total_num_edges)
    n2n_vals = torch.FloatTensor(total_num_edges)

    increm = 0
    idx = 0
    for graph in graph_batch:
        n2n_idxes[0][idx:idx + graph.num_edge] = graph.node_adj[0] + increm
        n2n_idxes[1][idx:idx + graph.num_edge] = graph.node_adj[1] + increm
        n2n_vals[idx:idx + graph.num_edge] = 1
        increm += graph.num_node
        idx += graph.num_edge

    n2n_sp = torch.sparse.FloatTensor(n2n_idxes, n2n_vals, torch.Size([total_num_nodes, total_num_nodes]))

    return n2n_sp
    
def glorot_uniform(t):
    if len(t.size()) == 2:
        fan_in, fan_out = t.size()
    elif len(t.size()) == 3:
        # out_ch, in_ch, kernel for Conv 1
        fan_in = t.size()[1] * t.size()[2]
        fan_out = t.size()[0] * t.size()[2]
    else:
        fan_in = np.prod(t.size())
        fan_out = np.prod(t.size())

    limit = np.sqrt(6.0 / (fan_in + fan_out))
    t.uniform_(-limit, limit)

def _param_init(m):
    if isinstance(m, Parameter):
        glorot_uniform(m.data)
    elif isinstance(m, nn.Linear):
        m.bias.data.zero_()
        glorot_uniform(m.weight.data)

def weights_init(m):
    for p in m.modules():
        if isinstance(p, nn.ParameterList):
            for pp in p:
                _param_init(pp)
        else:
            _param_init(p)

    for name, p in m.named_parameters():
        if not '.' in name: # top-level parameters
            _param_init(p)
import torch
import angr
import numpy as np
import networkx as nx
import os

SAMPLE_PATH = 'datasets/'

class ExtractFeats(object):
    def __init__(self):
        self.feat_num = 1024
        # self.bytez = None
        self.sha256 = None

    def CountInsn(self, node):
        dict = {}
        if node.block is not None:
            instructions = [Dis.mnemonic for Dis in node.block.capstone.insns]
            for insn in set(instructions):
                dict[insn] = instructions.count(insn)
        return dict

    def raw_features(self, sha256):
        location = os.path.join(SAMPLE_PATH, sha256)
        self.sha256 = sha256
        # self.bytez = bytez
        proj = angr.Project(location, load_options={'auto_load_libs': False})
        cfg = proj.analyses.CFGFast()
        self.num_node = len(cfg.graph.nodes())
        self.num_edge = len(cfg.graph.edges())
        self.node2num = {}
        # FIXME:    由于解析PE过程中angr会产生孤立的基本块，无法计算cfg度矩阵的逆，因此暂时删除孤立点
        i = 0
        for node in cfg.graph.nodes():
            if len(node.successors) or len(node.predecessors):
                self.node2num[node] = i
                i += 1
        self.valid_num_node = len(self.node2num)
        self.valid_num_edge = set()

        # get opcode list of PE (Disassembly)
        # opcode_list = np.unique([Disasm.mnemonic for nd in cfg.graph.nodes() for Disasm in nd.block.capstone.insns]).tolist()
        _oplt = set()
        for nd in cfg.graph.nodes():
            _oplt = set.union(_oplt, set(self.CountInsn(nd).keys()))
        # opcode_list = list(_oplt)
        opcode_num_types = 1024         ### FIXME: 暂定汇编指令类型总数
        self.opcode_encode = {op:i for i,op in enumerate(_oplt)}

        # create the adjacency matrix of CFG
        self.node_adj = torch.zeros([self.valid_num_node, self.valid_num_node], dtype=torch.float32)
        for nd in self.node2num.keys():
            for suc in list(nd.successors):
                self.node_adj[self.node2num[nd]][self.node2num[suc]] = 1
                if suc in self.node2num.keys():
                    self.valid_num_edge.add((nd, suc))
            for prs in list(nd.predecessors):
                self.node_adj[self.node2num[prs]][self.node2num[nd]] = 1
                if prs in self.node2num.keys():
                    self.valid_num_edge.add((prs, nd))

        self.valid_num_edge = len(self.valid_num_edge)
        
        # create the node information matrix
        self.node_infos = torch.zeros([self.valid_num_node, opcode_num_types], dtype=torch.float32)
        for nd in self.node2num.keys():
            cntInsn = self.CountInsn(nd)
            for insn, cnt in cntInsn.items():
                self.node_infos[self.node2num[nd]][self.opcode_encode[insn]] = cnt

        output = {
            'num_node': self.valid_num_node,
            'num_edge': self.valid_num_edge,
            'feat_num': opcode_num_types,
            # 'node2num': node2num,
            # 'op_encode': opcode_encode,
            # 'opcode_num': opcode_num_types,
            # 'deg_mat': deg_mat,
            'node_adj': self.node_adj,
            'node_feats': self.node_infos
        }
        return output

    def process_raw_features(self, raw_obj):
        return np.hstack([raw_obj['num_node'], 
                        raw_obj['num_edge'],
                        raw_obj['feat_num'],
                        raw_obj['node_adj'].flatten(), 
                        raw_obj['node_feats'].flatten()]).astype(np.float32)
    
    def get_features(self):
        return self.opcode_encode, self.feat_num, self.node_infos

    def feature_extr(self, sha256):
        return self.process_raw_features(self.raw_features(sha256)) if self.sha256 is None else\
            np.hstack([self.valid_num_node, 
                        self.valid_num_edge,
                        self.feat_num,
                        self.node_adj.flatten(), 
                        self.node_infos.flatten()]).astype(np.float32)

    def update_feats(self, node_infos=None, opcode_encode=None, feat_num=None):
        if node_infos is not None:
            self.node_infos = node_infos
        if opcode_encode is not None:
            self.opcode_encode = opcode_encode
        if feat_num is not None:
            self.feat_num = feat_num
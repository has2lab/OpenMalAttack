#coding:utf-8
import itertools
import sys
sys.path.insert(0, '/usr/local/lib/python2.7/dist-packages/')
import networkx as nx
#import numpy as np
from subprocess import Popen, PIPE
import pdb
import os
import re, mmap
import jsonlines
#from graph_edit_new import *

__MODIFY__ = True

def write_data_to_filename(filename, data):
    """
    向文件中写入内容
    """
    # data = json.dumps(data)
    with jsonlines.open(filename, mode='a') as writer:
        writer.write(data)

class raw_graph:
	def __init__(self, funcname, g, func_f=None):
		"""
		funcname: 函数名
		g: Genius的ACFG
		func_f: DiscovRe的特征
		"""
		self.funcname = funcname
		# old_g应该是函数的cfg，不是acfg
		self.old_g = g
		self.g = nx.DiGraph()
		# 这个discovre_features在这里没什么用
		self.discovre_features = func_f
		# 获取offsprings并整合所有属性
		self.attributing()

	def __len__(self):
		return len(self.g)

	# 应该是在这里改
	def attributing(self):
		# 这里是获得offspring，old_g是函数的cfg，这里不获取offspring
		if False:
			self.obtainOffsprings(self.old_g)

		for node in self.old_g:
			# 获取ACFG属性
			fvector = self.retrieveVec(node, self.old_g)  
			self.g.add_node(node)
			self.g.node[node]['v'] = fvector

		# 这个edges根本不对
		for edge in self.old_g.edges():  # 获取edges
			node1 = edge[0]
			node2 = edge[1]
			self.g.add_edge(node1, node2)

	def obtainOffsprings(self, g):
		nodes = g.nodes()
		for node in nodes:
			offsprings = {}
			self.getOffsprings(g, node, offsprings)  # 获取offsprings
			g.node[node]['offs'] = len(offsprings)
		return g

	def getOffsprings(self, g, node, offsprings):
		node_offs = 0
		sucs = g.successors(node)
		for suc in sucs:
			if suc not in offsprings:
				offsprings[suc] = 1
				self.getOffsprings(g, suc, offsprings)

	def retrieveVec(self, id_, g):
		feature_vec = []
		# numC0
		numc = g.node[id_]['consts']
		feature_vec.append(numc)

		# nums1
		nums = g.node[id_]['strings']
		feature_vec.append(nums)

		# offsprings2
		# offs = g.node[id_]['offs']
		# feature_vec.append(offs)

		# numAs2
		numAs = g.node[id_]['numAs']
		feature_vec.append(numAs)

		# of calls3
		calls = g.node[id_]['numCalls']
		feature_vec.append(calls)

		# of insts4
		insts = g.node[id_]['numIns']
		feature_vec.append(insts)

		# of LIs5
		insts = g.node[id_]['numLIs']
		feature_vec.append(insts)

		# of TIs6
		insts = g.node[id_]['numTIs']
		feature_vec.append(insts)

		# of CmpIs7
		insts = g.node[id_]['numCmpIs']
		feature_vec.append(insts)

		# of MovIs8
		insts = g.node[id_]['numMovIs']
		feature_vec.append(insts)

		# of TermIs9
		insts = g.node[id_]['numTermIs']
		feature_vec.append(insts)

		# of DefIs10
		insts = g.node[id_]['numDefIs']
		feature_vec.append(insts)

		if __MODIFY__:
			insts = g.node[id_]['Opcodes']
			feature_vec.append(insts)

		return feature_vec


class raw_graphs:  # 二进制文件内的所有原生控制流图，用于初始化
	def __init__(self, binary_name):
		self.binary_name = binary_name
		self.raw_graph_list = []

	def append(self, raw_g):
		self.raw_graph_list.append(raw_g)

	def __len__(self):
		return len(self.raw_graph_list)

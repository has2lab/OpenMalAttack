#coding:utf-8
#
# Reference Lister
#
# List all functions and all references to them in the current section.
#
# Implemented with the idautils module
#
import networkx as nx
import cPickle as pickle
import pdb
from graph_analysis_ida import *
from graph_property import *


def get_discoverRe_feature(funcea, func, icfg):
    # start = func.startEA
    # end = func.endEA
    # 这个地方只用来判断block数是不是大于8999，如果大于的话就直接舍弃
    NumberOfFuncCalls, NumberOfLogicInsts, NumberOfTransferInsts, NumberOfIntrs = get_all_contributes(func)
    if NumberOfFuncCalls == -1 and NumberOfLogicInsts == -1 and NumberOfTransferInsts == -1 and NumberOfIntrs == -1:
        return None
    features = []
    # # FunctionCalls = getFuncCalls(func)  # No. of FunctionCalls
    # features.append(NumberOfFuncCalls)
    #
    # # LogicInsts = getLogicInsts(func)  # No. of LogicInsts
    # features.append(NumberOfLogicInsts)
    #
    # # Transfer = getTransferInsts(func)  # No. of TransferInsts
    # features.append(NumberOfTransferInsts)
    #
    # # Locals = getLocalVariables(func)  # No. of LocalVariables
    # features.append(3)
    #
    # BB = getBasicBlocks(func)  # No. of BasicBlocks
    # features.append(BB)
    #
    Edges = icfg.edges()  # No. of Edges
    # features.append(len(Edges))
    #
    # Incoming = getIncommingCalls(func)  # No. of IncommingCalls
    # features.append(Incoming)
    #
    # Insts = getIntrs(func)  # No. of Insts
    # features.append(NumberOfIntrs)
    #
    # between = retrieveGP(icfg)  # Between
    # features.append(between)
    #
    # strings, consts = getfunc_consts(func)  # Consts and Strings
    # features.append(strings)
    # features.append(consts)

    edge_block = []
    for ed in Edges:
        edge_block.append(ed)
    features.append(edge_block)
    return features

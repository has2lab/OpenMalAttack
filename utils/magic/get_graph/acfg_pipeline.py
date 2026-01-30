# -*- coding: utf-8 -*-
# @Time : 2021/1/3 10:49 PM
# @Author : wd
# @File : main.py
import numpy as np
import scipy as sp
import os
from utils.magic.get_graph.cfg_builder import AcfgBuilder
import threading
from queue import Queue
from argparse import ArgumentParser
from typing import List, Dict
from utils.magic.get_graph.dp_utils import delCodeSegLog, loadBinaryIds
from utils.magic.get_graph.python23_common import list2Str, neighborsFromAdjacentMatrix
from utils.magic.get_graph.python23_common import matchConstant


class AcfgWorker(threading.Thread):
    """
    Handle/convert a batch of binary to ACFG
    """

    def __init__(self, file_queue: Queue, resultPrefix: str, label: str) -> None:
        # 这里的pathPrefix 并不是 prefix，而是prefix + 文件名
        super(AcfgWorker, self).__init__()
        self.file_queue: Queue = file_queue
        self.resultPrefix: str = resultPrefix
        self.label = label

    def run(self) -> None:
        while True:
            if self.file_queue.empty():
                break
            filename = self.file_queue.get()
            # 这里的1指binary_id没什么用
            acfgBuilder = AcfgBuilder('1', filename)
            features, adjMatrix = acfgBuilder.getAttributedCfg()
            if features is None or adjMatrix is None:
                continue
            outputFileName = os.path.join(self.resultPrefix, filename.split('/')[-1])
            output = open(outputFileName + '.acfg', 'w')
            # number of block -> features.shape[0]
            output.write("%d %d\n" % (features.shape[0], int(self.label)))
            # 邻接矩阵构成的字典?
            indices = neighborsFromAdjacentMatrix(adjMatrix)
            for (i, feature) in enumerate(features):
                neighbors = indices[i] if i in indices else []
                nAndF = list2Str(neighbors, feature)
                output.write("%d %s\n" % (len(neighbors), nAndF))
            output.close()


class AcfgMaster(object):
    def __init__(self, samplePath: str, resultPrefix: str, label: str) -> None:
        super(AcfgMaster, self).__init__()
        self.samplePath = samplePath
        self.resultPrefix = resultPrefix
        self.label = label

    def dispatchWorkers(self) -> None:
        workers: List[AcfgWorker] = []
        file_queue = Queue()
        file_queue.put(self.samplePath)

        for i in range(os.cpu_count()):
            worker = AcfgWorker(file_queue, self.resultPrefix, self.label)
            workers.append(worker)
            worker.start()
        for worker in workers:
            worker.join()
        # print('finish')


def processGetACFG(samplePath,resultPrefix,label):
    master = AcfgMaster(samplePath, resultPrefix, label)
    master.dispatchWorkers()


"""
MSACFG.txt 文件写入的内容
line_1: total_graph_number
line_2: total_block 1/0[1 -> malicious, 0 -> benign]
line_3 -> line_n: 边的条数 和该block相连的block 33个feature
"""

if __name__ == '__main__':
    cmdOpt = ArgumentParser(description='Multithreading ACFG processing pipeline')
    cmdOpt.add_argument('-label', type=str, required=True,
                        help='Which label the dataset is, 0 for benign and 1 for malware: {1, 0}')
    cmdArgs, _ = cmdOpt.parse_known_args()
    if cmdArgs.label == '1':
        processGetACFG(1)
    elif cmdArgs.label == '0':
        processGetACFG(0)
    else:
        raise ValueError('Invalid argument: -label from {1, 0}')

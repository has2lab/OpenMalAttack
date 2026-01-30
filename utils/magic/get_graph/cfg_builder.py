# -*- coding: utf-8 -*-
# @Time : 2021/1/3 10:49 PM
# @Author : wd
# @File : main.py
import re
import os
import glog as log
import networkx as nx
import utils.magic.get_graph.instructions as isn
import numpy as np
import matplotlib.pyplot as plt
from utils.magic.get_graph.dp_utils import FakeCalleeAddr, addCodeSegLog, InvalidAddr
from collections import OrderedDict
from typing import List, Dict, Set


class Block(object):
    """Block of control flow graph."""
    instDim = len(isn.Instruction.operandTypes) + len(isn.Instruction.operatorTypes)

    """Types of structual-related vertex features"""
    vertexTypes = {'degree': instDim, 'num_inst': instDim + 1}

    def __init__(self) -> None:
        super(Block, self).__init__()
        self.startAddr = -1
        self.endAddr = -1
        self.instList: List[isn.Instruction] = []
        self.edgeList: List[int] = []

    def bytesFromInsts(self) -> List[str]:
        byteList = []
        for inst in self.instList:
            for byte in inst.bytes:
                byte = byte.rstrip('\n+')
                byteList.append(byte)

        return byteList

    def getAttributes(self):
        instAttr = np.zeros((1, Block.instDim))
        # 遍历block中de所有指令
        for inst in self.instList:
            # 指令类型 分为
            # operandTypes = {'trans': 0, 'call': 1, 'math': 2, 'cmp': 3, 'mov': 4, 'term': 5, 'def': 6}
            # 7纬
            attr = inst.getOperandFeatures()
            # 数字 和 常量字符串的个数，两个元素 2纬
            attr += inst.getOperatorFeatures()
            instAttr += np.array(attr)

        # 9 + 2 纬[边的数量、指令条数] = 11纬
        degree = len(self.edgeList)
        numInst = len(self.instList)

        return np.concatenate((instAttr, [degree, numInst]), axis=None)

    @staticmethod
    def getAttributesDim():
        return Block.instDim + len(Block.vertexTypes)


class ControlFlowGraphBuilder(object):
    """
    For building a control flow graph from a program
    """
    # 这里的pathPrefix 并不是 prefix，而是prefix + 文件名
    def __init__(self, binaryId: str, pathPrefix: str) -> None:
        super(ControlFlowGraphBuilder, self).__init__()
        self.cfg = nx.DiGraph()
        self.instBuilder: isn.InstBuilder = isn.InstBuilder()
        self.binaryId: str = binaryId
        self.filePrefix: str = pathPrefix 
        self.programEnd: int = -1
        self.programStart: int = -1

        self.text: Dict[int, str] = {}  # Line number to raw string instruction
        self.program: Dict[str, str] = {}  # Addr to raw string instruction
        self.addr2Inst: OrderedDict[int, isn.Instruction] = OrderedDict()
        self.addr2InstAux: OrderedDict[int, isn.Instruction] = OrderedDict()
        self.addr2Bytes: OrderedDict[int, List[str]] = OrderedDict()
        self.addr2RawStr: OrderedDict[int, List[str]] = OrderedDict()
        self.addr2Block: Dict[int, Block] = {}

    def getControlFlowGraph(self) -> nx.DiGraph:
        self.buildControlFlowGraph()
        self.exportToNxGraph()
        # self.drawCfg()  # 画出cfg
        return self.cfg

    def buildControlFlowGraph(self) -> None:
        self.parseInstructions()
        self.parseBlocks()

    def parseInstructions(self) -> Set[str]:
        """First pass on instructions"""
        self.extractTextSeg()
        self.createProgram()
        self.buildInsts()
        return self.instBuilder.seenInst

    def parseBlocks(self) -> None:
        """Second pass on blocks"""
        self.visitInsts()
        self.connectBlocks()

    def addrInCodeSegment(self, seg: str) -> str:
        """
        可能有问题???
        如果seg中有冒号，则取冒号后的所有
        如果seg中没有冒号，则取最后8位
        """
        segNames = ['.text:', 'CODE:', 'UPX1:', 'seg000:', 'qmoyiu:', '.UfPOkc:', '.brick:', '.icode:', 'seg001:',
            '.Much:', 'iuagwws:', '.idata:', '.edata:', '.IqR:', '.data:', '.bss:', '.idata:', '.rsrc:',
            '.tls:', '.reloc:', '.unpack:', '_1:', '.Upack:', '.mF:']
        for prefix in segNames:
            if seg.startswith(prefix) is True:
                colonIdx = seg.rfind(':')
                if colonIdx != -1:
                    return seg[colonIdx + 1:]
                else:
                    return seg[-8:]
        return "NotInCodeSeg"

    def appendRawBytes(self, addrStr: str, byte: str):
        addr = int(addrStr, 16)
        if addr in self.addr2Bytes:
            self.addr2Bytes[addr].append(byte)
        else:
            self.addr2Bytes[addr] = [byte]

    def indexOfInst(self, decodedElems: List[str], addrStr: str) -> int:
        idx = 0
        bytePattern = re.compile(r'^[A-F0-9?][A-F0-9?]\+?$')
        while idx < len(decodedElems) and bytePattern.match(decodedElems[idx]):
            self.appendRawBytes(addrStr, decodedElems[idx])
            idx += 1
        return idx

    def indexOfComment(self, decodedElems: List[str]) -> int:
        for (i, elem) in enumerate(decodedElems):
            if elem.find(';') != -1:
                return i
        return len(decodedElems)

    def extractTextSeg(self) -> None:
        """
        Extract text segment from .asm file
        """
        lineNum = 1
        fileInput = open(self.filePrefix, 'rb')
        for line in fileInput:
            elems = line.split()
            decodedElems = [x.decode("utf-8", "ignore") for x in elems]
            if len(decodedElems) == 0:
                lineNum += 1
                continue
            seg = decodedElems.pop(0)
            addr = self.addrInCodeSegment(seg)
            if addr is "NotInCodeSeg":
                lineNum += 1
                continue
            startIdx = self.indexOfInst(decodedElems, addr)
            endIdx = self.indexOfComment(decodedElems)
            if startIdx < endIdx:
                instElems = [addr] + decodedElems[startIdx: endIdx]
                self.text[lineNum] = " ".join(instElems)
            lineNum += 1
        fileInput.close()

    def isHeaderInfo(self, sameAddrInsts: List[str]) -> bool:
        for inst in sameAddrInsts:
            if inst.startswith('_text segment') or inst.find('.mmx') != -1:
                return True
        return False

    def appendRawString(self, addr: int, instRawStrs: List[str]):
        for inst in instRawStrs:
            if addr in self.addr2RawStr:
                self.addr2RawStr[addr].append(inst)
            else:
                self.addr2RawStr[addr] = [inst]

    def aggregate(self, addrStr: str, sameAddrInsts: List[str]) -> None:
        """
        Case 1: Header info
        Case 2: 'xxxxxx proc near' => keep last inst
        Case 3: 'xxxxxx endp' => ignore second
        Case 4: dd, db, dw instructions => d? var_name
        Case 5: location label followed by regular inst
        Case 6: Just 1 regular inst
        """
        addr = int(addrStr, 16)
        self.appendRawString(addr, sameAddrInsts)
        if self.isHeaderInfo(sameAddrInsts):
            self.program[addrStr] = sameAddrInsts[-1]
            return

        validInst: List[str] = []
        foundDataDeclare: str = ''
        ptrPattern = re.compile(r'.+=.+ ptr .+')
        for inst in sameAddrInsts:
            if inst.find('proc near') != -1 or inst.find('proc far') != -1:
                continue
            if inst.find('public') != -1:
                continue
            if inst.find('assume') != -1:
                continue
            if inst.find('endp') != -1 or inst.find('ends') != -1:
                continue
            if inst.find(' = ') != -1 or ptrPattern.match(inst):
                # log.debug(f'Ptr declare found: {inst}')
                foundDataDeclare += inst + ' '
                continue
            if inst.startswith('dw ') or inst.find(' dw ') != -1:
                foundDataDeclare += inst + ' '
                continue
            if inst.startswith('dd ') or inst.find(' dd ') != -1:
                foundDataDeclare += inst + ' '
                continue
            if inst.startswith('db ') or inst.find(' db ') != -1:
                foundDataDeclare += inst + ' '
                continue
            if inst.startswith('dt ') or inst.find(' dt ') != -1:
                foundDataDeclare += inst + ' '
                continue
            if inst.startswith('unicode '):
                foundDataDeclare += inst + ' '
                continue
            if inst.endswith(':'):
                continue

            validInst.append(inst)

        if len(validInst) == 1:
            progLine = validInst[0] + ' ' + foundDataDeclare
            self.program[addrStr] = progLine.rstrip(' ')
        elif len(foundDataDeclare.rstrip(' ')) > 0:
            self.program[addrStr] = foundDataDeclare.rstrip(' ')
        else:
            progLine = ''
            for inst in validInst:
                progLine += inst.rstrip('\n\\') + ' '
            self.program[addrStr] = progLine.rstrip(' ')

    def createProgram(self) -> None:
        """
        Generate unique-addressed program, store in self.program
        """
        currAddr = -1
        sameAddrInsts = []
        for _, line in self.text.items():
            elems = line.split(' ')
            addr, inst = elems[0], elems[1:]
            if currAddr == -1:
                currAddr = addr
                sameAddrInsts.append(" ".join(inst))
            else:
                if addr != currAddr:
                    self.aggregate(currAddr, sameAddrInsts)
                    sameAddrInsts.clear()

                currAddr = addr
                sameAddrInsts.append(" ".join(inst))
        if len(sameAddrInsts) > 0:
            self.aggregate(currAddr, sameAddrInsts)

    def buildInsts(self) -> None:
        """
        Create Instruction object for each address, store in addr2Inst
        """
        prevAddr = -1
        for (addr, line) in self.program.items():
            inst = self.instBuilder.createInst(addr + ' ' + line)
            if inst is None:
                continue
            if prevAddr != -1:
                self.addr2Inst[prevAddr].size = inst.address - prevAddr
            self.addr2Inst[inst.address] = inst
            if self.programStart == -1:
                self.programStart = inst.address
            self.programEnd = max(inst.address, self.programEnd)
            prevAddr = inst.address
        # Last inst get default size 2
        if prevAddr > 0:
            self.addr2Inst[prevAddr].size = 2
        else:
            addCodeSegLog(self.binaryId)

    def visitInsts(self) -> None:
        for addr, inst in self.addr2Inst.items():
            inst.accept(self)
            if addr in self.addr2Bytes:
                inst.bytes = self.addr2Bytes[addr]

            if addr in self.addr2RawStr:
                inst.rawStrs = self.addr2RawStr[addr]

        self.addr2Inst.update(self.addr2InstAux)

    def addAuxilaryInst(self, addr, operandName='') -> None:
        if addr not in self.addr2InstAux:
            self.addr2InstAux[addr] = isn.Instruction(addr, operand=operandName)
            self.addr2InstAux[addr].start = True
            self.addr2InstAux[addr].fallThrough = False

    def enter(self, inst, enterAddr: int) -> None:
        if enterAddr == FakeCalleeAddr:
            self.addAuxilaryInst(enterAddr, 'extrn_sym')
        elif 0 <= enterAddr < 256:
            self.addAuxilaryInst(enterAddr, 'softirq_%X' % enterAddr)
        elif enterAddr not in self.addr2Inst:
            if inst.operand in ['call', 'syscall']:
                self.addAuxilaryInst(enterAddr, 'extrn_sym')
            else:
                self.addAuxilaryInst(InvalidAddr, 'invalid')
                self.addr2Inst[inst.address].branchTo = InvalidAddr
        else:
            self.addr2Inst[enterAddr].start = True

    def branch(self, inst) -> None:
        """
        Conditional jump to another address or fall throught
        """
        branchToAddr = inst.findAddrInInst()
        self.addr2Inst[inst.address].branchTo = branchToAddr
        self.enter(inst, branchToAddr)
        self.enter(inst, inst.address + inst.size)

    def call(self, inst) -> None:
        """Jump out and then back"""
        self.addr2Inst[inst.address].call = True
        # Likely NOT able to find callee's address (e.g. extern symbols)
        callAddr = inst.findAddrInInst()

        self.addr2Inst[inst.address].branchTo = callAddr
        self.enter(inst, callAddr)

    def jump(self, inst) -> None:
        """Unconditional jump to another address"""
        jumpAddr = inst.findAddrInInst()
        self.addr2Inst[inst.address].fallThrough = False
        self.addr2Inst[inst.address].branchTo = jumpAddr
        self.enter(inst, jumpAddr)
        self.enter(inst, inst.address + inst.size)

    def end(self, inst) -> None:
        """Stop fall throught"""
        self.addr2Inst[inst.address].fallThrough = False
        if inst.address + inst.size <= self.programEnd:
            self.enter(inst, inst.address + inst.size)

    def visitDefault(self, inst) -> None:
        pass

    def visitCalling(self, inst) -> None:
        self.call(inst)

    def visitConditionalJump(self, inst) -> None:
        self.branch(inst)

    def visitUnconditionalJump(self, inst) -> None:
        self.jump(inst)

    def visitEndHere(self, inst) -> None:
        self.end(inst)

    def getBlockAtAddr(self, addr: int) -> Block:
        if addr not in self.addr2Block:
            block = Block()
            block.startAddr = addr
            block.endAddr = addr
            self.addr2Block[addr] = block

        return self.addr2Block[addr]

    def connectBlocks(self) -> None:
        """
        Group instructions into blocks, and
        connected based on branch and fall through.
        """
        currBlock = None
        for (addr, inst) in sorted(self.addr2Inst.items()):
            if currBlock is None or inst.start is True:
                currBlock = self.getBlockAtAddr(addr)
            nextAddr = addr + inst.size
            nextBlock = currBlock
            if nextAddr in self.addr2Inst:
                nextInst = self.addr2Inst[nextAddr]
                if inst.fallThrough is True and nextInst.start is True:
                    nextBlock = self.getBlockAtAddr(nextAddr)
                    currBlock.edgeList.append(nextBlock.startAddr)
                    addr1, addr2 = currBlock.startAddr, nextBlock.startAddr
                    log.debug(f'[ConnectBlocks] B{addr1:x} falls to B{addr2:x}')

            if inst.branchTo is not None:
                block = self.getBlockAtAddr(inst.branchTo)
                if block.startAddr not in currBlock.edgeList:
                    currBlock.edgeList.append(block.startAddr)

                if inst.call is True:
                    if currBlock.startAddr not in block.edgeList:
                        block.edgeList.append(currBlock.startAddr)

            currBlock.instList.append(inst)
            currBlock.endAddr = max(currBlock.endAddr, inst.address)
            self.addr2Block[currBlock.startAddr] = currBlock
            currBlock = nextBlock

    def exportToNxGraph(self):
        """Assume block/node is represented by its startAddr"""
        for (addr, block) in sorted(self.addr2Block.items()):
            self.cfg.add_node(addr, block=block)

        for (addr, block) in self.addr2Block.items():
            for neighboor in block.edgeList:
                self.cfg.add_edge(addr, neighboor)

    def drawCfg(self) -> None:
        nx.draw(self.cfg, with_labels=True, font_weight='normal')
        plt.savefig('%s.pdf' % self.filePrefix, format='pdf')
        plt.clf()

    def printCfg(self):
        for (addr, block) in sorted(self.addr2Block.items()):
            start, end = block.startAddr, block.endAddr
            log.debug(f'[PrintCfg] Block {addr:x}: [{start:x}, {end:x}]')

        log.debug(f'[PrintCfg] Print {nx.number_of_edges(self.cfg)} edges')
        for (addr, block) in sorted(self.addr2Block.items()):
            for neighboor in block.edgeList:
                log.debug(f'[PrintCfg] Edge {addr:x} -> {neighboor:x}')

        self.drawCfg()

    def saveProgram(self) -> None:
        """
        后续调用看看
        :return:
        """
        progFile = open(self.filePrefix + '.prog', 'w')
        for (addr, inst) in self.program.items():
            progFile.write(addr + ' ' + inst + '\n')
        progFile.close()

    def saveText(self) -> None:
        textFile = open(self.filePrefix + '.text', 'w')
        for (lineNum, inst) in self.text.items():
            textFile.write(lineNum + ' ' + inst + '\n')
        textFile.close()

    def clearTmpFiles(self) -> None:
        log.debug('[ClearTmpFiles] Remove temporary files')
        for ext in ['.text', '.prog']:
            os.remove(self.filePrefix + ext)


class AcfgBuilder(object):
    def __init__(self, binaryId: str, pathPrefix: str) -> None:
        # 这里的pathPrefix 并不是 prefix，而是prefix + 文件名
        super(AcfgBuilder, self).__init__()
        self.cfgBuilder = ControlFlowGraphBuilder(binaryId, pathPrefix)
        self.cfg: nx.DiGraph = None

    def extractBlockAttributes(self):
        """
        Extract features in each block.
        """
        # 加上2个centrality
        features = np.zeros((self.cfg.number_of_nodes(), Block.getAttributesDim()), dtype=float)
        # graph_degree_centrality = nx.degree_centrality(self.cfg)
        # graph_closeness_centrality = nx.closeness_centrality(self.cfg)
        for (i, (block_address, attributes)) in enumerate(sorted(self.cfg.nodes(data=True))):
            block = attributes['block']
            # node_degree_centrality = graph_degree_centrality[block_address]
            # node_closeness_centrality = graph_closeness_centrality[block_address]
            attributes = block.getAttributes()
            # print(attributes)
            # centrality = [node_degree_centrality, node_closeness_centrality]
            features[i, :] = attributes
        return features

    def getAttributedCfg(self):
        self.cfg = self.cfgBuilder.getControlFlowGraph()
        number_of_nodes = self.cfg.number_of_nodes()
        if number_of_nodes == 0 or number_of_nodes > 10000:
            return [None, None]
        blockAttrs = self.extractBlockAttributes()
        adjMatrix = nx.adjacency_matrix(self.cfg, nodelist=sorted(self.cfg.nodes()))
        return [blockAttrs, adjMatrix]

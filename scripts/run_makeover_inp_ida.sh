#!/usr/bin/env bash

BIN=/OpenMalAttack/dataset/malware/040f0360b1822ecd23fdcef06b48049a296e6fe07f0f26faf85f90dc03aca1bc
IDA_BIN=/root/IDA_Pro_v6.4/idaq64
IDA_SCRIPT=/OpenMalAttack/ThirdParty/MakeOver/enhanced-binary-randomization/orp/inp_ida.py
LOG=/tmp/ida_044c.log

"$IDA_BIN" -A -S"$IDA_SCRIPT" -L"$LOG" "$BIN"
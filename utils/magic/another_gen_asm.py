# -*- coding: utf-8 -*-
# @Author : matrix-wd
import idc
import idaapi
import idautils
import os


def main():
    """
    生成 ASM 文件
    """
    idc.Wait()
    PATH = "/home/zju/qu/graphAttack/asm"
    filename = '/home/zju/qu/2020-machine-learning-security-evasion-competition-master/classifier/magic/asm_and_acfg/another_sample.asm'
    try:
        idc.GenerateFile(idc.OFILE_LST, filename, 0, idc.BADADDR, 0)
    except:
        print('something wrong')
    idc.Exit(0)


if __name__ == "__main__":
    main()



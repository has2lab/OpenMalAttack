# -*- coding: utf-8 -*- 
# @Time : 2020/11/30 3:47 PM 
# @Author : wd
# @File : batch.py
import glob
import os
import subprocess
import json

def main():
    IDA_PATH = '/home/wzy/IDA_Pro_v6.4/idaq64'
    SCRIPT_PATH = '/home/wzy/call_graph_and_acfg_wd/call_graph_and_acfg/processing_ida_new.py'
    # FILE_PATH = '/Users/xiaod/Desktop/graduate/20_sample/*'
    FILE_PATH = '/home/benign_data/origin_less_than_2MB/exe/*'

    # with open('/home/wzy/get_test_dataset_acfg/hash_list_path.txt', 'r') as f:
    #     data = f.readline()
    #     dataset_hash_list = json.loads(data.strip())
        
    # f.close()
    f = open('/home/wzy/get_test_dataset_acfg/benign_hash_list_path.txt', 'r')
    line = f.readline()
    i=0
    while line:
        # i+=1
        # if i >2000:
        #     break
        filename = json.loads(line.strip())
        if filename.find(".") != -1:
            continue
        cmd = IDA_PATH + ' -c -A -S' + SCRIPT_PATH + ' ' + filename
        # print(filename)
        p = subprocess.Popen(cmd, shell=True)
        p.wait()
        line = f.readline()
    f.close()
    # i=0
    # for filename in glob.glob(FILE_PATH):
    #     i+=1
    #     if i >2000:
    #         break
    #     if filename.find(".") != -1:
    #         continue
    #     cmd = IDA_PATH + ' -c -A -S' + SCRIPT_PATH + ' ' + filename
    #     print(filename)
    #     p = subprocess.Popen(cmd, shell=True)
    #     p.wait()



if __name__ == '__main__':
    main()

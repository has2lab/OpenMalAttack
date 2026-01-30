import os
import sys
import pefile
import hashlib
import time
import rpyc
import zerorpc
import psutil
import subprocess
import numpy as np
from multiprocessing import Process, Pool
sys.path.append("../../")
from classifiers import MalConv

def malfoxProcess(path, perturb_path, pe_tmp_path):
    ret = subprocess.Popen(f"wine python utils/run_malfox.py --pe_path {path} --tmp_path {pe_tmp_path} --perturb_path \
                            {perturb_path[0].astype(int)} {perturb_path[1].astype(int)} {perturb_path[2].astype(int)}", 
                        shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    string_std = ret.stdout.read().decode()
    string_err = ret.stderr.read().decode()
    return string_std.split('\r\n')[1]


class MalPerturbator():
    def __init__(self, rpc_type='singleprocess', ip='localhost', port=8888, pe_tmp_path="tmp/malfox"):
        self.rpc_type = rpc_type
        self.pe_tmp_path = pe_tmp_path
        if self.rpc_type == 'rpyc':
            self.conn = rpyc.connect(ip, port)
        elif self.rpc_type == 'zerorpc':
            self.conn = zerorpc.Client()
            self.conn.connect(f"tcp://{ip}:{port}")

    # @classmethod
    def __call__(self, malware_pe, perturbations, paths=None, processing_type=None):
        """
        mode = 0: return pe objects
             = 1: return sha256
        """
        processing_type = processing_type if processing_type is not None else self.rpc_type
        # 考虑使用多线程处理batch
        # os.system(f"rm {self.pe_tmp_path}*")
        res = []
        hashs = []
        avg_size = 0
        if processing_type == 'multiprocess':
            results = []
            pool = Pool(processes=len(paths))
            for i in range(len(paths)):
                result = pool.apply_async(malfoxProcess, (paths[i], perturbations[i], self.pe_tmp_path))
                results.append(result)
            pool.close()
            pool.join()
            for result in results:
                hash_value = result.get()
                hashs.append(hash_value)
                res.append(pefile.PE(self.pe_tmp_path+hash_value))
                # res.append(pefile.PE(self.pe_tmp_path+hash_value).__data__[:])

        elif processing_type == 'singleprocess':
            for i in range(len(malware_pe)):
                hash_value = malfoxProcess(paths[i], perturbations[i], self.pe_tmp_path)
                hashs.append(hash_value)
                res.append(pefile.PE(self.pe_tmp_path+hash_value))
        elif processing_type == 'rpyc':
            for i, mal in enumerate(malware_pe):
                pe_data = self.conn.root.Perturb(mal.__data__[:], perturbations[i].tolist())
                res.append(pefile.PE(data=pe_data).__data__[:])
        else:
            for i, mal in enumerate(malware_pe):
                try:
                    if processing_type == 'zerorpc':
                        hash_value, pe_size = self.conn.Perturb(mal.__data__[:], perturbations[i].tolist())
                    elif processing_type == 'none':
                        ret = subprocess.Popen(f"wine python run_malfox.py -pe_path {paths[i]} -perturb_path \
                                                {perturbations[i][0].astype(int)} {perturbations[i][1].astype(int)} {perturbations[i][2].astype(int)}", 
                                            shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        string_std = ret.stdout.read().decode()
                        string_err = ret.stderr.read().decode()
                        hash_value = string_std.split('\r\n')[1]
                    res.append(pefile.PE(self.pe_tmp_path+hash_value))

                    mem = psutil.virtual_memory()
                    total_mem = float(mem.total) / 1024 / 1024 / 1024
                    used_mem = float(mem.used) / 1024 / 1024 / 1024
                except:
                    # ! 如果Python是32位的，那么pandas和Numpy也只能是32位的，那么当内存使用超过2G时，就会自动终止。
                    # ! 因此查看内存会发现占用并不高却频繁报错：
                    # !    MemoryError: bad allocation
                    print("Memory: {:.4f}GB/{:.4f}GB".format(used_mem, total_mem))
                    raise Exception(f"[ERROR] {i}: Something wrong with {paths[i]}, Perturbation Path is {perturbations[i]}")
        return res, hashs

if __name__ == "__main__":
    pertb = MalPerturbator(rpc_type='rpyc')
    malconv = MalConv(model_file='/home/Projects/8.8/OpenMalAttack/models/MalConv-base_model_5838.pt')
    data = "/home/mal_data/2018-06-19/Win32_EXE/7beaf9f4f33da19b1896b51f0ab97ac42df2897b4fde939cda603f8796a59bcb"#"/home/mal_data/2018-06-19/Win32_EXE/555ed2b8f69c3774b6b7202b03205079aa0ba2cac9a6d15b1c3c0895bd83b44f"
    perturbations = np.array([[0,0,0],[1,0,0],[0,1,0],[0,0,1],[1,1,0],[1,0,1],[0,1,1],[1,1,1]])
    PEs = pefile.PE(data)
    for p in perturbations:
        adv_pes = pertb([PEs], [p])
        print(f'Perturb: {p}, Result: {malconv([adv_pes[0].__data__[:]])}')

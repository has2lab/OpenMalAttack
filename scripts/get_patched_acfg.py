# -*- coding: utf-8 -*- 
import glob
import os
import subprocess
import json
from multiprocessing import Pool, Process, Value, Lock
import glob
import hydra
import omegaconf
from omegaconf import DictConfig

cfg_path = "/OpenMalAttack/configs/attack_mal.yaml"
config = omegaconf.OmegaConf.load(cfg_path)

def obtain_acfg(cmd):
    p = subprocess.Popen(cmd, shell=True)
    p.wait()

@hydra.main(config_path="/OpenMalAttack/configs", config_name="attack_mal.yaml")
def main(config: DictConfig):
    IDA_PATH = config.Acfg.IDA_PATH
    SCRIPT_PATH = config.Acfg.patch_script_path

    cmd_list = []
    for f in glob.glob(config.Feature_Attack.patched_pe_file_path + '/*'):
        if f.find(".") != -1:
            continue
        cmd = IDA_PATH + ' -c -A -S' + SCRIPT_PATH + ' ' + f
        cmd_list.append(cmd)

    # filename = '/home/000GitHub/MalGuise/pe_changes_and_acfgs/patched_pe_files/878ecb072c4a518321f7e282a9994ef7dd3c1ec86743e7419fa8e54a6a600823_patched'
    # cmd = IDA_PATH + ' -c -A -S' + SCRIPT_PATH + ' ' + filename
    # cmd_list.append(cmd)
    with Pool(processes = config.Feature_Attack.num_workers) as p:
        p.map(obtain_acfg,cmd_list)


if __name__ == '__main__':
    main()

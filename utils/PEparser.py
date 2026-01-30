import glob
import pefile
import json
import numpy as np

MALWARE_NUM = 14000
GOODWARE_NUM = 1800

def pe_parser(dic, inputs, mode=1):
    """
    dic:        map dll names to number
    inputs:     program paths   when mode=1
                object of PEs   when mode=0
    """
    feat_vec = []
    for f in inputs:
        vec = np.zeros(len(dic))
        if mode:    pe = pefile.PE(f)
        else:       pe = f
        if hasattr(pe, 'DIRECTORY_ENTRY_DELAY_IMPORT'):
            for importeddll in pe.DIRECTORY_ENTRY_DELAY_IMPORT:
                for importedapi in importeddll.imports:
                    if importedapi.name is not None and importedapi.name.decode() in dic:
                        vec[dic[importedapi.name.decode()]] = 1
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for importeddll in pe.DIRECTORY_ENTRY_IMPORT:
                for importedapi in importeddll.imports:
                    if importedapi.name is not None and importedapi.name.decode() in dic:
                        vec[dic[importedapi.name.decode()]] = 1
        feat_vec.append(vec)
    return np.array(feat_vec)

def pe_readin(inputs):
    """
    inputs: a list of PE Paths.
    """
    return [pefile.PE(path) for path in inputs]


def getDLL(paths):
    apis = {}
    for p in paths:
        p = p.replace('/bolin', '')
        print(p)
        pe = pefile.PE(p)
        if hasattr(pe, 'DIRECTORY_ENTRY_DELAY_IMPORT'):
            for importeddll in pe.DIRECTORY_ENTRY_DELAY_IMPORT:
                for importedapi in importeddll.imports:
                    if str(importedapi.name) == 'None':
                        continue
                    if importedapi.name not in apis:
                        apis[importedapi.name] = 1
                    else:
                        apis[importedapi.name] += 1
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for importeddll in pe.DIRECTORY_ENTRY_IMPORT:
                for importedapi in importeddll.imports:
                    if str(importedapi.name) == 'None':
                        continue
                    if importedapi.name not in apis:
                        apis[importedapi.name] = 1
                    else:
                        apis[importedapi.name] += 1

    print(len(apis))
    items = list(apis.items())
    items.sort(key=lambda x:x[1],reverse=True)
    print(items[:10])
    return {item[0].decode():i for i,item in enumerate(items[:16156])}
    # return {item[0]:i for i,item in enumerate(items[:16156])}


if __name__ == '__main__':
    # TODO: pre-scan all file to ensure the reliability
    with open('/home/__TMP__/MalPerturb/malfox_dataset_v3.json') as f:
        dataset = json.load(f)
    dll2num = getDLL(dataset["malware"]["train"] + dataset["goodware"]["train"])
    with open('dll2num2.json', 'w') as f:
        json.dump(dll2num, f)
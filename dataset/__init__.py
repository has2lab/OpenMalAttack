from os import PathLike
from pathlib import Path
from torch.utils.data import Dataset
import json

class PEDataset(Dataset):
    def __init__(self, root: PathLike, filt=None):
        '''basic PE dataset

        Args:
            root (str): root abspath of dataset
        '''
        self.root = root
        filt = filt or (lambda x: '.' not in x)
        self.paths = list(Path(root).rglob("*"))
        self.paths = [str(p) for p in self.paths if filt(p.name) and p.is_file()]

    def __getitem__(self, index):
        return self.paths[index]

    def __len__(self):
        return len(self.paths)

malware_data = PEDataset(str(Path('dataset/malware/').expanduser()))[:]
goodware_data = PEDataset(str(Path('dataset/goodware/').expanduser()))[:]

def get_rl_data(path):
    root = str(Path(path).expanduser())
    filt = lambda x: '.' not in x
    paths = list(Path(root).rglob("*"))
    paths = [str(p).split('/')[-1] for p in paths if filt(p.name) and p.is_file()]

malware_train = PEDataset(str(Path('dataset/mal_train/').expanduser()))[:]
malware_test = PEDataset(str(Path('dataset/mal_test/').expanduser()))[:]
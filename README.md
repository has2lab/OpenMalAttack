# OpenMalAttack-v0.1
refactor OpenMalAttack

The code is available under the MIT Open Source License, along with the licenses of our dependencies:
- [Malware Makeover](https://github.com/pwwl/enhanced-binary-diversification) - Copyright (c) 2021, Mahmood Sharif
- [MAB-malware](https://github.com/weisong-ucr/MAB-malware) - Copyright (c) 2021, Wei Song
- [nn_robust_attacks](https://github.com/carlini/nn_robust_attacks) - Copyright (c) 2016, Nicholas Carlini

## How to use
### Docker image.
```
$ sudo apt install docker.io
$ sudo docker pull linj610/openmalattack:v0.1
$ sudo docker run -it --gpus all -p 22 -p 5901 linj610/openmalattack:v0.1 /bin/bash
```

#### Run the adversarial attacks on classifiers.
We provide a easy-to-use framework that requires only a few lines of code to perform the attack as well as the evaluation. To get you started, here's a simple example of using Gamma to attack Malconv.
```
from attack_evals.base import Evaler
from attackers import GammaAttacker
from classifiers import MalConv

attacker = GammaAttacker()
clsf = MalConv()
eval_gamma_malconv = Evaler(attacker=attacker, clsf=clsf)
eval_gamma_malconv()
```

We have provided some sample code in the `sample` folder, which you can run directly in the docker container:

```
$ python main_gamma_malconv.py
```

After the attack, the evasive samples are in the folder: `output/evasive/`.

By default, the framework uses samples under the folder `data/malware/` and `data/goodware/`. You can use your own dataset by mounting your folder to the docker.

```
$ sudo docker run -it --gpus all -p 22 -p 5901 -v [malware_folder_path]:/root/OpenMalAttack/data/malware -v [goodware_folder_path]:/root/OpenMalAttack/data/goodware linj610/openmalattack:v0.1 /bin/bash
```


### Installation.
#### Install vncserver
```
apt-get update
# install gnome desktop
apt-get install gnome-core
# install vncserver
apt-get install vnc4server
# start
vncserver
```

#### Install [IDA Pro](https://hex-rays.com/IDA-pro/)
How to use IDA...

#### Install wine && python(32-bit)
```
$ apt-get install wine

$ wine ./python(32-bit)_for_windows.exe
```


#### Install the necessary packages
```
$ pip install requirements.txt
```

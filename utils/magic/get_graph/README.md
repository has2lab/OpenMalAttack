```
requirement.txt 是依赖文件，现在还没装

跑的时候，执行python acfg_pipeline.py -label=1 就可以了，如果asm文件是善意的-label=0,如果是恶意的，则-label=1


只需要修改acfg_pipeline.py中的如下代码中的pathPrefix【asm文件所在目录】 和 resultPrefix【生成的graph存储目录】，记得最后需要加一个/，也就是不要`dll_4`, 而是要`dll_4/`

def processGetACFG(label):
    pathPrefix = '/home/zju/wd/Benign_asm/dll_4/'
    resultPrefix = '/home/zju/wd/xiang_acfg_code/dll_4_result_5008/'
    master = AcfgMaster(pathPrefix, resultPrefix, label)
    master.dispatchWorkers()

```

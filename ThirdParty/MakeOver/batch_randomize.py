import os
import sys
import glob
import time

sys.path.append('/binary-transform/enhanced-binary-randomization')
sys.path.append('/binary-transform/enhanced-binary-randomization/orp')

import peLib
import func
import inp
import swap
import reorder
import equiv
import preserv
import disp
import semnops
from randtoolkit import reanalyze_functions, patch

def randomize_one(input_path, output_dir, n_randomize=200):
    basename = os.path.basename(input_path)
    out_path = os.path.join(output_dir, basename + "_patched")
    if os.path.exists(out_path):
        return out_path

    pe_file, epilog = peLib.read_pe(pe_path=input_path, remove_rubbish=False)
    disp_state = disp.DispState(pe_file)
    imagebase = disp_state.peinfo.getImageBase()
    functions = inp.get_functions(input_path)
    levels = func.classify_functions(functions)
    func.analyze_functions(functions, levels)

    ALLOWED = ['equiv', 'swap', 'preserv', 'reorder', 'disp', 'semnops']
    start = time.time()
    disp_iter = 0

    for i_r in range(n_randomize):
        if time.time() - start > 20*60:
            break
        for f in filter(lambda x: x.level != -1, functions.itervalues()):
            section = pe_file.get_section_by_rva(f.addr - imagebase)
            if 'reloc' in section.Name:
                continue
            if "_SEH_" in f.name:
                continue

            import random
            sel = random.choice(ALLOWED)

            diffs = None
            if sel == 'equiv':
                diffs, c_b, c_i = equiv.do_equiv_instrs(f, p=0.5)
            elif sel == 'swap':
                swap.liveness_analysis(f.code)
                live_regs = swap.get_reg_live_subsets(f.instrs, f.code, f.igraph)
                swaps = swap.get_reg_swaps(live_regs)
                diffs, c_b, c_i = swap.do_multiple_swaps(f, swaps, p=0.5)
            elif sel == 'preserv':
                preservs, avail_regs = preserv.get_reg_preservations(f)
                diffs, c_b, c_i = preserv.do_reg_preservs(f, preservs, avail_regs, p=0.5)
            elif sel == 'reorder':
                diffs, c_b = reorder.do_random_reordering(f, pe_file)
            elif sel == 'disp':
                diffs, c_b, c_i = disp.displace_block(f, disp_state)
            elif sel == 'semnops':
                diffs, c_b = semnops.do_semnops(f)

            if not diffs:
                continue

            patch(pe_file, disp_state, diffs)

        if i_r < n_randomize - 1:
            reanalyze_functions(functions, levels)

    if not os.path.isdir(output_dir):
        os.makedirs(output_dir)
    peLib.write_pe(out_path, pe_file, epilog)
    return out_path

def main(list_file, output_dir):
    with open(list_file) as f:
        paths = [line.strip() for line in f if line.strip()]
    for i, p in enumerate(paths):
        try:
            out = randomize_one(p, output_dir)
            print("[{} / {}] {}".format(i+1, len(paths), out))
        except Exception as e:
            print("ERROR on {}: {}".format(p, e))

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: batch_randomize.py <list_file> <output_dir>")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])

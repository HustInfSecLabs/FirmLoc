import os
import subprocess
import multiprocessing
import time
from util.pairdata import pairdata
import shutil
import argparse

ida_path = "/home/ubuntu-24-04-4/linux_ida/idat"
work_dir = os.path.abspath('.')
dataset_dir = './dataset/'
strip_path = "./dataset_strip/"
script_path = f"./process.py"
SAVE_ROOT = "./extract"

def getTarget(path, prefixfilter=None):
    target = []
    for root, dirs, files in os.walk(path):
        for file in files:
            if prefixfilter is None:
                target.append(os.path.join(root, file))
            else:
                for prefix in prefixfilter:
                    if file.startswith(prefix):
                        target.append(os.path.join(root, file))
    return target

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="jTrans feature extraction runner")
    parser.add_argument("--mode", choices=["all", "cve"], default="all", help="all: extract all funcs; cve: use cve_map.csv")
    parser.add_argument("--no-pair", action="store_true", help="skip pairing step")
    args = parser.parse_args()

    # prefixfilter = ['libcap-git-setcap']
    os.makedirs("log", exist_ok=True)
    os.makedirs("idb", exist_ok=True)
    os.makedirs("dataset_strip", exist_ok=True)
    os.makedirs("extract", exist_ok=True)

    start = time.time()
    target_list = getTarget(dataset_dir)

    pool = multiprocessing.Pool(processes=8)
    for target in target_list:
        filename = target.split('/')[-1]
        filename_strip = filename  + '.strip'
        ida_input = os.path.join(strip_path, filename_strip)
        strip_ret = os.system(f"strip -s {target} -o {ida_input}")
        print(f"strip -s {target} -o {ida_input}")
        if strip_ret != 0 or not os.path.exists(ida_input):
            print(f"[!] strip failed, fallback to original binary: {target}")
            ida_input = target

        cmd_str = f'{ida_path} -Llog/{filename}.log -c -A -S{script_path} -oidb/{filename}.idb {ida_input}'
        print(cmd_str)
        cmd = [ida_path, f'-Llog/{filename}.log', '-c', '-A', f'-S{script_path}', f'-oidb/{filename}.idb', f'{ida_input}']
        env = os.environ.copy()
        env["JTRANS_USE_CVE_MAP"] = "1" if args.mode == "cve" else "0"
        pool.apply_async(subprocess.call, args=(cmd,), kwds={"env": env})
    pool.close()
    pool.join()
    print('[*] Features Extracting Done')
    if not args.no_pair:
        pairdata(SAVE_ROOT)
    end = time.time()
    print(f"[*] Time Cost: {end - start} seconds")

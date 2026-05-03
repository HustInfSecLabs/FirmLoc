import idc
import idautils
import idaapi
import pickle
import networkx as nx
from util.base import Binarybase
import os
import csv

SAVEROOT = "./extract" # dir of pickle files saved by IDA
DATAROOT = "./dataset" # dir of binaries (not stripped)
CVE_MAP_PATH = "./cve_map.csv"  # optional: cve,binary,func_name
CVE_MAP_ENV = "JTRANS_USE_CVE_MAP"  # set to "1" to enable cve_map filtering/renaming

class BinaryData(Binarybase):
    def __init__(self, unstrip_path):
        super(BinaryData, self).__init__(unstrip_path)
        self.fix_up()
    
    def fix_up(self):
        for addr in self.addr2name:
            # incase some functions' instructions are not recognized by IDA
            idc.create_insn(addr)  
            idc.add_func(addr) 

    def get_asm(self, func):
        instGenerator = idautils.FuncItems(func)
        asm_list = []
        for inst in instGenerator:
            asm_list.append(idc.GetDisasm(inst))
        return asm_list

    def get_rawbytes(self, func):
        instGenerator = idautils.FuncItems(func)
        rawbytes_list = b""
        for inst in instGenerator:
            rawbytes_list += idc.get_bytes(inst, idc.get_item_size(inst))
        return rawbytes_list

    def get_cfg(self, func):

        def get_attr(block, func_addr_set):
            asm,raw=[],b""
            curr_addr = block.start_ea
            if curr_addr not in func_addr_set:
                return -1
            # print(f"[*] cur: {hex(curr_addr)}, block_end: {hex(block.end_ea)}")
            while curr_addr <= block.end_ea:
                asm.append(idc.GetDisasm(curr_addr))
                raw+=idc.get_bytes(curr_addr, idc.get_item_size(curr_addr))
                curr_addr = idc.next_head(curr_addr, block.end_ea)
            return asm, raw

        nx_graph = nx.DiGraph()
        flowchart = idaapi.FlowChart(idaapi.get_func(func), flags=idaapi.FC_PREDS)
        func_addr_set = set([addr for addr in idautils.FuncItems(func)])
        for block in flowchart:
            # Make sure all nodes are added (including edge-less nodes)
            attr = get_attr(block, func_addr_set)
            if attr == -1:
                continue
            nx_graph.add_node(block.start_ea, asm=attr[0], raw=attr[1])
            # print(f"[*] bb: {hex(block.start_ea)}, asm: {attr[0]}")
            for pred in block.preds():
                if pred.start_ea not in func_addr_set:
                    continue
                nx_graph.add_edge(pred.start_ea, block.start_ea)
            for succ in block.succs():
                if succ.start_ea not in func_addr_set:
                    continue
                nx_graph.add_edge(block.start_ea, succ.start_ea)
        return nx_graph  

    def get_binai_feature(self, func):
        return []

    def extract_all(self):
        for func in idautils.Functions():
            if idc.get_segm_name(func) in ['.plt','extern','.init','.fini']:
                continue
            ida_name = idc.get_func_name(func)
            if not ida_name:
                continue
            fname = self.addr2name[func]
            if fname == -1 or fname is None:
                # Only keep auto-generated sub_* names when no symbol info exists.
                if not ida_name.startswith("sub_"):
                    continue
                fname = ida_name
            # Drop dot-prefixed names like ".strstr", ".free".
            if fname.startswith("."):
                continue
            fname = self.get_func_name(fname, {})  
            print("[+] %s" % fname)
            asm_list = self.get_asm(func)
            rawbytes_list = self.get_rawbytes(func)
            cfg = self.get_cfg(func)
            bai_feature = self.get_binai_feature(func)
            yield (fname, func, asm_list, rawbytes_list, cfg, bai_feature)
if __name__ == "__main__":
    from collections import defaultdict

    assert os.path.exists(DATAROOT), "DATAROOT does not exist"
    assert os.path.exists(SAVEROOT), "SAVEROOT does not exist"

    cve_map = {}
    use_cve_map = os.environ.get(CVE_MAP_ENV, "0") == "1"

    if use_cve_map and os.path.exists(CVE_MAP_PATH):
        with open(CVE_MAP_PATH, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            for row in reader:
                if not row or len(row) < 3:
                    continue
                cve = row[0].strip()
                binary_key = row[1].strip()
                func_name = row[2].strip()
                if not cve or not binary_key or not func_name:
                    continue
                cve_map.setdefault(binary_key, {}).setdefault(func_name, set()).add(cve)

    binary_abs_path = idc.get_input_file_path()
    filename = os.path.basename(binary_abs_path)
    if filename.endswith('.strip'):
        filename = filename[:-6]
    unstrip_path = os.path.join(DATAROOT, filename)
    binary_keys = {filename, os.path.basename(unstrip_path), unstrip_path, binary_abs_path}
    cve_funcs = set()
    if use_cve_map:
        for key in binary_keys:
            if key in cve_map:
                cve_funcs |= set(cve_map[key].keys())
        print(f"[*] cve_funcs for {filename}: {sorted(cve_funcs)}")

    idc.auto_wait()
    binary_data = BinaryData(unstrip_path)

    saved_dict = defaultdict(lambda: list)
    saved_path = os.path.join(SAVEROOT, filename + "_extract.pkl") # unpair data
    with open(saved_path, 'wb') as f:
        for func_name, func, asm_list, rawbytes_list, cfg, bai_feature in binary_data.extract_all():
            if use_cve_map and cve_funcs and func_name not in cve_funcs:
                continue
            saved_name = func_name
            if use_cve_map:
                for key in binary_keys:
                    func_cves = cve_map.get(key, {}).get(func_name)
                    if func_cves:
                        # If multiple CVEs map to the same function, emit one entry per CVE.
                        for cve in func_cves:
                            tagged_name = f"{cve}-{filename}-{func_name}"
                            saved_dict[tagged_name] = [func, asm_list, rawbytes_list, cfg, bai_feature]
                        break
                else:
                    saved_dict[saved_name] = [func, asm_list, rawbytes_list, cfg, bai_feature]
            else:
                saved_dict[saved_name] = [func, asm_list, rawbytes_list, cfg, bai_feature]
        print(f"[*] saved_dict keys for {filename}: {sorted(saved_dict.keys())}")
        pickle.dump(dict(saved_dict), f)
    idc.qexit(0) # exit IDA


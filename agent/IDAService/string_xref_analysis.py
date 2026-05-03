"""
IDA String Cross-Reference Analysis Script

Usage: Execute in IDA headless mode to analyze string cross-references.
Input/output files are placed in the same directory as the IDB.

Environment Variables:
    - IDA_INPUT_FILE: Path to input JSON file (contains strings to analyze)
    - IDA_OUTPUT_FILE: Path to output JSON file
"""

import json
import os
import traceback

import ida_auto
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_idaapi
import ida_nalt
import ida_segment
import ida_strlist
import idautils
import idc


# Global log file path
LOG_PATH = ""

# Hex-Rays plugin status
USE_HEXRAYS = False


def log_message(msg: str):
    """Log message to file and console."""
    print(msg)
    if LOG_PATH:
        try:
            with open(LOG_PATH, 'a', encoding='utf-8') as f:
                f.write(msg + "\n")
        except:
            pass


def init_hexrays():
    """Initialize Hex-Rays decompiler plugin."""
    global USE_HEXRAYS
    try:
        USE_HEXRAYS = ida_hexrays.init_hexrays_plugin()
        log_message(f"[xref] Hex-Rays status: {'OK' if USE_HEXRAYS else 'FAILED'}")
    except Exception as e:
        log_message(f"[xref] Hex-Rays init error: {e}")
        USE_HEXRAYS = False


def decode_string_at(ea: int, max_len: int = 512) -> str:
    """Decode string at given address."""
    try:
        # Get string length from IDA
        str_len = ida_bytes.get_max_strlit_length(ea, ida_nalt.STRTYPE_C, ida_bytes.ALOPT_IGNHEADS)
        if 0 < str_len < max_len:
            max_len = str_len
        
        for strtype in [ida_nalt.STRTYPE_C, ida_nalt.STRTYPE_C_16]:
            raw = ida_bytes.get_strlit_contents(ea, max_len, strtype)
            if not raw:
                continue
                
            if isinstance(raw, bytes):
                for encoding in ['utf-8', 'latin-1']:
                    try:
                        decoded = raw.decode(encoding, errors="ignore")
                        null_pos = decoded.find('\x00')
                        return (decoded[:null_pos] if null_pos >= 0 else decoded).strip()
                    except:
                        continue
            else:
                result = str(raw)
                null_pos = result.find('\x00')
                return (result[:null_pos] if null_pos >= 0 else result).strip()
    except:
        pass
    return None


def build_string_map():
    """Build address-to-value and value-to-addresses mappings."""
    addr_to_value = {}
    value_to_addrs = {}
    
    log_message("[xref] Building string map...")
    
    # Setup string list
    str_list = idautils.Strings()
    strtypes = [getattr(ida_nalt, name) for name in ['STRTYPE_C', 'STRTYPE_C_16'] if hasattr(ida_nalt, name)]
    str_list.setup(strtypes=strtypes or [0])
    
    count = 0
    for item in str_list:
        try:
            ea = int(item.ea)
            text = decode_string_at(ea, min(int(item.length) + 1, 512))
            if text and len(text) >= 2:
                text = text.strip()
                addr_to_value[ea] = text
                value_to_addrs.setdefault(text, []).append(ea)
                count += 1
        except:
            continue
    
    log_message(f"[xref] String map built: {count} strings")
    return addr_to_value, value_to_addrs


def find_string_address(search_value: str, value_to_addrs: dict) -> int:
    """Find string address by value (exact or fuzzy match)."""
    if not search_value:
        return None
    
    # Exact match
    if search_value in value_to_addrs:
        return value_to_addrs[search_value][0]
    
    # Fuzzy match
    for val, addrs in value_to_addrs.items():
        if search_value in val or val in search_value:
            return addrs[0]
    
    return None


def get_string_xrefs(string_addr: int) -> list:
    """Get all cross-references to a string address."""
    xrefs = []
    try:
        for xref in idautils.XrefsTo(string_addr):
            func = ida_funcs.get_func(xref.frm)
            xrefs.append({
                'xref_addr': hex(xref.frm),
                'xref_type': xref.type,
                'func_name': ida_funcs.get_func_name(func.start_ea) if func else "",
                'func_addr': hex(func.start_ea) if func else None
            })
    except Exception as e:
        log_message(f"[xref] Error getting xrefs: {e}")
    return xrefs


def decompile_function(func_addr: int) -> str:
    """Decompile function and return pseudo code."""
    if not USE_HEXRAYS:
        return None
    
    try:
        cfunc = ida_hexrays.decompile(func_addr)
        if cfunc:
            return str(cfunc)
    except Exception as e:
        log_message(f"[xref] Decompile {hex(func_addr)} failed: {e}")
    
    return None


def get_disasm_context(addr: int, before: int = 5, after: int = 5) -> str:
    """Get disassembly context around an address."""
    lines = []
    
    try:
        # Get lines before
        current = addr
        for _ in range(before):
            current = idc.prev_head(current)
            if current == ida_idaapi.BADADDR:
                break
            disasm = idc.GetDisasm(current)
            if disasm:
                lines.insert(0, f"{hex(current)}: {disasm}")
        
        # Current line
        lines.append(f"{hex(addr)}: {idc.GetDisasm(addr)} <-- TARGET")
        
        # Get lines after
        current = addr
        for _ in range(after):
            current = idc.next_head(current)
            if current == ida_idaapi.BADADDR:
                break
            disasm = idc.GetDisasm(current)
            if disasm:
                lines.append(f"{hex(current)}: {disasm}")
    except Exception as e:
        log_message(f"[xref] Error getting disasm: {e}")
    
    return '\n'.join(lines)


def analyze_single_string(string_addr: int, string_value: str, addr_to_value: dict, 
                          value_to_addrs: dict, max_xrefs: int = 10) -> dict:
    """Analyze a single string's cross-references and context."""
    
    result = {
        'string_addr': None,
        'string_value': None,
        'xref_count': 0,
        'xrefs_analyzed': 0,
        'contexts': []
    }
    
    # Resolve string address
    resolved_addr = None
    resolved_value = None
    
    if string_addr and string_addr in addr_to_value:
        resolved_addr = string_addr
        resolved_value = addr_to_value[string_addr]
    elif string_value:
        resolved_addr = find_string_address(string_value, value_to_addrs)
        if resolved_addr:
            resolved_value = addr_to_value.get(resolved_addr)
    
    if not resolved_addr:
        result['error'] = f"String not found: {string_value}"
        return result
    
    result['string_addr'] = hex(resolved_addr)
    result['string_value'] = resolved_value
    
    # Get cross-references
    xrefs = get_string_xrefs(resolved_addr)
    result['xref_count'] = len(xrefs)
    
    # Analyze context for each xref
    contexts = []
    for xref in xrefs[:max_xrefs]:
        try:
            xref_addr = int(xref['xref_addr'], 16)
            func_addr = int(xref['func_addr'], 16) if xref['func_addr'] else None
            
            context = {
                'xref_addr': xref['xref_addr'],
                'func_name': xref['func_name'],
                'func_addr': xref['func_addr'],
                'disasm': get_disasm_context(xref_addr),
                'decompiled': None
            }
            
            # Try decompile
            if func_addr and USE_HEXRAYS:
                context['decompiled'] = decompile_function(func_addr)
            
            contexts.append(context)
        except Exception as e:
            log_message(f"[xref] Error analyzing xref: {e}")
    
    result['xrefs_analyzed'] = len(contexts)
    result['contexts'] = contexts
    return result


def analyze_strings(strings_list: list, addr_to_value: dict, 
                    value_to_addrs: dict, max_xrefs: int = 10) -> list:
    """Batch analyze a list of strings."""
    results = []
    total = len(strings_list)
    
    for idx, item in enumerate(strings_list):
        if idx % 10 == 0:
            log_message(f"[xref] Progress: {idx}/{total}")
        
        try:
            # Parse address
            addr_str = item.get('vaddr') or item.get('address')
            addr = None
            if addr_str:
                try:
                    addr = int(addr_str, 16) if isinstance(addr_str, str) else int(addr_str)
                except:
                    pass
            
            # Analyze
            result = analyze_single_string(addr, item.get('value'), addr_to_value, value_to_addrs, max_xrefs)
            result['original_query'] = item
            results.append(result)
            
        except Exception as e:
            log_message(f"[xref] Error: {e}")
            results.append({'error': str(e), 'original_query': item})
    
    log_message(f"[xref] Complete: {len(results)} results")
    return results


def main():
    """Main entry point."""
    global LOG_PATH
    
    # Get paths
    bin_path = ida_nalt.get_input_file_path()
    bin_name = os.path.basename(bin_path)
    idb_path = idc.get_idb_path()
    dir_path = os.path.dirname(idb_path) or os.path.dirname(bin_path) or os.getcwd()
    
    # Initialize log
    LOG_PATH = os.path.join(dir_path, f"{bin_name}_xref_log.txt")
    with open(LOG_PATH, 'w', encoding='utf-8') as f:
        f.write(f"String xref analysis: {bin_name}\nIDB: {idb_path}\nDir: {dir_path}\n")
    
    log_message(f"[xref] Starting: {bin_name}")
    
    # Wait for auto-analysis
    log_message("[xref] Waiting for auto-analysis...")
    ida_auto.auto_wait()
    log_message("[xref] Auto-analysis complete")
    
    # Initialize Hex-Rays
    init_hexrays()
    
    # Get environment variables
    input_file = os.environ.get('IDA_INPUT_FILE', '')
    output_file = os.environ.get('IDA_OUTPUT_FILE', '') or os.path.join(dir_path, f"{bin_name}_xref_output.json")
    
    log_message(f"[xref] Input: {input_file}")
    log_message(f"[xref] Output: {output_file}")
    
    # Build string map
    addr_to_value, value_to_addrs = build_string_map()
    
    # Read input
    strings_list = []
    max_xrefs = 10
    
    if input_file and os.path.exists(input_file):
        try:
            with open(input_file, 'r', encoding='utf-8') as f:
                input_data = json.load(f)
                strings_list = input_data.get('strings', [])
                max_xrefs = input_data.get('max_xrefs', 10)
            log_message(f"[xref] Loaded {len(strings_list)} strings")
        except Exception as e:
            log_message(f"[xref] Error reading input: {e}")
    
    # Execute analysis
    try:
        if strings_list:
            log_message(f"[xref] Analyzing {len(strings_list)} strings...")
            results = analyze_strings(strings_list, addr_to_value, value_to_addrs, max_xrefs)
            result = {
                'mode': 'batch',
                'binary': bin_name,
                'total_strings': len(addr_to_value),
                'analyzed_count': len(results),
                'results': results
            }
        else:
            # No input, export string list
            log_message("[xref] No input, exporting strings...")
            all_strings = [
                {'address': hex(addr), 'value': value, 'xref_count': len(get_string_xrefs(addr))}
                for addr, value in list(addr_to_value.items())[:1000]
            ]
            result = {
                'mode': 'export',
                'binary': bin_name,
                'total_strings': len(addr_to_value),
                'strings': all_strings
            }
    except Exception as e:
        log_message(f"[xref] Analysis error: {e}\n{traceback.format_exc()}")
        result = {'error': str(e), 'traceback': traceback.format_exc()}
    
    # Write output
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        log_message(f"[xref] Output written: {output_file}")
    except Exception as e:
        log_message(f"[xref] Error writing output: {e}")
        try:
            with open(os.path.join(dir_path, f"{bin_name}_xref_error.json"), 'w') as f:
                json.dump({'error': str(e)}, f)
        except:
            pass
    
    log_message("[xref] Done")
    idc.qexit(0)


# Script entry point
if __name__ == "__main__":
    main()

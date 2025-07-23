import subprocess
import sys
import json
import os
import threading
import lief
from arg_parser import parse_arg
from vuln_safe_mapping import VULN_SAFE_MAP

def get_got_address(binary, func_name):
    for f in binary.pltgot_relocations:
        if f.has_symbol and f.symbol.name == func_name:
            print(f"{f.symbol.name} address is 0x{f.address:x}===")
            return f.address

    safe_func_sym = binary.get_dynamic_symbol(func_name)
    if safe_func_sym is not None:
        print(f"No address before , New address for {func_name} | address :  0x{safe_func_sym.value:x}")
        return safe_func_sym.value
        
    print(f'no {func_name} symbol founded')
    return None

def get_safe_func(vuln_list):
    safe_funcs = []
    for i in vuln_list:
        safe_funcs.append(VULN_SAFE_MAP[i]['safe_func'])

    print(f"got safe func {safe_funcs}") 
    return safe_funcs   

def register_symbol(binary_info,segments,vuln_func):

    print(f"========{vuln_func}=======")

    safe_funcs  = get_safe_func(vuln_func)
    for sym in safe_file.dynamic_symbols:
        if sym.name is not None and sym.name in safe_funcs:
            existing_symbol = binary_info.get_dynamic_symbol(sym.name)
            if existing_symbol:
                print(f"Already has {existing_symbol.name}")
                continue
            
            new_symbol = lief.ELF.Symbol()
            new_symbol.name = sym.name
            new_symbol.type = sym.type
            new_symbol.binding = sym.binding
            new_symbol.visibility = sym.visibility
            new_symbol.size = sym.size
            
            new_symbol.value = segments.virtual_address + sym.value
            
            binary_info.add_dynamic_symbol(new_symbol)
            print(f"Registered symbol: {sym.name} at 0x{new_symbol.value:x}")




def patch_the_function(binary_info,file_path):
    for reloc in binary_info.pltgot_relocations:
        if reloc.has_symbol:
            vuln_func = reloc.symbol.name
            if vuln_func in VULN_SAFE_MAP:
                safe_func = VULN_SAFE_MAP[vuln_func]
                safe_func_addr = get_got_address(binary_info, safe_func['safe_func'])
                if isinstance(safe_func_addr, int):
                    binary_info.patch_address(reloc.address, safe_func_addr)
                    print(f"Patched {vuln_func} → {safe_func['safe_func']} at 0x{reloc.address:x} with address 0x{safe_func_addr:x}\n")
                else:
                    print(f"Cannot patch: {vuln_func} → {safe_func['safe_func']}.  : [ symbol address not found ]\n")                    

    parsed_path = file_path.split('/')
    dst_path = "test_ELF_file/patched/"+parsed_path[1]
    print(f"\033[96mPatched ELF saved as {dst_path}\033[0m")
    #binary_info.write(dst_path)




def find_location_vul_symbol(file_path,found_funcs):
    binary_info = lief.parse(file_path)
    symbol_names =[]
    symbol_location =[]
    dynamic_symbols =[]
    count = 0
    combined_segment = binary_info.add(safe_file.segments[0])  

    register_symbol(binary_info,combined_segment,found_funcs)

    print(f"Checking Symbols in {file_path}...")
        
    for reloc in binary_info.pltgot_relocations:
        if reloc.has_symbol:
            if reloc.symbol.name in VULN_SAFE_MAP:
                symbol_names.append(reloc.symbol.name)
                symbol_location.append(f"0x{reloc.address:x}")
                print(f"\033[91mGOT entry for [ {reloc.symbol.name} ]: 0x{reloc.address:x} \033[0m")
                count+=1

    for sym in binary_info.dynamic_symbols:
        if sym.name in VULN_SAFE_MAP:
            if sym.name not in symbol_names:
                dynamic_symbols.append(sym.name)
                print(f"\033[93mDynamic symbol [ {sym.name} ] found (not in GOT)\033[0m")
                count+=1


    if(count >0):
        print(f"total {count} vuln functions\n")
        print("call the patch func\n")
        patch_the_function(binary_info,file_path)
    else:
        print("No Vulnerable Symbol Detected")
    
    print("=========================================================================================\n")


    detection_results.append({
        "file": file_path,
        "dangerous_functions": found_funcs,
        "symbol_name" : symbol_names,
        "symbol_location" : symbol_location,
        "dynamic_only" : dynamic_symbols,
        "total_num" : count
        })


def check_vulnerable_strings(file_path):
    found_funcs = []
    with result_lock:

        output = subprocess.check_output(["strings",file_path],text=True)

        for func in VULN_SAFE_MAP:
            if func in output:
                found_funcs.append(func)

        print(f"▼ There are {len(found_funcs)} vulnerable_commands in ['\033[92m strings {file_path} \033[0m'] ▼")
        if found_funcs:
            print(f"\033[91m[ Warning ] : string < {', '.join(found_funcs)} > Founded \033[0m \n")
            find_location_vul_symbol(file_path,found_funcs)
        else:
            print("\033[92m[ It's safe as far as I checked  :) ] \033[0m")


def get_elf_files(directory):
    file_name = []

    for fname in os.listdir(directory):
        full_path = os.path.join(directory, fname)

        if os.path.isfile(full_path):
            try:
                output = subprocess.check_output(["file", full_path], text=True)

                if "ELF" in output:
                    result = directory+fname
                    file_name.append(result)

            except subprocess.CalledProcessError:
                continue  

    return file_name


args = parse_arg()
detection_results = []  
result_lock = threading.Lock()
default_dir_path = "test_ELF_file/"
target_files = get_elf_files(default_dir_path)
threads = []
safe_file = lief.parse("safe_func")

for i in target_files:
#    print(i,"hit\n")
    t = threading.Thread(target=check_vulnerable_strings, args=(i,))
    threads.append(t)
    t.start()


for t in threads:
    t.join()


if args.json:
    print("hit")
    with open("result.json", "w") as f:
        json.dump(detection_results, f, indent=2)

import subprocess
import sys
import json
import os
import threading
import lief
from flask import Flask, request, jsonify, render_template
from vuln_safe_mapping import VULN_SAFE_MAP

app = Flask(__name__)
detection_results = []
result_lock = threading.Lock()
default_dir_path = "test_ELF_file/"
patched_dir = os.path.join(default_dir_path, "patched")

if not os.path.exists(patched_dir):
    os.makedirs(patched_dir)

dangerous_funcs = list(VULN_SAFE_MAP.keys())


def get_plt_address(binary, func_name):
    for f in binary.pltgot_relocations:
        if f.has_symbol and f.symbol.name == func_name:
            return f.address
    return None


def patch_the_function(binary_info, file_path):
    for reloc in binary_info.pltgot_relocations:
        if reloc.has_symbol:
            vuln_func = reloc.symbol.name
            if vuln_func in VULN_SAFE_MAP:
                print(f"\033[91m[!] GOT entry for {vuln_func}: 0x{reloc.address:x}\033[0m")

                safe_func = VULN_SAFE_MAP[vuln_func]
                safe_func_addr = get_plt_address(binary_info, safe_func)

                if isinstance(safe_func_addr, int):
                    binary_info.patch_address(reloc.address, safe_func_addr)
                    print(f"Patched {vuln_func} → {safe_func} at 0x{reloc.address:x} with address 0x{safe_func_addr:x}\n")
                else:
                    print(f"Cannot patch: {vuln_func} → {safe_func}  : [ symbol address not found ]\n")

    parsed_path = file_path.split('/')
    dst_path = os.path.join(patched_dir, parsed_path[-1])
    binary_info.write(dst_path)
    print(f"\033[96mPatched ELF saved as {dst_path}\033[0m")
    return dst_path


def find_location_vul_symbol(file_path, found_funcs):
    binary_info = lief.parse(file_path)
    symbol_names = []
    symbol_location = []
    dynamic_symbols = []
    count = 0

    print(f"Checking Symbols in {file_path}...")

    for reloc in binary_info.pltgot_relocations:
        if reloc.has_symbol and reloc.symbol.name in dangerous_funcs:
            symbol_names.append(reloc.symbol.name)
            symbol_location.append(f"0x{reloc.address:x}")
            print(f"\033[91mGOT entry for [ {reloc.symbol.name} ]: 0x{reloc.address:x} \033[0m")
            count += 1

    for sym in binary_info.dynamic_symbols:
        if sym.name in dangerous_funcs and sym.name not in symbol_names:
            dynamic_symbols.append(sym.name)
            print(f"\033[93mDynamic symbol [ {sym.name} ] found (not in GOT)\033[0m")
            count += 1

    if count > 0:
        print("call the patch func\n")
        patched_path = patch_the_function(binary_info, file_path)
    else:
        patched_path = None

    print("=========================================================================================\n")
    
    detection_results.append({
        "dangerous_functions": found_funcs,
        "symbol_name": symbol_names,
        "symbol_location": symbol_location,
        "dynamic_only": dynamic_symbols,
        "patched_path": patched_path
    })


def check_vulnerable_strings(file_path):
    found_funcs = []
    with result_lock:
        output = subprocess.check_output(["strings", file_path], text=True)
        for func in dangerous_funcs:
            if func in output:
                found_funcs.append(func)

        print(f"▼ There are {len(found_funcs)} vulnerable_command in ['\033[92m strings {file_path} \033[0m'] ▼")

        if found_funcs:
            print(f"\033[91m[ Warning ] : String {', '.join(found_funcs)} Founded \033[0m \n")
            find_location_vul_symbol(file_path, found_funcs)
        else:
            print("\033[92m[ It's safe as far as I checked  :) ] \033[0m")
            detection_results.append({
                "file": file_path,
                "result": "No Vulnerable Command Detected"
            })
            


@app.route('/analyze', methods=['POST'])
def analyze():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    save_path = os.path.join(default_dir_path, file.filename)
    file.save(save_path)

    detection_results.clear()
    check_vulnerable_strings(save_path)

    return jsonify(file.filename,detection_results)


@app.route('/')
def upload_form():
    return render_template('upload.html')


if __name__ == '__main__':
    app.run(debug=True)

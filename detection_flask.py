import subprocess
import os
import threading
import lief
from flask import Flask, request, jsonify, redirect
from vuln_safe_mapping import VULN_SAFE_MAP
from flask_cors import CORS

app = Flask(__name__)
CORS(app, origins="*")

# Globals
detection_results = []
result_lock = threading.Lock()
default_dir_path = "test_ELF_file/"
patched_dir = os.path.join(default_dir_path, "patched")

# Ensure dirs exist
os.makedirs(default_dir_path, exist_ok=True)
os.makedirs(patched_dir, exist_ok=True)

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
                safe_func_addr = get_plt_address(binary_info, safe_func['safe_func'])
                if isinstance(safe_func_addr, int):
                    binary_info.patch_address(reloc.address, safe_func_addr)
                    print(f"Patched {vuln_func} → {safe_func['safe_func']} at 0x{reloc.address:x} with 0x{safe_func_addr:x}\n")
                else:
                    print(f"Cannot patch: {vuln_func} → {safe_func['safe_func']} : [ symbol address not found ]\n")

    dst_path = os.path.join(patched_dir, os.path.basename(file_path))
    binary_info.write(dst_path)
    print(f"\033[96mPatched ELF saved as {dst_path}\033[0m")
    return dst_path

def is_fortify_enabled(binary):
    fortify_funcs = [
        "__sprintf_chk", "__snprintf_chk", "__fprintf_chk",
        "__vsprintf_chk", "__vfprintf_chk", "__memcpy_chk", "__strcpy_chk"
    ]
    for sym in binary.symbols:
        if sym.name in fortify_funcs:
            return True
    return False

def get_checksec(bin_info):
    checksec = []
    if hasattr(bin_info, "relro"):
        checksec.append(f"RELRO: {bin_info.relro.name}")
    else:
        checksec.append("RELRO: None")
    if getattr(bin_info, "has_canary", False):
        checksec.append("Canary")
    if getattr(bin_info, "has_nx", False):
        checksec.append("NX")
    if getattr(bin_info, "has_pie", False):
        checksec.append("PIE")
    if is_fortify_enabled(bin_info):
        checksec.append("Fortify")
    return checksec

def find_location_vul_symbol(file_path, found_funcs):
    symbol_names = []
    dynamic_symbols = []
    safe_funcs = []
    count = 0

    binary_info = lief.parse(file_path)
    checksec = get_checksec(binary_info)
    print(f"Checking Symbols in {file_path}...")

    for reloc in binary_info.pltgot_relocations:
        if reloc.has_symbol and reloc.symbol.name in dangerous_funcs:
            symbol_names.append(reloc.symbol.name)
            safe_funcs.append((reloc.symbol.name, VULN_SAFE_MAP[reloc.symbol.name]))
            print(f"\033[91mGOT entry for [ {reloc.symbol.name} ]: 0x{reloc.address:x} \033[0m")
            count += 1

    for sym in binary_info.dynamic_symbols:
        if sym.name in dangerous_funcs and sym.name not in symbol_names:
            dynamic_symbols.append(sym.name)
            if (sym.name, VULN_SAFE_MAP[sym.name]) not in safe_funcs:
                safe_funcs.append((sym.name, VULN_SAFE_MAP[sym.name]))
                count += 1
        print(f"\033[93mDynamic symbol [ {sym.name} ] found (not in GOT)\033[0m")

    patched_path = patch_the_function(binary_info, file_path) if count > 0 else None
    print("=========================================================================================\n")

    detection_results.append({
        "dynamic_only": dynamic_symbols,
        "function_mapping": safe_funcs,
        "count": count,
        "checksec": checksec,
        "patched_path": patched_path
    })

def check_vulnerable_strings(file_path):
    found_funcs = []
    with result_lock:
        output = subprocess.check_output(["strings", file_path], text=True)
        for func in dangerous_funcs:
            if func in output:
                found_funcs.append(func)

        print(f"▼ Found {len(found_funcs)} vulnerable_command in ['\033[92m strings {file_path} \033[0m'] ▼")

        if found_funcs:
            print(f"\033[91m[ Warning ] : String {', '.join(found_funcs)} Found \033[0m \n")
            find_location_vul_symbol(file_path, found_funcs)
        else:
            print("\033[92m[ It's safe as far as I checked  :) ] \033[0m")
            detection_results.append({
                "file": file_path,
                "result": "No Vulnerable Command Detected",
                "count": 0,
                "checksec": []
            })

@app.errorhandler(400)
def handle_400(e):
    return jsonify({"status": "error", "error": "Bad Request", "message": str(e)}), 400

@app.errorhandler(500)
def handle_500(e):
    return jsonify({"status": "error", "error": "Internal Server Error", "message": "Analysis failed", "detail": str(e)}), 500

@app.route('/analyze', methods=['POST'])
def analyze():
    if 'file' not in request.files:
        return jsonify({"status": "error", "error": "Bad Request", "message": "No file part"}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"status": "error", "error": "Bad Request", "message": "No selected file"}), 400

    save_path = os.path.join(default_dir_path, file.filename)
    file.save(save_path) 

    detection_results.clear()
    try:
        try:
            check_vulnerable_strings(save_path)
            results_payload = detection_results[:]  # copy
            is_empty = not results_payload or all(
                (r.get("count", 0) == 0) for r in results_payload
            )
            if is_empty:
                return jsonify({
                    "status": "ok",
                    "filename": file.filename,
                    "message": "No findings",
                    "results": results_payload
                }), 200
            else:
                return jsonify({
                    "status": "ok",
                    "filename": file.filename,
                    "message": "Analysis complete",
                    "results": results_payload
                }), 200
        except subprocess.TimeoutExpired as te:
            return jsonify({
                "status": "error",
                "error": "Timeout",
                "message": "Analysis exceeded time limit",
                "detail": str(te)
            }), 500
        except Exception as ex:
            return jsonify({
                "status": "error",
                "error": "Internal Server Error",
                "message": "Analysis failed",
                "detail": str(ex)
            }), 500
    finally:
        try:
            if os.path.exists(save_path):
                os.remove(save_path)
        except Exception as e:
            app.logger.error(f"Failed to remove uploaded file {save_path}: {e}")

@app.route('/')
def upload_form():
    return redirect("https://vuln-detection-front.vercel.app/")

if __name__ == '__main__':
    app.run(debug=True)

import subprocess
import os
import threading
import lief
from vuln_safe_mapping import VULN_SAFE_MAP

SAFE_FUNC_PATH = "safe_func.so"

def get_got_address(binary, func_name):
    for reloc in binary.pltgot_relocations:
        if reloc.has_symbol and reloc.symbol.name == func_name:
            print(f"{reloc.symbol.name} address is 0x{reloc.address:x} ===")
            return reloc.address
    print(f"[!] GOT address for [ {func_name} ] not found")
    return None

def get_custom_func_addr_by_hook_segment(binary_info, safe_func_path, custom_func_name):
    hook = lief.parse(safe_func_path)
    sym  = hook.get_symbol(custom_func_name)
    if sym is None:
        print(f"[!] {custom_func_name} not found in safe_func.so")
        return None

    # safe_func.so 내에서 함수가 속한 실행 세그먼트 찾기
    base_seg = None
    for seg in hook.segments:
        if (seg.type == lief.ELF.Segment.TYPE.LOAD and
            seg.flags & lief.ELF.Segment.FLAGS.X):
            if seg.virtual_address <= sym.value < seg.virtual_address + seg.virtual_size:
                base_seg = seg
                break
    if base_seg is None:
        print(f"[!] cannot locate segment in safe_func.so for {custom_func_name}")
        return None

    # 병합된 ELF에서 동일 크기의 실행(LOAD+X) 세그먼트 후보 찾기
    candidates = []
    for seg in binary_info.segments:
        if (seg.type == lief.ELF.Segment.TYPE.LOAD and
            seg.flags & lief.ELF.Segment.FLAGS.X):
            if seg.physical_size == base_seg.physical_size:
                candidates.append(seg)
    if not candidates:
        print(f"[!] no matching LOAD segment in merged ELF for {custom_func_name}")
        return None

    target = candidates[0]
    offset = sym.value - base_seg.virtual_address
    addr   = target.virtual_address + offset
    print(f"[+] Custom function address for {custom_func_name} = 0x{addr:x} "
          f"(seg VA 0x{target.virtual_address:x}, off 0x{offset:x})")
    return addr

def patch_the_function(binary_info, file_path, detected_vuln_funcs, safe_func_path=SAFE_FUNC_PATH):
    patched = False
    for vuln_func in detected_vuln_funcs:
        if vuln_func not in VULN_SAFE_MAP:
            print(f"[!] {vuln_func}은 VULN_SAFE_MAP에 없는 함수입니다.")
            continue

        got_addr = get_got_address(binary_info, vuln_func)
        if got_addr is None:
            continue

        custom_name = VULN_SAFE_MAP[vuln_func]['custom_func']
        custom_addr = get_custom_func_addr_by_hook_segment(
            binary_info, safe_func_path, custom_name
        )
        if custom_addr is None:
            continue

        binary_info.patch_address(got_addr, custom_addr)
        print(f"[✓] Patched {vuln_func} → {custom_name} at 0x{got_addr:x} "
              f"with address 0x{custom_addr:x}")
        patched = True

    dst = os.path.join("test_ELF_file/patched", os.path.basename(file_path))
    if patched:
        binary_info.write(dst)
        print(f"\033[96mPatched ELF saved as {dst}\033[0m")
    else:
        print("\n[!] No functions patched.\n")

def combine_segment(orig_file_path):
    try:
        subprocess.run(["./add_segment", orig_file_path], check=True)
        print(f"[+] Combined segment for {orig_file_path} successfully.")
    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to combine segment for {orig_file_path}: {e}")

def find_location_vul_symbol(orig_file_path, found_funcs, safe_func_path=SAFE_FUNC_PATH):
    filename      = os.path.basename(orig_file_path)
    combine_segment(filename)
    combined_path = os.path.join("combined", filename)

    if not os.path.exists(combined_path):
        print(f"[!] Combined file not found: {combined_path}")
        detection_results.append({
            "orig_file": orig_file_path,
            "combined_file": None,
            "dangerous_functions": found_funcs,
            "symbol_name": [],
            "symbol_location": [],
            "dynamic_only": [],
            "total_num": 0
        })
        return

    binary_info = lief.parse(combined_path)
    symbol_names    = []
    symbol_location = []
    dynamic_only    = []
    count = 0

    print(f"Checking Symbols in {combined_path}...")

    for reloc in binary_info.pltgot_relocations:
        if reloc.has_symbol and reloc.symbol.name in VULN_SAFE_MAP:
            symbol_names.append(reloc.symbol.name)
            symbol_location.append(f"0x{reloc.address:x}")
            print(f"\033[91mGOT entry for [ {reloc.symbol.name} ]: 0x{reloc.address:x} \033[0m")
            count += 1

    for sym in binary_info.dynamic_symbols:
        if sym.name in VULN_SAFE_MAP and sym.name not in symbol_names:
            dynamic_only.append(sym.name)
            print(f"\033[93mDynamic symbol [ {sym.name} ] found (not in GOT)\033[0m")
            count += 1

    if count > 0:
        print(f"\nTotal {count} vulnerable functions detected.\nCalling the patch function...\n")
        patch_the_function(binary_info, combined_path, found_funcs, safe_func_path)
    else:
        print("No Vulnerable Symbol Detected.")

    print("="*90 + "\n")
    detection_results.append({
        "orig_file": orig_file_path,
        "combined_file": combined_path,
        "dangerous_functions": found_funcs,
        "symbol_name": symbol_names,
        "symbol_location": symbol_location,
        "dynamic_only": dynamic_only,
        "total_num": count
    })

def check_vulnerable_strings(file_path, safe_func_path=SAFE_FUNC_PATH):
    found_funcs = []
    with result_lock:
        output = subprocess.check_output(["strings", file_path], text=True)

        for func in VULN_SAFE_MAP:
            if func in output:
                found_funcs.append(func)

        print(f"\n▼ {len(found_funcs)} vulnerable commands found in ['\033[92m strings {file_path} \033[0m'] ▼")
        if found_funcs:
            print(f"\033[91m[ Warning ]: strings found < {', '.join(found_funcs)} >\033[0m\n")
            find_location_vul_symbol(file_path, found_funcs, safe_func_path)
        else:
            print("\033[92m[ It's safe as far as I checked :) ]\033[0m")

def get_elf_files(directory):
    file_names = []
    for fname in os.listdir(directory):
        full = os.path.join(directory, fname)
        if os.path.isfile(full):
            try:
                out = subprocess.check_output(["file", full], text=True)
                if "ELF" in out:
                    file_names.append(full)
            except subprocess.CalledProcessError:
                continue
    return file_names

# === Main ===
detection_results = []
result_lock = threading.Lock()
default_dir = "test_ELF_file/"
target_files = get_elf_files(default_dir)
threads = []

for path in target_files:
    t = threading.Thread(target=check_vulnerable_strings, args=(path,))
    threads.append(t)
    t.start()

for t in threads:
    t.join()

#!/usr/bin/env python3
import subprocess
import os
import lief
import shutil
import stat
from vuln_safe_mapping import VULN_SAFE_MAP

SAFE_FUNC_PATH = "safe_func.so"
DEST_PATH = "test_ELF_file/patched/"

def get_got_address(binary, func_name):
    for reloc in binary.pltgot_relocations:
        if reloc.has_symbol and reloc.symbol.name == func_name:
            print(f"[+] Found {reloc.symbol.name} at GOT 0x{reloc.address:x}")
            return reloc.address
    return None

def add_safe_segments_and_build_map(binary_info, safe):
    """
    safe의 모든 LOAD 세그먼트를 binary_info에 추가하고,
    원본 세그먼트의 virtual_address -> 추가된 segment (lief segment object) 맵을 반환.
    """
    seg_map = {}
    for seg in safe.segments:
        if seg.type == lief.ELF.Segment.TYPE.LOAD:
            added = binary_info.add(seg)
            seg_map[seg.virtual_address] = added
            print(f"[+] Added safe LOAD seg: orig_base=0x{seg.virtual_address:x} "
                  f"=> added_base=0x{added.virtual_address:x} "
                  f"(vsize=0x{seg.virtual_size:x}, flags=0x{int(seg.flags):x})")
    return seg_map

def patch_binary(binary_info, file_path, vuln_funcs):
    """safe의 모든 LOAD 세그먼트를 추가한 뒤, 심볼 소속 세그먼트를 찾아 정확한 주소로 patch_pltgot 호출"""
    patch_count = 0
    file_name = os.path.basename(file_path)
    patched_path = os.path.join(DEST_PATH, file_name)
    os.makedirs(DEST_PATH, exist_ok=True)
    print(f"======={patched_path}======")

    # parse safe
    safe = lief.parse(SAFE_FUNC_PATH)
    if safe is None:
        print(f"[!] Cannot parse {SAFE_FUNC_PATH}")
        return 0

    # add all LOAD segments and keep map
    seg_map = add_safe_segments_and_build_map(binary_info, safe)

    for vuln_func in vuln_funcs:
        if vuln_func not in VULN_SAFE_MAP:
            continue

        custom_name = VULN_SAFE_MAP[vuln_func]['custom_func']
        sym = safe.get_symbol(custom_name)
        print(f"sym is : {sym}")
        if sym is None:
            print(f"[!] {custom_name} not found in {SAFE_FUNC_PATH}")
            continue

        # find the source LOAD seg that contains this symbol in safe
        src_seg = None
        for seg in safe.segments:
            if seg.type == lief.ELF.Segment.TYPE.LOAD:
                va = seg.virtual_address
                end = va + (seg.virtual_size if seg.virtual_size else seg.physical_size)
                if va <= sym.value < end:
                    src_seg = seg
                    break

        if src_seg is None:
            print(f"[!] No LOAD segment contains {custom_name} (sym@0x{sym.value:x})")
            continue

        added_seg = seg_map.get(src_seg.virtual_address)
        if added_seg is None:
            print(f"[!] Added segment not found for src base 0x{src_seg.virtual_address:x}")
            continue

        offset_in_seg = sym.value - src_seg.virtual_address
        custom_addr = added_seg.virtual_address + offset_in_seg

        # sanity checks before patching
        print(f"[DEBUG] Will patch {vuln_func} -> {custom_name} at 0x{custom_addr:x} "
              f"(src_base=0x{src_seg.virtual_address:x}, added_base=0x{added_seg.virtual_address:x}, offset=0x{offset_in_seg:x})")

        try:
            binary_info.patch_pltgot(vuln_func, custom_addr)
            print(f"[✓] Patched {vuln_func} → {custom_name} (0x{custom_addr:x})")
            patch_count += 1
        except Exception as e:
            print(f"[!] Failed to patch {vuln_func}: {e}")
            continue

    if patch_count > 0:
        binary_info.write(patched_path)
        print(f"[✓] Patched ELF saved as {patched_path} ({patch_count} functions patched)")
    else:
        print(f"[!] No functions were patched for {file_name}")

    return patch_count

def process_elf_file(file_path):
    filename = os.path.basename(file_path)

    # 1) strings로 취약함수 존재 확인
    try:
        output = subprocess.check_output(["strings", file_path], text=True)
        found_funcs = [func for func in VULN_SAFE_MAP if func in output]
        if not found_funcs:
            print(f"[+] No vulnerable functions found in {filename}")
            return
        print(f"[!] Found vulnerable functions in {filename}: {', '.join(found_funcs)}")
    except subprocess.CalledProcessError as e:
        print(f"[!] Error running strings on {file_path}: {e}")
        return

    # 2) parse the binary (original, not combined)
    binary_info = lief.parse(file_path)
    if binary_info is None:
        print(f"[!] Cannot parse {file_path}")
        return

    # 3) GOT에서 실제로 존재하는 취약함수 수집
    got_funcs = []
    for reloc in binary_info.pltgot_relocations:
        if reloc.has_symbol and reloc.symbol.name in found_funcs:
            got_funcs.append(reloc.symbol.name)

    if not got_funcs:
        print(f"[!] No vulnerable functions found in GOT for {filename}")
        return

    print(f"[+] Found {len(got_funcs)} vulnerable functions in GOT: {', '.join(got_funcs)}")

    # 4) patch
    patch_count = patch_binary(binary_info, file_path, got_funcs)
    if patch_count <= 0:
        print(f"[!] No functions were successfully patched for {filename}")

def get_elf_files(directory):
    elf_files = []
    if not os.path.exists(directory):
        print(f"[!] Directory not found: {directory}")
        return elf_files
    for fname in os.listdir(directory):
        full_path = os.path.join(directory, fname)
        if os.path.isfile(full_path):
            try:
                output = subprocess.check_output(["file", full_path], text=True)
                if "ELF" in output:
                    elf_files.append(full_path)
            except subprocess.CalledProcessError:
                continue
    return elf_files

def main():
    target_dir = "test_ELF_file/"
    print("=== ELF Binary Vulnerability Patcher ===")
    print(f"Scanning directory: {target_dir}")
    elf_files = get_elf_files(target_dir)
    if not elf_files:
        print(f"[!] No ELF files found in {target_dir}")
        return
    print(f"[+] Found {len(elf_files)} ELF files")
    for i, file_path in enumerate(elf_files, 1):
        print(f"\n{'='*60}")
        print(f"[{i}/{len(elf_files)}] Processing: {os.path.basename(file_path)}")
        print(f"{'='*60}")
        process_elf_file(file_path)
    print(f"\n{'='*60}")
    print("[+] All files processed (attempted).")
    print(f"{'='*60}")

if __name__ == "__main__":
    main()

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

def get_custom_func_address(binary_info, safe_func_path, custom_func_name):
    try:
        hook = lief.parse(safe_func_path)
        if hook is None:
            print(f"[!] Cannot parse {safe_func_path}")
            return None
            
        sym = hook.get_symbol(custom_func_name)
        if sym is None:
            print(f"[!] {custom_func_name} not found in {safe_func_path}")
            return None
        
        hook_text_base = None
        for seg in hook.segments:
            if seg.type == lief.ELF.Segment.TYPE.LOAD and seg.flags & lief.ELF.Segment.FLAGS.X:
                hook_text_base = seg.virtual_address
                break
                
        if hook_text_base is None:
            print(f"[!] No executable segment found in {safe_func_path}")
            return None
        
        func_offset = sym.value - hook_text_base
        
        target_segment = None
        for seg in binary_info.segments:
            if (seg.type == lief.ELF.Segment.TYPE.LOAD and 
                seg.flags & lief.ELF.Segment.FLAGS.X and
                seg.virtual_address >= 0x405000): 
                target_segment = seg
                break
        
        if target_segment is None:
            print(f"[!] No added executable segment found in merged ELF")
            return None
        
        final_address = target_segment.virtual_address + func_offset
        print(f"[+] {custom_func_name} mapped to 0x{final_address:x} (offset: 0x{func_offset:x})")
        
        return final_address
        
    except Exception as e:
        print(f"[!] Error calculating custom function address: {e}")
        return None

def patch_binary(binary_info, file_path, vuln_funcs):
    patch_count = 0
    path_tmp = file_path.split("/") 
    file_name = path_tmp[-1]

    patched_dir = os.path.join(DEST_PATH,file_name)
    print(f"======={patched_dir}======")
    for vuln_func in vuln_funcs:
        if vuln_func not in VULN_SAFE_MAP:
            continue
        
        got_addr = get_got_address(binary_info, vuln_func)
        if got_addr is None:
            continue
        
        custom_name = VULN_SAFE_MAP[vuln_func]['custom_func']
        
        custom_addr = get_custom_func_address(binary_info, SAFE_FUNC_PATH, custom_name)
        if custom_addr is None:
            continue
        
        try:
            binary_info.patch_pltgot(vuln_func, custom_addr)
            print(f"[✓] Successfully patched {vuln_func} → {custom_name}")
            patch_count += 1
            binary_info.write(patched_dir)
            print(f"[✓] Patched ELF saved as {patched_dir} ({patch_count} functions patched)")

        except Exception as e:
            print(f"[!] Failed to patch {vuln_func}: {e}")
            continue
    
    return patch_count

def combine_segment_safe(orig_file_path):
    filename = os.path.basename(orig_file_path)
    
    current_dir = os.getcwd()
    add_segment_path = os.path.join(current_dir, "add_segment")
    
    if not os.path.exists(add_segment_path):
        print(f"[!] add_segment not found at {add_segment_path}")
        return False
    
    try:
        result = subprocess.run(
            [add_segment_path, filename],
            cwd=current_dir,
            capture_output=True,
            text=True,
            check=True
        )
        
        print(f"[+] Successfully combined segment for {filename}")
        if result.stdout:
            print(f"[DEBUG] stdout: {result.stdout.strip()}")
            
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to combine segment for {filename}")
        print(f"[!] Error: {e}")
        if e.stdout:
            print(f"[!] stdout: {e.stdout}")
        if e.stderr:
            print(f"[!] stderr: {e.stderr}")
        return False

def process_elf_file(file_path):
    filename = os.path.basename(file_path)
    
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
    
    if not combine_segment_safe(file_path):
        return
    
    combined_path = os.path.join("combined", filename)
    if not os.path.exists(combined_path):
        print(f"[!] Combined file not found: {combined_path}")
        return
    
    try:
        print(f"opening the {combined_path}")
        binary_info = lief.parse(combined_path)
        if binary_info is None:
            print(f"[!] Cannot parse combined binary: {combined_path}")
            return
        
        got_funcs = []
        for reloc in binary_info.pltgot_relocations:
            if reloc.has_symbol and reloc.symbol.name in found_funcs:
                got_funcs.append(reloc.symbol.name)
        
        if not got_funcs:
            print(f"[!] No vulnerable functions found in GOT for {filename}")
            return
        
        print(f"[+] Found {len(got_funcs)} vulnerable functions in GOT")
        
        patch_count = patch_binary(binary_info, combined_path, got_funcs)
        
        if patch_count <= 0:
            print(f"[!] No functions were successfully patched for {filename}")
            
    except Exception as e:
        print(f"[!] Error processing binary {combined_path}: {e}")

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
    print("[+] All files processed successfully!")
    print(f"{'='*60}")

if __name__ == "__main__":
    main()
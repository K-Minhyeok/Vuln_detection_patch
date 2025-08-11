import subprocess
import os
import lief
import shutil
import stat
from vuln_safe_mapping import VULN_SAFE_MAP

SAFE_FUNC_PATH = "safe_func.so"

def get_got_address(binary, func_name):
    """GOT 주소 찾기"""
    for reloc in binary.pltgot_relocations:
        if reloc.has_symbol and reloc.symbol.name == func_name:
            print(f"[+] Found {reloc.symbol.name} at GOT 0x{reloc.address:x}")
            return reloc.address
    return None

def get_custom_func_address(binary_info, safe_func_path, custom_func_name):
    """커스텀 함수 주소 계산 - 개선된 버전"""
    try:
        # safe_func.so 파싱
        hook = lief.parse(safe_func_path)
        if hook is None:
            print(f"[!] Cannot parse {safe_func_path}")
            return None
            
        # 커스텀 함수 심볼 찾기
        sym = hook.get_symbol(custom_func_name)
        if sym is None:
            print(f"[!] {custom_func_name} not found in {safe_func_path}")
            return None
        
        # safe_func.so의 첫 번째 LOAD 세그먼트 (텍스트 세그먼트)
        hook_text_base = None
        for seg in hook.segments:
            if seg.type == lief.ELF.Segment.TYPE.LOAD and seg.flags & lief.ELF.Segment.FLAGS.X:
                hook_text_base = seg.virtual_address
                break
                
        if hook_text_base is None:
            print(f"[!] No executable segment found in {safe_func_path}")
            return None
        
        # 함수 오프셋 계산
        func_offset = sym.value - hook_text_base
        
        # 병합된 ELF에서 추가된 실행 세그먼트 찾기 (0x405000)
        target_segment = None
        for seg in binary_info.segments:
            if (seg.type == lief.ELF.Segment.TYPE.LOAD and 
                seg.flags & lief.ELF.Segment.FLAGS.X and
                seg.virtual_address >= 0x405000):  # 추가된 세그먼트
                target_segment = seg
                break
        
        if target_segment is None:
            print(f"[!] No added executable segment found in merged ELF")
            return None
        
        # 최종 주소 계산
        final_address = target_segment.virtual_address + func_offset
        print(f"[+] {custom_func_name} mapped to 0x{final_address:x} (offset: 0x{func_offset:x})")
        
        return final_address
        
    except Exception as e:
        print(f"[!] Error calculating custom function address: {e}")
        return None

def patch_binary(binary_info, file_path, vuln_funcs):
    """바이너리 패치 - LIEF 내장 기능 사용"""
    patch_count = 0
    
    for vuln_func in vuln_funcs:
        if vuln_func not in VULN_SAFE_MAP:
            continue
        
        # GOT 주소 찾기
        got_addr = get_got_address(binary_info, vuln_func)
        if got_addr is None:
            continue
        
        # 커스텀 함수 이름 처리
        custom_name = VULN_SAFE_MAP[vuln_func]['custom_func']
        
        # 커스텀 함수 주소 계산
        custom_addr = get_custom_func_address(binary_info, SAFE_FUNC_PATH, custom_name)
        if custom_addr is None:
            continue
        
        try:
            # LIEF의 patch_address 사용
            binary_info.patch_address(got_addr, custom_addr)
            print(f"[✓] Successfully patched {vuln_func} → {custom_name}")
            patch_count += 1
            
        except Exception as e:
            print(f"[!] Failed to patch {vuln_func}: {e}")
            continue
    
    return patch_count

def combine_segment_safe(orig_file_path):
    """세그먼트 결합 - 안전한 방식"""
    filename = os.path.basename(orig_file_path)
    
    # 현재 디렉토리 확인
    current_dir = os.getcwd()
    add_segment_path = os.path.join(current_dir, "add_segment")
    
    if not os.path.exists(add_segment_path):
        print(f"[!] add_segment not found at {add_segment_path}")
        return False
    
    try:
        # 안전한 subprocess 실행
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
    """ELF 파일 처리 메인 함수"""
    filename = os.path.basename(file_path)
    
    # 1. 취약 함수 탐지
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
    
    # 2. 세그먼트 결합
    if not combine_segment_safe(file_path):
        return
    
    # 3. 결합된 파일 확인
    combined_path = os.path.join("combined", filename)
    if not os.path.exists(combined_path):
        print(f"[!] Combined file not found: {combined_path}")
        return
    
    # 4. 바이너리 파싱 및 패치
    try:
        binary_info = lief.parse(combined_path)
        if binary_info is None:
            print(f"[!] Cannot parse combined binary: {combined_path}")
            return
        
        # GOT에서 취약 함수 확인
        got_funcs = []
        for reloc in binary_info.pltgot_relocations:
            if reloc.has_symbol and reloc.symbol.name in found_funcs:
                got_funcs.append(reloc.symbol.name)
        
        if not got_funcs:
            print(f"[!] No vulnerable functions found in GOT for {filename}")
            return
        
        print(f"[+] Found {len(got_funcs)} vulnerable functions in GOT")
        
        # 패치 수행
        patch_count = patch_binary(binary_info, combined_path, got_funcs)
        
        if patch_count > 0:
            # 패치된 파일 저장
            patched_dir = "test_ELF_file/patched"
            os.makedirs(patched_dir, exist_ok=True)
            
            dst_path = os.path.join(patched_dir, filename)
            binary_info.write(dst_path)
            
            # 실행 권한 설정
            os.chmod(dst_path, os.stat(dst_path).st_mode | stat.S_IEXEC)
            
            print(f"[✓] Patched ELF saved as {dst_path} ({patch_count} functions patched)")
        else:
            print(f"[!] No functions were successfully patched for {filename}")
            
    except Exception as e:
        print(f"[!] Error processing binary {combined_path}: {e}")

def get_elf_files(directory):
    """디렉토리에서 ELF 파일 찾기"""
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
    """메인 함수"""
    target_dir = "test_ELF_file/"
    
    print("=== ELF Binary Vulnerability Patcher ===")
    print(f"Scanning directory: {target_dir}")
    
    # ELF 파일들 찾기
    elf_files = get_elf_files(target_dir)
    
    if not elf_files:
        print(f"[!] No ELF files found in {target_dir}")
        return
    
    print(f"[+] Found {len(elf_files)} ELF files")
    
    # 각 파일 처리
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

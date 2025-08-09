import lief
from vuln_safe_mapping import VULN_SAFE_MAP

# 1. 대상 바이너리와 “안전 함수” ELF 경로
TARGET_BIN = "test_ELF_file/b_test"
HOOK_SO    = "safe_func"

# 2. ELF 파싱
binary = lief.parse(TARGET_BIN)
hook   = lief.parse(HOOK_SO)

# 3. 훅 세그먼트 삽입
segment_added = binary.add(hook.segments[0])
base_addr     = segment_added.virtual_address
print(f"[+] Hook segment injected at 0x{base_addr:x}")

# 4. VULN_SAFE_MAP 구조 검증
for vuln_name, info in VULN_SAFE_MAP.items():
    if not isinstance(info, dict):
        raise TypeError(f"VULN_SAFE_MAP['{vuln_name}'] must be a dict")

# 5. 취약 함수마다 RELA 엔트리 추가 및 GOT/PLT 패치
for vuln_name, info in VULN_SAFE_MAP.items():
    safe_name = info["safe_func"]
    print(f"[>] Preparing hook for {vuln_name} → {safe_name}")

    # 5-1. 동적 심볼 조회
    symbol = binary.get_dynamic_symbol(vuln_name)
    if symbol is None:
        print(f"    [!] 동적 심볼에 없음: {vuln_name}, 건너뜀")
        continue

    # 5-2. RELA 레코드 생성 (JUMP_SLOT)
    rela = lief.ELF.Relocation()
    rela.address = 0
    rela.addend  = 0
    # X86_64 Jump Slot 타입 상수 사용
    rela.type    = lief.ELF.X86_JUMP_SLOT
    rela.symbol  = symbol
    binary.add_dynamic_relocation(rela)

    # 5-3. 안전 함수 심볼 조회 및 훅 주소 계산
    hook_sym = hook.get_symbol(safe_name)
    if hook_sym is None:
        print(f"    [!] 안전 함수 심볼 없음: {safe_name}, 건너뜀")
        continue

    hook_addr = base_addr + hook_sym.value
    print(f"    Patching `{vuln_name}` GOT → `{safe_name}` @ 0x{hook_addr:x}")

    # 5-4. GOT/PLT 엔트리 패치
    try:
        binary.patch_pltgot(vuln_name, hook_addr)
    except lief.exception as e:
        print(f"    [!] GOT 패치 실패 {vuln_name}: {e}")

# 6. 수정된 바이너리 저장
out_path = TARGET_BIN + ".hooked"
binary.write(out_path)
print(f"[+] Patched binary saved as `{out_path}`")

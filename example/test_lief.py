import lief
from vuln_safe_mapping import VULN_SAFE_MAP

def get_plt_address(binary, func_name):
    for f in binary.pltgot_relocations:
        if f.has_symbol and f.symbol.name == func_name:
            return f.address
    return None

binary_info = lief.parse("test_ELF_file/test_gets_w_fgets")
# Mapping Vuln functions with Safe Functions
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
        else:
            print(f"[ {vuln_func} ] is symboled, but not in Vuln functions.\n")


binary_info.write("test_ELF_file/b_test_patched")
print("\033[96mPatched ELF saved as b_test_patched\033[0m")
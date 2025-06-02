import lief

binary_info = lief.parse("test_ELF_file/a")
with open("vuln_functions", "r") as f:
    dangerous_funcs = [line.strip() for line in f]

for reloc in binary_info.pltgot_relocations:
            if reloc.has_symbol:
                if reloc.symbol.name in dangerous_funcs:
                    print(f"\033[91mGOT entry for [ {reloc.symbol.name} ]: 0x{reloc.address:x} \033[0m")

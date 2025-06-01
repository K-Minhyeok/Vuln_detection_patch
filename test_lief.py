import lief

binary = lief.parse("test_ELF_file/a")

for reloc in binary.pltgot_relocations:
    if reloc.has_symbol:
        print(reloc)
        if reloc.symbol.name == "gets":
            print(f"[+] GOT entry for gets: 0x{reloc.address:x}")

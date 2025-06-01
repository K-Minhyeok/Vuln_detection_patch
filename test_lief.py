import lief

binary = lief.parse("test_ELF_file/a")
print(type(binary))
print(binary.pltgot_relocations)
import lief

crackme = lief.parse("test_ELF_file/mul2")
safe = lief.parse("safe_func.so")

segment_added = crackme.add(safe.segments[0])

my_strcpy = safe.get_symbol("my_strcpy")
my_strcpy_addr = segment_added.virtual_address + my_strcpy.value

print(my_strcpy)
print(my_strcpy_addr)

crackme.patch_pltgot('strcpy',my_strcpy_addr)
crackme.write("already_hooked")
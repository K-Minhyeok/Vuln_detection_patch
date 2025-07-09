from pwn import *

elf = ELF("./my_application")
checksec(elf.path)
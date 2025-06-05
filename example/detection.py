import subprocess
import sys
import json

default_dir_path = "test_ELF_file/"
file_name = ""

with open("vuln_functions", "r") as f:
    dangerous_funcs = [line.strip() for line in f]

#print(dangerous_funcs)


file_name +="b"
default_dir_path += file_name

output = subprocess.check_output(["strings",default_dir_path],text=True)

found_funcs = []

for func in dangerous_funcs:
    if func in output:
        found_funcs.append(func)

print(f"Result of ELF file [ {default_dir_path} ] Inspection \n")

if found_funcs:
    print(" [ Warning ] :", ", ".join(found_funcs))
else:
    print(" [ It's safe as far as i checked :) ]")
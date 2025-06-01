
import subprocess
import sys
import json
import os
import threading

def check_has_vulnerable_command(file_path):
    found_funcs = []
    output = subprocess.check_output(["strings",file_path],text=True)

    for func in dangerous_funcs:
        if func in output:
            found_funcs.append(func)

    print(f"▼ There are {len(found_funcs)} vulnerable_command in [ {file_path} ] ▼")
    if found_funcs:
        print(" [ Warning ] :", ", ".join(found_funcs))
    else:
        print(" [ It's safe as far as i checked  :) ]")

    print('------------------------------------\n')


def get_elf_files(directory):
    file_name = []

    for fname in os.listdir(directory):
        full_path = os.path.join(directory, fname)

        if os.path.isfile(full_path):
            try:
                output = subprocess.check_output(["file", full_path], text=True)

                if "ELF" in output:
                    result = directory+fname
                    file_name.append(result)

            except subprocess.CalledProcessError:
                continue  

    return file_name

with open("vuln_functions", "r") as f:
    dangerous_funcs = [line.strip() for line in f]


default_dir_path = "test_ELF_file/"
target_files = get_elf_files(default_dir_path)
threads = []

#print(target_files)

for i in target_files:
    print(i)
    t = threading.Thread(target=check_has_vulnerable_command, args=(i,))
    threads.append(t)
    t.start()


for t in threads:
    t.join()
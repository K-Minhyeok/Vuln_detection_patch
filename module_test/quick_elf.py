import subprocess

base_path = "test_ELF_file/"
file_name = base_path+"test_gets_w_fgets"

def run_command(cmd_list, description):
    print(f"\n=== {description} ===")
    try:
        result = subprocess.run(cmd_list, check=True, text=True, capture_output=True)
        print(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"[!] Error while executing {description}")
        print(e.stderr)

run_command(["readelf", "-r", file_name], "Relocation entries (readelf -r)")
run_command(["objdump", "-R", file_name], "Dynamic relocation records (objdump -R)")

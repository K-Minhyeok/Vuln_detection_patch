VULN_SAFE_MAP = {
    "gets": "fgets",
    "strcpy": "strncpy",
    "sprintf": "snprintf",
    "scanf": "fscanf",
    "__isoc99_scanf": "fscanf",
    "scanf_chk": "fscanf",
    "IO_vfscanf": "fscanf",
    "system": "execve",  
    "strcat": "strncat",
    "printf": "snprintf"  
}

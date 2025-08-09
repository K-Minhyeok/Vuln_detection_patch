VULN_SAFE_MAP = {
    "gets": {
        "safe_func": "fgets",
        "risk_level": "Critical",
        "custom_func": "my_gets"
    },
    "strcpy": {
        "safe_func": "strncpy",
        "risk_level": "High",
        "custom_func": "my_strcpy"
    },
    "sprintf": {
        "safe_func": "snprintf",
        "risk_level": "Medium",
        "custom_func": "my_sprintf"
    },
    "scanf": {
        "safe_func": "fscanf",
        "risk_level": "Medium",
        "custom_func": "my_scanf"
    },
    "system": {
        "safe_func": "execve",
        "risk_level": "Critical",
        "custom_func": "my_system"
    },
    "strcat": {
        "safe_func": "strncat",
        "risk_level": "High",
        "custom_func": "my_strcat"
    },
    "printf": {
        "safe_func": "snprintf",
        "risk_level": "Low",
        "custom_func": "my_printf"
    },
    "memcpy": {
        "safe_func": "memmove",
        "risk_level": "High",
        "custom_func": "my_memcpy"
    },
    "getwd": {
        "safe_func": "getcwd",
        "risk_level": "High",
        "custom_func": "my_getwd"
    },
}

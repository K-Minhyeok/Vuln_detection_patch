VULN_SAFE_MAP = {
    "gets": {
        "safe_func": "fgets",
        "risk_level": "Critical"
    },
    "strcpy": {
        "safe_func": "strncpy",
        "risk_level": "High"
    },
    "sprintf": {
        "safe_func": "snprintf",
        "risk_level": "Medium"
    },
    "scanf": {
        "safe_func": "fscanf",
        "risk_level": "Medium"
    },
    "__isoc99_scanf": {
        "safe_func": "fscanf",
        "risk_level": "Medium"
    },
    "scanf_chk": {
        "safe_func": "fscanf",
        "risk_level": "Medium"
    },
    "IO_vfscanf": {
        "safe_func": "fscanf",
        "risk_level": "Medium"
    },
    "system": {
        "safe_func": "execve",
        "risk_level": "Critical"
    },
    "strcat": {
        "safe_func": "strncat",
        "risk_level": "High"
    },
    "printf": {
        "safe_func": "snprintf",
        "risk_level": "Low"
    },
    "memcpy": {
        "safe_func": "memmove",
        "risk_level": "High"
    },
    "mktemp": {
        "safe_func": "mkstemp",
        "risk_level": "Critical"
    },
    "tempnam": {
        "safe_func": "mkstemp",
        "risk_level": "Critical"
    },
    "popen": {
        "safe_func": "execve",
        "risk_level": "Critical"
    },
    "getwd": {
        "safe_func": "getcwd",
        "risk_level": "High"
    },
    "readlink": {
        "safe_func": "readlinkat",
        "risk_level": "High"
    },
    "gcvt": {
        "safe_func": "snprintf",
        "risk_level": "High"
    },
    "ecvt": {
        "safe_func": "snprintf",
        "risk_level": "High"
    },
    "fcvt": {
        "safe_func": "snprintf",
        "risk_level": "High"
    }
}
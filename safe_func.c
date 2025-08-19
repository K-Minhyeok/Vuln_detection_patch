// 시스템 콜 정의
#define SYS_write 1

static inline long _write(int fd, const void *buf, unsigned long count) {
    long ret;
    __asm__ volatile (
        "syscall"
        : "=a" (ret)
        : "a" (SYS_write), "D" (fd), "S" (buf), "d" (count)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static void hooked_msg(const char *name) {
    _write(2, "hooked ", 7);  // stderr에 출력
    
    int len = 0;
    while (name[len] != '\0') len++;
    
    _write(2, name, len);
    _write(2, "\n", 1);
}

// ------------------- safe wrappers -------------------

char* my_gets(char *s) {
    hooked_msg("my_gets");
    return s;  // 원래 gets는 입력을 받아 s를 반환 → 단순히 포인터 반환
}

char* my_strcpy(char *dest, const char *src) {
    hooked_msg("my_strcpy");
    char *orig_dest = dest;
    while ((*dest++ = *src++));
    return orig_dest;
}

int my_sprintf(char *str, const char *format, ...) {
    hooked_msg("my_sprintf");
    return 0;
}

char* my_strcat(char *dest, const char *src) {
    hooked_msg("my_strcat");
    char *orig_dest = dest;
    while (*dest) dest++;
    while ((*dest++ = *src++));
    return orig_dest;
}

int my_printf(const char *format, ...) {
    hooked_msg("my_printf");
    return 0;
}

void* my_memcpy(void *dest, const void *src, unsigned long n) {
    hooked_msg("my_memcpy");
    char *d = (char*)dest;
    const char *s = (const char*)src;
    while (n--) *d++ = *s++;
    return dest;
}

char* my_getwd(char *buf) {
    hooked_msg("my_getwd");
    return buf;
}

int my_scanf_wrapper(const char *format, ...) {
    hooked_msg("my_scanf");
    return 0;
}

int my_system(const char *command) {
    hooked_msg("my_system");
    const char msg[] = "[SECURITY] system() call blocked\n";
    _write(2, msg, sizeof(msg) - 1);
    return -1;
}

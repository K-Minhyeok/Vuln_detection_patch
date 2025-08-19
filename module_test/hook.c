#define SYS_write 1
#define stdout 1

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

int my_memcmp(const void* lhs, const void* rhs, int n) {
    const char msg[] = "Hook memcmp\n";
    _write(stdout, msg, sizeof(msg) - 1);
    _write(stdout, (const char*)lhs, n);
    _write(stdout, "\n", 1);
    _write(stdout, (const char*)rhs, n);
    _write(stdout, "\n", 1);
    return 0;
}

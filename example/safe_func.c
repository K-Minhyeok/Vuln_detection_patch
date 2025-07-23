#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/wait.h>

int main() {
    char buf[100];
    fgets(buf, sizeof(buf), stdin);

    char src[] = "Hello, World!";
    char dest[20];
    strncpy(dest, src, sizeof(dest) - 1);
    dest[sizeof(dest) - 1] = '\0';

    char snbuf[50];
    int n = 42;
    snprintf(snbuf, sizeof(snbuf), "%d", n);

    FILE *fp = fopen("input.txt", "r");
    int x = 0;
    if (fp) {
        fscanf(fp, "%d", &x);
        fclose(fp);
    }

    char *argv[] = {"/bin/echo", "execve example", NULL};
    if (fork() == 0) {
        execve("/bin/echo", argv, NULL);
        exit(1);
    } else {
        wait(NULL);
    }

    char catdest[20] = "Hello";
    char catsrc[] = " World";
    strncat(catdest, catsrc, sizeof(catdest) - strlen(catdest) - 1);

    char membuf[20] = "abcdef";
    memmove(membuf + 2, membuf, 4);
    membuf[6] = '\0';

    char cwd[256];
    getcwd(cwd, sizeof(cwd));

    return 0;
}

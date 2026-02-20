#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(void) {
    setuid(0);
    setgid(0);
    FILE *f = fopen("/root/flag.txt", "r");
    if (!f) {
        fprintf(stderr, "permission denied\n");
        return 1;
    }
    char buf[512];
    while (fgets(buf, sizeof(buf), f))
        fputs(buf, stdout);
    fclose(f);
    return 0;
}

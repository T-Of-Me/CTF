#define _GNU_SOURCE
#include <dlfcn.h>
#include <string.h>
#include <fcntl.h>
#include <stdarg.h>

// Fake open() - make /proc/version and /proc/self/status fail (returns -1 = clean)
int open(const char *pathname, int flags, ...) {
    if (pathname && (strstr(pathname, "/proc/version") || strstr(pathname, "/proc/self/status")))
        return -1;
    int (*real_open)(const char*, int, ...) = dlsym(RTLD_NEXT, "open");
    if (!real_open) return -1;
    va_list ap;
    va_start(ap, flags);
    int mode = va_arg(ap, int);
    va_end(ap);
    return real_open(pathname, flags, mode);
}

// Fake ptrace - always return 0 (no debugger)
long ptrace(int request, ...) {
    return 0;
}

// Fake strstr to block Microsoft/WSL detection
char *strstr(const char *haystack, const char *needle) {
    if (needle && (strcmp(needle, "Microsoft") == 0 ||
                   strcmp(needle, "microsoft") == 0 ||
                   strcmp(needle, "WSL") == 0))
        return NULL;
    char *(*real_strstr)(const char*, const char*) = dlsym(RTLD_NEXT, "strstr");
    if (!real_strstr) return NULL;
    return real_strstr(haystack, needle);
}

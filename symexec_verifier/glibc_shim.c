#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <math.h>

#undef strtol
#undef strtoul
#undef strtoll
#undef strtoull

extern long __strtol_internal(const char *, char **, int, int);
extern unsigned long __strtoul_internal(const char *, char **, int, int);
extern long long __strtoll_internal(const char *, char **, int, int);
extern unsigned long long __strtoull_internal(const char *, char **, int, int);

long __isoc23_strtol(const char *nptr, char **endptr, int base) { return __strtol_internal(nptr, endptr, base, 0); }
unsigned long __isoc23_strtoul(const char *nptr, char **endptr, int base) { return __strtoul_internal(nptr, endptr, base, 0); }
long long __isoc23_strtoll(const char *nptr, char **endptr, int base) { return __strtoll_internal(nptr, endptr, base, 0); }
unsigned long long __isoc23_strtoull(const char *nptr, char **endptr, int base) { return __strtoull_internal(nptr, endptr, base, 0); }
int __isoc23_sscanf(const char *str, const char *format, ...) {
    va_list ap; va_start(ap, format); int r = vsscanf(str, format, ap); va_end(ap); return r;
}
int __isoc23_fscanf(FILE *stream, const char *format, ...) {
    va_list ap; va_start(ap, format); int r = vfscanf(stream, format, ap); va_end(ap); return r;
}
double __shim_fmod(double x, double y) { return fmod(x, y); }
void _ZSt21ios_base_library_initv(void) {}
void __cxa_call_terminate(void *ue_header) { abort(); }

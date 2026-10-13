/*
 * Minimal libc stubs for bare-metal RISC-V
 * 
 * These provide basic string and I/O functions without the full C library
 * to save code size.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>

// Forward declarations of bare-metal print functions
extern int kprintf(const char *format, ...);
extern void vkprintf(const char *format, va_list vl);

// ============================================
// Memory Functions
// ============================================

void *memcpy(void *dest, const void *src, size_t n) {
    uint8_t *d = (uint8_t *)dest;
    const uint8_t *s = (const uint8_t *)src;
    
    while (n--) {
        *d++ = *s++;
    }
    
    return dest;
}

void *memset(void *s, int c, size_t n) {
    uint8_t *p = (uint8_t *)s;
    
    while (n--) {
        *p++ = (uint8_t)c;
    }
    
    return s;
}

size_t strlen(const char *s) {
    size_t len = 0;
    
    while (*s++) {
        len++;
    }
    
    return len;
}

char *strncpy(char *dest, const char *src, size_t n) {
    size_t i;
    
    for (i = 0; i < n && src[i] != '\0'; i++) {
        dest[i] = src[i];
    }
    
    // Pad with null bytes if needed
    for (; i < n; i++) {
        dest[i] = '\0';
    }
    
    return dest;
}

int memcmp(const void *s1, const void *s2, size_t n) {
    const uint8_t *p1 = (const uint8_t *)s1;
    const uint8_t *p2 = (const uint8_t *)s2;
    
    while (n--) {
        if (*p1 != *p2) {
            return *p1 - *p2;
        }
        p1++;
        p2++;
    }
    
    return 0;
}

void *memmove(void *dest, const void *src, size_t n) {
    uint8_t *d = (uint8_t *)dest;
    const uint8_t *s = (const uint8_t *)src;
    
    if (d < s) {
        // Copy forward
        while (n--) {
            *d++ = *s++;
        }
    } else {
        // Copy backward
        d += n;
        s += n;
        while (n--) {
            *--d = *--s;
        }
    }
    
    return dest;
}

// ============================================
// I/O Functions (stub implementations)
// ============================================

int printf(const char *format, ...) {
    va_list args;
    va_start(args, format);
    vkprintf(format, args);
    va_end(args);
    return 0;
}

// ============================================
// Other commonly needed stubs
// ============================================

void abort(void) {
    while (1) { __asm__ volatile("nop"); }
}

void exit(int status) {
    (void)status;
    while (1) { __asm__ volatile("nop"); }
}

void __assert_func(const char *file, int line, const char *func, const char *expr) {
    (void)file;
    (void)line;
    (void)func;
    (void)expr;
    abort();
}

// For newer GCC
void __stack_chk_fail(void) {
    abort();
}

void *__stack_chk_guard = (void *)0xdeadbeef;

// ============================================
// Memory allocation stubs (not actually implemented)
// ============================================

/* LIFO bump allocator over a static arena. Historically PQClean fips202's
 * incremental SHAKE API malloc'd ~200-byte contexts; ML-KEM here is now
 * malloc-free (kyber_shake256_rkprf rewritten one-shot), so the arena is dead
 * at runtime on the KEM/EDHOC paths. Size is overridable: pass
 * -DHEAP_ARENA_SIZE=<n> to shrink it for malloc-free builds. */
/* 1 kB is enough because the crypto paths are malloc-free: ML-KEM is one-shot
 * (see above) and wolfCrypt runs with WOLFSSL_SP_NO_MALLOC, which keeps SP's
 * temporaries on the stack. Raise it with -DHEAP_ARENA_SIZE=<n> if a future
 * backend allocates. The old 16 kB default is what pushed the P-256/P-384
 * suites past the 64 kB scratchpad. */
#ifndef HEAP_ARENA_SIZE
#define HEAP_ARENA_SIZE 1024
#endif
static uint8_t  heap_arena[HEAP_ARENA_SIZE] __attribute__((aligned(8)));
static size_t   heap_top = 0;

void *malloc(size_t size) {
    size = (size + 7u) & ~(size_t)7u;          /* 8-byte align */
    if (size + sizeof(size_t) > HEAP_ARENA_SIZE - heap_top)
        return (void *)0;                       /* out of arena */
    size_t *hdr = (size_t *)&heap_arena[heap_top];
    *hdr = size;                                /* size header for free() */
    void *p = &heap_arena[heap_top + sizeof(size_t)];
    heap_top += sizeof(size_t) + size;
    return p;
}

void *calloc(size_t nmemb, size_t size) {
    size_t n = nmemb * size;
    void *p = malloc(n);
    if (p) for (size_t i = 0; i < n; i++) ((uint8_t *)p)[i] = 0;
    return p;
}

void *realloc(void *ptr, size_t size) {
    (void)ptr;
    return malloc(size);
}

void free(void *ptr) {
    /* LIFO reclaim: pop only if ptr is the most-recent allocation. */
    if (ptr != (void *)0) {
        uint8_t *blk = (uint8_t *)ptr - sizeof(size_t);
        if (blk >= heap_arena && blk < heap_arena + HEAP_ARENA_SIZE) {
            size_t sz = *(size_t *)blk;
            if (blk + sizeof(size_t) + sz == &heap_arena[heap_top])
                heap_top = (size_t)(blk - heap_arena);
        }
    }
    // Do nothing - no heap management
}

/* File I/O stubs intentionally removed: wolfSSL is built with NO_FILESYSTEM,
 * and no app code calls fopen/fread/etc. If a future build references one,
 * the linker will fail loudly — better than a silent no-op.
 */

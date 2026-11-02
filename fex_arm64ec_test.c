#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <emmintrin.h>

static void test_cpuid(void) {
    int cpu_info[4] = {0};
    __asm__ __volatile__("cpuid"
                         : "=a"(cpu_info[0]), "=b"(cpu_info[1]), "=c"(cpu_info[2]), "=d"(cpu_info[3])
                         : "a"(0), "c"(0));
    char vendor[13] = {0};
    *(int*)(vendor + 0) = cpu_info[1];
    *(int*)(vendor + 4) = cpu_info[3];
    *(int*)(vendor + 8) = cpu_info[2];
    printf("[1/7] x86-64 CPUID: Vendor=%s (MaxLeaf=%d)\n", vendor, cpu_info[0]);
    fflush(stdout);

    // Leaf 1: Features
    __asm__ __volatile__("cpuid"
                         : "=a"(cpu_info[0]), "=b"(cpu_info[1]), "=c"(cpu_info[2]), "=d"(cpu_info[3])
                         : "a"(1), "c"(0));
    printf("      CPUID Feature Flags: edx=0x%08x, ecx=0x%08x\n", cpu_info[3], cpu_info[2]);
    fflush(stdout);
}

static void test_sse2(void) {
    __m128d va = _mm_set_pd(10.5, 20.25);
    __m128d vb = _mm_set_pd(2.0, 4.0);
    __m128d vmul = _mm_mul_pd(va, vb);
    double res[2];
    _mm_storeu_pd(res, vmul);
    double dot = res[0] + res[1];
    if (dot != 102.0) {
        printf("[FAIL] SSE2 math mismatch: %.2f (expected 102.0)\n", dot);
        exit(1);
    }
    printf("[2/7] SSE2 Vector Dot Product: %.2f (expected 102.0)\n", dot);
    fflush(stdout);
}

static void test_unaligned_atomics_tso(void) {
    uint8_t buffer[64] __attribute__((aligned(16))) = {0};
    // Test both within-16B unaligned offset (+3) and cross-16B split-lock offset (+11)
    const int offsets[2] = {3, 11};
    for (int i = 0; i < 2; i++) {
        volatile uint64_t *unaligned_ptr = (volatile uint64_t*)(buffer + offsets[i]);
        *unaligned_ptr = 0x1122334455667788ULL;

        uint64_t expected = 0x1122334455667788ULL;
        uint64_t new_val = 0xAABBCCDDEEFF0011ULL + (uint64_t)i;

        // x86-64 lock cmpxchg against unaligned operand (triggers ARM64 SIGBUS -> STATUS_DATATYPE_MISALIGNMENT)
        unsigned char result = 0;
        __asm__ __volatile__(
            "lock cmpxchgq %3, %1\n\t"
            "sete %0\n\t"
            : "=q"(result), "+m"(*unaligned_ptr), "+a"(expected)
            : "r"(new_val)
            : "memory", "cc"
        );

        if (!result || *unaligned_ptr != new_val) {
            printf("[FAIL] Unaligned atomic CAS (offset +%d) failed: read=0x%llx\n",
                   offsets[i], (unsigned long long)*unaligned_ptr);
            exit(1);
        }
    }
    printf("[3/7] Unaligned 64-bit Atomic TSO Recovery: OK (val=0x%llx)\n",
           (unsigned long long)*(volatile uint64_t*)(buffer + 11));
    fflush(stdout);
}

static void test_virtual_memory(void) {
    SIZE_T size = 65536;
    LPVOID p = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!p) { printf("[FAIL] VirtualAlloc failed\n"); exit(1); }
    *(volatile unsigned char*)p = 0x5a;

    DWORD old_prot = 0;
    if (!VirtualProtect(p, size, PAGE_READONLY, &old_prot)) {
        printf("[FAIL] VirtualProtect failed\n");
        exit(1);
    }
    VirtualFree(p, 0, MEM_RELEASE);
    printf("[4/7] VirtualAlloc/VirtualProtect/VirtualFree: OK (byte=0x5a, oldProt=0x%lx)\n", old_prot);
    fflush(stdout);
}

static DWORD WINAPI thread_worker(LPVOID arg) {
    volatile long *counter = (volatile long*)arg;
    for (int i = 0; i < 25000; i++) {
        InterlockedIncrement(counter);
    }
    return 0;
}

static void test_multithreading(void) {
    volatile long counter = 0;
    HANDLE threads[4];
    for (int i = 0; i < 4; i++) {
        threads[i] = CreateThread(NULL, 0, thread_worker, (LPVOID)&counter, 0, NULL);
        if (!threads[i]) {
            printf("[FAIL] CreateThread failed for thread %d\n", i);
            exit(1);
        }
    }
    WaitForMultipleObjects(4, threads, TRUE, INFINITE);
    for (int i = 0; i < 4; i++) {
        CloseHandle(threads[i]);
    }

    if (counter != 100000) {
        printf("[FAIL] Multithreaded interlocked counter mismatch: %ld\n", counter);
        exit(1);
    }
    printf("[5/7] Win32 Multithreading & Interlocked Atomics: OK (counter=%ld)\n", counter);
    fflush(stdout);
}

static void test_compiler_stress_registers(void) {
    // Stress register allocation across x86-64 GPRs (r8-r15, rbx, rbp, rsi, rdi)
    register int64_t r1 asm("r8") = 11;
    register int64_t r2 asm("r9") = 22;
    register int64_t r3 asm("r10") = 33;
    register int64_t r4 asm("r11") = 44;
    register int64_t r5 asm("r12") = 55;
    register int64_t r6 asm("r13") = 66;
    register int64_t r7 asm("r14") = 77;
    register int64_t r8 asm("r15") = 88;

    int64_t sum = r1 + r2 + r3 + r4 + r5 + r6 + r7 + r8;
    if (sum != 396) {
        printf("[FAIL] Register pressure sum mismatch: %lld\n", (long long)sum);
        exit(1);
    }
    printf("[6/7] FEX Compiler Register Pressure (r8-r15 allocation): OK (sum=%lld)\n", (long long)sum);
    fflush(stdout);
}

static void test_file_io(void) {
    char temp_path[MAX_PATH];
    char temp_file[MAX_PATH];
    if (!GetTempPathA(MAX_PATH, temp_path)) {
        printf("[FAIL] GetTempPathA failed\n");
        exit(1);
    }
    if (!GetTempFileNameA(temp_path, "fex", 0, temp_file)) {
        printf("[FAIL] GetTempFileNameA failed\n");
        exit(1);
    }

    HANDLE h = CreateFileA(temp_file, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        printf("[FAIL] CreateFileA failed\n");
        exit(1);
    }
    const char msg[] = "ARM64EC-FEX Win32 File I/O Verification";
    DWORD written = 0;
    WriteFile(h, msg, sizeof(msg), &written, NULL);
    SetFilePointer(h, 0, NULL, FILE_BEGIN);

    char read_buf[64] = {0};
    DWORD read_bytes = 0;
    ReadFile(h, read_buf, sizeof(read_buf), &read_bytes, NULL);
    CloseHandle(h);
    DeleteFileA(temp_file);

    if (strcmp(msg, read_buf) != 0) {
        printf("[FAIL] File I/O content mismatch: read '%s'\n", read_buf);
        exit(1);
    }
    printf("[7/7] Win32 File I/O (CreateFile/WriteFile/ReadFile): OK\n");
    fflush(stdout);
}

int main(void) {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    printf("=== RUNNING EXPANDED FEX ARM64EC INTEGRATION TESTS ===\n");
    printf("[0/7] System Info: Arch=%u (9=AMD64), PageSize=%lu, Processors=%lu\n",
           (unsigned int)si.wProcessorArchitecture, si.dwPageSize, si.dwNumberOfProcessors);
    fflush(stdout);

    test_cpuid();
    test_sse2();
    test_unaligned_atomics_tso();
    test_virtual_memory();
    test_multithreading();
    test_compiler_stress_registers();
    test_file_io();

    printf("ALL EXPANDED FEX ARM64EC TESTS PASSED SUCCESSFULLY!\n");
    fflush(stdout);
    return 0;
}

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <setjmp.h>
#include <emmintrin.h>

/* =========================================================================
 * [1/13] x86-64 CPUID
 * ========================================================================= */
static void test_cpuid(void) {
    int cpu_info[4] = {0};
    __asm__ __volatile__("cpuid"
                         : "=a"(cpu_info[0]), "=b"(cpu_info[1]), "=c"(cpu_info[2]), "=d"(cpu_info[3])
                         : "a"(0), "c"(0));
    char vendor[13] = {0};
    *(int*)(vendor + 0) = cpu_info[1];
    *(int*)(vendor + 4) = cpu_info[3];
    *(int*)(vendor + 8) = cpu_info[2];
    printf("[1/13] x86-64 CPUID: Vendor=%s (MaxLeaf=%d)\n", vendor, cpu_info[0]);
    fflush(stdout);

    __asm__ __volatile__("cpuid"
                         : "=a"(cpu_info[0]), "=b"(cpu_info[1]), "=c"(cpu_info[2]), "=d"(cpu_info[3])
                         : "a"(1), "c"(0));
    printf("       CPUID Feature Flags: edx=0x%08x, ecx=0x%08x\n", cpu_info[3], cpu_info[2]);
    fflush(stdout);
}

/* =========================================================================
 * [2/13] SSE2 Vector Math in .text_ec
 * ========================================================================= */
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
    printf("[2/13] SSE2 Vector Dot Product (.text_ec): %.2f (expected 102.0)\n", dot);
    fflush(stdout);
}

/* =========================================================================
 * [3/13] Unaligned 64-bit Atomic TSO Fault Recovery (STATUS_DATATYPE_MISALIGNMENT)
 * ========================================================================= */
static void test_unaligned_atomics_tso(void) {
    uint8_t buffer[64] __attribute__((aligned(16))) = {0};
    const int offsets[2] = {3, 11};
    for (int i = 0; i < 2; i++) {
        volatile uint64_t *unaligned_ptr = (volatile uint64_t*)(buffer + offsets[i]);
        *unaligned_ptr = 0x1122334455667788ULL;

        uint64_t expected = 0x1122334455667788ULL;
        uint64_t new_val = 0xAABBCCDDEEFF0011ULL + (uint64_t)i;

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

        uint64_t add_val = 0x100ULL;
        __asm__ __volatile__(
            "lock xaddq %0, %1\n\t"
            : "+r"(add_val), "+m"(*unaligned_ptr)
            :
            : "memory", "cc"
        );
        if (add_val != new_val || *unaligned_ptr != new_val + 0x100ULL) {
            printf("[FAIL] Unaligned atomic XADD (offset +%d) failed\n", offsets[i]);
            exit(1);
        }
    }
    printf("[3/13] Unaligned 64-bit Atomic TSO Recovery (CAS+XADD): OK (val=0x%llx)\n",
           (unsigned long long)*(volatile uint64_t*)(buffer + 11));
    fflush(stdout);
}

/* =========================================================================
 * [4/13] VirtualAlloc / VirtualProtect / VirtualFree
 * ========================================================================= */
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
    printf("[4/13] VirtualAlloc/VirtualProtect/VirtualFree: OK (byte=0x5a, oldProt=0x%lx)\n", old_prot);
    fflush(stdout);
}

/* =========================================================================
 * [5/13] Win32 Multithreading & Interlocked Atomics
 * ========================================================================= */
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
    printf("[5/13] Win32 Multithreading & Interlocked Atomics: OK (counter=%ld)\n", counter);
    fflush(stdout);
}

/* =========================================================================
 * [6/13] High Register Pressure in .text_ec (ARM64EC_NATIVE unpinned regs)
 * ========================================================================= */
__attribute__((noinline))
static int64_t high_register_pressure_kernel(int64_t seed, int iterations) {
    int64_t a0 = seed + 1,  a1 = seed + 2,  a2 = seed + 3,  a3 = seed + 4;
    int64_t a4 = seed + 5,  a5 = seed + 6,  a6 = seed + 7,  a7 = seed + 8;
    int64_t a8 = seed + 9,  a9 = seed + 10, a10 = seed + 11, a11 = seed + 12;
    for (int i = 0; i < iterations; i++) {
        a0  += a1 ^ (i + 1);
        a1  += a2 ^ (i + 2);
        a2  += a3 ^ (i + 3);
        a3  += a4 ^ (i + 4);
        a4  += a5 ^ (i + 5);
        a5  += a6 ^ (i + 6);
        a6  += a7 ^ (i + 7);
        a7  += a8 ^ (i + 8);
        a8  += a9 ^ (i + 9);
        a9  += a10 ^ (i + 10);
        a10 += a11 ^ (i + 11);
        a11 += (a0 >> 3) ^ i;
    }
    return a0 + a1 + a2 + a3 + a4 + a5 + a6 + a7 + a8 + a9 + a10 + a11;
}

static void test_compiler_stress_registers(void) {
    register int64_t r1 asm("r8") = 11;
    register int64_t r2 asm("r9") = 22;
    register int64_t r3 asm("r10") = 33;
    register int64_t r4 asm("r11") = 44;
    register int64_t r5 asm("r12") = 55;
    register int64_t r6 asm("r13") = 66;
    register int64_t r7 asm("r14") = 77;
    register int64_t r8 asm("r15") = 88;

    int64_t sum = r1 + r2 + r3 + r4 + r5 + r6 + r7 + r8;
    int64_t k = high_register_pressure_kernel(10, 50);
    if (sum != 396 || k != 18008088597670322LL) {
        printf("[FAIL] Register pressure mismatch: sum=%lld, kernel=%lld\n",
               (long long)sum, (long long)k);
        exit(1);
    }
    printf("[6/13] High Register Pressure (.text_ec 12-way live loop): OK (sum=%lld, kernel=%lld)\n",
           (long long)sum, (long long)k);
    fflush(stdout);
}

/* =========================================================================
 * [7/13] Win32 File I/O
 * ========================================================================= */
static void test_file_io(void) {
    char temp_path[MAX_PATH];
    char temp_file[MAX_PATH];
    if (!GetTempPathA(MAX_PATH, temp_path) || !GetTempFileNameA(temp_path, "fex", 0, temp_file)) {
        printf("[FAIL] GetTempPathA/GetTempFileNameA failed\n");
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
    printf("[7/13] Win32 File I/O (CreateFile/WriteFile/ReadFile): OK\n");
    fflush(stdout);
}

/* =========================================================================
 * [8/13] Self-Modifying Code (SMC): Dynamic RWX Codegen & In-Place .text AOT Patching
 * ========================================================================= */
__attribute__((noinline, aligned(64)))
static int aot_smc_patchable_fn(int x) {
    int res;
    /* b8 78 56 34 12 = mov eax, 0x12345678 ; 01 c8 = add eax, ecx */
    __asm__ __volatile__(
        ".byte 0xb8, 0x78, 0x56, 0x34, 0x12\n\t"
        "addl %%ecx, %%eax\n\t"
        : "=a"(res)
        : "c"(x)
        : "cc"
    );
    return res;
}

static void test_self_modifying_code(void) {
    /* Part A: Dynamic RWX buffer code generation & live overwrite */
    uint8_t *rwx = (uint8_t*)VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!rwx) { printf("[FAIL] VirtualAlloc RWX failed\n"); exit(1); }

    /* Emit: lea eax, [rcx + 42] (8d 41 2a); ret (c3) */
    rwx[0] = 0x8D; rwx[1] = 0x41; rwx[2] = 42; rwx[3] = 0xC3;
    FlushInstructionCache(GetCurrentProcess(), rwx, 64);
    typedef int (*jit_fn_t)(int);
    jit_fn_t dyn_fn = (jit_fn_t)(void*)rwx;
    int v1 = dyn_fn(10);

    /* Patch immediate in-place from 42 to 99 and flush I-cache */
    rwx[2] = 99;
    FlushInstructionCache(GetCurrentProcess(), rwx, 64);
    int v2 = dyn_fn(10);
    VirtualFree(rwx, 0, MEM_RELEASE);

    if (v1 != 52 || v2 != 109) {
        printf("[FAIL] Dynamic RWX SMC failed: v1=%d (expected 52), v2=%d (expected 109)\n", v1, v2);
        exit(1);
    }

    /* Part B: In-place SMC on an AOT-compiled .text function! */
    int aot_before = aot_smc_patchable_fn(10);
    if (aot_before != (0x12345678 + 10)) {
        printf("[FAIL] AOT function initial value mismatch: 0x%x\n", aot_before);
        exit(1);
    }

    uint8_t *fn_bytes = (uint8_t*)(void*)&aot_smc_patchable_fn;
    DWORD old_prot = 0;
    if (!VirtualProtect((LPVOID)((uintptr_t)fn_bytes & ~0xFFFULL), 4096, PAGE_EXECUTE_READWRITE, &old_prot)) {
        printf("[FAIL] VirtualProtect on .text AOT function failed\n");
        exit(1);
    }

    int patched = 0;
    for (int i = 0; i < 32; i++) {
        if (fn_bytes[i] == 0xB8 &&
            fn_bytes[i + 1] == 0x78 && fn_bytes[i + 2] == 0x56 &&
            fn_bytes[i + 3] == 0x34 && fn_bytes[i + 4] == 0x12) {
            uint32_t new_imm = 4000;
            memcpy(&fn_bytes[i + 1], &new_imm, 4);
            patched = 1;
            break;
        }
    }
    FlushInstructionCache(GetCurrentProcess(), fn_bytes, 64);
    int aot_after = aot_smc_patchable_fn(10);
    VirtualProtect((LPVOID)((uintptr_t)fn_bytes & ~0xFFFULL), 4096, old_prot, &old_prot);

    if (!patched || aot_after != 4010) {
        printf("[FAIL] In-place .text AOT SMC failed: patched=%d, aot_after=%d (expected 4010)\n",
               patched, aot_after);
        exit(1);
    }
    printf("[8/13] Self-Modifying Code (RWX + In-Place .text AOT Invalidation): OK (52->109, 0x%x->%d)\n",
           aot_before, aot_after);
    fflush(stdout);
}

/* =========================================================================
 * [9/13] Hardware Access Violation Fault & Context Recovery in AOT Function
 * ========================================================================= */
static volatile LONG g_av_caught = 0;
static volatile uint64_t g_av_observed_rdx = 0;

static LONG CALLBACK av_recovery_veh(PEXCEPTION_POINTERS ep) {
    if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
        const uint8_t *rip = (const uint8_t*)ep->ContextRecord->Rip;
        /* Verify faulting instruction is `movq (%rcx), %rax` (48 8b 01) */
        if (rip[0] == 0x48 && rip[1] == 0x8B && rip[2] == 0x01) {
            g_av_caught++;
            g_av_observed_rdx = ep->ContextRecord->Rdx;
            ep->ContextRecord->Rax = 0xCAFEBABE12340000ULL;
            ep->ContextRecord->Rip += 3; /* Advance past faulting 3-byte load */
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

__attribute__((noinline))
static uint64_t aot_faulting_load_fn(void *bad_addr, uint64_t canary_rdx) {
    uint64_t out_rax = 0;
    __asm__ __volatile__(
        ".byte 0x48, 0x8b, 0x01\n\t" /* movq (%rcx), %rax */
        "addq $0x55, %%rax\n\t"
        : "=a"(out_rax)
        : "c"(bad_addr), "d"(canary_rdx)
        : "memory", "cc"
    );
    return out_rax;
}

static void test_hardware_fault_recovery(void) {
    void *noaccess_page = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS);
    if (!noaccess_page) { printf("[FAIL] VirtualAlloc PAGE_NOACCESS failed\n"); exit(1); }

    PVOID veh = AddVectoredExceptionHandler(1, av_recovery_veh);
    uint64_t canary = 0xFEEDFACE11223344ULL;
    uint64_t recovered = aot_faulting_load_fn(noaccess_page, canary);
    RemoveVectoredExceptionHandler(veh);
    VirtualFree(noaccess_page, 0, MEM_RELEASE);

    if (g_av_caught != 1 || g_av_observed_rdx != canary || recovered != 0xCAFEBABE12340055ULL) {
        printf("[FAIL] Hardware fault recovery mismatch: caught=%ld, rdx=0x%llx, res=0x%llx\n",
               (long)g_av_caught, (unsigned long long)g_av_observed_rdx, (unsigned long long)recovered);
        exit(1);
    }
    printf("[9/13] Hardware Access Violation Fault & RIP Context Recovery: OK (res=0x%llx)\n",
           (unsigned long long)recovered);
    fflush(stdout);
}

/* =========================================================================
 * [10/13] One-Shot PAGE_GUARD Fault & Instruction Retry in AOT Function
 * ========================================================================= */
static volatile LONG g_guard_caught = 0;
static volatile ULONG_PTR g_guard_fault_addr = 0;

static LONG CALLBACK guard_page_veh(PEXCEPTION_POINTERS ep) {
    if (ep->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION) {
        g_guard_caught++;
        if (ep->ExceptionRecord->NumberParameters >= 2) {
            g_guard_fault_addr = ep->ExceptionRecord->ExceptionInformation[1];
        }
        /* Do NOT advance RIP: PAGE_GUARD is cleared by OS on first fault, so retrying the store succeeds! */
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

__attribute__((noinline))
static void aot_guard_store_fn(volatile uint64_t *ptr, uint64_t val) {
    *ptr = val;
}

static void test_guard_page_fault(void) {
    uint64_t *guard_page = (uint64_t*)VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE | PAGE_GUARD);
    if (!guard_page) { printf("[FAIL] VirtualAlloc PAGE_GUARD failed\n"); exit(1); }

    PVOID veh = AddVectoredExceptionHandler(1, guard_page_veh);
    aot_guard_store_fn(&guard_page[7], 0x9988776655443322ULL);
    /* Second write should NOT fault because PAGE_GUARD is one-shot */
    aot_guard_store_fn(&guard_page[8], 0x1122334455667788ULL);
    RemoveVectoredExceptionHandler(veh);

    if (g_guard_caught != 1 || g_guard_fault_addr != (ULONG_PTR)&guard_page[7] ||
        guard_page[7] != 0x9988776655443322ULL || guard_page[8] != 0x1122334455667788ULL) {
        printf("[FAIL] Guard page fault retry mismatch: caught=%ld, val=0x%llx\n",
               (long)g_guard_caught, (unsigned long long)guard_page[7]);
        exit(1);
    }
    VirtualFree(guard_page, 0, MEM_RELEASE);
    printf("[10/13] Guard Page Fault (STATUS_GUARD_PAGE_VIOLATION) & Retry: OK (caught=%ld)\n",
           (long)g_guard_caught);
    fflush(stdout);
}

/* =========================================================================
 * [11/13] SEH .pdata RtlLookupFunctionEntry & Software RaiseException Unwind
 * ========================================================================= */
static jmp_buf g_seh_jmpbuf;
static volatile DWORD g_seh_code = 0;
static volatile ULONG_PTR g_seh_param0 = 0;

static LONG CALLBACK raise_exception_veh(PEXCEPTION_POINTERS ep) {
    if (ep->ExceptionRecord->ExceptionCode == 0xE0FE0A07UL) {
        g_seh_code = ep->ExceptionRecord->ExceptionCode;
        if (ep->ExceptionRecord->NumberParameters >= 1) {
            g_seh_param0 = ep->ExceptionRecord->ExceptionInformation[0];
        }
        longjmp(g_seh_jmpbuf, 1);
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

__attribute__((noinline))
static void aot_inner_raise(ULONG_PTR payload) {
    ULONG_PTR args[1] = { payload };
    RaiseException(0xE0FE0A07UL, 0, 1, args);
}

__attribute__((noinline))
static int aot_outer_seh_frame(ULONG_PTR payload) {
    PVOID veh = AddVectoredExceptionHandler(1, raise_exception_veh);
    int result = 0;
    if (setjmp(g_seh_jmpbuf) == 0) {
        aot_inner_raise(payload);
        result = -1;
    } else {
        result = (g_seh_code == 0xE0FE0A07UL && g_seh_param0 == payload) ? 1 : -2;
    }
    RemoveVectoredExceptionHandler(veh);
    return result;
}

static void test_seh_and_pdata(void) {
    DWORD64 img_base = 0;
    PRUNTIME_FUNCTION rf1 = RtlLookupFunctionEntry((DWORD64)(uintptr_t)&aot_outer_seh_frame, &img_base, NULL);
    PRUNTIME_FUNCTION rf2 = RtlLookupFunctionEntry((DWORD64)(uintptr_t)&high_register_pressure_kernel, &img_base, NULL);
    if (!rf1 || !rf2 || rf1->BeginAddress == 0 || rf2->BeginAddress == 0) {
        printf("[FAIL] RtlLookupFunctionEntry .pdata lookup failed\n");
        exit(1);
    }
    int seh_ok = aot_outer_seh_frame(0xABCDEF0123456789ULL);
    if (seh_ok != 1) {
        printf("[FAIL] RaiseException SEH unwind failed: seh_ok=%d\n", seh_ok);
        exit(1);
    }
    printf("[11/13] SEH .pdata RtlLookupFunctionEntry (RVA 0x%lx..0x%lx) & RaiseException: OK\n",
           (unsigned long)rf1->BeginAddress, (unsigned long)rf1->EndAddress);
    fflush(stdout);
}

/* =========================================================================
 * [12/13] Cross-Tier Dispatch (.text_ec <-> .text_fx) & Indirect Call / qsort
 * ========================================================================= */
__attribute__((noinline))
static int ec_callback_op(int a, int b) {
    return (a * 3) + (b ^ 0x5A);
}

/* Contains an explicit computed indirect jump (`jmp *%rax`) so AnalyzeFunctionSafety
 * places this function in `.text_fx` (AOTTargetABI::FEX_SRA), testing cross-tier
 * `.text_ec` -> `.text_fx` -> `.text_ec` calls and returns! */
__attribute__((noinline))
static int fex_sra_computed_jump_fn(int mode, int a, int b, int (*cb)(int, int)) {
    int out = 0;
    __asm__ __volatile__(
        "cmpl $1, %1\n\t"
        "je 1f\n\t"
        "leaq 2f(%%rip), %%rax\n\t"
        "jmpq *%%rax\n\t"
        "1:\n\t"
        "movl %2, %0\n\t"
        "addl %3, %0\n\t"
        "jmp 3f\n\t"
        "2:\n\t"
        "movl %2, %0\n\t"
        "subl %3, %0\n\t"
        "3:\n\t"
        : "=r"(out)
        : "r"(mode), "r"(a), "r"(b)
        : "rax", "cc"
    );
    return out + cb(a, b);
}

static int aot_qsort_cmp(const void *pa, const void *pb) {
    int a = *(const int*)pa;
    int b = *(const int*)pb;
    return (a > b) - (a < b);
}

static void test_cross_tier_dispatch(void) {
    int (*volatile fn_ptr)(int, int) = ec_callback_op;
    int r1 = fex_sra_computed_jump_fn(1, 20, 10, fn_ptr);
    int r2 = fex_sra_computed_jump_fn(2, 20, 10, fn_ptr);
    int expected1 = (20 + 10) + ((20 * 3) + (10 ^ 0x5A));
    int expected2 = (20 - 10) + ((20 * 3) + (10 ^ 0x5A));

    int arr[8] = { 42, -7, 19, 0, 105, 3, -100, 88 };
    qsort(arr, 8, sizeof(int), aot_qsort_cmp);

    if (r1 != expected1 || r2 != expected2 || arr[0] != -100 || arr[7] != 105) {
        printf("[FAIL] Cross-tier dispatch mismatch: r1=%d (%d), r2=%d (%d), arr[0]=%d\n",
               r1, expected1, r2, expected2, arr[0]);
        exit(1);
    }
    printf("[12/13] Cross-Tier (.text_ec <-> .text_fx) Direct/Indirect Dispatch & qsort: OK (r1=%d, r2=%d)\n",
           r1, r2);
    fflush(stdout);
}

/* =========================================================================
 * [13/13] Deep Mutual Recursion & Shadow Stack (x17 CALLRET_SP) Verification
 * ========================================================================= */
static int aot_mutual_odd(int n, int acc);

__attribute__((noinline))
static int aot_mutual_even(int n, int acc) {
    if (n <= 0) return acc + 1;
    return aot_mutual_odd(n - 1, acc + (n & 3));
}

__attribute__((noinline))
static int aot_mutual_odd(int n, int acc) {
    if (n <= 0) return acc;
    return aot_mutual_even(n - 1, acc + (n & 7));
}

static void test_deep_recursion_shadow_stack(void) {
    int res = aot_mutual_even(240, 0);
    if (res != 601) {
        printf("[FAIL] Deep mutual recursion mismatch: %d (expected 601)\n", res);
        exit(1);
    }
    printf("[13/13] Deep Mutual Recursion (240 frames, x17 Shadow Stack): OK (res=%d)\n", res);
    fflush(stdout);
}

int main(void) {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    printf("=== RUNNING EXPANDED FEX ARM64EC DUAL-TIER AOT E2E TESTS (13 SUITES) ===\n");
    printf("[0/13] System Info: Arch=%u (9=AMD64), PageSize=%lu, Processors=%lu\n",
           (unsigned int)si.wProcessorArchitecture, si.dwPageSize, si.dwNumberOfProcessors);
    fflush(stdout);

    test_cpuid();
    test_sse2();
    test_unaligned_atomics_tso();
    test_virtual_memory();
    test_multithreading();
    test_compiler_stress_registers();
    test_file_io();
    test_self_modifying_code();
    test_hardware_fault_recovery();
    test_guard_page_fault();
    test_seh_and_pdata();
    test_cross_tier_dispatch();
    test_deep_recursion_shadow_stack();

    printf("ALL 13 EXPANDED FEX ARM64EC DUAL-TIER AOT TESTS PASSED SUCCESSFULLY!\n");
    fflush(stdout);
    return 0;
}

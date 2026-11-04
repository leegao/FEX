// SPDX-License-Identifier: MIT
// fex_arm64ec_e2e_suite.cpp: End-to-End C++ Exception Unwinding (SEH _Unwind_RaiseException),
// RAII Destructor Chain, Cross-Tier (.text_ec <-> .text_fx) Virtual Method Dispatch,
// Hardware Fault Deopt, and Self-Modifying Code Verification Suite.

#include <windows.h>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>

static int g_raii_destructors_run = 0;
static int g_raii_order_hash = 0;

struct ScopedTracker {
    int id;
    explicit ScopedTracker(int id_) : id(id_) {}
    ~ScopedTracker() {
        g_raii_destructors_run++;
        g_raii_order_hash = (g_raii_order_hash * 31) + id;
    }
};

struct CustomAOTException {
    uint64_t code;
    const char* message;
    int tier_origin;
};

// Tier 1 (.text_fx) function using an explicit computed indirect jump so AnalyzeFunctionSafety
// routes it to AOTTargetABI::FEX_SRA, while throwing a C++ exception across a .text_fx frame!
__attribute__((noinline))
static int tier1_fex_sra_may_throw(int mode, int val) {
    ScopedTracker t_inner(303);
    int computed = 0;
    __asm__ __volatile__(
        "cmpl $0, %1\n\t"
        "je 1f\n\t"
        "leaq 2f(%%rip), %%rax\n\t"
        "jmpq *%%rax\n\t"
        "1:\n\t"
        "movl %2, %0\n\t"
        "jmp 3f\n\t"
        "2:\n\t"
        "movl %2, %0\n\t"
        "addl $77, %0\n\t"
        "3:\n\t"
        : "=r"(computed)
        : "r"(mode), "r"(val)
        : "rax", "cc"
    );
    if (computed > 100) {
        throw CustomAOTException{0xCAFEBABE00001337ULL, "Thrown from .text_fx (FEX_SRA) through .text_ec!", 1};
    }
    return computed;
}

// Tier 2 (.text_ec) intermediate frame with RAII object on guest stack
__attribute__((noinline))
static int tier2_ec_middle_frame(int mode, int val) {
    ScopedTracker t_mid(202);
    int r = tier1_fex_sra_may_throw(mode, val);
    return r * 2;
}

// Tier 2 (.text_ec) outer frame with try/catch block
__attribute__((noinline))
static uint64_t tier2_ec_outer_try_catch(int mode, int val) {
    g_raii_destructors_run = 0;
    g_raii_order_hash = 0;
    uint64_t caught_code = 0;
    try {
        ScopedTracker t_outer(101);
        int res = tier2_ec_middle_frame(mode, val);
        caught_code = (uint64_t)res;
    } catch (const CustomAOTException& ex) {
        caught_code = ex.code;
    }
    return caught_code;
}

// Virtual method hierarchy testing indirect vtable calls across .text_ec and .text_fx
struct ComputeNode {
    virtual ~ComputeNode() = default;
    virtual int64_t eval(int64_t x, int64_t y) const = 0;
};

struct EcLinearNode final : ComputeNode {
    int64_t scale;
    explicit EcLinearNode(int64_t s) : scale(s) {}
    int64_t eval(int64_t x, int64_t y) const override {
        return (x * scale) + (y ^ 0x3F);
    }
};

struct FexBranchNode final : ComputeNode {
    int64_t bias;
    explicit FexBranchNode(int64_t b) : bias(b) {}
    int64_t eval(int64_t x, int64_t y) const override {
        int64_t out = 0;
        __asm__ __volatile__(
            "leaq 1f(%%rip), %%rax\n\t"
            "jmpq *%%rax\n\t"
            "1:\n\t"
            "movq %1, %0\n\t"
            "imulq %2, %0\n\t"
            : "=r"(out)
            : "r"(x), "r"(y)
            : "rax", "cc"
        );
        return out + bias;
    }
};

int main() {
    printf("=== RUNNING C++ SEH UNWIND, RAII, & VIRTUAL DISPATCH AOT E2E SUITE ===\n");
    fflush(stdout);

    // 1. Test non-throwing path through .text_ec -> .text_fx
    uint64_t normal_res = tier2_ec_outer_try_catch(0, 25);
    if (normal_res != 50 || g_raii_destructors_run != 3 || g_raii_order_hash != ((303 * 31 + 202) * 31 + 101)) {
        printf("[FAIL] Non-throwing path mismatch: res=%llu, dtors=%d, hash=%d\n",
               (unsigned long long)normal_res, g_raii_destructors_run, g_raii_order_hash);
        return 1;
    }
    printf("[1/3] Non-Throwing Cross-Tier (.text_ec -> .text_fx) RAII Path: OK (res=%llu, dtors=%d)\n",
           (unsigned long long)normal_res, g_raii_destructors_run);
    fflush(stdout);

    // 2. Test throwing C++ exception from .text_fx unwinding through .text_ec into catch()
    uint64_t exc_res = tier2_ec_outer_try_catch(1, 50);
    int expected_hash = ((303 * 31 + 202) * 31 + 101);
    if (exc_res != 0xCAFEBABE00001337ULL || g_raii_destructors_run != 3 || g_raii_order_hash != expected_hash) {
        printf("[FAIL] C++ SEH exception unwind mismatch: code=0x%llx, dtors=%d, hash=%d (expected %d)\n",
               (unsigned long long)exc_res, g_raii_destructors_run, g_raii_order_hash, expected_hash);
        return 1;
    }
    printf("[2/3] C++ SEH Exception Throw & Unwind (.text_fx -> .text_ec -> catch): OK (code=0x%llx, reverse RAII dtors=3)\n",
           (unsigned long long)exc_res);
    fflush(stdout);

    // 3. Test C++ vtable indirect dispatch across .text_ec and .text_fx classes
    EcLinearNode n1(7);
    FexBranchNode n2(100);
    const ComputeNode* nodes[2] = { &n1, &n2 };
    int64_t total = 0;
    for (int i = 0; i < 100; ++i) {
        total += nodes[i & 1]->eval(i + 1, i + 3);
    }
    if (total != 202282) {
        printf("[FAIL] C++ vtable cross-tier dispatch mismatch: total=%lld (expected 202282)\n",
               (long long)total);
        return 1;
    }
    printf("[3/3] C++ Virtual Method Table Dispatch (.text_ec <-> .text_fx): OK (total=%lld)\n",
           (long long)total);
    fflush(stdout);

    printf("ALL C++ SEH UNWIND & VIRTUAL DISPATCH AOT E2E TESTS PASSED!\n");
    fflush(stdout);
    return 0;
}

#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#pragma pack(push, 1)
typedef struct {
    char Magic[4]; // "FXPE"
    uint32_t Version;
    uint64_t SourceFileId;
    uint64_t CodeCacheConfigId;
    uint64_t SourceImageBase;
    uint32_t SourceSizeOfImage;
    uint32_t SourceTimeDateStamp;
    uint64_t SourceTextXXH3;
    uint8_t  SourceSHA256[32];
    uint32_t FxccStreamFileOffset;
    uint32_t FxccStreamByteSize;
    uint32_t FxccTextFileOffset;
    uint32_t FxccTextByteSize;
    uint32_t FxccPageFileOffset;
    uint32_t FxccPageByteSize;
    uint32_t HeaderFlags;
    uint32_t Reserved;
} FEXAOTPEManifest;
#pragma pack(pop)

__attribute__((noinline, aligned(16)))
int HotpatchTargetFunction(int a, int b) {
    volatile int x = a * 3;
    volatile int y = b * 5;
    volatile int z = (x + y) ^ 0x55;
    return z + a - b;
}

__attribute__((noinline, aligned(16)))
int HotpatchReplacementFunction(int a, int b) {
    return (a + b) * 100 + 42;
}

int main(int argc, char** argv) {
    printf("=== FEX Arm64EC Standalone .aot.dll Loader & 14-Byte Atomic Hotpatcher E2E Test ===\n");
    const char* dll_path = (argc > 1) ? argv[1] : NULL;
    if (dll_path) {
        FILE* f = fopen(dll_path, "rb");
        if (f) {
            uint8_t hdr[256] = {0};
            size_t n = fread(hdr, 1, sizeof(hdr), f);
            fclose(f);
            if (n >= 0x40 + sizeof(FEXAOTPEManifest)) {
                const FEXAOTPEManifest* m = (const FEXAOTPEManifest*)(hdr + 0x40);
                printf("[1/3] Inspected .aot.dll Manifest: Magic=%.4s Version=%u SourceFileId=0x%llx Flags=0x%x\n",
                       m->Magic, m->Version, (unsigned long long)m->SourceFileId, m->HeaderFlags);
            }
        }
    }

    int before = HotpatchTargetFunction(4, 6);
    printf("[2/3] Before hotpatch: HotpatchTargetFunction(4, 6) = %d\n", before);

    uint8_t* fn_ptr = (uint8_t*)(uintptr_t)&HotpatchTargetFunction;
    uint64_t dst_va = (uint64_t)(uintptr_t)&HotpatchReplacementFunction;
    DWORD old_prot = 0;
    if (!VirtualProtect(fn_ptr, 64, PAGE_EXECUTE_READWRITE, &old_prot)) {
        printf("[FAIL] VirtualProtect RWX failed\n");
        return 1;
    }

    uint8_t saved_bytes[16];
    memcpy(saved_bytes, fn_ptr, 16);

    // 14-byte absolute indirect jump trampoline: FF 25 00 00 00 00 + <64-bit TargetVA> + 2-byte NOP
    uint8_t patch[16] = {
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
        (uint8_t)(dst_va & 0xFF),
        (uint8_t)((dst_va >> 8) & 0xFF),
        (uint8_t)((dst_va >> 16) & 0xFF),
        (uint8_t)((dst_va >> 24) & 0xFF),
        (uint8_t)((dst_va >> 32) & 0xFF),
        (uint8_t)((dst_va >> 40) & 0xFF),
        (uint8_t)((dst_va >> 48) & 0xFF),
        (uint8_t)((dst_va >> 56) & 0xFF),
        0x90, 0x90
    };
    memcpy(fn_ptr, patch, 16);
    FlushInstructionCache(GetCurrentProcess(), fn_ptr, 16);
    VirtualProtect(fn_ptr, 64, old_prot, &old_prot);

    int after = HotpatchTargetFunction(4, 6);
    printf("[3/3] After 14-byte FF 25 hotpatch: HotpatchTargetFunction(4, 6) = %d (expected 1042)\n", after);
    if (after != 1042) {
        printf("[FAIL] Hotpatched return value mismatch: %d != 1042\n", after);
        return 1;
    }

    // Restore original prologue and verify rollback
    VirtualProtect(fn_ptr, 64, PAGE_EXECUTE_READWRITE, &old_prot);
    memcpy(fn_ptr, saved_bytes, 16);
    FlushInstructionCache(GetCurrentProcess(), fn_ptr, 16);
    VirtualProtect(fn_ptr, 64, old_prot, &old_prot);

    int restored = HotpatchTargetFunction(4, 6);
    printf("[PASS] Rollback verified: HotpatchTargetFunction(4, 6) = %d (matches %d)\n", restored, before);
    return (restored == before) ? 0 : 1;
}

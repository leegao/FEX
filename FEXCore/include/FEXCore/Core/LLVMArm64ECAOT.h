// SPDX-License-Identifier: MIT
#pragma once

#include <FEXCore/Core/CodeCache.h>
#include <FEXCore/Core/Context.h>
#include <FEXCore/Utils/CompilerDefs.h>
#include <FEXCore/fextl/map.h>
#include <FEXCore/fextl/set.h>
#include <FEXCore/fextl/string.h>
#include <FEXCore/fextl/vector.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace FEXCore::IR {
class IRListView;
} // namespace FEXCore::IR

namespace FEXCore::CPU {
union Relocation;
} // namespace FEXCore::CPU

namespace FEXCore::Context {
class ContextImpl;
} // namespace FEXCore::Context

namespace FEXCore::AOT {

// Target ABI tier for AOT compilation:
// - FEX_SRA: Pinned 18-GPR / 16-FPR Static Register Allocation ABI (.text_fex section)
//            for open-CFG blocks, computed jumps, or inline SMC / trap blocks.
// - ARM64EC_NATIVE: Liveness-pruned, unpinned Arm64EC-native ABI (.text_ec section)
//                   for statically proven closed-CFG functions, freeing unused SRA
//                   GPRs/FPRs and flag registers so LLVM -O2 has full register allocation freedom.
enum class AOTTargetABI : uint8_t {
  FEX_SRA        = 0,
  ARM64EC_NATIVE = 1,
};

// Bitmask reasons why a function was disqualified from AOTTargetABI::ARM64EC_NATIVE
// and routed to the fallback AOTTargetABI::FEX_SRA (.text_fex) partition.
enum FunctionDisqualificationFlags : uint32_t {
  DISQUALIFY_NONE                      = 0,
  DISQUALIFY_UNRESOLVED_INDIRECT_JUMP  = (1u << 0), // Mid-function indirect jmp (not call/ret)
  DISQUALIFY_HAS_OP_BREAK              = (1u << 1), // Contains OP_BREAK trap/exception op
  DISQUALIFY_SINGLE_INST_THUNK         = (1u << 2), // Single-instruction trampoline/stub
  DISQUALIFY_NON_STANDARD_STACK        = (1u << 3), // Unbalanced or non-standard RSP overwrite
  DISQUALIFY_OPEN_INTERNAL_CFG         = (1u << 4), // Internal branch targets missing block ID
  DISQUALIFY_FORCED_SRA_MODE           = (1u << 5), // Forced to FEX_SRA via compiler options
};

struct FEX_DEFAULT_VISIBILITY FunctionSafetyAnalysis {
  AOTTargetABI SelectedABI = AOTTargetABI::FEX_SRA;
  uint32_t DisqualificationMask = DISQUALIFY_NONE;
  uint32_t LiveInGPRMask = 0;   // Bitmask of guest SRA GPRs [0..17] read before write
  uint32_t LiveOutGPRMask = 0;  // Bitmask of guest SRA GPRs [0..17] written in function
  uint32_t UsedGPRMask = 0;     // Union of read or written SRA GPRs [0..17]
  uint16_t LiveInFPRMask = 0;   // Bitmask of guest XMM registers [0..15] read before write
  uint16_t LiveOutFPRMask = 0;  // Bitmask of guest XMM registers [0..15] written in function
  uint16_t UsedFPRMask = 0;     // Union of read or written XMM registers [0..15]
  bool ReadsFlagsIn = false;    // Reads NZCV/PF/AF before writing them
  bool WritesFlagsOut = false;  // Writes NZCV/PF/AF
  bool HasDirectCalls = false;
  bool HasIndirectCalls = false;
  bool HasReturns = false;
  bool HasAtomicOps = false;
  std::string SummaryReason;
};

// Flags stored in CodeCacheHeader::Flags (formerly padding at offset 0x28)
enum CodeCacheHeaderFlags : uint32_t {
  CACHE_FLAG_NONE              = 0,
  CACHE_FLAG_LLVM_AOT_O2       = (1u << 0),
  CACHE_FLAG_PE_COFF_CONTAINER = (1u << 1),
  CACHE_FLAG_PROTECTED_AOT     = (1u << 2),
  CACHE_FLAG_PER_BINARY_HASH   = (1u << 3),
  CACHE_FLAG_DUAL_ABI_EC_FEX   = (1u << 4), // Partitioned into .text_ec and .text_fex
  CACHE_FLAG_SEH_DEOPT_TABLE   = (1u << 5), // Includes .fxdeopt SEH/fault recovery metadata
};

// Deoptimization & SEH Fault Recovery Table (.rdata / .fxdeopt)
// Maps host AArch64 PC ranges inside .text_ec and .text_fex back to exact guest x86-64 RIP
// and active register masks so synchronous faults (unaligned atomics, access violations)
// and Win32 SEH / C++ exception unwinds reconstruct guest context deterministically.
struct __attribute__((packed)) FEXAOTDeoptHeader {
  char Magic[4] = {'F', 'X', 'D', 'P'};
  uint32_t Version = 1;
  uint32_t NumEntries = 0;
  uint32_t TextEcRVA = 0;
  uint32_t TextEcSize = 0;
  uint32_t TextFexRVA = 0;
  uint32_t TextFexSize = 0;
  uint32_t Reserved = 0;
};
static_assert(sizeof(FEXAOTDeoptHeader) == 32, "FEXAOTDeoptHeader must be 32 bytes");

struct __attribute__((packed)) FEXAOTDeoptEntry {
  uint32_t HostStartRVA = 0;     // Start RVA in PE container (or offset in CodeBuffer + SecTextRVA)
  uint32_t HostEndRVA = 0;       // End RVA of instruction range
  uint32_t GuestEntryRVA = 0;    // Guest function entry RVA
  uint16_t GuestByteOffset = 0;  // Offset from GuestEntryRVA to faulting/active guest instruction
  uint8_t TargetABI = 0;         // 0 = FEX_SRA (.text_fex), 1 = ARM64EC_NATIVE (.text_ec)
  uint8_t Flags = 0;             // Bit 0: HasAtomic, Bit 1: HasCall, Bit 2: HasSEHUnwind
  uint32_t LiveOutGPRMask = 0;   // Active guest GPR write mask
  uint16_t LiveOutFPRMask = 0;   // Active guest FPR write mask
  uint16_t StackAdjustBytes = 0; // Host stack adjustment in bytes
};
static_assert(sizeof(FEXAOTDeoptEntry) == 24, "FEXAOTDeoptEntry must be 24 bytes");

// Embedded in the DOS stub (at file offset 0x40) and .rdata of Dual PE/COFF + FXCC AOT binaries.
// Enables zero-copy FXCC loading by FEXCore::Context::CodeCache::LoadCache as well as
// strict per-binary cache invalidation when the underlying Windows PE (.exe/.dll) changes.
struct __attribute__((packed)) FEXAOTPEManifest {
  char Magic[4] = {'F', 'X', 'P', 'E'};
  uint32_t Version = 2;
  uint32_t FxccStreamFileOffset = 0x1000; // Offset of CodeCacheHeader (.fxmeta section)
  uint32_t FxccTextFileOffset = 0;        // Offset of page-aligned AArch64 CodeBuffer (.text_ec + .text_fex)
  uint32_t FxccPageFileOffset = 0;        // Offset of CodePages table (.fxpage section)
  uint32_t HeaderFlags = CACHE_FLAG_LLVM_AOT_O2 | CACHE_FLAG_PE_COFF_CONTAINER |
                         CACHE_FLAG_PROTECTED_AOT | CACHE_FLAG_PER_BINARY_HASH |
                         CACHE_FLAG_DUAL_ABI_EC_FEX | CACHE_FLAG_SEH_DEOPT_TABLE;
  uint64_t SourceFileId = 0;              // FEX ComputeCodeMapId(BaseName, TimeDateStamp, SizeOfImage)
  uint64_t CodeCacheConfigId = 0;         // Hash of codegen config + CPU features + AOT opt level
  uint64_t SourceImageBase = 0;           // Original PE ImageBase (e.g. 0x140000000)
  uint32_t SourceSizeOfImage = 0;         // Original PE SizeOfImage
  uint32_t SourceTimeDateStamp = 0;       // Original PE TimeDateStamp
  uint64_t SourceTextXXH3 = 0;            // XXH3_64bits digest of guest .text section
  uint8_t SourceSHA256[32] = {};          // Full SHA-256 digest of source PE image
};

static_assert(sizeof(FEXAOTPEManifest) == 96, "FEXAOTPEManifest must be 96 bytes");

struct FEX_DEFAULT_VISIBILITY DiscoveredFunctionInfo {
  uint64_t EntryVA = 0;
  uint32_t EntryRVA = 0;
  uint32_t EndRVA = 0;
  uint32_t GuestInstCount = 0;
  uint32_t GuestByteSize = 0;
  uint32_t BasicBlockCount = 0;
  AOTTargetABI TargetABI = AOTTargetABI::FEX_SRA;
  FunctionSafetyAnalysis Safety {};
  uint32_t FEXJITCodeOnlyBytes = 0;
  uint32_t FEXJITTaiLAndHeaderBytes = 0;
  uint32_t FEXJITTotalBytes = 0;
  uint32_t LLVMAOTCodeOnlyBytes = 0;
  uint32_t LLVMAOTTailAndHeaderBytes = 0;
  uint32_t LLVMAOTTotalBytes = 0;
  uint32_t LLVMRawBodyBytes = 0;
  double FEXJITCompileTimeUs = 0.0;
  uint32_t LLVMSRACodeOnlyBytes = 0;
  uint32_t LLVMSRARawBodyBytes = 0;
  double LLVMAOTCompileTimeUs = 0.0;
  uint32_t HostCodeOffset = 0;
  std::string SymbolName;
  std::string LLVMIRText;
  std::vector<uint32_t> FEXJITWords;
  std::vector<uint32_t> LLVMAOTWords;
  std::vector<uint32_t> LLVMSRAWords;
};

struct FEX_DEFAULT_VISIBILITY CompiledAOTBlock {
  uint64_t GuestEntryVA = 0;
  uint32_t GuestEntryRVA = 0;
  uint32_t GuestSize = 0;
  uint32_t GuestInstCount = 0;
  uint32_t BasicBlockCount = 0;
  AOTTargetABI TargetABI = AOTTargetABI::FEX_SRA;
  FunctionSafetyAnalysis Safety {};
  uint32_t CodeOnlyBytes = 0;      // Instructions + jump thunks (excluding JITCodeHeader and JITCodeTail)
  uint32_t RawLLVMInstBytes = 0;   // Pure LLVM -O2 instruction body bytes (excluding FEX link thunks)
  uint32_t TotalBlockBytes = 0;    // Aligned size including JITCodeHeader + Code + JITCodeTail + RIP entries
  uint32_t HostOffsetInBuffer = 0; // Offset within the page-aligned CodeBuffer
  uint16_t HostStackAdjustBytes = 0;
  std::vector<uint8_t> BlockBytes;
  std::vector<FEXCore::CPU::Relocation> Relocations;
  std::vector<uint64_t> GuestCodePages;
  std::vector<std::pair<uint64_t, uint32_t>> EntryPoints; // (GuestVA, OffsetInBlock)
  std::vector<std::pair<uint32_t, uint32_t>> GuestOpcodes; // (GuestEntryOffset, HostWordOffset)
  std::string SymbolName;
};

struct FEX_DEFAULT_VISIBILITY Arm64ECThunkRecord {
  std::string Name;
  std::vector<uint8_t> Bytes;
  bool IsEntryThunk = true;
};

struct FEX_DEFAULT_VISIBILITY PEModuleAOTResult {
  std::string SourcePath;
  std::string BaseName;
  FEXAOTPEManifest Manifest {};
  uint64_t TotalFunctions = 0;
  uint64_t Arm64ECNativeFunctions = 0;
  uint64_t FEXSRAFunctions = 0;
  uint64_t SingleInstThunkFunctions = 0;
  uint64_t TotalBasicBlocks = 0;
  uint64_t TotalGuestInstructions = 0;
  uint64_t TotalGuestBytes = 0;

  // FEX-JIT totals
  uint64_t FEXJITInstructionBytes = 0;
  uint64_t FEXJITInstructionCount = 0;
  uint64_t FEXJITTotalBufferBytes = 0;
  double FEXJITTotalCompileTimeMs = 0.0;

  // LLVM-Arm64EC -O2 totals
  uint64_t LLVMAOTRawInstBytes = 0;
  uint64_t LLVMAOTRawInstCount = 0;
  uint64_t LLVMAOTInstructionBytes = 0; // Including FEX block prologues & deduplicated exit link stubs
  uint64_t LLVMAOTInstructionCount = 0;
  uint64_t LLVMAllSRARawInstBytes = 0;
  uint64_t LLVMAllSRARawInstCount = 0;
  uint64_t LLVMAllSRAInstructionBytes = 0;
  uint64_t LLVMAllSRAInstructionCount = 0;
  uint64_t LLVMAOTTotalBufferBytes = 0;
  uint64_t Arm64ECNativeSectionBytes = 0;
  uint64_t FEXSRASectionBytes = 0;
  uint64_t DeoptEntryCount = 0;
  double LLVMAOTBatchCompileTimeMs = 0.0;
  double LLVMAOTPerFnCompileTimeMs = 0.0;

  std::vector<DiscoveredFunctionInfo> Functions;
  std::vector<CompiledAOTBlock> CompiledBlocks;
  std::vector<Arm64ECThunkRecord> Arm64ECThunks;
  std::vector<uint8_t> DualPECOFFBytes;
  std::vector<uint8_t> RawFXCCBytes;
};

class FEX_DEFAULT_VISIBILITY LLVMArm64ECAOTCompiler {
public:
  struct Options {
    std::string OptPipeline = "default<O2>";
    std::string TargetTriple = "arm64ec-pc-windows-msvc";
    std::string CpuArch = "generic";
    bool DeduplicateExitStubs = true;
    bool EmitArm64ECThunks = true;
    bool MeasurePerFunctionLatency = true;
    bool EnableDualABIPartitioning = true; // Partition safe functions into ARM64EC_NATIVE (.text_ec) vs FEX_SRA (.text_fex)
    bool ForceAllFEXSRA = false;           // Force all functions into FEX_SRA mode (for A/B benchmarking)
    bool UseGVisorOffset = false;          // If true, uses August Hangover 11.16 gVisor offset (0xB60); default false (0xA68 for GitHub CI)
  };

  LLVMArm64ECAOTCompiler();
  explicit LLVMArm64ECAOTCompiler(const Options& Opts);
  ~LLVMArm64ECAOTCompiler();

  // Statically analyzes a FEX IRListView for a discovered guest function, computing register/flag
  // dataflow liveness and classifying whether the function is safe for AOTTargetABI::ARM64EC_NATIVE
  // (.text_ec) or requires fallback to AOTTargetABI::FEX_SRA (.text_fex).
  FunctionSafetyAnalysis AnalyzeFunctionSafety(uint64_t GuestEntryVA, uint64_t GuestSize,
                                               uint32_t GuestInstCount,
                                               const FEXCore::IR::IRListView& IR) const;

  // Lifts a single FEX IRListView into LLVM IR text using a single unified lifter core with
  // ABI lowering specialized by TargetABI (FEX_SRA vs. ARM64EC_NATIVE).
  struct LiftedFunctionIR {
    uint64_t GuestEntryVA = 0;
    uint64_t GuestSize = 0;
    uint32_t GuestInstCount = 0;
    uint32_t BasicBlockCount = 0;
    bool SingleInst = false;
    AOTTargetABI TargetABI = AOTTargetABI::FEX_SRA;
    FunctionSafetyAnalysis Safety {};
    std::string FunctionName;
    std::string LLVMIRBody;
    struct ExitSite {
      uint32_t ExitId = 0;
      bool IsDirect = false;
      uint64_t DirectNewRIP = 0;
      uint64_t CallReturnAddress = 0;
      uint32_t CallReturnBlockId = 0;
      bool HasCallReturnBlock = false;
      uint8_t Hint = 0; // FEXCore::IR::BranchHint
      int64_t PatchSiteAddress = 0;
      int64_t PatchSiteSize = 0;
    };
    std::vector<ExitSite> ExitSites;
    std::vector<std::pair<uint32_t, uint32_t>> GuestOpcodes; // (GuestEntryOffset, HostWordIdx)
  };

  LiftedFunctionIR LiftIRToLLVM(uint64_t GuestEntryVA, uint64_t GuestSize, uint32_t GuestInstCount,
                                const FEXCore::IR::IRListView& IR) const;

  LiftedFunctionIR LiftIRToLLVM(uint64_t GuestEntryVA, uint64_t GuestSize, uint32_t GuestInstCount,
                                const FEXCore::IR::IRListView& IR, AOTTargetABI ExplicitABI) const;

  // Batch-compiles a set of lifted functions in a single LLVM Module (-O2) and wraps each
  // into a FEX-compatible CompiledAOTBlock with JITCodeHeader, JITCodeTail, and Relocations.
  bool CompileModuleBatch(const std::vector<LiftedFunctionIR>& LiftedFunctions,
                          uint64_t SerializedBaseAddress,
                          std::vector<CompiledAOTBlock>& OutBlocks,
                          std::vector<Arm64ECThunkRecord>& OutThunks,
                          double& OutBatchCompileMs,
                          std::vector<double>* OutPerFnCompileUs = nullptr) const;

  // Wraps raw LLVM-emitted AArch64 function code bytes into a FEX JIT block (with JITCodeHeader,
  // entry prologue, deduplicated exit stubs + ExitFunctionLinkData, and JITCodeTail).
  CompiledAOTBlock WrapLLVMCodeInFEXBlock(const LiftedFunctionIR& Lifted,
                                          std::span<const uint8_t> RawFuncBytes,
                                          uint64_t SerializedBaseAddress) const;

private:
  Options Opts;
  bool CompileSingleModuleChunk(const std::vector<LiftedFunctionIR>& LiftedFunctions,
                                uint64_t SerializedBaseAddress,
                                std::vector<CompiledAOTBlock>& OutBlocks,
                                std::vector<Arm64ECThunkRecord>& OutThunks,
                                double& OutBatchCompileMs,
                                std::vector<double>* OutPerFnCompileUs) const;
};

// Serializes compiled AOT blocks into both:
// 1. A Dual-Consumable PE32+ Arm64EC (.dll) + FXCC binary partitioned into .text_ec (ARM64EC_NATIVE)
//    and .text_fex (FEX_SRA), with .pdata/.xdata unwind tables, .fxdeopt fault recovery records,
//    and CHPEv2 CodeMap + RedirectionMetadata.
// 2. A raw FXCC v2 stream.
FEX_DEFAULT_VISIBILITY bool BuildDualPECOFFAndFXCCContainer(
    const FEXAOTPEManifest& BaseManifest,
    const std::vector<CompiledAOTBlock>& Blocks,
    const std::vector<Arm64ECThunkRecord>& Thunks,
    std::vector<uint8_t>& OutDualPECOFF,
    std::vector<uint8_t>& OutRawFXCC,
    uint64_t* OutTextEcSize = nullptr,
    uint64_t* OutTextFexSize = nullptr,
    uint64_t* OutDeoptCount = nullptr);

// Independently audits a Dual PE/COFF Arm64EC (.aot.dll) binary using LLVM's COFFObjectFile parser
// and AArch64 MCDisassembler, returning a formatted audit report.
FEX_DEFAULT_VISIBILITY bool AuditPECOFFContainer(
    std::span<const uint8_t> ContainerBytes,
    std::string& OutReport,
    bool DisassembleAll = false);

// Queries the embedded .fxdeopt table in a Dual PE/COFF (.aot.dll) container to resolve a host RVA
// to its exact guest x86-64 RIP and register state mask for SEH unwinding and hardware fault recovery.
FEX_DEFAULT_VISIBILITY bool LookupDeoptEntryByHostRVA(
    std::span<const uint8_t> ContainerBytes,
    uint32_t HostRVA,
    FEXAOTDeoptEntry& OutEntry);

// Computes deterministic FEX FileId and content hashes for a PE binary.
FEX_DEFAULT_VISIBILITY uint64_t ComputePEFileId(
    std::string_view BaseNameLower, uint32_t TimeDateStamp, uint32_t SizeOfImage);
FEX_DEFAULT_VISIBILITY uint64_t ComputeCodeCacheConfigId(
    const FEXCore::Context::ContextImpl* CTX, bool IsLLVMAOT = true);

} // namespace FEXCore::AOT

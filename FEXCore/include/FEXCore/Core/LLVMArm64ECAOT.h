// SPDX-License-Identifier: MIT
#pragma once

#include <FEXCore/Core/CodeCache.h>
#include <FEXCore/Core/Context.h>
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

// Flags stored in CodeCacheHeader::Flags (formerly padding at offset 0x28)
enum CodeCacheHeaderFlags : uint32_t {
  CACHE_FLAG_NONE              = 0,
  CACHE_FLAG_LLVM_AOT_O2       = (1u << 0),
  CACHE_FLAG_PE_COFF_CONTAINER = (1u << 1),
  CACHE_FLAG_PROTECTED_AOT     = (1u << 2),
  CACHE_FLAG_PER_BINARY_HASH   = (1u << 3),
};

// Embedded in the DOS stub (at file offset 0x40) and .rdata of Dual PE/COFF + FXCC AOT binaries.
// Enables zero-copy FXCC loading by FEXCore::Context::CodeCache::LoadCache as well as
// strict per-binary cache invalidation when the underlying Windows PE (.exe/.dll) changes.
struct __attribute__((packed)) FEXAOTPEManifest {
  char Magic[4] = {'F', 'X', 'P', 'E'};
  uint32_t Version = 1;
  uint32_t FxccStreamFileOffset = 0x1000; // Offset of CodeCacheHeader (.fxmeta section)
  uint32_t FxccTextFileOffset = 0;        // Offset of page-aligned AArch64 CodeBuffer (.text section)
  uint32_t FxccPageFileOffset = 0;        // Offset of CodePages table (.fxpage section)
  uint32_t HeaderFlags = CACHE_FLAG_LLVM_AOT_O2 | CACHE_FLAG_PE_COFF_CONTAINER | CACHE_FLAG_PROTECTED_AOT | CACHE_FLAG_PER_BINARY_HASH;
  uint64_t SourceFileId = 0;              // FEX ComputeCodeMapId(BaseName, TimeDateStamp, SizeOfImage)
  uint64_t CodeCacheConfigId = 0;         // Hash of codegen config + CPU features + AOT opt level
  uint64_t SourceImageBase = 0;           // Original PE ImageBase (e.g. 0x140000000)
  uint32_t SourceSizeOfImage = 0;         // Original PE SizeOfImage
  uint32_t SourceTimeDateStamp = 0;       // Original PE TimeDateStamp
  uint64_t SourceTextXXH3 = 0;            // XXH3_64bits digest of guest .text section
  uint8_t SourceSHA256[32] = {};          // Full SHA-256 digest of source PE image
};

static_assert(sizeof(FEXAOTPEManifest) == 96, "FEXAOTPEManifest must be 96 bytes");

struct DiscoveredFunctionInfo {
  uint64_t EntryVA = 0;
  uint32_t EntryRVA = 0;
  uint32_t EndRVA = 0;
  uint32_t GuestInstCount = 0;
  uint32_t GuestByteSize = 0;
  uint32_t BasicBlockCount = 0;
  uint32_t FEXJITCodeOnlyBytes = 0;
  uint32_t FEXJITTaiLAndHeaderBytes = 0;
  uint32_t FEXJITTotalBytes = 0;
  uint32_t LLVMAOTCodeOnlyBytes = 0;
  uint32_t LLVMAOTTailAndHeaderBytes = 0;
  uint32_t LLVMAOTTotalBytes = 0;
  uint32_t LLVMRawBodyBytes = 0;
  double FEXJITCompileTimeUs = 0.0;
  double LLVMAOTCompileTimeUs = 0.0;
  uint32_t HostCodeOffset = 0;
  std::string SymbolName;
};

struct CompiledAOTBlock {
  uint64_t GuestEntryVA = 0;
  uint32_t GuestEntryRVA = 0;
  uint32_t GuestSize = 0;
  uint32_t GuestInstCount = 0;
  uint32_t BasicBlockCount = 0;
  uint32_t CodeOnlyBytes = 0;      // Instructions + jump thunks (excluding JITCodeHeader and JITCodeTail)
  uint32_t RawLLVMInstBytes = 0;   // Pure LLVM -O2 instruction body bytes (excluding FEX link thunks)
  uint32_t TotalBlockBytes = 0;    // Aligned size including JITCodeHeader + Code + JITCodeTail + RIP entries
  uint32_t HostOffsetInBuffer = 0; // Offset within the page-aligned CodeBuffer
  std::vector<uint8_t> BlockBytes;
  std::vector<FEXCore::CPU::Relocation> Relocations;
  std::vector<uint64_t> GuestCodePages;
  std::vector<std::pair<uint64_t, uint32_t>> EntryPoints; // (GuestVA, OffsetInBlock)
  std::string SymbolName;
};

struct Arm64ECThunkRecord {
  std::string Name;
  std::vector<uint8_t> Bytes;
  bool IsEntryThunk = true;
};

struct PEModuleAOTResult {
  std::string SourcePath;
  std::string BaseName;
  FEXAOTPEManifest Manifest {};
  uint64_t TotalFunctions = 0;
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
  uint64_t LLVMAOTTotalBufferBytes = 0;
  double LLVMAOTBatchCompileTimeMs = 0.0;
  double LLVMAOTPerFnCompileTimeMs = 0.0;

  std::vector<DiscoveredFunctionInfo> Functions;
  std::vector<CompiledAOTBlock> CompiledBlocks;
  std::vector<Arm64ECThunkRecord> Arm64ECThunks;
  std::vector<uint8_t> DualPECOFFBytes;
  std::vector<uint8_t> RawFXCCBytes;
};

class LLVMArm64ECAOTCompiler {
public:
  struct Options {
    std::string OptPipeline = "default<O2>";
    std::string TargetTriple = "arm64ec-pc-windows-msvc";
    std::string CpuArch = "generic";
    bool DeduplicateExitStubs = true;
    bool EmitArm64ECThunks = true;
    bool MeasurePerFunctionLatency = true;
  };

  LLVMArm64ECAOTCompiler();
  explicit LLVMArm64ECAOTCompiler(const Options& Opts);
  ~LLVMArm64ECAOTCompiler();

  // Lifts a single FEX IRListView into LLVM IR text for a function in an Arm64EC module.
  struct LiftedFunctionIR {
    uint64_t GuestEntryVA = 0;
    uint64_t GuestSize = 0;
    uint32_t GuestInstCount = 0;
    uint32_t BasicBlockCount = 0;
    bool SingleInst = false;
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
    std::vector<std::pair<uint32_t, uint32_t>> GuestOpcodes; // GuestEntryOffset
  };

  LiftedFunctionIR LiftIRToLLVM(uint64_t GuestEntryVA, uint64_t GuestSize, uint32_t GuestInstCount,
                                const FEXCore::IR::IRListView& IR) const;

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
};

// Serializes compiled AOT blocks into both:
// 1. A Dual-Consumable PE32+ Arm64EC (.dll) + FXCC binary (consumable by FEX's CodeCache::LoadCache
//    AND independently auditable by PE/COFF tools & llvm::object::COFFObjectFile).
// 2. A raw FXCC v2 stream.
bool BuildDualPECOFFAndFXCCContainer(
    const FEXAOTPEManifest& BaseManifest,
    const std::vector<CompiledAOTBlock>& Blocks,
    const std::vector<Arm64ECThunkRecord>& Thunks,
    std::vector<uint8_t>& OutDualPECOFF,
    std::vector<uint8_t>& OutRawFXCC);

// Independently audits a Dual PE/COFF Arm64EC (.aot.dll) binary using LLVM's COFFObjectFile parser
// and AArch64 MCDisassembler, returning a formatted audit report.
bool AuditPECOFFContainer(std::span<const uint8_t> ContainerBytes,
                          std::string& OutReport,
                          bool DisassembleAll = false);

// Computes deterministic FEX FileId and content hashes for a PE binary.
uint64_t ComputePEFileId(std::string_view BaseNameLower, uint32_t TimeDateStamp, uint32_t SizeOfImage);
uint64_t ComputeCodeCacheConfigId(const FEXCore::Context::ContextImpl* CTX, bool IsLLVMAOT = true);

} // namespace FEXCore::AOT

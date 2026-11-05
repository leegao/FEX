// SPDX-License-Identifier: MIT
#include <FEXCore/Core/LLVMArm64ECAOT.h>

#include "Interface/Core/AOT/LLVM/BlockWrapper.h"
#include "Interface/Core/AOT/LLVM/CompilationEngine.h"
#include "Interface/Core/AOT/LLVM/Internal.h"
#include "Interface/Core/AOT/LLVM/Lifter.h"
#include "Interface/Core/AOT/LLVM/SafetyAnalysis.h"

#include <xxhash.h>

namespace FEXCore::AOT {

uint64_t ComputePEFileId(std::string_view BaseNameLower, uint32_t TimeDateStamp, uint32_t SizeOfImage) {
  return XXH3_64bits(BaseNameLower.data(), BaseNameLower.size()) ^
         ((static_cast<uint64_t>(SizeOfImage) << 32) | static_cast<uint64_t>(TimeDateStamp));
}

uint64_t ComputeCodeCacheConfigId(const FEXCore::Context::ContextImpl* CTX, bool IsLLVMAOT) {
  uint64_t Hash = IsLLVMAOT ? 0x4C4C564D414F5432ULL : 0x4645584A49543030ULL;
  uint64_t ConfigBits = 0;
  if (CTX) {
    ConfigBits |= (CTX->Config.Is64BitMode ? 1ULL : 0ULL) << 0;
    ConfigBits |= (CTX->Config.Multiblock ? 1ULL : 0ULL) << 1;
    ConfigBits |= (static_cast<uint64_t>(CTX->Config.SMCChecks) & 0x3ULL) << 2;
    ConfigBits |= (CTX->Config.TSOEnabled ? 1ULL : 0ULL) << 4;
    ConfigBits |= (static_cast<uint64_t>(5000) & 0xFFFFULL) << 16;
  } else {
    // Default 64-bit multiblock configuration matching offline AOT compilation
    ConfigBits |= 1ULL << 0; // Is64BitMode = true
    ConfigBits |= 1ULL << 1; // Multiblock = true
    ConfigBits |= (static_cast<uint64_t>(FEXCore::Config::CONFIG_SMC_MTRACK) & 0x3ULL) << 2;
    ConfigBits |= (static_cast<uint64_t>(5000) & 0xFFFFULL) << 16;
  }
  Hash ^= XXH3_64bits(&ConfigBits, sizeof(ConfigBits));
  return Hash;
}

LLVMArm64ECAOTCompiler::LLVMArm64ECAOTCompiler() : Opts(Options{}) {
  EnsureLLVMInitialized();
}

LLVMArm64ECAOTCompiler::LLVMArm64ECAOTCompiler(const Options& Opts_)
  : Opts(Opts_) {
  EnsureLLVMInitialized();
}

LLVMArm64ECAOTCompiler::~LLVMArm64ECAOTCompiler() = default;

FunctionSafetyAnalysis
LLVMArm64ECAOTCompiler::AnalyzeFunctionSafety(uint64_t GuestEntryVA, uint64_t GuestSize,
                                              uint32_t GuestInstCount,
                                              const FEXCore::IR::IRListView& IR) const {
  SafetyAnalyzer Analyzer(Opts);
  return Analyzer.Analyze(GuestEntryVA, GuestSize, GuestInstCount, IR);
}

LLVMArm64ECAOTCompiler::LiftedFunctionIR
LLVMArm64ECAOTCompiler::LiftIRToLLVM(uint64_t GuestEntryVA, uint64_t GuestSize, uint32_t GuestInstCount,
                                     const FEXCore::IR::IRListView& IR) const {
  Lifter L(Opts);
  return L.Lift(GuestEntryVA, GuestSize, GuestInstCount, IR);
}

LLVMArm64ECAOTCompiler::LiftedFunctionIR
LLVMArm64ECAOTCompiler::LiftIRToLLVM(uint64_t GuestEntryVA, uint64_t GuestSize, uint32_t GuestInstCount,
                                     const FEXCore::IR::IRListView& IR, AOTTargetABI ExplicitABI) const {
  Lifter L(Opts);
  return L.Lift(GuestEntryVA, GuestSize, GuestInstCount, IR, ExplicitABI);
}

CompiledAOTBlock
LLVMArm64ECAOTCompiler::WrapLLVMCodeInFEXBlock(const LiftedFunctionIR& Lifted,
                                               std::span<const uint8_t> RawFuncBytes,
                                               uint64_t SerializedBaseAddress) const {
  BlockWrapper Wrapper(Opts);
  return Wrapper.Wrap(Lifted, RawFuncBytes, SerializedBaseAddress);
}

bool LLVMArm64ECAOTCompiler::CompileModuleBatch(const std::vector<LiftedFunctionIR>& LiftedFunctions,
                                                uint64_t SerializedBaseAddress,
                                                std::vector<CompiledAOTBlock>& OutBlocks,
                                                std::vector<Arm64ECThunkRecord>& OutThunks,
                                                double& OutBatchCompileMs,
                                                std::vector<double>* OutPerFnCompileUs) const {
  CompilationEngine Engine(Opts);
  return Engine.CompileBatch(LiftedFunctions, SerializedBaseAddress, OutBlocks, OutThunks, OutBatchCompileMs, OutPerFnCompileUs);
}

bool LLVMArm64ECAOTCompiler::CompileSingleModuleChunk(const std::vector<LiftedFunctionIR>& LiftedFunctions,
                                                      uint64_t SerializedBaseAddress,
                                                      std::vector<CompiledAOTBlock>& OutBlocks,
                                                      std::vector<Arm64ECThunkRecord>& OutThunks,
                                                      double& OutBatchCompileMs,
                                                      std::vector<double>* OutPerFnCompileUs) const {
  CompilationEngine Engine(Opts);
  return Engine.CompileBatch(LiftedFunctions, SerializedBaseAddress, OutBlocks, OutThunks, OutBatchCompileMs, OutPerFnCompileUs);
}

} // namespace FEXCore::AOT

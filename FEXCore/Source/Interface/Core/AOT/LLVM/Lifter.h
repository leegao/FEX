// SPDX-License-Identifier: MIT
#pragma once

#include <FEXCore/Core/LLVMArm64ECAOT.h>
#include <FEXCore/IR/IR.h>
#include "Interface/Core/AOT/LLVM/Internal.h"
#include "Interface/Core/AOT/RellumeLifter.h"

#include <cstdint>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

namespace FEXCore::AOT {

struct LifterContext {
  const LLVMArm64ECAOTCompiler::Options& Opts;
  const FunctionSafetyAnalysis& Safety;
  AOTTargetABI TargetABI;
  uint64_t GuestEntryVA;
  uint64_t GuestSize;
  uint32_t GuestInstCount;
  uint32_t BasicBlockCount = 0;
  bool UsesFPR = false;
  bool UsesEntrypointOffset = false;
  const FEXCore::IR::IRListView& IR;
  std::string FunctionName;
  std::ostringstream OS;
  std::vector<LLVMArm64ECAOTCompiler::LiftedFunctionIR::ExitSite> ExitSites;
  std::vector<std::pair<uint32_t, uint32_t>> GuestOpcodes;
  bool HasUnhandledIR = false;
  uint32_t ValCounter = 1;
  rellume::x86_64::Lifter Rellume;

  // Block-level state
  std::unordered_map<uint32_t, uint32_t> BlockNodeToId;
  uint32_t CurrentBlockId = 0;
  bool BlockTerminated = false;
  bool UnconsumedNonRspFlags = false;
  uint32_t ByteLoadsInBB = 0;

  LifterContext(const LLVMArm64ECAOTCompiler::Options& Opts_,
                const FunctionSafetyAnalysis& Safety_,
                AOTTargetABI TargetABI_,
                uint64_t GuestEntryVA_,
                uint64_t GuestSize_,
                uint32_t GuestInstCount_,
                const FEXCore::IR::IRListView& IR_);

  bool IsArm64ECNative() const { return TargetABI == AOTTargetABI::ARM64EC_NATIVE; }

  std::string NextVal();
  std::string LoadGPROperand(FEXCore::IR::OrderedNodeWrapper W);
  void StoreGPRDest(FEXCore::IR::Ref Node, const std::string& Val64);
  void StoreGPRWrapper(FEXCore::IR::OrderedNodeWrapper W, const std::string& Val64);
  std::string LoadFPROperand(FEXCore::IR::OrderedNodeWrapper W);
  void StoreFPRDest(FEXCore::IR::Ref Node, const std::string& VecVal);
  void StoreFPRWrapper(FEXCore::IR::OrderedNodeWrapper W, const std::string& VecVal);
  std::string ZeroUpperFPRBits(const std::string& VecVal, unsigned KeepBits);
  std::string MakeVec128Const(uint64_t Lo, uint64_t Hi);
  std::string MaskToOpSize(const std::string& Val64, FEXCore::IR::OpSize Size);
  std::string ComputeEffectiveAddress(FEXCore::IR::OrderedNodeWrapper BaseW,
                                     FEXCore::IR::OrderedNodeWrapper OffsetW,
                                     FEXCore::IR::MemOffsetType OffsetType,
                                     uint8_t OffsetScale);
  void PackNZCVFromAddSub(const std::string& Src1_64, const std::string& Src2_64,
                          const std::string& Res_64, FEXCore::IR::OpSize Size, bool IsSub);
  std::string EvaluateNZCVCond(FEXCore::IR::CondClass Cond);
};

// Handlers for opcode families:
bool LiftALUOp(LifterContext& Ctx, FEXCore::IR::Ref CodeNode, const FEXCore::IR::IROp_Header* IROp);
bool LiftMemoryOp(LifterContext& Ctx, FEXCore::IR::Ref CodeNode, const FEXCore::IR::IROp_Header* IROp);
bool LiftVectorOp(LifterContext& Ctx, FEXCore::IR::Ref CodeNode, const FEXCore::IR::IROp_Header* IROp);
bool LiftFlagsOp(LifterContext& Ctx, FEXCore::IR::Ref CodeNode, const FEXCore::IR::IROp_Header* IROp);

class Lifter {
public:
  explicit Lifter(const LLVMArm64ECAOTCompiler::Options& Opts);

  LLVMArm64ECAOTCompiler::LiftedFunctionIR Lift(
      uint64_t GuestEntryVA, uint64_t GuestSize, uint32_t GuestInstCount,
      const FEXCore::IR::IRListView& IR) const;

  LLVMArm64ECAOTCompiler::LiftedFunctionIR Lift(
      uint64_t GuestEntryVA, uint64_t GuestSize, uint32_t GuestInstCount,
      const FEXCore::IR::IRListView& IR, AOTTargetABI ExplicitABI) const;

private:
  const LLVMArm64ECAOTCompiler::Options& Opts;
};

} // namespace FEXCore::AOT

// SPDX-License-Identifier: MIT
#include "Interface/Core/AOT/LLVM/SafetyAnalysis.h"
#include "Interface/IR/IR.h"
#include "Interface/IR/IntrusiveIRList.h"
#include "Interface/IR/RegisterAllocationData.h"
#include <FEXCore/IR/IR.h>

#include <cstdlib>
#include <string>
#include <string_view>
#include <unordered_map>

namespace FEXCore::AOT {

SafetyAnalyzer::SafetyAnalyzer(const LLVMArm64ECAOTCompiler::Options& Opts_)
  : Opts(Opts_) {}

FunctionSafetyAnalysis
SafetyAnalyzer::Analyze(uint64_t GuestEntryVA, uint64_t GuestSize,
                        uint32_t GuestInstCount,
                        const FEXCore::IR::IRListView& IR) const {
  (void)GuestEntryVA;
  (void)GuestSize;
  FunctionSafetyAnalysis Analysis {};

  std::unordered_map<uint32_t, uint32_t> BlockNodeToId;
  for (auto [BlockNode, BlockHeader] : IR.GetBlocks()) {
    auto BlockIROp = BlockHeader->CW<FEXCore::IR::IROp_CodeBlock>();
    BlockNodeToId[IR.GetID(BlockNode).Value] = BlockIROp->ID;
  }

  bool FlagsWrittenSoFar = false;

  auto RecordReadOperand = [&](FEXCore::IR::OrderedNodeWrapper W) {
    if (W.IsInvalid() || !W.IsImmediate()) return;
    FEXCore::IR::PhysicalRegister PR(W);
    if (PR.IsInvalid()) return;
    if (PR.AsRegClass() == FEXCore::IR::RegClass::GPRFixed && PR.Reg < 18) {
      uint32_t Bit = 1u << PR.Reg;
      if ((Analysis.LiveOutGPRMask & Bit) == 0) {
        Analysis.LiveInGPRMask |= Bit;
      }
      Analysis.UsedGPRMask |= Bit;
    } else if (PR.AsRegClass() == FEXCore::IR::RegClass::FPRFixed && PR.Reg < 16) {
      uint16_t Bit = static_cast<uint16_t>(1u << PR.Reg);
      if ((Analysis.LiveOutFPRMask & Bit) == 0) {
        Analysis.LiveInFPRMask |= Bit;
      }
      Analysis.UsedFPRMask |= Bit;
    }
  };

  auto RecordWriteDest = [&](FEXCore::IR::Ref Node) {
    if (!Node) return;
    FEXCore::IR::PhysicalRegister PR(Node);
    if (PR.IsInvalid()) return;
    if (PR.AsRegClass() == FEXCore::IR::RegClass::GPRFixed && PR.Reg < 18) {
      uint32_t Bit = 1u << PR.Reg;
      Analysis.LiveOutGPRMask |= Bit;
      Analysis.UsedGPRMask |= Bit;
    } else if (PR.AsRegClass() == FEXCore::IR::RegClass::FPRFixed && PR.Reg < 16) {
      uint16_t Bit = static_cast<uint16_t>(1u << PR.Reg);
      Analysis.LiveOutFPRMask |= Bit;
      Analysis.UsedFPRMask |= Bit;
    }
  };

  auto RecordWriteWrapper = [&](FEXCore::IR::OrderedNodeWrapper W) {
    if (W.IsInvalid()) return;
    if (W.IsImmediate()) {
      FEXCore::IR::PhysicalRegister PR(W);
      if (PR.IsInvalid()) return;
      if (PR.AsRegClass() == FEXCore::IR::RegClass::GPRFixed && PR.Reg < 18) {
        uint32_t Bit = 1u << PR.Reg;
        Analysis.LiveOutGPRMask |= Bit;
        Analysis.UsedGPRMask |= Bit;
      } else if (PR.AsRegClass() == FEXCore::IR::RegClass::FPRFixed && PR.Reg < 16) {
        uint16_t Bit = static_cast<uint16_t>(1u << PR.Reg);
        Analysis.LiveOutFPRMask |= Bit;
        Analysis.UsedFPRMask |= Bit;
      }
    } else if (W.IsPointer()) {
      RecordWriteDest(IR.GetNode(W));
    }
  };

  for (auto [BlockNode, BlockHeader] : IR.GetBlocks()) {
    (void)BlockHeader;
    for (auto [CodeNode, IROp] : IR.GetCode(BlockNode)) {
      const uint8_t NumArgs = FEXCore::IR::GetArgs(IROp->Op);
      for (uint8_t i = 0; i < NumArgs; ++i) {
        RecordReadOperand(IROp->Args[i]);
      }

      switch (IROp->Op) {
      case FEXCore::IR::OP_LOADREGISTER: {
        auto* Op = IROp->C<FEXCore::IR::IROp_LoadRegister>();
        if (Op->Class == FEXCore::IR::RegClass::GPR && Op->Reg < 18) {
          uint32_t Bit = 1u << Op->Reg;
          if ((Analysis.LiveOutGPRMask & Bit) == 0) Analysis.LiveInGPRMask |= Bit;
          Analysis.UsedGPRMask |= Bit;
        } else if (Op->Class == FEXCore::IR::RegClass::FPR && Op->Reg < 16) {
          uint16_t Bit = static_cast<uint16_t>(1u << Op->Reg);
          if ((Analysis.LiveOutFPRMask & Bit) == 0) Analysis.LiveInFPRMask |= Bit;
          Analysis.UsedFPRMask |= Bit;
        }
        break;
      }
      case FEXCore::IR::OP_STOREREGISTER: {
        RecordWriteDest(CodeNode);
        break;
      }
      case FEXCore::IR::OP_LOADPF:
      case FEXCore::IR::OP_LOADAF:
      case FEXCore::IR::OP_LOADNZCV:
      case FEXCore::IR::OP_ADC:
      case FEXCore::IR::OP_ADCWITHFLAGS:
      case FEXCore::IR::OP_ADCNZCV:
      case FEXCore::IR::OP_ADCZERO:
      case FEXCore::IR::OP_ADCZEROWITHFLAGS:
      case FEXCore::IR::OP_SBB:
      case FEXCore::IR::OP_SBBWITHFLAGS:
      case FEXCore::IR::OP_SBBNZCV:
      case FEXCore::IR::OP_NZCVSELECT:
      case FEXCore::IR::OP_NZCVSELECTINCREMENT:
      case FEXCore::IR::OP_CONDADDNZCV:
      case FEXCore::IR::OP_CONDSUBNZCV:
      case FEXCore::IR::OP_CARRYINVERT: {
        if (!FlagsWrittenSoFar) {
          Analysis.ReadsFlagsIn = true;
        }
        if (IROp->Op == FEXCore::IR::OP_ADCWITHFLAGS || IROp->Op == FEXCore::IR::OP_ADCNZCV ||
            IROp->Op == FEXCore::IR::OP_ADCZEROWITHFLAGS || IROp->Op == FEXCore::IR::OP_SBBWITHFLAGS ||
            IROp->Op == FEXCore::IR::OP_SBBNZCV || IROp->Op == FEXCore::IR::OP_CONDADDNZCV ||
            IROp->Op == FEXCore::IR::OP_CONDSUBNZCV || IROp->Op == FEXCore::IR::OP_CARRYINVERT) {
          FlagsWrittenSoFar = true;
          Analysis.WritesFlagsOut = true;
        }
        break;
      }
      case FEXCore::IR::OP_STOREPF: {
        FlagsWrittenSoFar = true;
        Analysis.WritesFlagsOut = true;
        Analysis.LiveOutGPRMask |= (1u << 16);
        Analysis.UsedGPRMask |= (1u << 16);
        break;
      }
      case FEXCore::IR::OP_STOREAF: {
        FlagsWrittenSoFar = true;
        Analysis.WritesFlagsOut = true;
        Analysis.LiveOutGPRMask |= (1u << 17);
        Analysis.UsedGPRMask |= (1u << 17);
        break;
      }
      case FEXCore::IR::OP_STORENZCV:
      case FEXCore::IR::OP_ADDWITHFLAGS:
      case FEXCore::IR::OP_ADDNZCV:
      case FEXCore::IR::OP_SUBWITHFLAGS:
      case FEXCore::IR::OP_SUBNZCV:
      case FEXCore::IR::OP_ANDWITHFLAGS:
      case FEXCore::IR::OP_TESTNZ:
      case FEXCore::IR::OP_TESTZ:
      case FEXCore::IR::OP_RMIFNZCV:
      case FEXCore::IR::OP_SETSMALLNZV: {
        FlagsWrittenSoFar = true;
        Analysis.WritesFlagsOut = true;
        break;
      }
      case FEXCore::IR::OP_NEG: {
        auto* Op = IROp->C<FEXCore::IR::IROp_Neg>();
        if (Op->Cond != FEXCore::IR::CondClass::AL) {
          FlagsWrittenSoFar = true;
          Analysis.WritesFlagsOut = true;
        }
        break;
      }
      case FEXCore::IR::OP_PUSH: {
        break;
      }
      case FEXCore::IR::OP_PUSHTWO: {
        auto* Op = IROp->C<FEXCore::IR::IROp_PushTwo>();
        RecordWriteWrapper(Op->Addr);
        break;
      }
      case FEXCore::IR::OP_POP: {
        auto* Op = IROp->C<FEXCore::IR::IROp_Pop>();
        RecordWriteWrapper(Op->OutValue);
        RecordWriteWrapper(Op->InoutAddr);
        break;
      }
      case FEXCore::IR::OP_POPTWO: {
        auto* Op = IROp->C<FEXCore::IR::IROp_PopTwo>();
        RecordWriteWrapper(Op->OutValue1);
        RecordWriteWrapper(Op->OutValue2);
        RecordWriteWrapper(Op->InoutAddr);
        break;
      }
      case FEXCore::IR::OP_DIV:
      case FEXCore::IR::OP_UDIV: {
        auto* Op = IROp->C<FEXCore::IR::IROp_Div>();
        RecordWriteWrapper(Op->OutQuotient);
        RecordWriteWrapper(Op->OutRemainder);
        break;
      }
      case FEXCore::IR::OP_CPUID: {
        auto* Op = IROp->C<FEXCore::IR::IROp_CPUID>();
        RecordWriteWrapper(Op->OutEAX);
        RecordWriteWrapper(Op->OutEBX);
        RecordWriteWrapper(Op->OutECX);
        RecordWriteWrapper(Op->OutEDX);
        break;
      }
      case FEXCore::IR::OP_XGETBV: {
        auto* Op = IROp->C<FEXCore::IR::IROp_XGetBV>();
        RecordWriteWrapper(Op->OutEAX);
        RecordWriteWrapper(Op->OutEDX);
        break;
      }
      case FEXCore::IR::OP_ATOMICFETCHADD:
      case FEXCore::IR::OP_ATOMICFETCHSUB:
      case FEXCore::IR::OP_ATOMICFETCHAND:
      case FEXCore::IR::OP_ATOMICFETCHOR:
      case FEXCore::IR::OP_ATOMICFETCHXOR:
      case FEXCore::IR::OP_CAS:
      case FEXCore::IR::OP_ATOMICSWAP: {
        Analysis.HasAtomicOps = true;
        break;
      }
      case FEXCore::IR::OP_JUMP: {
        auto* Op = IROp->C<FEXCore::IR::IROp_Jump>();
        if (!BlockNodeToId.contains(Op->TargetBlock.ID().Value)) {
          Analysis.DisqualificationMask |= DISQUALIFY_OPEN_INTERNAL_CFG;
        }
        break;
      }
      case FEXCore::IR::OP_CONDJUMP: {
        auto* Op = IROp->C<FEXCore::IR::IROp_CondJump>();
        if (Op->FromNZCV && !FlagsWrittenSoFar) {
          Analysis.ReadsFlagsIn = true;
        }
        if (!BlockNodeToId.contains(Op->TrueBlock.ID().Value) ||
            !BlockNodeToId.contains(Op->FalseBlock.ID().Value)) {
          Analysis.DisqualificationMask |= DISQUALIFY_OPEN_INTERNAL_CFG;
        }
        break;
      }
      case FEXCore::IR::OP_EXITFUNCTION: {
        auto* Op = IROp->C<FEXCore::IR::IROp_ExitFunction>();
        bool IsDirect = false;
        if (Op->NewRIP.IsPointer()) {
          auto* RipHdr = IR.GetOp<FEXCore::IR::IROp_Header>(Op->NewRIP);
          if (RipHdr->Op == FEXCore::IR::OP_INLINECONSTANT ||
              RipHdr->Op == FEXCore::IR::OP_INLINEENTRYPOINTOFFSET) {
            IsDirect = true;
          }
        }
        if (Op->Hint == FEXCore::IR::BranchHint::Call) {
          if (IsDirect) Analysis.HasDirectCalls = true;
          else Analysis.HasIndirectCalls = true;
        } else if (Op->Hint == FEXCore::IR::BranchHint::Return) {
          Analysis.HasReturns = true;
        } else if (!IsDirect) {
          // Indirect jump that is neither a Return nor a Call (e.g. unrecovered switch table / tail dispatch)
          Analysis.DisqualificationMask |= DISQUALIFY_UNRESOLVED_INDIRECT_JUMP;
        }
        break;
      }
      case FEXCore::IR::OP_BREAK: {
        Analysis.DisqualificationMask |= DISQUALIFY_HAS_OP_BREAK;
        break;
      }
      default:
        break;
      }

      if (FEXCore::IR::GetHasDest(IROp->Op)) {
        RecordWriteDest(CodeNode);
      }
    }
  }

  if (GuestInstCount <= 1 && !Analysis.HasReturns) {
    Analysis.DisqualificationMask |= DISQUALIFY_SINGLE_INST_THUNK;
  }

  const char* EnvMode = std::getenv("FEX_AOT_MODE");
  if (Opts.ForceAllFEXSRA || !Opts.EnableDualABIPartitioning ||
      (EnvMode && std::string_view(EnvMode) == "sra")) {
    Analysis.DisqualificationMask |= DISQUALIFY_FORCED_SRA_MODE;
  }

  if (Analysis.DisqualificationMask == DISQUALIFY_NONE) {
    Analysis.SelectedABI = AOTTargetABI::ARM64EC_NATIVE;
    Analysis.SummaryReason = "SAFE_ARM64EC_NATIVE";
  } else {
    Analysis.SelectedABI = AOTTargetABI::FEX_SRA;
    std::string Reasons;
    if (Analysis.DisqualificationMask & DISQUALIFY_UNRESOLVED_INDIRECT_JUMP) Reasons += "unresolved_indirect_jmp,";
    if (Analysis.DisqualificationMask & DISQUALIFY_HAS_OP_BREAK) Reasons += "op_break,";
    if (Analysis.DisqualificationMask & DISQUALIFY_SINGLE_INST_THUNK) Reasons += "single_inst_thunk,";
    if (Analysis.DisqualificationMask & DISQUALIFY_OPEN_INTERNAL_CFG) Reasons += "open_cfg,";
    if (Analysis.DisqualificationMask & DISQUALIFY_FORCED_SRA_MODE) Reasons += "forced_sra,";
    if (!Reasons.empty() && Reasons.back() == ',') Reasons.pop_back();
    Analysis.SummaryReason = "FALLBACK_FEX_SRA(" + Reasons + ")";
  }

  return Analysis;
}

} // namespace FEXCore::AOT

// SPDX-License-Identifier: MIT
#include "Interface/Core/AOT/LLVM/Lifter.h"
#include "Interface/Core/AOT/LLVM/SafetyAnalysis.h"

namespace FEXCore::AOT {

LifterContext::LifterContext(const LLVMArm64ECAOTCompiler::Options& Opts_,
                            const FunctionSafetyAnalysis& Safety_,
                            AOTTargetABI TargetABI_,
                            uint64_t GuestEntryVA_,
                            uint64_t GuestSize_,
                            uint32_t GuestInstCount_,
                            const FEXCore::IR::IRListView& IR_)
  : Opts(Opts_), Safety(Safety_), TargetABI(TargetABI_),
    GuestEntryVA(GuestEntryVA_), GuestSize(GuestSize_),
    GuestInstCount(GuestInstCount_), IR(IR_),
    Rellume(OS, [this]() { return NextVal(); }) {}

std::string LifterContext::NextVal() {
  return "%v" + std::to_string(ValCounter++);
}

std::string LifterContext::LoadGPROperand(FEXCore::IR::OrderedNodeWrapper W) {
  if (W.IsInvalid()) {
    return "0";
  }
  if (W.IsImmediate()) {
    FEXCore::IR::PhysicalRegister PR(W);
    std::string Val = NextVal();
    if (PR.AsRegClass() == FEXCore::IR::RegClass::GPRFixed && PR.Reg < 18) {
      OS << "  " << Val << " = load i64, ptr %sra_gpr_" << unsigned(PR.Reg) << ", align 8\n";
    } else {
      OS << "  " << Val << " = load i64, ptr %tmp_gpr_" << (unsigned(PR.Reg) & 15) << ", align 8\n";
    }
    return Val;
  }
  if (!W.IsPointer()) return "0";
  auto* OpHdr = IR.GetOp<FEXCore::IR::IROp_Header>(W);
  if (OpHdr->Op == FEXCore::IR::OP_INLINECONSTANT) {
    auto* ConstOp = OpHdr->C<FEXCore::IR::IROp_InlineConstant>();
    return std::to_string(static_cast<int64_t>(ConstOp->Constant));
  }
  if (OpHdr->Op == FEXCore::IR::OP_INLINEENTRYPOINTOFFSET) {
    auto* OffOp = OpHdr->C<FEXCore::IR::IROp_InlineEntrypointOffset>();
    std::string BaseVa = "%runtime_entry_va";
    if (BasicBlockCount <= 128) {
      const uint32_t InlineHdrOff = static_cast<uint32_t>(offsetof(FEXCore::Core::CPUState, InlineJITBlockHeader));
      const uint32_t TailRipOff = static_cast<uint32_t>(offsetof(FEXCore::CPU::CPUBackend::JITCodeTail, RIP));
      std::string StVal = NextVal(), HSlotAddr = NextVal(), HSlotPtr = NextVal(), HPtrInt = NextVal();
      std::string HPtr = NextVal(), TOff32 = NextVal(), TOff64 = NextVal(), TRipAddr = NextVal();
      std::string TRipAddr2 = NextVal(), TRipPtr = NextVal(), Reva = NextVal();
      OS << "  " << StVal << " = call i64 asm sideeffect \"\", \"={x28}\"()\n";
      OS << "  " << HSlotAddr << " = add i64 " << StVal << ", " << InlineHdrOff << "\n";
      OS << "  " << HSlotPtr << " = inttoptr i64 " << HSlotAddr << " to ptr\n";
      OS << "  " << HPtrInt << " = load i64, ptr " << HSlotPtr << ", align 8\n";
      OS << "  " << HPtr << " = inttoptr i64 " << HPtrInt << " to ptr\n";
      OS << "  " << TOff32 << " = load i32, ptr " << HPtr << ", align 4\n";
      OS << "  " << TOff64 << " = zext i32 " << TOff32 << " to i64\n";
      OS << "  " << TRipAddr << " = add i64 " << HPtrInt << ", " << TOff64 << "\n";
      OS << "  " << TRipAddr2 << " = add i64 " << TRipAddr << ", " << TailRipOff << "\n";
      OS << "  " << TRipPtr << " = inttoptr i64 " << TRipAddr2 << " to ptr\n";
      OS << "  " << Reva << " = load i64, ptr " << TRipPtr << ", align 8\n";
      BaseVa = Reva;
    }
    std::string Val = NextVal();
    OS << "  " << Val << " = add i64 " << BaseVa << ", " << static_cast<int64_t>(OffOp->Offset) << "\n";
    if (OpHdr->Size == FEXCore::IR::OpSize::i32Bit) {
      std::string Masked = NextVal();
      OS << "  " << Masked << " = and i64 " << Val << ", 4294967295\n";
      return Masked;
    }
    return Val;
  }
  return "0";
}

void LifterContext::StoreGPRDest(FEXCore::IR::Ref Node, const std::string& Val64) {
  if (!Node) return;
  FEXCore::IR::PhysicalRegister PR(Node);
  if (PR.IsInvalid()) return;
  if (PR.AsRegClass() == FEXCore::IR::RegClass::GPRFixed && PR.Reg < 18) {
    OS << "  store i64 " << Val64 << ", ptr %sra_gpr_" << unsigned(PR.Reg) << ", align 8\n";
  } else {
    OS << "  store i64 " << Val64 << ", ptr %tmp_gpr_" << (unsigned(PR.Reg) & 15) << ", align 8\n";
  }
}

void LifterContext::StoreGPRWrapper(FEXCore::IR::OrderedNodeWrapper W, const std::string& Val64) {
  if (W.IsInvalid()) return;
  if (W.IsImmediate()) {
    FEXCore::IR::PhysicalRegister PR(W);
    if (PR.IsInvalid()) return;
    if (PR.AsRegClass() == FEXCore::IR::RegClass::GPRFixed && PR.Reg < 18) {
      OS << "  store i64 " << Val64 << ", ptr %sra_gpr_" << unsigned(PR.Reg) << ", align 8\n";
    } else {
      OS << "  store i64 " << Val64 << ", ptr %tmp_gpr_" << (unsigned(PR.Reg) & 15) << ", align 8\n";
    }
  } else if (W.IsPointer()) {
    StoreGPRDest(IR.GetNode(W), Val64);
  }
}

std::string LifterContext::LoadFPROperand(FEXCore::IR::OrderedNodeWrapper W) {
  if (!UsesFPR || W.IsInvalid()) return "zeroinitializer";
  if (W.IsImmediate()) {
    FEXCore::IR::PhysicalRegister PR(W);
    std::string Val = NextVal();
    if (PR.AsRegClass() == FEXCore::IR::RegClass::FPRFixed && PR.Reg < 16) {
      OS << "  " << Val << " = load <2 x i64>, ptr %sra_fpr_" << unsigned(PR.Reg) << ", align 16\n";
    } else {
      OS << "  " << Val << " = load <2 x i64>, ptr %tmp_fpr_" << (unsigned(PR.Reg) & 15) << ", align 16\n";
    }
    return Val;
  }
  return "zeroinitializer";
}

void LifterContext::StoreFPRDest(FEXCore::IR::Ref Node, const std::string& VecVal) {
  if (!UsesFPR || !Node) return;
  FEXCore::IR::PhysicalRegister PR(Node);
  if (PR.IsInvalid()) return;
  if (PR.AsRegClass() == FEXCore::IR::RegClass::FPRFixed && PR.Reg < 16) {
    OS << "  store <2 x i64> " << VecVal << ", ptr %sra_fpr_" << unsigned(PR.Reg) << ", align 16\n";
  } else {
    OS << "  store <2 x i64> " << VecVal << ", ptr %tmp_fpr_" << (unsigned(PR.Reg) & 15) << ", align 16\n";
  }
}

void LifterContext::StoreFPRWrapper(FEXCore::IR::OrderedNodeWrapper W, const std::string& VecVal) {
  if (!UsesFPR || W.IsInvalid()) return;
  if (W.IsImmediate()) {
    FEXCore::IR::PhysicalRegister PR(W);
    if (PR.IsInvalid()) return;
    if (PR.AsRegClass() == FEXCore::IR::RegClass::FPRFixed && PR.Reg < 16) {
      OS << "  store <2 x i64> " << VecVal << ", ptr %sra_fpr_" << unsigned(PR.Reg) << ", align 16\n";
    } else {
      OS << "  store <2 x i64> " << VecVal << ", ptr %tmp_fpr_" << (unsigned(PR.Reg) & 15) << ", align 16\n";
    }
  } else if (W.IsPointer()) {
    StoreFPRDest(IR.GetNode(W), VecVal);
  }
}

std::string LifterContext::ZeroUpperFPRBits(const std::string& VecVal, unsigned KeepBits) {
  if (KeepBits >= 128) return VecVal;
  if (KeepBits == 64) {
    std::string Z = NextVal();
    OS << "  " << Z << " = insertelement <2 x i64> " << VecVal << ", i64 0, i32 1\n";
    return Z;
  }
  if (KeepBits == 32 || KeepBits == 16 || KeepBits == 8) {
    uint64_t Mask = (1ULL << KeepBits) - 1ULL;
    std::string E0 = NextVal(), M0 = NextVal(), Z = NextVal();
    OS << "  " << E0 << " = extractelement <2 x i64> " << VecVal << ", i32 0\n";
    OS << "  " << M0 << " = and i64 " << E0 << ", " << Mask << "\n";
    OS << "  " << Z << " = insertelement <2 x i64> zeroinitializer, i64 " << M0 << ", i32 0\n";
    return Z;
  }
  return VecVal;
}

std::string LifterContext::MaskToOpSize(const std::string& Val64, FEXCore::IR::OpSize Size) {
  unsigned Bits = OpSizeToBits(Size);
  if (Bits >= 64) return Val64;
  uint64_t Mask = (1ULL << Bits) - 1ULL;
  std::string Res = NextVal();
  OS << "  " << Res << " = and i64 " << Val64 << ", " << Mask << "\n";
  return Res;
}

std::string LifterContext::ComputeEffectiveAddress(FEXCore::IR::OrderedNodeWrapper BaseW,
                                                   FEXCore::IR::OrderedNodeWrapper OffsetW,
                                                   FEXCore::IR::MemOffsetType OffsetType,
                                                   uint8_t OffsetScale) {
  std::string Base = LoadGPROperand(BaseW);
  if (OffsetW.IsInvalid()) {
    return Base;
  }
  std::string Off = LoadGPROperand(OffsetW);
  if (OffsetType == FEXCore::IR::MemOffsetType::UXTW) {
    std::string Zext = NextVal();
    OS << "  " << Zext << " = and i64 " << Off << ", 4294967295\n";
    Off = Zext;
  } else if (OffsetType == FEXCore::IR::MemOffsetType::SXTW) {
    std::string Tr = NextVal();
    std::string Sext = NextVal();
    OS << "  " << Tr << " = trunc i64 " << Off << " to i32\n";
    OS << "  " << Sext << " = sext i32 " << Tr << " to i64\n";
    Off = Sext;
  }
  if (OffsetScale > 1) {
    unsigned Shift = FEXCore::ilog2(static_cast<uint32_t>(OffsetScale));
    if (Shift > 0) {
      std::string Scaled = NextVal();
      OS << "  " << Scaled << " = shl i64 " << Off << ", " << Shift << "\n";
      Off = Scaled;
    }
  }
  std::string Addr = NextVal();
  OS << "  " << Addr << " = add i64 " << Base << ", " << Off << "\n";
  return Addr;
}

void LifterContext::PackNZCVFromAddSub(const std::string& Src1_64, const std::string& Src2_64,
                                       const std::string& Res_64, FEXCore::IR::OpSize Size, bool IsSub) {
  Rellume.FlagCalcAddSub(Src1_64, Src2_64, Res_64, OpSizeToBits(Size), IsSub);
}

std::string LifterContext::EvaluateNZCVCond(FEXCore::IR::CondClass Cond) {
  std::string NZCV = NextVal();
  OS << "  " << NZCV << " = load i64, ptr %nzcv_reg, align 8\n";
  auto GetBit = [&](unsigned BitPos) -> std::string {
    std::string Sh = NextVal(), And1 = NextVal(), Cmp = NextVal();
    OS << "  " << Sh << " = lshr i64 " << NZCV << ", " << BitPos << "\n";
    OS << "  " << And1 << " = and i64 " << Sh << ", 1\n";
    OS << "  " << Cmp << " = icmp ne i64 " << And1 << ", 0\n";
    return Cmp;
  };
  switch (Cond) {
  case FEXCore::IR::CondClass::EQ: return GetBit(30);
  case FEXCore::IR::CondClass::NEQ: {
    std::string Z = GetBit(30), R = NextVal();
    OS << "  " << R << " = xor i1 " << Z << ", true\n";
    return R;
  }
  case FEXCore::IR::CondClass::UGE:
  case FEXCore::IR::CondClass::FGE: return GetBit(29);
  case FEXCore::IR::CondClass::ULT:
  case FEXCore::IR::CondClass::FLU: {
    std::string C = GetBit(29), R = NextVal();
    OS << "  " << R << " = xor i1 " << C << ", true\n";
    return R;
  }
  case FEXCore::IR::CondClass::MI: return GetBit(31);
  case FEXCore::IR::CondClass::PL: {
    std::string N = GetBit(31), R = NextVal();
    OS << "  " << R << " = xor i1 " << N << ", true\n";
    return R;
  }
  case FEXCore::IR::CondClass::VS:
  case FEXCore::IR::CondClass::FU: return GetBit(28);
  case FEXCore::IR::CondClass::VC:
  case FEXCore::IR::CondClass::FNU: {
    std::string V = GetBit(28), R = NextVal();
    OS << "  " << R << " = xor i1 " << V << ", true\n";
    return R;
  }
  case FEXCore::IR::CondClass::UGT:
  case FEXCore::IR::CondClass::FGT: {
    std::string C = GetBit(29), Z = GetBit(30), NotZ = NextVal(), R = NextVal();
    OS << "  " << NotZ << " = xor i1 " << Z << ", true\n";
    OS << "  " << R << " = and i1 " << C << ", " << NotZ << "\n";
    return R;
  }
  case FEXCore::IR::CondClass::ULE:
  case FEXCore::IR::CondClass::FLEU: {
    std::string C = GetBit(29), Z = GetBit(30), NotC = NextVal(), R = NextVal();
    OS << "  " << NotC << " = xor i1 " << C << ", true\n";
    OS << "  " << R << " = or i1 " << NotC << ", " << Z << "\n";
    return R;
  }
  case FEXCore::IR::CondClass::SGE: {
    std::string N = GetBit(31), V = GetBit(28), R = NextVal();
    OS << "  " << R << " = icmp eq i1 " << N << ", " << V << "\n";
    return R;
  }
  case FEXCore::IR::CondClass::SLT: {
    std::string N = GetBit(31), V = GetBit(28), R = NextVal();
    OS << "  " << R << " = icmp ne i1 " << N << ", " << V << "\n";
    return R;
  }
  case FEXCore::IR::CondClass::SGT: {
    std::string Z = GetBit(30), N = GetBit(31), V = GetBit(28), NotZ = NextVal(), EqNV = NextVal(), R = NextVal();
    OS << "  " << NotZ << " = xor i1 " << Z << ", true\n";
    OS << "  " << EqNV << " = icmp eq i1 " << N << ", " << V << "\n";
    OS << "  " << R << " = and i1 " << NotZ << ", " << EqNV << "\n";
    return R;
  }
  case FEXCore::IR::CondClass::SLE: {
    std::string Z = GetBit(30), N = GetBit(31), V = GetBit(28), NeNV = NextVal(), R = NextVal();
    OS << "  " << NeNV << " = icmp ne i1 " << N << ", " << V << "\n";
    OS << "  " << R << " = or i1 " << Z << ", " << NeNV << "\n";
    return R;
  }
  default: return "true";
  }
}

Lifter::Lifter(const LLVMArm64ECAOTCompiler::Options& Opts_)
  : Opts(Opts_) {}

LLVMArm64ECAOTCompiler::LiftedFunctionIR
Lifter::Lift(uint64_t GuestEntryVA, uint64_t GuestSize, uint32_t GuestInstCount,
             const FEXCore::IR::IRListView& IR) const {
  SafetyAnalyzer Analyzer(Opts);
  FunctionSafetyAnalysis Safety = Analyzer.Analyze(GuestEntryVA, GuestSize, GuestInstCount, IR);
  LLVMArm64ECAOTCompiler::LiftedFunctionIR Res = Lift(GuestEntryVA, GuestSize, GuestInstCount, IR, Safety.SelectedABI);
  Res.Safety = std::move(Safety);
  return Res;
}

LLVMArm64ECAOTCompiler::LiftedFunctionIR
Lifter::Lift(uint64_t GuestEntryVA, uint64_t GuestSize, uint32_t GuestInstCount,
             const FEXCore::IR::IRListView& IR, AOTTargetABI ExplicitABI) const {
  SafetyAnalyzer Analyzer(Opts);
  FunctionSafetyAnalysis Safety = Analyzer.Analyze(GuestEntryVA, GuestSize, GuestInstCount, IR);
  Safety.SelectedABI = ExplicitABI;

  LifterContext Ctx(Opts, Safety, ExplicitABI, GuestEntryVA, GuestSize, GuestInstCount, IR);

  char FnNameBuf[64];
  snprintf(FnNameBuf, sizeof(FnNameBuf), "fex_fn_%llx", static_cast<unsigned long long>(GuestEntryVA));
  Ctx.FunctionName = FnNameBuf;

  uint32_t BlockIdx = 0;
  for (auto [BlockNode, BlockHeader] : IR.GetBlocks()) {
    auto BlockIROp = BlockHeader->CW<FEXCore::IR::IROp_CodeBlock>();
    Ctx.BlockNodeToId[IR.GetID(BlockNode).Value] = BlockIROp->ID;
    BlockIdx++;
    for (auto [CodeNode, IROp] : IR.GetCode(BlockNode)) {
      if (IROp->Op == FEXCore::IR::OP_ENTRYPOINTOFFSET || IROp->Op == FEXCore::IR::OP_INLINEENTRYPOINTOFFSET) {
        Ctx.UsesEntrypointOffset = true;
      }
      FEXCore::IR::PhysicalRegister DstReg(CodeNode);
      if (!DstReg.IsInvalid() &&
          (DstReg.AsRegClass() == FEXCore::IR::RegClass::FPR || DstReg.AsRegClass() == FEXCore::IR::RegClass::FPRFixed)) {
        Ctx.UsesFPR = true;
      }
      const uint8_t NumArgs = FEXCore::IR::GetArgs(IROp->Op);
      for (uint8_t i = 0; i < NumArgs; ++i) {
        if (IROp->Args[i].IsImmediate()) {
          FEXCore::IR::PhysicalRegister ArgReg(IROp->Args[i]);
          if (ArgReg.AsRegClass() == FEXCore::IR::RegClass::FPR || ArgReg.AsRegClass() == FEXCore::IR::RegClass::FPRFixed) {
            Ctx.UsesFPR = true;
          }
        } else if (IROp->Args[i].IsPointer()) {
          auto* ArgHdr = IR.GetOp<FEXCore::IR::IROp_Header>(IROp->Args[i]);
          if (ArgHdr && ArgHdr->Op == FEXCore::IR::OP_INLINEENTRYPOINTOFFSET) {
            Ctx.UsesEntrypointOffset = true;
          }
        }
      }
    }
  }
  Ctx.BasicBlockCount = BlockIdx;

  const bool IsArm64ECNative = Ctx.IsArm64ECNative();
  auto& OS = Ctx.OS;
  const char* SectionPrefix = IsArm64ECNative ? ".text_ec$" : ".text_fex$";
  const char* AttrGroup = IsArm64ECNative ? "#1" : "#0";
  OS << "define ghccc void @" << Ctx.FunctionName << "() " << AttrGroup
     << " section \"" << SectionPrefix << Ctx.FunctionName << "\" {\n";
  OS << "entry:\n";

  for (int i = 0; i < 18; ++i) {
    OS << "  %sra_gpr_" << i << " = alloca i64, align 8\n";
  }
  for (int i = 0; i < 16; ++i) {
    OS << "  %tmp_gpr_" << i << " = alloca i64, align 8\n";
  }
  OS << "  %nzcv_reg = alloca i64, align 8\n";
  OS << "  %callret_sp_reg = alloca i64, align 8\n";
  if (Ctx.UsesFPR) {
    for (int i = 0; i < 16; ++i) {
      OS << "  %sra_fpr_" << i << " = alloca <2 x i64>, align 16\n";
      OS << "  %tmp_fpr_" << i << " = alloca <2 x i64>, align 16\n";
    }
  }

  if (!Safety.ReadsFlagsIn) {
    OS << "  %sra_in = call %SRAStateEC asm \"\", "
          "\"={x8},={x0},={x1},={x27},={x23},={fp},={x25},={x26},={x2},={x3},={x4},={x5},={x19},={x20},={x21},={x22},={x17},={x28}\"()\n";
    for (int i = 0; i < 16; ++i) {
      OS << "  %in_gpr_" << i << " = extractvalue %SRAStateEC %sra_in, " << i << "\n";
      OS << "  store i64 %in_gpr_" << i << ", ptr %sra_gpr_" << i << ", align 8\n";
    }
    OS << "  store i64 1, ptr %sra_gpr_16, align 8\n";
    OS << "  store i64 0, ptr %sra_gpr_17, align 8\n";
    OS << "  %in_crsp = extractvalue %SRAStateEC %sra_in, 16\n";
    OS << "  store i64 %in_crsp, ptr %callret_sp_reg, align 8\n";
    OS << "  %state_ptr_int = extractvalue %SRAStateEC %sra_in, 17\n";
  } else {
    OS << "  %sra_in = call %SRAState asm \"\", "
          "\"={x8},={x0},={x1},={x27},={x23},={fp},={x25},={x26},={x2},={x3},={x4},={x5},={x19},={x20},={x21},={x22},={x9},={x24},={x17},={x28}\"()\n";
    for (int i = 0; i < 18; ++i) {
      OS << "  %in_gpr_" << i << " = extractvalue %SRAState %sra_in, " << i << "\n";
      OS << "  store i64 %in_gpr_" << i << ", ptr %sra_gpr_" << i << ", align 8\n";
    }
    OS << "  %in_crsp = extractvalue %SRAState %sra_in, 18\n";
    OS << "  store i64 %in_crsp, ptr %callret_sp_reg, align 8\n";
    OS << "  %state_ptr_int = extractvalue %SRAState %sra_in, 19\n";
  }
  for (int i = 0; i < 16; ++i) {
    OS << "  store i64 0, ptr %tmp_gpr_" << i << ", align 8\n";
  }

  if (!IsArm64ECNative || Safety.ReadsFlagsIn) {
    OS << "  %in_nzcv = call i64 asm \"mrs $0, nzcv\", \"=r\"()\n";
    OS << "  store i64 %in_nzcv, ptr %nzcv_reg, align 8\n";
  } else {
    OS << "  store i64 0, ptr %nzcv_reg, align 8\n";
  }

  if (Ctx.UsesFPR) {
    OS << "  %fpr_in = call %SRAFPRState asm \"\", "
          "\"={q0},={q1},={q2},={q3},={q4},={q5},={q6},={q7},={q8},={q9},={q10},={q11},={q12},={q13},={q14},={q15}\"()\n";
    for (int i = 0; i < 16; ++i) {
      OS << "  %in_fpr_" << i << " = extractvalue %SRAFPRState %fpr_in, " << i << "\n";
      OS << "  store <2 x i64> %in_fpr_" << i << ", ptr %sra_fpr_" << i << ", align 16\n";
      OS << "  store <2 x i64> zeroinitializer, ptr %tmp_fpr_" << i << ", align 16\n";
    }
  }

  auto [FirstBlockNode, FirstBlockHdr] = *IR.GetBlocks().begin();
  (void)FirstBlockNode;
  uint32_t FirstBlockId = FirstBlockHdr->CW<FEXCore::IR::IROp_CodeBlock>()->ID;

  if (Ctx.UsesEntrypointOffset && Ctx.BasicBlockCount > 128) {
    const uint32_t InlineHdrOff = static_cast<uint32_t>(offsetof(FEXCore::Core::CPUState, InlineJITBlockHeader));
    const uint32_t TailRipOff = static_cast<uint32_t>(offsetof(FEXCore::CPU::CPUBackend::JITCodeTail, RIP));
    OS << "  %hdr_slot_addr = add i64 %state_ptr_int, " << InlineHdrOff << "\n";
    OS << "  %hdr_slot_ptr = inttoptr i64 %hdr_slot_addr to ptr\n";
    OS << "  %hdr_ptr_int = load i64, ptr %hdr_slot_ptr, align 8\n";
    OS << "  %hdr_ptr = inttoptr i64 %hdr_ptr_int to ptr\n";
    OS << "  %tail_off32 = load i32, ptr %hdr_ptr, align 4\n";
    OS << "  %tail_off64 = zext i32 %tail_off32 to i64\n";
    OS << "  %tail_rip_addr = add i64 %hdr_ptr_int, %tail_off64\n";
    OS << "  %tail_rip_addr2 = add i64 %tail_rip_addr, " << TailRipOff << "\n";
    OS << "  %tail_rip_ptr = inttoptr i64 %tail_rip_addr2 to ptr\n";
    OS << "  %runtime_entry_va = load i64, ptr %tail_rip_ptr, align 8\n";
  }
  OS << "  br label %bb_" << FirstBlockId << "\n\n";

  for (auto [BlockNode, BlockHeader] : IR.GetBlocks()) {
    auto BlockIROp = BlockHeader->CW<FEXCore::IR::IROp_CodeBlock>();
    OS << "bb_" << BlockIROp->ID << ":\n";
    Ctx.CurrentBlockId = BlockIROp->ID;
    Ctx.BlockTerminated = false;
    Ctx.UnconsumedNonRspFlags = false;
    Ctx.ByteLoadsInBB = 0;

    for (auto [CodeNode, IROp] : IR.GetCode(BlockNode)) {
      if (Ctx.BlockTerminated) break;

      switch (IROp->Op) {
      case FEXCore::IR::OP_BEGINBLOCK:
      case FEXCore::IR::OP_ENDBLOCK:
      case FEXCore::IR::OP_INLINECONSTANT:
      case FEXCore::IR::OP_INLINEENTRYPOINTOFFSET:
      case FEXCore::IR::OP_INVALIDATEFLAGS:
      case FEXCore::IR::OP_DUMMY:
        break;

      case FEXCore::IR::OP_GUESTOPCODE: {
        auto* Op = IROp->C<FEXCore::IR::IROp_GuestOpcode>();
        Ctx.GuestOpcodes.push_back({Op->GuestEntryOffset, BlockIROp->ID});
        break;
      }

      case FEXCore::IR::OP_ALLOCATEGPR:
      case FEXCore::IR::OP_ALLOCATEGPRAFTER:
      case FEXCore::IR::OP_ALLOCATEFPR:
        break;

      default:
        if (LiftALUOp(Ctx, CodeNode, IROp)) {
          // Handled by ALU
        } else if (LiftMemoryOp(Ctx, CodeNode, IROp)) {
          // Handled by Memory
        } else if (LiftFlagsOp(Ctx, CodeNode, IROp)) {
          // Handled by Flags
        } else if (LiftVectorOp(Ctx, CodeNode, IROp)) {
          // Handled by Vector
        } else {
          Ctx.HasUnhandledIR = true;
          if (getenv("FEX_DUMP_UNHANDLED_OPS")) {
            fprintf(stderr, "UNHANDLED_OP: %u (%s) in 0x%llx\n",
                    static_cast<unsigned>(IROp->Op),
                    FEXCore::IR::GetName(IROp->Op).data(),
                    static_cast<unsigned long long>(GuestEntryVA));
          }
          if (FEXCore::IR::GetHasDest(IROp->Op)) {
            FEXCore::IR::PhysicalRegister PR(CodeNode);
            if (!PR.IsInvalid()) {
              if (PR.AsRegClass() == FEXCore::IR::RegClass::FPR || PR.AsRegClass() == FEXCore::IR::RegClass::FPRFixed) {
                Ctx.StoreFPRDest(CodeNode, "zeroinitializer");
              } else {
                Ctx.StoreGPRDest(CodeNode, "0");
              }
            }
          }
        }
        break;
      }
    }

    if (!Ctx.BlockTerminated) {
      OS << "  ret void\n";
    }
  }

  OS << "}\n\n";

  LLVMArm64ECAOTCompiler::LiftedFunctionIR Result;
  Result.GuestEntryVA = GuestEntryVA;
  Result.GuestSize = GuestSize;
  Result.GuestInstCount = GuestInstCount;
  Result.BasicBlockCount = Ctx.BasicBlockCount;
  Result.SingleInst = (GuestInstCount == 1);
  Result.HasUnhandledIR = Ctx.HasUnhandledIR;
  Result.TargetABI = ExplicitABI;
  Result.Safety = std::move(Safety);
  Result.FunctionName = std::move(Ctx.FunctionName);
  Result.LLVMIRBody = OS.str();
  Result.ExitSites = std::move(Ctx.ExitSites);
  Result.GuestOpcodes = std::move(Ctx.GuestOpcodes);

  return Result;
}

} // namespace FEXCore::AOT

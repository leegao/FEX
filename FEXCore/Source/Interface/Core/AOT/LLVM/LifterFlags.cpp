// SPDX-License-Identifier: MIT
#include "Interface/Core/AOT/LLVM/Lifter.h"

namespace FEXCore::AOT {

using LiftedFunctionIR = LLVMArm64ECAOTCompiler::LiftedFunctionIR;

bool LiftFlagsOp(LifterContext& Ctx, FEXCore::IR::Ref CodeNode, const FEXCore::IR::IROp_Header* IROp) {
  auto& OS = Ctx.OS;
  auto& IR = Ctx.IR;
  const bool IsArm64ECNative = Ctx.IsArm64ECNative();
  const uint64_t GuestEntryVA = Ctx.GuestEntryVA;
  const auto OpSize = IROp->Size;
  const unsigned Bits = OpSizeToBits(OpSize);
  const bool UsesFPR = Ctx.UsesFPR;
  bool& BlockTerminated = Ctx.BlockTerminated;
  bool& UnconsumedNonRspFlags = Ctx.UnconsumedNonRspFlags;
  uint32_t& ByteLoadsInBB = Ctx.ByteLoadsInBB;
  auto& BlockNodeToId = Ctx.BlockNodeToId;
  auto& Rellume = Ctx.Rellume;
  const auto& Opts = Ctx.Opts;

  struct {
    std::vector<LiftedFunctionIR::ExitSite>& ExitSites;
    const uint32_t BasicBlockCount;
    bool& HasUnhandledIR;
    std::vector<std::pair<uint32_t, uint32_t>>& GuestOpcodes;
  } Result{Ctx.ExitSites, Ctx.BasicBlockCount, Ctx.HasUnhandledIR, Ctx.GuestOpcodes};

  (void)OS; (void)IR; (void)IsArm64ECNative; (void)GuestEntryVA; (void)OpSize; (void)Bits; (void)UsesFPR;
  (void)BlockTerminated; (void)UnconsumedNonRspFlags; (void)ByteLoadsInBB; (void)BlockNodeToId; (void)Rellume; (void)Opts; (void)Result;

  auto NextVal = [&]() { return Ctx.NextVal(); };
  auto LoadGPROperand = [&](FEXCore::IR::OrderedNodeWrapper W) { return Ctx.LoadGPROperand(W); };
  auto StoreGPRDest = [&](FEXCore::IR::Ref Node, const std::string& Val) { Ctx.StoreGPRDest(Node, Val); };
  auto StoreGPRWrapper = [&](FEXCore::IR::OrderedNodeWrapper W, const std::string& Val) { Ctx.StoreGPRWrapper(W, Val); };
  auto LoadFPROperand = [&](FEXCore::IR::OrderedNodeWrapper W) { return Ctx.LoadFPROperand(W); };
  auto StoreFPRDest = [&](FEXCore::IR::Ref Node, const std::string& Val) { Ctx.StoreFPRDest(Node, Val); };
  auto StoreFPRWrapper = [&](FEXCore::IR::OrderedNodeWrapper W, const std::string& Val) { Ctx.StoreFPRWrapper(W, Val); };
  auto ZeroUpperFPRBits = [&](const std::string& Val, unsigned B) { return Ctx.ZeroUpperFPRBits(Val, B); };
  auto MaskToOpSize = [&](const std::string& Val, FEXCore::IR::OpSize S) { return Ctx.MaskToOpSize(Val, S); };
  auto ComputeEffectiveAddress = [&](FEXCore::IR::OrderedNodeWrapper B, FEXCore::IR::OrderedNodeWrapper O, FEXCore::IR::MemOffsetType T, uint8_t S) {
    return Ctx.ComputeEffectiveAddress(B, O, T, S);
  };
  auto PackNZCVFromAddSub = [&](const std::string& S1, const std::string& S2, const std::string& R, FEXCore::IR::OpSize S, bool Sub) {
    Ctx.PackNZCVFromAddSub(S1, S2, R, S, Sub);
  };
  auto EvaluateNZCVCond = [&](FEXCore::IR::CondClass Cond) { return Ctx.EvaluateNZCVCond(Cond); };

  (void)NextVal; (void)LoadGPROperand; (void)StoreGPRDest; (void)StoreGPRWrapper;
  (void)LoadFPROperand; (void)StoreFPRDest; (void)StoreFPRWrapper;
  (void)ZeroUpperFPRBits; (void)MaskToOpSize; (void)ComputeEffectiveAddress;
  (void)PackNZCVFromAddSub; (void)EvaluateNZCVCond;

  switch (IROp->Op) {
      case FEXCore::IR::OP_LOADPF: {
        std::string V = NextVal();
        OS << "  " << V << " = load i64, ptr %sra_gpr_16, align 8\n";
        StoreGPRDest(CodeNode, V);
        break;
      }

      case FEXCore::IR::OP_LOADAF: {
        std::string V = NextVal();
        OS << "  " << V << " = load i64, ptr %sra_gpr_17, align 8\n";
        StoreGPRDest(CodeNode, V);
        break;
      }

      case FEXCore::IR::OP_STOREPF: {
        auto* Op = IROp->C<FEXCore::IR::IROp_StorePF>();
        std::string V = LoadGPROperand(Op->Value);
        OS << "  store i64 " << V << ", ptr %sra_gpr_16, align 8\n";
        break;
      }

      case FEXCore::IR::OP_STOREAF: {
        auto* Op = IROp->C<FEXCore::IR::IROp_StoreAF>();
        std::string V = LoadGPROperand(Op->Value);
        OS << "  store i64 " << V << ", ptr %sra_gpr_17, align 8\n";
        break;
      }

      case FEXCore::IR::OP_LOADNZCV: {
        std::string V = NextVal();
        OS << "  " << V << " = load i64, ptr %nzcv_reg, align 8\n";
        StoreGPRDest(CodeNode, V);
        UnconsumedNonRspFlags = false;
        break;
      }

      case FEXCore::IR::OP_STORENZCV: {
        auto* Op = IROp->C<FEXCore::IR::IROp_StoreNZCV>();
        std::string V = LoadGPROperand(Op->Value);
        OS << "  store i64 " << V << ", ptr %nzcv_reg, align 8\n";
        UnconsumedNonRspFlags = true;
        break;
      }

      case FEXCore::IR::OP_SBB:
      case FEXCore::IR::OP_SBBWITHFLAGS:
      case FEXCore::IR::OP_SBBNZCV: {
        auto* Op = IROp->C<FEXCore::IR::IROp_Sbb>();
        std::string A = LoadGPROperand(Op->Src1);
        std::string B = LoadGPROperand(Op->Src2);
        std::string NZCV = NextVal(), CSh = NextVal(), CBit = NextVal(), Borrow = NextVal(), Sub1 = NextVal(), R = NextVal();
        OS << "  " << NZCV << " = load i64, ptr %nzcv_reg, align 8\n";
        OS << "  " << CSh << " = lshr i64 " << NZCV << ", 29\n";
        OS << "  " << CBit << " = and i64 " << CSh << ", 1\n";
        OS << "  " << Borrow << " = xor i64 " << CBit << ", 1\n";
        OS << "  " << Sub1 << " = sub i64 " << A << ", " << B << "\n";
        OS << "  " << R << " = sub i64 " << Sub1 << ", " << Borrow << "\n";
        R = MaskToOpSize(R, OpSize);
        UnconsumedNonRspFlags = false;
        if (IROp->Op != FEXCore::IR::OP_SBB) {
          PackNZCVFromAddSub(A, B, R, OpSize, true);
          UnconsumedNonRspFlags = !DestinationIsGuestRSP(CodeNode);
        }
        if (IROp->Op != FEXCore::IR::OP_SBBNZCV) {
          StoreGPRDest(CodeNode, R);
        }
        break;
      }

      case FEXCore::IR::OP_ADC:
      case FEXCore::IR::OP_ADCWITHFLAGS:
      case FEXCore::IR::OP_ADCNZCV: {
        auto* Op = IROp->C<FEXCore::IR::IROp_Adc>();
        std::string A = LoadGPROperand(Op->Src1);
        std::string B = LoadGPROperand(Op->Src2);
        std::string NZCV = NextVal(), CSh = NextVal(), CBit = NextVal(), Add1 = NextVal(), R = NextVal();
        OS << "  " << NZCV << " = load i64, ptr %nzcv_reg, align 8\n";
        OS << "  " << CSh << " = lshr i64 " << NZCV << ", 29\n";
        OS << "  " << CBit << " = and i64 " << CSh << ", 1\n";
        OS << "  " << Add1 << " = add i64 " << A << ", " << B << "\n";
        OS << "  " << R << " = add i64 " << Add1 << ", " << CBit << "\n";
        R = MaskToOpSize(R, OpSize);
        UnconsumedNonRspFlags = false;
        if (IROp->Op != FEXCore::IR::OP_ADC) {
          PackNZCVFromAddSub(A, B, R, OpSize, false);
          UnconsumedNonRspFlags = !DestinationIsGuestRSP(CodeNode);
        }
        if (IROp->Op != FEXCore::IR::OP_ADCNZCV) {
          StoreGPRDest(CodeNode, R);
        }
        break;
      }

      case FEXCore::IR::OP_ADCZERO:
      case FEXCore::IR::OP_ADCZEROWITHFLAGS: {
        auto* Op = IROp->C<FEXCore::IR::IROp_AdcZero>();
        std::string A = LoadGPROperand(Op->Src1);
        std::string NZCV = NextVal(), CSh = NextVal(), CBit = NextVal(), R = NextVal();
        OS << "  " << NZCV << " = load i64, ptr %nzcv_reg, align 8\n";
        OS << "  " << CSh << " = lshr i64 " << NZCV << ", 29\n";
        OS << "  " << CBit << " = and i64 " << CSh << ", 1\n";
        OS << "  " << R << " = add i64 " << A << ", " << CBit << "\n";
        R = MaskToOpSize(R, OpSize);
        UnconsumedNonRspFlags = false;
        if (IROp->Op == FEXCore::IR::OP_ADCZEROWITHFLAGS) {
          PackNZCVFromAddSub(A, CBit, R, OpSize, false);
          UnconsumedNonRspFlags = true;
        }
        StoreGPRDest(CodeNode, R);
        break;
      }

      case FEXCore::IR::OP_CARRYINVERT: {
        std::string NZCV = NextVal(), Flipped = NextVal();
        OS << "  " << NZCV << " = load i64, ptr %nzcv_reg, align 8\n";
        OS << "  " << Flipped << " = xor i64 " << NZCV << ", " << (1ULL << 29) << "\n";
        OS << "  store i64 " << Flipped << ", ptr %nzcv_reg, align 8\n";
        UnconsumedNonRspFlags = true;
        break;
      }

      case FEXCore::IR::OP_RMIFNZCV: {
        auto* Op = IROp->C<FEXCore::IR::IROp_RmifNZCV>();
        std::string Src = LoadGPROperand(Op->Src);
        std::string Rot = (Op->Rotate == 0) ? Src : NextVal();
        if (Op->Rotate != 0) {
          OS << "  " << Rot << " = call i64 @llvm.fshr.i64(i64 " << Src << ", i64 " << Src << ", i64 " << unsigned(Op->Rotate) << ")\n";
        }
        uint64_t MaskBits = (static_cast<uint64_t>(Op->Mask & 0xFu) << 28);
        std::string ShBits = NextVal(), MaskedNew = NextVal(), OldNZCV = NextVal(), KeptOld = NextVal(), NewNZCV = NextVal();
        OS << "  " << ShBits << " = shl i64 " << Rot << ", 28\n";
        OS << "  " << MaskedNew << " = and i64 " << ShBits << ", " << MaskBits << "\n";
        OS << "  " << OldNZCV << " = load i64, ptr %nzcv_reg, align 8\n";
        OS << "  " << KeptOld << " = and i64 " << OldNZCV << ", " << static_cast<int64_t>(~MaskBits) << "\n";
        OS << "  " << NewNZCV << " = or i64 " << KeptOld << ", " << MaskedNew << "\n";
        OS << "  store i64 " << NewNZCV << ", ptr %nzcv_reg, align 8\n";
        UnconsumedNonRspFlags = true;
        break;
      }

      case FEXCore::IR::OP_SETSMALLNZV: {
        auto* Op = IROp->C<FEXCore::IR::IROp_SetSmallNZV>();
        std::string Src = LoadGPROperand(Op->Src);
        unsigned ShiftLeft = (Bits == 16) ? 16 : 24;
        std::string S32 = NextVal(), Sh = NextVal(), NBit = NextVal(), ZBit = NextVal();
        std::string N64 = NextVal(), Z64 = NextVal(), NS = NextVal(), ZS = NextVal(), OrNZ = NextVal();
        OS << "  " << S32 << " = trunc i64 " << Src << " to i32\n";
        OS << "  " << Sh << " = shl i32 " << S32 << ", " << ShiftLeft << "\n";
        OS << "  " << NBit << " = icmp slt i32 " << Sh << ", 0\n";
        OS << "  " << ZBit << " = icmp eq i32 " << Sh << ", 0\n";
        OS << "  " << N64 << " = zext i1 " << NBit << " to i64\n";
        OS << "  " << Z64 << " = zext i1 " << ZBit << " to i64\n";
        OS << "  " << NS << " = shl i64 " << N64 << ", 31\n";
        OS << "  " << ZS << " = shl i64 " << Z64 << ", 30\n";
        OS << "  " << OrNZ << " = or i64 " << NS << ", " << ZS << "\n";
        OS << "  store i64 " << OrNZ << ", ptr %nzcv_reg, align 8\n";
        UnconsumedNonRspFlags = true;
        break;
      }

      case FEXCore::IR::OP_TESTZ: {
        auto* Op = IROp->C<FEXCore::IR::IROp_TestZ>();
        std::string A = MaskToOpSize(LoadGPROperand(Op->Src1), OpSize);
        std::string B = MaskToOpSize(LoadGPROperand(Op->Src2), OpSize);
        std::string AndR = NextVal(), ZBit = NextVal(), Z64 = NextVal(), ZS = NextVal(), R = NextVal();
        OS << "  " << AndR << " = and i64 " << A << ", " << B << "\n";
        OS << "  " << ZBit << " = icmp eq i64 " << AndR << ", 0\n";
        OS << "  " << Z64 << " = zext i1 " << ZBit << " to i64\n";
        OS << "  " << ZS << " = shl i64 " << Z64 << ", 30\n";
        OS << "  store i64 " << ZS << ", ptr %nzcv_reg, align 8\n";
        OS << "  " << R << " = select i1 " << ZBit << ", i64 0, i64 " << A << "\n";
        StoreGPRDest(CodeNode, R);
        UnconsumedNonRspFlags = true;
        break;
      }

      case FEXCore::IR::OP_NZCVSELECT: {
        auto* Op = IROp->C<FEXCore::IR::IROp_NZCVSelect>();
        std::string CondBit = EvaluateNZCVCond(Op->Cond);
        UnconsumedNonRspFlags = false;
        std::string TV = LoadGPROperand(Op->TrueVal);
        std::string FV = LoadGPROperand(Op->FalseVal);
        std::string R = NextVal();
        OS << "  " << R << " = select i1 " << CondBit << ", i64 " << TV << ", i64 " << FV << "\n";
        StoreGPRDest(CodeNode, MaskToOpSize(R, OpSize));
        break;
      }

      case FEXCore::IR::OP_NZCVSELECTINCREMENT: {
        auto* Op = IROp->C<FEXCore::IR::IROp_NZCVSelectIncrement>();
        std::string CondBit = EvaluateNZCVCond(Op->Cond);
        UnconsumedNonRspFlags = false;
        std::string TV = LoadGPROperand(Op->TrueVal);
        std::string FV = LoadGPROperand(Op->FalseVal);
        std::string FVInc = NextVal(), R = NextVal();
        OS << "  " << FVInc << " = add i64 " << FV << ", 1\n";
        OS << "  " << R << " = select i1 " << CondBit << ", i64 " << TV << ", i64 " << FVInc << "\n";
        StoreGPRDest(CodeNode, MaskToOpSize(R, OpSize));
        break;
      }

      case FEXCore::IR::OP_CONDADDNZCV: {
        auto* Op = IROp->C<FEXCore::IR::IROp_CondAddNZCV>();
        std::string CondBit = EvaluateNZCVCond(Op->Cond);
        std::string A = LoadGPROperand(Op->Src1);
        std::string B = LoadGPROperand(Op->Src2);
        std::string R = NextVal();
        OS << "  " << R << " = add i64 " << A << ", " << B << "\n";
        PackNZCVFromAddSub(A, B, R, OpSize, false);
        std::string TrueNZCV = NextVal(), FalseNZCV = std::to_string(uint64_t(Op->FalseNZCV) << 28), SelNZCV = NextVal();
        OS << "  " << TrueNZCV << " = load i64, ptr %nzcv_reg, align 8\n";
        OS << "  " << SelNZCV << " = select i1 " << CondBit << ", i64 " << TrueNZCV << ", i64 " << FalseNZCV << "\n";
        OS << "  store i64 " << SelNZCV << ", ptr %nzcv_reg, align 8\n";
        UnconsumedNonRspFlags = true;
        break;
      }

      case FEXCore::IR::OP_PARITY: {
        auto* Op = IROp->C<FEXCore::IR::IROp_Parity>();
        StoreGPRDest(CodeNode, Rellume.LiftParity(LoadGPROperand(Op->Raw), Op->Invert));
        break;
      }

      case FEXCore::IR::OP_LOADDF: {
        const uint32_t DfOff = static_cast<uint32_t>(offsetof(FEXCore::Core::CPUState, flags[10]));
        std::string Addr = NextVal(), Ptr = NextVal(), DfByte = NextVal(), Df64 = NextVal(), Sh = NextVal(), R = NextVal();
        OS << "  " << Addr << " = add i64 %state_ptr_int, " << DfOff << "\n";
        OS << "  " << Ptr << " = inttoptr i64 " << Addr << " to ptr\n";
        OS << "  " << DfByte << " = load i8, ptr " << Ptr << ", align 1\n";
        OS << "  " << Df64 << " = zext i8 " << DfByte << " to i64\n";
        OS << "  " << Sh << " = shl i64 " << Df64 << ", 1\n";
        OS << "  " << R << " = sub i64 1, " << Sh << "\n";
        StoreGPRDest(CodeNode, R);
        break;
      }

      case FEXCore::IR::OP_CONDSUBNZCV: {
        auto* Op = IROp->C<FEXCore::IR::IROp_CondSubNZCV>();
        std::string CondBit = EvaluateNZCVCond(Op->Cond);
        std::string A = LoadGPROperand(Op->Src1);
        std::string B = LoadGPROperand(Op->Src2);
        std::string R = NextVal();
        OS << "  " << R << " = sub i64 " << A << ", " << B << "\n";
        PackNZCVFromAddSub(A, B, R, OpSize, true);
        std::string TrueNZCV = NextVal(), FalseNZCV = std::to_string(uint64_t(Op->FalseNZCV) << 28), SelNZCV = NextVal();
        OS << "  " << TrueNZCV << " = load i64, ptr %nzcv_reg, align 8\n";
        OS << "  " << SelNZCV << " = select i1 " << CondBit << ", i64 " << TrueNZCV << ", i64 " << FalseNZCV << "\n";
        OS << "  store i64 " << SelNZCV << ", ptr %nzcv_reg, align 8\n";
        UnconsumedNonRspFlags = true;
        break;
      }

      case FEXCore::IR::OP_FCMP: {
        auto* Op = IROp->C<FEXCore::IR::IROp_FCmp>();
        std::string V1 = LoadFPROperand(Op->Scalar1);
        std::string V2 = LoadFPROperand(Op->Scalar2);
        unsigned ElemBits = OpSizeToBits(Op->ElementSize);
        std::string Nzcv = NextVal();
        if (ElemBits == 64) {
          std::string BC1 = NextVal(), BC2 = NextVal(), E1 = NextVal(), E2 = NextVal();
          OS << "  " << BC1 << " = bitcast <2 x i64> " << V1 << " to <2 x double>\n";
          OS << "  " << BC2 << " = bitcast <2 x i64> " << V2 << " to <2 x double>\n";
          OS << "  " << E1 << " = extractelement <2 x double> " << BC1 << ", i32 0\n";
          OS << "  " << E2 << " = extractelement <2 x double> " << BC2 << ", i32 0\n";
          OS << "  " << Nzcv << " = call i64 asm sideeffect \"fcmp ${1:d}, ${2:d} ; mrs $0, nzcv\", \"=r,w,w\"(double " << E1 << ", double " << E2 << ")\n";
        } else {
          std::string BC1 = NextVal(), BC2 = NextVal(), E1 = NextVal(), E2 = NextVal();
          OS << "  " << BC1 << " = bitcast <2 x i64> " << V1 << " to <4 x float>\n";
          OS << "  " << BC2 << " = bitcast <2 x i64> " << V2 << " to <4 x float>\n";
          OS << "  " << E1 << " = extractelement <4 x float> " << BC1 << ", i32 0\n";
          OS << "  " << E2 << " = extractelement <4 x float> " << BC2 << ", i32 0\n";
          OS << "  " << Nzcv << " = call i64 asm sideeffect \"fcmp ${1:s}, ${2:s} ; mrs $0, nzcv\", \"=r,w,w\"(float " << E1 << ", float " << E2 << ")\n";
        }
        OS << "  store i64 " << Nzcv << ", ptr %nzcv_reg, align 8\n";
        UnconsumedNonRspFlags = true;
        break;
      }

      case FEXCore::IR::OP_AXFLAG: {
        auto* Op = IROp->C<FEXCore::IR::IROp_AXFlag>();
        std::string VInv = Op->V_inv.IsInvalid() ? "0" : LoadGPROperand(Op->V_inv);
        std::string CurNzcv = NextVal(), NewNzcv = NextVal();
        OS << "  " << CurNzcv << " = load i64, ptr %nzcv_reg, align 8\n";
        OS << "  " << NewNzcv << " = call i64 asm sideeffect \"msr nzcv, $1 ; csetm x10, eq ; ccmn $2, x10, #2, le ; mrs $0, nzcv\", \"=r,r,r,~{x10},~{cc}\"(i64 " << CurNzcv << ", i64 " << VInv << ")\n";
        OS << "  store i64 " << NewNzcv << ", ptr %nzcv_reg, align 8\n";
        UnconsumedNonRspFlags = true;
        break;
      }

      case FEXCore::IR::OP_NZCVSELECTV: {
        auto* Op = IROp->C<FEXCore::IR::IROp_NZCVSelectV>();
        std::string CondBit = EvaluateNZCVCond(Op->Cond);
        UnconsumedNonRspFlags = false;
        std::string TV = LoadFPROperand(Op->TrueVal);
        std::string FV = LoadFPROperand(Op->FalseVal);
        std::string Sel = NextVal();
        OS << "  " << Sel << " = select i1 " << CondBit << ", <2 x i64> " << TV << ", <2 x i64> " << FV << "\n";
        StoreFPRDest(CodeNode, ZeroUpperFPRBits(Sel, OpSizeToBits(IROp->ElementSize)));
        break;
      }

      case FEXCore::IR::OP_SHIFTFLAGS: {
        auto* Op = IROp->C<FEXCore::IR::IROp_ShiftFlags>();
        std::string Res = LoadGPROperand(Op->Result);
        std::string Src1 = LoadGPROperand(Op->Src1);
        std::string Src2 = LoadGPROperand(Op->Src2);
        std::string PFIn = LoadGPROperand(Op->PFInput);
        unsigned ShBits = OpSizeToBits(Op->Size);
        uint64_t Mask = (ShBits == 64) ? 63 : 31;
        std::string Cnt = NextVal(), IsNz = NextVal(), NewPF = NextVal();
        OS << "  " << Cnt << " = and i64 " << Src2 << ", " << Mask << "\n";
        OS << "  " << IsNz << " = icmp ne i64 " << Cnt << ", 0\n";
        OS << "  " << NewPF << " = select i1 " << IsNz << ", i64 " << Res << ", i64 " << PFIn << "\n";
        StoreGPRDest(CodeNode, NewPF);
        break;
      }

  default:
    return false;
  }
  return true;
}

} // namespace FEXCore::AOT

// SPDX-License-Identifier: MIT
#include "Interface/Core/AOT/LLVM/Lifter.h"

namespace FEXCore::AOT {

using LiftedFunctionIR = LLVMArm64ECAOTCompiler::LiftedFunctionIR;

bool LiftALUOp(LifterContext& Ctx, FEXCore::IR::Ref CodeNode, const FEXCore::IR::IROp_Header* IROp) {
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
      case FEXCore::IR::OP_CONSTANT: {
        auto* Op = IROp->C<FEXCore::IR::IROp_Constant>();
        StoreGPRDest(CodeNode, std::to_string(static_cast<int64_t>(Op->Constant)));
        break;
      }

      case FEXCore::IR::OP_ENTRYPOINTOFFSET: {
        auto* Op = IROp->C<FEXCore::IR::IROp_EntrypointOffset>();
        std::string BaseVa = "%runtime_entry_va";
        if (Result.BasicBlockCount <= 128) {
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
        OS << "  " << Val << " = add i64 " << BaseVa << ", " << static_cast<int64_t>(Op->Offset) << "\n";
        StoreGPRDest(CodeNode, MaskToOpSize(Val, OpSize));
        break;
      }

      case FEXCore::IR::OP_COPY:
      case FEXCore::IR::OP_RMWHANDLE: {
        StoreGPRDest(CodeNode, LoadGPROperand(IROp->Args[0]));
        break;
      }

      case FEXCore::IR::OP_CPUID: {
        auto* Op = IROp->C<FEXCore::IR::IROp_CPUID>();
        std::string Fn = MaskToOpSize(LoadGPROperand(Op->Function), FEXCore::IR::OpSize::i32Bit);
        std::string Leaf = MaskToOpSize(LoadGPROperand(Op->Leaf), FEXCore::IR::OpSize::i32Bit);
        std::string Is0 = NextVal(), Is1 = NextVal(), Is7 = NextVal(), Is80 = NextVal(), Is81 = NextVal(), Is88 = NextVal();
        OS << "  " << Is0 << " = icmp eq i64 " << Fn << ", 0\n";
        OS << "  " << Is1 << " = icmp eq i64 " << Fn << ", 1\n";
        OS << "  " << Is7 << " = icmp eq i64 " << Fn << ", 7\n";
        OS << "  " << Is80 << " = icmp eq i64 " << Fn << ", 2147483648\n";
        OS << "  " << Is81 << " = icmp eq i64 " << Fn << ", 2147483649\n";
        OS << "  " << Is88 << " = icmp eq i64 " << Fn << ", 2147483656\n";
        (void)Leaf;
        std::string Eax1 = NextVal(), Eax2 = NextVal(), Eax3 = NextVal(), Eax4 = NextVal();
        OS << "  " << Eax1 << " = select i1 " << Is0 << ", i64 13, i64 0\n";
        OS << "  " << Eax2 << " = select i1 " << Is1 << ", i64 198339, i64 " << Eax1 << "\n";
        OS << "  " << Eax3 << " = select i1 " << Is80 << ", i64 2147483656, i64 " << Eax2 << "\n";
        OS << "  " << Eax4 << " = select i1 " << Is88 << ", i64 12336, i64 " << Eax3 << "\n";
        std::string Ebx1 = NextVal(), Ebx2 = NextVal(), Ebx3 = NextVal();
        OS << "  " << Ebx1 << " = select i1 " << Is0 << ", i64 1970169159, i64 0\n";
        OS << "  " << Ebx2 << " = select i1 " << Is1 << ", i64 67584, i64 " << Ebx1 << "\n";
        OS << "  " << Ebx3 << " = select i1 " << Is7 << ", i64 265, i64 " << Ebx2 << "\n";
        std::string Ecx1 = NextVal(), Ecx2 = NextVal(), Ecx3 = NextVal();
        OS << "  " << Ecx1 << " = select i1 " << Is0 << ", i64 1818588270, i64 0\n";
        OS << "  " << Ecx2 << " = select i1 " << Is1 << ", i64 43574207, i64 " << Ecx1 << "\n";
        OS << "  " << Ecx3 << " = select i1 " << Is81 << ", i64 289, i64 " << Ecx2 << "\n";
        std::string Edx1 = NextVal(), Edx2 = NextVal(), Edx3 = NextVal();
        OS << "  " << Edx1 << " = select i1 " << Is0 << ", i64 1231384169, i64 0\n";
        OS << "  " << Edx2 << " = select i1 " << Is1 << ", i64 126614527, i64 " << Edx1 << "\n";
        OS << "  " << Edx3 << " = select i1 " << Is81 << ", i64 672139264, i64 " << Edx2 << "\n";
        StoreGPRWrapper(Op->OutEAX, Eax4);
        StoreGPRWrapper(Op->OutEBX, Ebx3);
        StoreGPRWrapper(Op->OutECX, Ecx3);
        StoreGPRWrapper(Op->OutEDX, Edx3);
        break;
      }

      case FEXCore::IR::OP_XGETBV: {
        auto* Op = IROp->C<FEXCore::IR::IROp_XGetBV>();
        StoreGPRWrapper(Op->OutEAX, "3");
        StoreGPRWrapper(Op->OutEDX, "0");
        break;
      }

      case FEXCore::IR::OP_ADD:
      case FEXCore::IR::OP_ADDWITHFLAGS:
      case FEXCore::IR::OP_ADDNZCV: {
        auto* Op = IROp->C<FEXCore::IR::IROp_Add>();
        std::string A = LoadGPROperand(Op->Src1);
        std::string B = LoadGPROperand(Op->Src2);
        std::string R = NextVal();
        OS << "  " << R << " = add i64 " << A << ", " << B << "\n";
        R = MaskToOpSize(R, OpSize);
        bool IsRspAdj = IsArm64ECNative && (DestinationIsGuestRSP(CodeNode) ||
                        (Op->Src1.IsImmediate() && FEXCore::IR::PhysicalRegister(Op->Src1).AsRegClass() == FEXCore::IR::RegClass::GPRFixed &&
                         FEXCore::IR::PhysicalRegister(Op->Src1).Reg == 4));
        if (IROp->Op != FEXCore::IR::OP_ADD && !IsRspAdj) {
          PackNZCVFromAddSub(A, B, R, OpSize, false);
          UnconsumedNonRspFlags = true;
        }
        if (IROp->Op != FEXCore::IR::OP_ADDNZCV) {
          StoreGPRDest(CodeNode, R);
        }
        break;
      }

      case FEXCore::IR::OP_SUB:
      case FEXCore::IR::OP_SUBWITHFLAGS:
      case FEXCore::IR::OP_SUBNZCV: {
        auto* Op = IROp->C<FEXCore::IR::IROp_Sub>();
        std::string A = LoadGPROperand(Op->Src1);
        std::string B = LoadGPROperand(Op->Src2);
        std::string R = NextVal();
        OS << "  " << R << " = sub i64 " << A << ", " << B << "\n";
        R = MaskToOpSize(R, OpSize);
        bool IsRspAdj = IsArm64ECNative && (DestinationIsGuestRSP(CodeNode) ||
                        (Op->Src1.IsImmediate() && FEXCore::IR::PhysicalRegister(Op->Src1).AsRegClass() == FEXCore::IR::RegClass::GPRFixed &&
                         FEXCore::IR::PhysicalRegister(Op->Src1).Reg == 4));
        if (IROp->Op != FEXCore::IR::OP_SUB && !IsRspAdj) {
          PackNZCVFromAddSub(A, B, R, OpSize, true);
          UnconsumedNonRspFlags = true;
        }
        if (IROp->Op != FEXCore::IR::OP_SUBNZCV) {
          StoreGPRDest(CodeNode, R);
        }
        break;
      }

      case FEXCore::IR::OP_NEG: {
        auto* Op = IROp->C<FEXCore::IR::IROp_Neg>();
        std::string Src = LoadGPROperand(Op->Src);
        std::string R = NextVal();
        OS << "  " << R << " = sub i64 0, " << Src << "\n";
        R = MaskToOpSize(R, OpSize);
        if (Op->Cond != FEXCore::IR::CondClass::AL) {
          PackNZCVFromAddSub("0", Src, R, OpSize, true);
          UnconsumedNonRspFlags = true;
        }
        StoreGPRDest(CodeNode, R);
        break;
      }

      case FEXCore::IR::OP_ADDSHIFT: {
        auto* Op = IROp->C<FEXCore::IR::IROp_AddShift>();
        std::string A = LoadGPROperand(Op->Src1);
        std::string B = LoadGPROperand(Op->Src2);
        if (Op->ShiftAmount > 0) {
          std::string Sh = NextVal();
          const char* ShOp = "shl";
          if (Op->Shift == FEXCore::IR::ShiftType::LSR) ShOp = "lshr";
          else if (Op->Shift == FEXCore::IR::ShiftType::ASR) ShOp = "ashr";
          OS << "  " << Sh << " = " << ShOp << " i64 " << B << ", " << unsigned(Op->ShiftAmount) << "\n";
          B = Sh;
        }
        std::string R = NextVal();
        OS << "  " << R << " = add i64 " << A << ", " << B << "\n";
        StoreGPRDest(CodeNode, MaskToOpSize(R, OpSize));
        break;
      }

      case FEXCore::IR::OP_SUBSHIFT: {
        auto* Op = IROp->C<FEXCore::IR::IROp_SubShift>();
        std::string A = LoadGPROperand(Op->Src1);
        std::string B = LoadGPROperand(Op->Src2);
        if (Op->ShiftAmount > 0) {
          std::string Sh = NextVal();
          const char* ShOp = "shl";
          if (Op->Shift == FEXCore::IR::ShiftType::LSR) ShOp = "lshr";
          else if (Op->Shift == FEXCore::IR::ShiftType::ASR) ShOp = "ashr";
          OS << "  " << Sh << " = " << ShOp << " i64 " << B << ", " << unsigned(Op->ShiftAmount) << "\n";
          B = Sh;
        }
        std::string R = NextVal();
        OS << "  " << R << " = sub i64 " << A << ", " << B << "\n";
        StoreGPRDest(CodeNode, MaskToOpSize(R, OpSize));
        break;
      }

      case FEXCore::IR::OP_ANDSHIFT:
      case FEXCore::IR::OP_XORSHIFT:
      case FEXCore::IR::OP_XORNSHIFT: {
        auto* Op = IROp->C<FEXCore::IR::IROp_AndShift>();
        std::string A = LoadGPROperand(Op->Src1);
        std::string B = LoadGPROperand(Op->Src2);
        if (Op->ShiftAmount > 0) {
          std::string Sh = NextVal();
          const char* ShOp = "shl";
          if (Op->Shift == FEXCore::IR::ShiftType::LSR) ShOp = "lshr";
          else if (Op->Shift == FEXCore::IR::ShiftType::ASR) ShOp = "ashr";
          OS << "  " << Sh << " = " << ShOp << " i64 " << B << ", " << unsigned(Op->ShiftAmount) << "\n";
          B = Sh;
        }
        if (IROp->Op == FEXCore::IR::OP_XORNSHIFT) {
          std::string NotB = NextVal();
          OS << "  " << NotB << " = xor i64 " << B << ", -1\n";
          B = NotB;
        }
        std::string R = NextVal();
        const char* LogicOp = (IROp->Op == FEXCore::IR::OP_ANDSHIFT) ? "and" : "xor";
        OS << "  " << R << " = " << LogicOp << " i64 " << A << ", " << B << "\n";
        StoreGPRDest(CodeNode, MaskToOpSize(R, OpSize));
        break;
      }

      case FEXCore::IR::OP_ORLSHL:
      case FEXCore::IR::OP_ORLSHR:
      case FEXCore::IR::OP_ORNROR: {
        auto* Op = IROp->C<FEXCore::IR::IROp_Orlshl>();
        std::string A = LoadGPROperand(Op->Src1);
        std::string B = LoadGPROperand(Op->Src2);
        if (Op->BitShift > 0) {
          std::string Sh = NextVal();
          if (IROp->Op == FEXCore::IR::OP_ORLSHL) {
            OS << "  " << Sh << " = shl i64 " << B << ", " << unsigned(Op->BitShift) << "\n";
          } else if (IROp->Op == FEXCore::IR::OP_ORLSHR) {
            OS << "  " << Sh << " = lshr i64 " << B << ", " << unsigned(Op->BitShift) << "\n";
          } else {
            OS << "  " << Sh << " = call i64 @llvm.fshr.i64(i64 " << B << ", i64 " << B << ", i64 " << unsigned(Op->BitShift) << ")\n";
          }
          B = Sh;
        }
        if (IROp->Op == FEXCore::IR::OP_ORNROR) {
          std::string NotB = NextVal();
          OS << "  " << NotB << " = xor i64 " << B << ", -1\n";
          B = NotB;
        }
        std::string R = NextVal();
        OS << "  " << R << " = or i64 " << A << ", " << B << "\n";
        StoreGPRDest(CodeNode, MaskToOpSize(R, OpSize));
        break;
      }

      case FEXCore::IR::OP_EXTR: {
        auto* Op = IROp->C<FEXCore::IR::IROp_Extr>();
        std::string Upper = MaskToOpSize(LoadGPROperand(Op->Upper), OpSize);
        std::string Lower = MaskToOpSize(LoadGPROperand(Op->Lower), OpSize);
        std::string R = NextVal();
        if (Bits == 32) {
          std::string ShU = NextVal(), Comb = NextVal(), Shr = NextVal();
          OS << "  " << ShU << " = shl i64 " << Upper << ", 32\n";
          OS << "  " << Comb << " = or i64 " << ShU << ", " << Lower << "\n";
          OS << "  " << Shr << " = lshr i64 " << Comb << ", " << unsigned(Op->LSB & 31) << "\n";
          R = MaskToOpSize(Shr, OpSize);
        } else {
          OS << "  " << R << " = call i64 @llvm.fshr.i64(i64 " << Upper << ", i64 " << Lower << ", i64 " << unsigned(Op->LSB & 63) << ")\n";
        }
        StoreGPRDest(CodeNode, R);
        break;
      }

      case FEXCore::IR::OP_AND:
      case FEXCore::IR::OP_ANDWITHFLAGS:
      case FEXCore::IR::OP_TESTNZ: {
        auto* Op = IROp->C<FEXCore::IR::IROp_And>();
        std::string A = LoadGPROperand(Op->Src1);
        std::string B = LoadGPROperand(Op->Src2);
        std::string R = NextVal();
        OS << "  " << R << " = and i64 " << A << ", " << B << "\n";
        R = MaskToOpSize(R, OpSize);
        if (IROp->Op != FEXCore::IR::OP_AND) {
          unsigned FlgBits = (Bits <= 64 && Bits >= 8) ? Bits : 64;
          std::string RTr = R;
          std::string Ty = "i" + std::to_string(FlgBits);
          if (FlgBits < 64) {
            RTr = NextVal();
            OS << "  " << RTr << " = trunc i64 " << R << " to " << Ty << "\n";
          }
          std::string NBit = NextVal(), ZBit = NextVal(), N64 = NextVal(), Z64 = NextVal(), NS = NextVal(), ZS = NextVal(), OrNZ = NextVal();
          OS << "  " << NBit << " = icmp slt " << Ty << " " << RTr << ", 0\n";
          OS << "  " << ZBit << " = icmp eq " << Ty << " " << RTr << ", 0\n";
          OS << "  " << N64 << " = zext i1 " << NBit << " to i64\n";
          OS << "  " << Z64 << " = zext i1 " << ZBit << " to i64\n";
          OS << "  " << NS << " = shl i64 " << N64 << ", 31\n";
          OS << "  " << ZS << " = shl i64 " << Z64 << ", 30\n";
          OS << "  " << OrNZ << " = or i64 " << NS << ", " << ZS << "\n";
          OS << "  store i64 " << OrNZ << ", ptr %nzcv_reg, align 8\n";
          UnconsumedNonRspFlags = !DestinationIsGuestRSP(CodeNode);
        }
        if (IROp->Op != FEXCore::IR::OP_TESTNZ) {
          StoreGPRDest(CodeNode, R);
        }
        break;
      }

      case FEXCore::IR::OP_ANDN: {
        auto* Op = IROp->C<FEXCore::IR::IROp_Andn>();
        std::string A = LoadGPROperand(Op->Src1);
        std::string B = LoadGPROperand(Op->Src2);
        std::string NotB = NextVal(), R = NextVal();
        OS << "  " << NotB << " = xor i64 " << B << ", -1\n";
        OS << "  " << R << " = and i64 " << A << ", " << NotB << "\n";
        StoreGPRDest(CodeNode, MaskToOpSize(R, OpSize));
        break;
      }

      case FEXCore::IR::OP_OR: {
        auto* Op = IROp->C<FEXCore::IR::IROp_Or>();
        std::string A = LoadGPROperand(Op->Src1);
        std::string B = LoadGPROperand(Op->Src2);
        std::string R = NextVal();
        OS << "  " << R << " = or i64 " << A << ", " << B << "\n";
        StoreGPRDest(CodeNode, MaskToOpSize(R, OpSize));
        break;
      }

      case FEXCore::IR::OP_XOR: {
        auto* Op = IROp->C<FEXCore::IR::IROp_Xor>();
        std::string A = LoadGPROperand(Op->Src1);
        std::string B = LoadGPROperand(Op->Src2);
        std::string R = NextVal();
        OS << "  " << R << " = xor i64 " << A << ", " << B << "\n";
        StoreGPRDest(CodeNode, MaskToOpSize(R, OpSize));
        break;
      }

      case FEXCore::IR::OP_NOT: {
        auto* Op = IROp->C<FEXCore::IR::IROp_Not>();
        std::string A = LoadGPROperand(Op->Src);
        std::string R = NextVal();
        OS << "  " << R << " = xor i64 " << A << ", -1\n";
        StoreGPRDest(CodeNode, MaskToOpSize(R, OpSize));
        break;
      }

      case FEXCore::IR::OP_LSHL: {
        auto* Op = IROp->C<FEXCore::IR::IROp_Lshl>();
        std::string A = LoadGPROperand(Op->Src1);
        std::string B = LoadGPROperand(Op->Src2);
        std::string MaskB = NextVal(), R = NextVal();
        OS << "  " << MaskB << " = and i64 " << B << ", " << (Bits == 32 ? 31 : 63) << "\n";
        OS << "  " << R << " = shl i64 " << A << ", " << MaskB << "\n";
        StoreGPRDest(CodeNode, MaskToOpSize(R, OpSize));
        break;
      }

      case FEXCore::IR::OP_LSHR: {
        auto* Op = IROp->C<FEXCore::IR::IROp_Lshr>();
        std::string A = MaskToOpSize(LoadGPROperand(Op->Src1), OpSize);
        std::string B = LoadGPROperand(Op->Src2);
        std::string MaskB = NextVal(), R = NextVal();
        OS << "  " << MaskB << " = and i64 " << B << ", " << (Bits == 32 ? 31 : 63) << "\n";
        OS << "  " << R << " = lshr i64 " << A << ", " << MaskB << "\n";
        StoreGPRDest(CodeNode, MaskToOpSize(R, OpSize));
        break;
      }

      case FEXCore::IR::OP_ASHR: {
        auto* Op = IROp->C<FEXCore::IR::IROp_Ashr>();
        std::string A = LoadGPROperand(Op->Src1);
        std::string B = LoadGPROperand(Op->Src2);
        if (Bits == 32) {
          std::string A32 = NextVal(), B32 = NextVal(), M32 = NextVal(), R32 = NextVal(), R64 = NextVal();
          OS << "  " << A32 << " = trunc i64 " << A << " to i32\n";
          OS << "  " << B32 << " = trunc i64 " << B << " to i32\n";
          OS << "  " << M32 << " = and i32 " << B32 << ", 31\n";
          OS << "  " << R32 << " = ashr i32 " << A32 << ", " << M32 << "\n";
          OS << "  " << R64 << " = zext i32 " << R32 << " to i64\n";
          StoreGPRDest(CodeNode, R64);
        } else {
          std::string MaskB = NextVal(), R = NextVal();
          OS << "  " << MaskB << " = and i64 " << B << ", 63\n";
          OS << "  " << R << " = ashr i64 " << A << ", " << MaskB << "\n";
          StoreGPRDest(CodeNode, R);
        }
        break;
      }

      case FEXCore::IR::OP_ROR: {
        auto* Op = IROp->C<FEXCore::IR::IROp_Ror>();
        std::string A = MaskToOpSize(LoadGPROperand(Op->Src1), OpSize);
        std::string B = LoadGPROperand(Op->Src2);
        std::string R = NextVal();
        OS << "  " << R << " = call i64 @llvm.fshr.i64(i64 " << A << ", i64 " << A << ", i64 " << B << ")\n";
        StoreGPRDest(CodeNode, MaskToOpSize(R, OpSize));
        break;
      }

      case FEXCore::IR::OP_BFE: {
        auto* Op = IROp->C<FEXCore::IR::IROp_Bfe>();
        std::string Src = LoadGPROperand(Op->Src);
        if (Op->lsb > 0) {
          std::string Sh = NextVal();
          OS << "  " << Sh << " = lshr i64 " << Src << ", " << unsigned(Op->lsb) << "\n";
          Src = Sh;
        }
        if (Op->Width < 64) {
          uint64_t Mask = (Op->Width == 0) ? 0ULL : ((1ULL << Op->Width) - 1ULL);
          std::string M = NextVal();
          OS << "  " << M << " = and i64 " << Src << ", " << Mask << "\n";
          Src = M;
        }
        StoreGPRDest(CodeNode, Src);
        break;
      }

      case FEXCore::IR::OP_SBFE: {
        auto* Op = IROp->C<FEXCore::IR::IROp_Sbfe>();
        std::string Src = LoadGPROperand(Op->Src);
        unsigned LeftShift = 64 - (Op->lsb + Op->Width);
        unsigned RightShift = 64 - Op->Width;
        if (LeftShift < 64 && RightShift < 64) {
          std::string L = NextVal(), R = NextVal();
          OS << "  " << L << " = shl i64 " << Src << ", " << LeftShift << "\n";
          OS << "  " << R << " = ashr i64 " << L << ", " << RightShift << "\n";
          Src = R;
        }
        StoreGPRDest(CodeNode, MaskToOpSize(Src, OpSize));
        break;
      }

      case FEXCore::IR::OP_BFI: {
        auto* Op = IROp->C<FEXCore::IR::IROp_Bfi>();
        std::string Dst = LoadGPROperand(Op->Dest);
        std::string Src = LoadGPROperand(Op->Src);
        uint64_t FieldMask = (Op->Width >= 64) ? ~0ULL : ((1ULL << Op->Width) - 1ULL);
        uint64_t ShiftedMask = FieldMask << Op->lsb;
        std::string MaskedSrc = NextVal(), ShiftedSrc = NextVal(), ClearedDst = NextVal(), R = NextVal();
        OS << "  " << MaskedSrc << " = and i64 " << Src << ", " << FieldMask << "\n";
        OS << "  " << ShiftedSrc << " = shl i64 " << MaskedSrc << ", " << unsigned(Op->lsb) << "\n";
        OS << "  " << ClearedDst << " = and i64 " << Dst << ", " << static_cast<int64_t>(~ShiftedMask) << "\n";
        OS << "  " << R << " = or i64 " << ClearedDst << ", " << ShiftedSrc << "\n";
        StoreGPRDest(CodeNode, MaskToOpSize(R, OpSize));
        break;
      }

      case FEXCore::IR::OP_BFXIL: {
        auto* Op = IROp->C<FEXCore::IR::IROp_Bfxil>();
        std::string Dst = LoadGPROperand(Op->Dest);
        std::string Src = LoadGPROperand(Op->Src);
        uint64_t FieldMask = (Op->Width >= 64) ? ~0ULL : ((1ULL << Op->Width) - 1ULL);
        if (Op->lsb > 0) {
          std::string Sh = NextVal();
          OS << "  " << Sh << " = lshr i64 " << Src << ", " << unsigned(Op->lsb) << "\n";
          Src = Sh;
        }
        std::string MaskedSrc = NextVal(), ClearedDst = NextVal(), R = NextVal();
        OS << "  " << MaskedSrc << " = and i64 " << Src << ", " << FieldMask << "\n";
        OS << "  " << ClearedDst << " = and i64 " << Dst << ", " << static_cast<int64_t>(~FieldMask) << "\n";
        OS << "  " << R << " = or i64 " << ClearedDst << ", " << MaskedSrc << "\n";
        StoreGPRDest(CodeNode, MaskToOpSize(R, OpSize));
        break;
      }

      case FEXCore::IR::OP_MUL:
      case FEXCore::IR::OP_UMUL: {
        auto* Op = IROp->C<FEXCore::IR::IROp_Mul>();
        std::string A = LoadGPROperand(Op->Src1);
        std::string B = LoadGPROperand(Op->Src2);
        std::string R = NextVal();
        OS << "  " << R << " = mul i64 " << A << ", " << B << "\n";
        StoreGPRDest(CodeNode, MaskToOpSize(R, OpSize));
        break;
      }

      case FEXCore::IR::OP_MULH:
      case FEXCore::IR::OP_UMULH: {
        auto* Op = IROp->C<FEXCore::IR::IROp_UMulH>();
        std::string A = LoadGPROperand(Op->Src1);
        std::string B = LoadGPROperand(Op->Src2);
        const char* ExtOp = (IROp->Op == FEXCore::IR::OP_MULH) ? "sext" : "zext";
        std::string A128 = NextVal(), B128 = NextVal(), P128 = NextVal(), Sh128 = NextVal(), R = NextVal();
        OS << "  " << A128 << " = " << ExtOp << " i64 " << A << " to i128\n";
        OS << "  " << B128 << " = " << ExtOp << " i64 " << B << " to i128\n";
        OS << "  " << P128 << " = mul i128 " << A128 << ", " << B128 << "\n";
        OS << "  " << Sh128 << " = lshr i128 " << P128 << ", 64\n";
        OS << "  " << R << " = trunc i128 " << Sh128 << " to i64\n";
        StoreGPRDest(CodeNode, R);
        break;
      }

      case FEXCore::IR::OP_SELECT: {
        auto* Op = IROp->C<FEXCore::IR::IROp_Select>();
        std::string C1 = LoadGPROperand(Op->Cmp1);
        std::string C2 = LoadGPROperand(Op->Cmp2);
        unsigned CmpBits = OpSizeToBits(Op->CompareSize);
        if (CmpBits == 32) {
          C1 = MaskToOpSize(C1, FEXCore::IR::OpSize::i32Bit);
          C2 = MaskToOpSize(C2, FEXCore::IR::OpSize::i32Bit);
        }
        std::string CondBit = NextVal();
        if (Op->Cond == FEXCore::IR::CondClass::TSTZ || Op->Cond == FEXCore::IR::CondClass::TSTNZ) {
          std::string MaskBit = NextVal(), Sh = NextVal(), BitVal = NextVal();
          OS << "  " << MaskBit << " = and i64 " << C2 << ", 63\n";
          OS << "  " << Sh << " = lshr i64 " << C1 << ", " << MaskBit << "\n";
          OS << "  " << BitVal << " = and i64 " << Sh << ", 1\n";
          const char* Pred = (Op->Cond == FEXCore::IR::CondClass::TSTZ) ? "eq" : "ne";
          OS << "  " << CondBit << " = icmp " << Pred << " i64 " << BitVal << ", 0\n";
        } else {
          const char* Pred = "eq";
          switch (Op->Cond) {
          case FEXCore::IR::CondClass::EQ: Pred = "eq"; break;
          case FEXCore::IR::CondClass::NEQ: Pred = "ne"; break;
          case FEXCore::IR::CondClass::UGE: case FEXCore::IR::CondClass::FGE: Pred = "uge"; break;
          case FEXCore::IR::CondClass::ULT: case FEXCore::IR::CondClass::FLU: Pred = "ult"; break;
          case FEXCore::IR::CondClass::UGT: case FEXCore::IR::CondClass::FGT: Pred = "ugt"; break;
          case FEXCore::IR::CondClass::ULE: case FEXCore::IR::CondClass::FLEU: Pred = "ule"; break;
          case FEXCore::IR::CondClass::SGE: Pred = "sge"; break;
          case FEXCore::IR::CondClass::SLT: Pred = "slt"; break;
          case FEXCore::IR::CondClass::SGT: Pred = "sgt"; break;
          case FEXCore::IR::CondClass::SLE: Pred = "sle"; break;
          default: Pred = "ne"; break;
          }
          OS << "  " << CondBit << " = icmp " << Pred << " i64 " << C1 << ", " << C2 << "\n";
        }
        std::string TV = LoadGPROperand(Op->TrueVal);
        std::string FV = LoadGPROperand(Op->FalseVal);
        std::string R = NextVal();
        OS << "  " << R << " = select i1 " << CondBit << ", i64 " << TV << ", i64 " << FV << "\n";
        StoreGPRDest(CodeNode, MaskToOpSize(R, OpSize));
        break;
      }

      case FEXCore::IR::OP_UMULL:
      case FEXCore::IR::OP_SMULL: {
        auto* Op = IROp->C<FEXCore::IR::IROp_UMull>();
        std::string Src1 = LoadGPROperand(Op->Src1);
        std::string Src2 = LoadGPROperand(Op->Src2);
        std::string A32 = NextVal(), B32 = NextVal(), A64 = NextVal(), B64 = NextVal(), R = NextVal();
        const char* ExtOp = (IROp->Op == FEXCore::IR::OP_SMULL) ? "sext" : "zext";
        OS << "  " << A32 << " = trunc i64 " << Src1 << " to i32\n";
        OS << "  " << B32 << " = trunc i64 " << Src2 << " to i32\n";
        OS << "  " << A64 << " = " << ExtOp << " i32 " << A32 << " to i64\n";
        OS << "  " << B64 << " = " << ExtOp << " i32 " << B32 << " to i64\n";
        OS << "  " << R << " = mul i64 " << A64 << ", " << B64 << "\n";
        StoreGPRDest(CodeNode, R);
        break;
      }

      case FEXCore::IR::OP_DIV:
      case FEXCore::IR::OP_UDIV: {
        auto* Op = IROp->C<FEXCore::IR::IROp_Div>();
        std::string Low = LoadGPROperand(Op->Lower);
        std::string High = Op->Upper.IsInvalid() ? "0" : LoadGPROperand(Op->Upper);
        std::string Div = LoadGPROperand(Op->Divisor);
        auto [Quot, Rem] = Rellume.LiftDiv(Low, High, !Op->Upper.IsInvalid(), Div,
                                           OpSizeToBits(OpSize), IROp->Op == FEXCore::IR::OP_DIV);
        StoreGPRWrapper(Op->OutQuotient, MaskToOpSize(Quot, OpSize));
        StoreGPRWrapper(Op->OutRemainder, MaskToOpSize(Rem, OpSize));
        break;
      }

      case FEXCore::IR::OP_JUMP: {
        auto* Op = IROp->C<FEXCore::IR::IROp_Jump>();
        uint32_t TargetId = BlockNodeToId[Op->TargetBlock.ID().Value];
        OS << "  br label %bb_" << TargetId << "\n";
        BlockTerminated = true;
        break;
      }

      case FEXCore::IR::OP_CONDJUMP: {
        auto* Op = IROp->C<FEXCore::IR::IROp_CondJump>();
        uint32_t TrueId = BlockNodeToId[Op->TrueBlock.ID().Value];
        uint32_t FalseId = BlockNodeToId[Op->FalseBlock.ID().Value];
        std::string CondBit;
        if (Op->FromNZCV) {
          CondBit = EvaluateNZCVCond(Op->Cond);
          UnconsumedNonRspFlags = false;
        } else {
          std::string C1 = LoadGPROperand(Op->Cmp1);
          std::string C2 = LoadGPROperand(Op->Cmp2);
          unsigned CmpBits = OpSizeToBits(Op->CompareSize);
          if (CmpBits == 32) {
            C1 = MaskToOpSize(C1, FEXCore::IR::OpSize::i32Bit);
            C2 = MaskToOpSize(C2, FEXCore::IR::OpSize::i32Bit);
          }
          CondBit = NextVal();
          if (Op->Cond == FEXCore::IR::CondClass::TSTZ || Op->Cond == FEXCore::IR::CondClass::TSTNZ) {
            std::string MaskBit = NextVal(), Sh = NextVal(), BitVal = NextVal();
            OS << "  " << MaskBit << " = and i64 " << C2 << ", 63\n";
            OS << "  " << Sh << " = lshr i64 " << C1 << ", " << MaskBit << "\n";
            OS << "  " << BitVal << " = and i64 " << Sh << ", 1\n";
            const char* Pred = (Op->Cond == FEXCore::IR::CondClass::TSTZ) ? "eq" : "ne";
            OS << "  " << CondBit << " = icmp " << Pred << " i64 " << BitVal << ", 0\n";
          } else {
            const char* Pred = "ne";
            switch (Op->Cond) {
            case FEXCore::IR::CondClass::EQ: Pred = "eq"; break;
            case FEXCore::IR::CondClass::NEQ: Pred = "ne"; break;
            case FEXCore::IR::CondClass::UGE: case FEXCore::IR::CondClass::FGE: Pred = "uge"; break;
            case FEXCore::IR::CondClass::ULT: case FEXCore::IR::CondClass::FLU: Pred = "ult"; break;
            case FEXCore::IR::CondClass::UGT: case FEXCore::IR::CondClass::FGT: Pred = "ugt"; break;
            case FEXCore::IR::CondClass::ULE: case FEXCore::IR::CondClass::FLEU: Pred = "ule"; break;
            case FEXCore::IR::CondClass::SGE: Pred = "sge"; break;
            case FEXCore::IR::CondClass::SLT: Pred = "slt"; break;
            case FEXCore::IR::CondClass::SGT: Pred = "sgt"; break;
            case FEXCore::IR::CondClass::SLE: Pred = "sle"; break;
            default: Pred = "ne"; break;
            }
            OS << "  " << CondBit << " = icmp " << Pred << " i64 " << C1 << ", " << C2 << "\n";
          }
        }
        OS << "  br i1 " << CondBit << ", label %bb_" << TrueId << ", label %bb_" << FalseId << "\n";
        BlockTerminated = true;
        break;
      }

      case FEXCore::IR::OP_EXITFUNCTION: {
        auto* Op = IROp->C<FEXCore::IR::IROp_ExitFunction>();
        LiftedFunctionIR::ExitSite Site {};
        Site.ExitId = static_cast<uint32_t>(Result.ExitSites.size());
        Site.Hint = static_cast<uint8_t>(Op->Hint);
        Site.PatchSiteAddress = Op->PatchSiteAddress;
        Site.PatchSiteSize = Op->PatchSiteSize;

        // Check if NewRIP is an inline constant or inline entrypoint offset
        if (Op->NewRIP.IsPointer()) {
          auto* RipHdr = IR.GetOp<FEXCore::IR::IROp_Header>(Op->NewRIP);
          if (RipHdr->Op == FEXCore::IR::OP_INLINECONSTANT) {
            Site.IsDirect = true;
            Site.DirectNewRIP = RipHdr->C<FEXCore::IR::IROp_InlineConstant>()->Constant;
          } else if (RipHdr->Op == FEXCore::IR::OP_INLINEENTRYPOINTOFFSET) {
            Site.IsDirect = true;
            Site.DirectNewRIP = GuestEntryVA + RipHdr->C<FEXCore::IR::IROp_InlineEntrypointOffset>()->Offset;
          }
        }
        if (Op->CallReturnAddress.IsPointer()) {
          auto* RetHdr = IR.GetOp<FEXCore::IR::IROp_Header>(Op->CallReturnAddress);
          if (RetHdr->Op == FEXCore::IR::OP_INLINEENTRYPOINTOFFSET) {
            Site.CallReturnAddress = GuestEntryVA + RetHdr->C<FEXCore::IR::IROp_InlineEntrypointOffset>()->Offset;
          } else if (RetHdr->Op == FEXCore::IR::OP_INLINECONSTANT) {
            Site.CallReturnAddress = RetHdr->C<FEXCore::IR::IROp_InlineConstant>()->Constant;
          }
        }
        if (!Op->CallReturnBlock.IsInvalid()) {
          auto It = BlockNodeToId.find(Op->CallReturnBlock.ID().Value);
          if (It != BlockNodeToId.end()) {
            Site.HasCallReturnBlock = true;
            Site.CallReturnBlockId = It->second;
          }
        }

        std::string IndirectRipVal = Site.IsDirect ? "0" : LoadGPROperand(Op->NewRIP);
        Result.ExitSites.push_back(Site);

        std::string OutGprs[18];
        for (int i = 0; i < 18; ++i) {
          OutGprs[i] = NextVal();
          OS << "  " << OutGprs[i] << " = load i64, ptr %sra_gpr_" << i << ", align 8\n";
        }
        std::string OutCrsp = NextVal();
        OS << "  " << OutCrsp << " = load i64, ptr %callret_sp_reg, align 8\n";

        if (UsesFPR) {
          std::string OutFprs[16];
          for (int i = 0; i < 16; ++i) {
            OutFprs[i] = NextVal();
            OS << "  " << OutFprs[i] << " = load <2 x i64>, ptr %sra_fpr_" << i << ", align 16\n";
          }
          OS << "  call void asm sideeffect \"\", "
                "\"{q0},{q1},{q2},{q3},{q4},{q5},{q6},{q7},{q8},{q9},{q10},{q11},{q12},{q13},{q14},{q15}\"(\n"
             << "    <2 x i64> " << OutFprs[0] << ", <2 x i64> " << OutFprs[1] << ", <2 x i64> " << OutFprs[2] << ", <2 x i64> " << OutFprs[3] << ",\n"
             << "    <2 x i64> " << OutFprs[4] << ", <2 x i64> " << OutFprs[5] << ", <2 x i64> " << OutFprs[6] << ", <2 x i64> " << OutFprs[7] << ",\n"
             << "    <2 x i64> " << OutFprs[8] << ", <2 x i64> " << OutFprs[9] << ", <2 x i64> " << OutFprs[10] << ", <2 x i64> " << OutFprs[11] << ",\n"
             << "    <2 x i64> " << OutFprs[12] << ", <2 x i64> " << OutFprs[13] << ", <2 x i64> " << OutFprs[14] << ", <2 x i64> " << OutFprs[15] << ")\n";
        }

        uint32_t MarkerInst = 0x00005000u | (Site.ExitId & 0x0FFFu);
        char MarkerHex[32];
        snprintf(MarkerHex, sizeof(MarkerHex), "0x%08x", MarkerInst);

        // Target-specialized exit ABI lowering:
        // In ARM64EC_NATIVE mode, across standard Call and Return exits where no unconsumed
        // non-RSP flags are live-out, RFLAGS (NZCV) is caller-saved (killed by the ABI / RSP epilogue).
        // Omitting the dead `%nzcv_reg` load and `msr nzcv, x10` lets LLVM's SROA/InstCombine/ADCE
        // fold `PackNZCVFromAddSub` + `EvaluateNZCVCond` into a single native AArch64 `cmp` + `b.cond`
        // and completely delete dead epilogue flag packing!
        const bool IsCallOrRet = (Op->Hint == FEXCore::IR::BranchHint::Call ||
                                  Op->Hint == FEXCore::IR::BranchHint::Return);
        if (IsArm64ECNative && IsCallOrRet && !UnconsumedNonRspFlags) {
          OS << "  call void asm sideeffect \".inst " << MarkerHex << "\", "
                "\"{x8},{x0},{x1},{x27},{x23},{fp},{x25},{x26},{x2},{x3},{x4},{x5},{x19},{x20},{x21},{x22},{x17},{x16},~{memory}\"(\n"
             << "    i64 " << OutGprs[0] << ", i64 " << OutGprs[1] << ", i64 " << OutGprs[2] << ", i64 " << OutGprs[3] << ",\n"
             << "    i64 " << OutGprs[4] << ", i64 " << OutGprs[5] << ", i64 " << OutGprs[6] << ", i64 " << OutGprs[7] << ",\n"
             << "    i64 " << OutGprs[8] << ", i64 " << OutGprs[9] << ", i64 " << OutGprs[10] << ", i64 " << OutGprs[11] << ",\n"
             << "    i64 " << OutGprs[12] << ", i64 " << OutGprs[13] << ", i64 " << OutGprs[14] << ", i64 " << OutGprs[15] << ",\n"
             << "    i64 " << OutCrsp << ", i64 " << IndirectRipVal << ")\n";
        } else {
          std::string OutNzcv = NextVal();
          OS << "  " << OutNzcv << " = load i64, ptr %nzcv_reg, align 8\n";
          OS << "  call void asm sideeffect \"msr nzcv, x10 ; .inst " << MarkerHex << "\", "
                "\"{x8},{x0},{x1},{x27},{x23},{fp},{x25},{x26},{x2},{x3},{x4},{x5},{x19},{x20},{x21},{x22},{x9},{x24},{x17},{x16},{x10},~{memory}\"(\n"
             << "    i64 " << OutGprs[0] << ", i64 " << OutGprs[1] << ", i64 " << OutGprs[2] << ", i64 " << OutGprs[3] << ",\n"
             << "    i64 " << OutGprs[4] << ", i64 " << OutGprs[5] << ", i64 " << OutGprs[6] << ", i64 " << OutGprs[7] << ",\n"
             << "    i64 " << OutGprs[8] << ", i64 " << OutGprs[9] << ", i64 " << OutGprs[10] << ", i64 " << OutGprs[11] << ",\n"
             << "    i64 " << OutGprs[12] << ", i64 " << OutGprs[13] << ", i64 " << OutGprs[14] << ", i64 " << OutGprs[15] << ",\n"
             << "    i64 " << OutGprs[16] << ", i64 " << OutGprs[17] << ", i64 " << OutCrsp << ", i64 " << IndirectRipVal << ", i64 " << OutNzcv << ")\n";
        }
        OS << "  ret void\n";
        BlockTerminated = true;
        break;
      }

      case FEXCore::IR::OP_POPCOUNT: {
        auto* Op = IROp->C<FEXCore::IR::IROp_Popcount>();
        std::string Src = MaskToOpSize(LoadGPROperand(Op->Src), OpSize);
        std::string Res = NextVal();
        OS << "  " << Res << " = call i64 @llvm.ctpop.i64(i64 " << Src << ")\n";
        StoreGPRDest(CodeNode, Res);
        break;
      }

      case FEXCore::IR::OP_FINDLSB: {
        auto* Op = IROp->C<FEXCore::IR::IROp_FindLSB>();
        std::string Src = MaskToOpSize(LoadGPROperand(Op->Src), OpSize);
        std::string Res = NextVal();
        OS << "  " << Res << " = call i64 @llvm.cttz.i64(i64 " << Src << ", i1 false)\n";
        StoreGPRDest(CodeNode, Res);
        break;
      }

      case FEXCore::IR::OP_COUNTLEADINGZEROES: {
        auto* Op = IROp->C<FEXCore::IR::IROp_CountLeadingZeroes>();
        std::string Src = LoadGPROperand(Op->Src);
        unsigned OpBits = (Bits <= 64 && Bits >= 16) ? Bits : 64;
        if (OpBits < 64) {
          std::string Tr = NextVal(), Clz = NextVal(), Z = NextVal();
          OS << "  " << Tr << " = trunc i64 " << Src << " to i" << OpBits << "\n";
          OS << "  " << Clz << " = call i" << OpBits << " @llvm.ctlz.i" << OpBits << "(i" << OpBits << " " << Tr << ", i1 false)\n";
          OS << "  " << Z << " = zext i" << OpBits << " " << Clz << " to i64\n";
          StoreGPRDest(CodeNode, Z);
        } else {
          std::string Clz = NextVal();
          OS << "  " << Clz << " = call i64 @llvm.ctlz.i64(i64 " << Src << ", i1 false)\n";
          StoreGPRDest(CodeNode, Clz);
        }
        break;
      }

      case FEXCore::IR::OP_RBIT: {
        auto* Op = IROp->C<FEXCore::IR::IROp_Rbit>();
        std::string Src = LoadGPROperand(Op->Src);
        if (Bits == 32) {
          std::string Tr = NextVal(), Rb = NextVal(), Z = NextVal();
          OS << "  " << Tr << " = trunc i64 " << Src << " to i32\n";
          OS << "  " << Rb << " = call i32 @llvm.bitreverse.i32(i32 " << Tr << ")\n";
          OS << "  " << Z << " = zext i32 " << Rb << " to i64\n";
          StoreGPRDest(CodeNode, Z);
        } else {
          std::string Rb = NextVal();
          OS << "  " << Rb << " = call i64 @llvm.bitreverse.i64(i64 " << Src << ")\n";
          StoreGPRDest(CodeNode, Rb);
        }
        break;
      }

      case FEXCore::IR::OP_MASKGENERATEFROMBITWIDTH: {
        auto* Op = IROp->C<FEXCore::IR::IROp_MaskGenerateFromBitWidth>();
        std::string BW = LoadGPROperand(Op->BitWidth);
        std::string IsZero = NextVal(), Sh = NextVal(), Inv = NextVal(), Res = NextVal();
        OS << "  " << IsZero << " = icmp eq i64 " << BW << ", 0\n";
        OS << "  " << Sh << " = shl i64 -1, " << BW << "\n";
        OS << "  " << Inv << " = xor i64 " << Sh << ", -1\n";
        OS << "  " << Res << " = select i1 " << IsZero << ", i64 0, i64 " << Inv << "\n";
        StoreGPRDest(CodeNode, Res);
        break;
      }

      case FEXCore::IR::OP_FINDMSB: {
        auto* Op = IROp->C<FEXCore::IR::IROp_FindMSB>();
        std::string Src = LoadGPROperand(Op->Src);
        unsigned OpBits = (Bits <= 64 && Bits >= 16) ? Bits : 64;
        std::string Val = Src;
        if (OpBits < 64) {
          std::string Tr = NextVal(), Clz = NextVal(), Z = NextVal();
          OS << "  " << Tr << " = trunc i64 " << Src << " to i" << OpBits << "\n";
          OS << "  " << Clz << " = call i" << OpBits << " @llvm.ctlz.i" << OpBits << "(i" << OpBits << " " << Tr << ", i1 false)\n";
          OS << "  " << Z << " = zext i" << OpBits << " " << Clz << " to i64\n";
          Val = Z;
        } else {
          std::string Clz = NextVal();
          OS << "  " << Clz << " = call i64 @llvm.ctlz.i64(i64 " << Src << ", i1 false)\n";
          Val = Clz;
        }
        std::string Res = NextVal();
        OS << "  " << Res << " = sub i64 " << (OpBits - 1) << ", " << Val << "\n";
        StoreGPRDest(CodeNode, Res);
        break;
      }

      case FEXCore::IR::OP_FINDTRAILINGZEROES: {
        auto* Op = IROp->C<FEXCore::IR::IROp_FindTrailingZeroes>();
        std::string Src = LoadGPROperand(Op->Src);
        unsigned OpBits = (Bits <= 64 && Bits >= 16) ? Bits : 64;
        if (OpBits < 64) {
          std::string Tr = NextVal(), Ctz = NextVal(), Z = NextVal();
          OS << "  " << Tr << " = trunc i64 " << Src << " to i" << OpBits << "\n";
          OS << "  " << Ctz << " = call i" << OpBits << " @llvm.cttz.i" << OpBits << "(i" << OpBits << " " << Tr << ", i1 false)\n";
          OS << "  " << Z << " = zext i" << OpBits << " " << Ctz << " to i64\n";
          StoreGPRDest(CodeNode, Z);
        } else {
          std::string Ctz = NextVal();
          OS << "  " << Ctz << " = call i64 @llvm.cttz.i64(i64 " << Src << ", i1 false)\n";
          StoreGPRDest(CodeNode, Ctz);
        }
        break;
      }

      case FEXCore::IR::OP_REV: {
        auto* Op = IROp->C<FEXCore::IR::IROp_Rev>();
        std::string Src = LoadGPROperand(Op->Src);
        unsigned OpBits = (Bits <= 64 && Bits >= 16) ? Bits : 64;
        if (OpBits < 64) {
          std::string Tr = NextVal(), Bsw = NextVal(), Z = NextVal();
          OS << "  " << Tr << " = trunc i64 " << Src << " to i" << OpBits << "\n";
          OS << "  " << Bsw << " = call i" << OpBits << " @llvm.bswap.i" << OpBits << "(i" << OpBits << " " << Tr << ")\n";
          OS << "  " << Z << " = zext i" << OpBits << " " << Bsw << " to i64\n";
          StoreGPRDest(CodeNode, Z);
        } else {
          std::string Bsw = NextVal();
          OS << "  " << Bsw << " = call i64 @llvm.bswap.i64(i64 " << Src << ")\n";
          StoreGPRDest(CodeNode, Bsw);
        }
        break;
      }

      case FEXCore::IR::OP_BREAK: {
        LiftedFunctionIR::ExitSite Site {};
        Site.ExitId = static_cast<uint32_t>(Result.ExitSites.size());
        Site.IsDirect = true;
        Site.DirectNewRIP = GuestEntryVA;
        Result.ExitSites.push_back(Site);
        uint32_t MarkerInst = 0x00005000u | (Site.ExitId & 0x0FFFu);
        char MarkerHex[32];
        snprintf(MarkerHex, sizeof(MarkerHex), "0x%08x", MarkerInst);
        OS << "  call void asm sideeffect \".inst " << MarkerHex << "\", \"\"()\n";
        OS << "  ret void\n";
        BlockTerminated = true;
        break;
      }

  default:
    return false;
  }
  return true;
}

} // namespace FEXCore::AOT

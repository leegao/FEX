// SPDX-License-Identifier: MIT
#include "Interface/Core/AOT/LLVM/Lifter.h"

namespace FEXCore::AOT {

using LiftedFunctionIR = LLVMArm64ECAOTCompiler::LiftedFunctionIR;

bool LiftMemoryOp(LifterContext& Ctx, FEXCore::IR::Ref CodeNode, const FEXCore::IR::IROp_Header* IROp) {
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
      case FEXCore::IR::OP_LOADREGISTER: {
        auto* Op = IROp->C<FEXCore::IR::IROp_LoadRegister>();
        if (Op->Class == FEXCore::IR::RegClass::GPR && Op->Reg < 18) {
          std::string V = NextVal();
          OS << "  " << V << " = load i64, ptr %sra_gpr_" << Op->Reg << ", align 8\n";
          StoreGPRDest(CodeNode, V);
        } else if (Op->Class == FEXCore::IR::RegClass::FPR && UsesFPR && Op->Reg < 16) {
          std::string V = NextVal();
          OS << "  " << V << " = load <2 x i64>, ptr %sra_fpr_" << Op->Reg << ", align 16\n";
          StoreFPRDest(CodeNode, V);
        }
        break;
      }

      case FEXCore::IR::OP_STOREREGISTER: {
        auto* Op = IROp->C<FEXCore::IR::IROp_StoreRegister>();
        FEXCore::IR::PhysicalRegister PR(CodeNode);
        if (PR.AsRegClass() == FEXCore::IR::RegClass::FPRFixed) {
          StoreFPRDest(CodeNode, LoadFPROperand(Op->Value));
        } else {
          StoreGPRDest(CodeNode, LoadGPROperand(Op->Value));
        }
        break;
      }

      case FEXCore::IR::OP_LOADCONTEXT: {
        auto* Op = IROp->C<FEXCore::IR::IROp_LoadContext>();
        std::string Addr = NextVal(), Ptr = NextVal();
        OS << "  " << Addr << " = add i64 %state_ptr_int, " << Op->Offset << "\n";
        OS << "  " << Ptr << " = inttoptr i64 " << Addr << " to ptr\n";
        if (Op->Class == FEXCore::IR::RegClass::GPR) {
          std::string V = NextVal();
          unsigned LoadBits = (Bits <= 64 && Bits >= 8) ? Bits : 64;
          OS << "  " << V << " = load i" << LoadBits << ", ptr " << Ptr << ", align 1\n";
          if (LoadBits < 64) {
            std::string Z = NextVal();
            OS << "  " << Z << " = zext i" << LoadBits << " " << V << " to i64\n";
            V = Z;
          }
          StoreGPRDest(CodeNode, V);
        } else if (UsesFPR) {
          if (Bits == 8 || Bits == 16 || Bits == 32 || Bits == 64) {
            std::string V = NextVal(), Z = NextVal(), Vec = NextVal();
            OS << "  " << V << " = load i" << Bits << ", ptr " << Ptr << ", align 1\n";
            if (Bits < 64) {
              OS << "  " << Z << " = zext i" << Bits << " " << V << " to i64\n";
            } else {
              Z = V;
            }
            OS << "  " << Vec << " = insertelement <2 x i64> zeroinitializer, i64 " << Z << ", i32 0\n";
            StoreFPRDest(CodeNode, Vec);
          } else {
            std::string V = NextVal();
            OS << "  " << V << " = load <2 x i64>, ptr " << Ptr << ", align 1\n";
            StoreFPRDest(CodeNode, V);
          }
        }
        break;
      }

      case FEXCore::IR::OP_STORECONTEXT: {
        auto* Op = IROp->C<FEXCore::IR::IROp_StoreContext>();
        std::string Addr = NextVal(), Ptr = NextVal();
        OS << "  " << Addr << " = add i64 %state_ptr_int, " << Op->Offset << "\n";
        OS << "  " << Ptr << " = inttoptr i64 " << Addr << " to ptr\n";
        if (Op->Class == FEXCore::IR::RegClass::GPR) {
          std::string V = LoadGPROperand(Op->Value);
          unsigned StoreBits = (Bits <= 64 && Bits >= 8) ? Bits : 64;
          if (StoreBits < 64) {
            std::string Tr = NextVal();
            OS << "  " << Tr << " = trunc i64 " << V << " to i" << StoreBits << "\n";
            OS << "  store i" << StoreBits << " " << Tr << ", ptr " << Ptr << ", align 1\n";
          } else {
            OS << "  store i64 " << V << ", ptr " << Ptr << ", align 1\n";
          }
        } else if (UsesFPR) {
          std::string V = LoadFPROperand(Op->Value);
          if (Bits == 8 || Bits == 16 || Bits == 32) {
            std::string E0 = NextVal(), Tr = NextVal();
            OS << "  " << E0 << " = extractelement <2 x i64> " << V << ", i32 0\n";
            OS << "  " << Tr << " = trunc i64 " << E0 << " to i" << Bits << "\n";
            OS << "  store i" << Bits << " " << Tr << ", ptr " << Ptr << ", align 1\n";
          } else if (Bits == 64) {
            std::string E0 = NextVal();
            OS << "  " << E0 << " = extractelement <2 x i64> " << V << ", i32 0\n";
            OS << "  store i64 " << E0 << ", ptr " << Ptr << ", align 1\n";
          } else {
            OS << "  store <2 x i64> " << V << ", ptr " << Ptr << ", align 1\n";
          }
        }
        break;
      }

      case FEXCore::IR::OP_LOADMEM:
      case FEXCore::IR::OP_LOADMEMTSO: {
        auto* Op = IROp->C<FEXCore::IR::IROp_LoadMem>();
        std::string EffAddr = ComputeEffectiveAddress(Op->Addr, Op->Offset, Op->OffsetType, Op->OffsetScale);
        std::string Ptr = NextVal();
        OS << "  " << Ptr << " = inttoptr i64 " << EffAddr << " to ptr\n";
        if (Op->Class == FEXCore::IR::RegClass::GPR) {
          unsigned LoadBits = (Bits <= 64 && Bits >= 8) ? Bits : 64;
          std::string V = NextVal();
          OS << "  " << V << " = load i" << LoadBits << ", ptr " << Ptr << ", align 1\n";
          if (LoadBits < 64) {
            std::string Z = NextVal();
            OS << "  " << Z << " = zext i" << LoadBits << " " << V << " to i64\n";
            V = Z;
            if (LoadBits == 8 && Result.BasicBlockCount <= 128 && ++ByteLoadsInBB >= 1) {
              std::string Bar = NextVal();
              OS << "  " << Bar << " = call i64 asm sideeffect \"\", \"=r,0\"(i64 " << V << ")\n";
              V = Bar;
            }
          }
          StoreGPRDest(CodeNode, V);
        } else if (UsesFPR) {
          if (Bits == 8 || Bits == 16 || Bits == 32 || Bits == 64) {
            std::string V = NextVal(), Z = NextVal(), Vec = NextVal();
            OS << "  " << V << " = load i" << Bits << ", ptr " << Ptr << ", align 1\n";
            if (Bits < 64) {
              OS << "  " << Z << " = zext i" << Bits << " " << V << " to i64\n";
            } else {
              Z = V;
            }
            OS << "  " << Vec << " = insertelement <2 x i64> zeroinitializer, i64 " << Z << ", i32 0\n";
            StoreFPRDest(CodeNode, Vec);
          } else {
            std::string Vec = NextVal();
            OS << "  " << Vec << " = load <2 x i64>, ptr " << Ptr << ", align 1\n";
            StoreFPRDest(CodeNode, Vec);
          }
        }
        break;
      }

      case FEXCore::IR::OP_STOREMEM:
      case FEXCore::IR::OP_STOREMEMTSO: {
        auto* Op = IROp->C<FEXCore::IR::IROp_StoreMem>();
        std::string EffAddr = ComputeEffectiveAddress(Op->Addr, Op->Offset, Op->OffsetType, Op->OffsetScale);
        std::string Ptr = NextVal();
        OS << "  " << Ptr << " = inttoptr i64 " << EffAddr << " to ptr\n";
        if (Op->Class == FEXCore::IR::RegClass::GPR) {
          std::string V = LoadGPROperand(Op->Value);
          unsigned StoreBits = (Bits <= 64 && Bits >= 8) ? Bits : 64;
          if (StoreBits < 64) {
            std::string Tr = NextVal();
            OS << "  " << Tr << " = trunc i64 " << V << " to i" << StoreBits << "\n";
            OS << "  store i" << StoreBits << " " << Tr << ", ptr " << Ptr << ", align 1\n";
          } else {
            OS << "  store i64 " << V << ", ptr " << Ptr << ", align 1\n";
          }
        } else if (UsesFPR) {
          std::string Vec = LoadFPROperand(Op->Value);
          if (Bits == 8 || Bits == 16 || Bits == 32) {
            std::string E0 = NextVal(), Tr = NextVal();
            OS << "  " << E0 << " = extractelement <2 x i64> " << Vec << ", i32 0\n";
            OS << "  " << Tr << " = trunc i64 " << E0 << " to i" << Bits << "\n";
            OS << "  store i" << Bits << " " << Tr << ", ptr " << Ptr << ", align 1\n";
          } else if (Bits == 64) {
            std::string E0 = NextVal();
            OS << "  " << E0 << " = extractelement <2 x i64> " << Vec << ", i32 0\n";
            OS << "  store i64 " << E0 << ", ptr " << Ptr << ", align 1\n";
          } else {
            OS << "  store <2 x i64> " << Vec << ", ptr " << Ptr << ", align 1\n";
          }
        }
        break;
      }

      case FEXCore::IR::OP_PUSH: {
        auto* Op = IROp->C<FEXCore::IR::IROp_Push>();
        unsigned PushBytes = OpSizeToBits(Op->ValueSize) / 8;
        if (PushBytes == 0) PushBytes = 8;
        std::string OldSp = LoadGPROperand(Op->Addr);
        std::string Val = LoadGPROperand(Op->Value);
        std::string NewSp = NextVal(), Ptr = NextVal();
        OS << "  " << NewSp << " = sub i64 " << OldSp << ", " << PushBytes << "\n";
        OS << "  " << Ptr << " = inttoptr i64 " << NewSp << " to ptr\n";
        if (PushBytes < 8) {
          std::string Tr = NextVal();
          OS << "  " << Tr << " = trunc i64 " << Val << " to i" << (PushBytes * 8) << "\n";
          OS << "  store i" << (PushBytes * 8) << " " << Tr << ", ptr " << Ptr << ", align 1\n";
        } else {
          OS << "  store i64 " << Val << ", ptr " << Ptr << ", align 1\n";
        }
        StoreGPRDest(CodeNode, MaskToOpSize(NewSp, OpSize));
        break;
      }

      case FEXCore::IR::OP_PUSHTWO: {
        auto* Op = IROp->C<FEXCore::IR::IROp_PushTwo>();
        unsigned PushBytes = OpSizeToBits(Op->ValueSize) / 8;
        if (PushBytes == 0) PushBytes = 8;
        std::string Sp = LoadGPROperand(Op->Addr);
        std::string V1 = LoadGPROperand(Op->Value1);
        std::string V2 = LoadGPROperand(Op->Value2);
        std::string Addr1 = NextVal(), Addr2 = NextVal(), Ptr1 = NextVal(), Ptr2 = NextVal();
        OS << "  " << Addr1 << " = sub i64 " << Sp << ", " << (PushBytes * 2) << "\n";
        OS << "  " << Addr2 << " = sub i64 " << Sp << ", " << PushBytes << "\n";
        OS << "  " << Ptr1 << " = inttoptr i64 " << Addr1 << " to ptr\n";
        OS << "  " << Ptr2 << " = inttoptr i64 " << Addr2 << " to ptr\n";
        OS << "  store i64 " << V1 << ", ptr " << Ptr1 << ", align 1\n";
        OS << "  store i64 " << V2 << ", ptr " << Ptr2 << ", align 1\n";
        StoreGPRWrapper(Op->Addr, MaskToOpSize(Addr1, OpSize));
        StoreGPRDest(CodeNode, MaskToOpSize(Addr1, OpSize));
        break;
      }

      case FEXCore::IR::OP_POP: {
        auto* Op = IROp->C<FEXCore::IR::IROp_Pop>();
        unsigned PopBytes = OpSizeToBits(Op->Size) / 8;
        if (PopBytes == 0) PopBytes = 8;
        std::string Sp = LoadGPROperand(Op->InoutAddr);
        std::string Ptr = NextVal(), Val = NextVal(), NewSp = NextVal();
        OS << "  " << Ptr << " = inttoptr i64 " << Sp << " to ptr\n";
        OS << "  " << Val << " = load i64, ptr " << Ptr << ", align 1\n";
        OS << "  " << NewSp << " = add i64 " << Sp << ", " << PopBytes << "\n";
        StoreGPRWrapper(Op->OutValue, Val);
        StoreGPRWrapper(Op->InoutAddr, NewSp);
        break;
      }

      case FEXCore::IR::OP_POPTWO: {
        auto* Op = IROp->C<FEXCore::IR::IROp_PopTwo>();
        unsigned PopBytes = OpSizeToBits(Op->Size) / 8;
        if (PopBytes == 0) PopBytes = 8;
        std::string Sp = LoadGPROperand(Op->InoutAddr);
        std::string Addr2 = NextVal(), Ptr1 = NextVal(), Ptr2 = NextVal(), V1 = NextVal(), V2 = NextVal(), NewSp = NextVal();
        OS << "  " << Addr2 << " = add i64 " << Sp << ", " << PopBytes << "\n";
        OS << "  " << Ptr1 << " = inttoptr i64 " << Sp << " to ptr\n";
        OS << "  " << Ptr2 << " = inttoptr i64 " << Addr2 << " to ptr\n";
        OS << "  " << V1 << " = load i64, ptr " << Ptr1 << ", align 1\n";
        OS << "  " << V2 << " = load i64, ptr " << Ptr2 << ", align 1\n";
        OS << "  " << NewSp << " = add i64 " << Sp << ", " << (PopBytes * 2) << "\n";
        StoreGPRWrapper(Op->OutValue1, V1);
        StoreGPRWrapper(Op->OutValue2, V2);
        StoreGPRWrapper(Op->InoutAddr, NewSp);
        break;
      }

      case FEXCore::IR::OP_LOADCONTEXTPAIR: {
        auto* Op = IROp->C<FEXCore::IR::IROp_LoadContextPair>();
        unsigned ElemBytes = OpSizeToBits(OpSize) / 8;
        if (ElemBytes == 0) ElemBytes = 8;
        std::string Addr1 = NextVal(), Addr2 = NextVal(), Ptr1 = NextVal(), Ptr2 = NextVal();
        OS << "  " << Addr1 << " = add i64 %state_ptr_int, " << Op->Offset << "\n";
        OS << "  " << Addr2 << " = add i64 %state_ptr_int, " << (Op->Offset + ElemBytes) << "\n";
        OS << "  " << Ptr1 << " = inttoptr i64 " << Addr1 << " to ptr\n";
        OS << "  " << Ptr2 << " = inttoptr i64 " << Addr2 << " to ptr\n";
        if (Op->Class == FEXCore::IR::RegClass::GPR) {
          unsigned LoadBits = (Bits == 32) ? 32 : 64;
          std::string V1 = NextVal(), V2 = NextVal();
          OS << "  " << V1 << " = load i" << LoadBits << ", ptr " << Ptr1 << ", align 1\n";
          OS << "  " << V2 << " = load i" << LoadBits << ", ptr " << Ptr2 << ", align 1\n";
          if (LoadBits < 64) {
            std::string Z1 = NextVal(), Z2 = NextVal();
            OS << "  " << Z1 << " = zext i32 " << V1 << " to i64\n";
            OS << "  " << Z2 << " = zext i32 " << V2 << " to i64\n";
            V1 = Z1; V2 = Z2;
          }
          StoreGPRWrapper(Op->OutValue1, V1);
          StoreGPRWrapper(Op->OutValue2, V2);
        } else if (UsesFPR) {
          if (Bits == 32 || Bits == 64) {
            std::string V1 = NextVal(), V2 = NextVal(), Z1 = V1, Z2 = V2, Vec1 = NextVal(), Vec2 = NextVal();
            OS << "  " << V1 << " = load i" << Bits << ", ptr " << Ptr1 << ", align 1\n";
            OS << "  " << V2 << " = load i" << Bits << ", ptr " << Ptr2 << ", align 1\n";
            if (Bits < 64) {
              Z1 = NextVal(); Z2 = NextVal();
              OS << "  " << Z1 << " = zext i32 " << V1 << " to i64\n";
              OS << "  " << Z2 << " = zext i32 " << V2 << " to i64\n";
            }
            OS << "  " << Vec1 << " = insertelement <2 x i64> zeroinitializer, i64 " << Z1 << ", i32 0\n";
            OS << "  " << Vec2 << " = insertelement <2 x i64> zeroinitializer, i64 " << Z2 << ", i32 0\n";
            StoreFPRWrapper(Op->OutValue1, Vec1);
            StoreFPRWrapper(Op->OutValue2, Vec2);
          } else {
            std::string Vec1 = NextVal(), Vec2 = NextVal();
            OS << "  " << Vec1 << " = load <2 x i64>, ptr " << Ptr1 << ", align 1\n";
            OS << "  " << Vec2 << " = load <2 x i64>, ptr " << Ptr2 << ", align 1\n";
            StoreFPRWrapper(Op->OutValue1, Vec1);
            StoreFPRWrapper(Op->OutValue2, Vec2);
          }
        }
        break;
      }

      case FEXCore::IR::OP_STORECONTEXTPAIR: {
        auto* Op = IROp->C<FEXCore::IR::IROp_StoreContextPair>();
        unsigned ElemBytes = OpSizeToBits(OpSize) / 8;
        if (ElemBytes == 0) ElemBytes = 8;
        std::string Addr1 = NextVal(), Addr2 = NextVal(), Ptr1 = NextVal(), Ptr2 = NextVal();
        OS << "  " << Addr1 << " = add i64 %state_ptr_int, " << Op->Offset << "\n";
        OS << "  " << Addr2 << " = add i64 %state_ptr_int, " << (Op->Offset + ElemBytes) << "\n";
        OS << "  " << Ptr1 << " = inttoptr i64 " << Addr1 << " to ptr\n";
        OS << "  " << Ptr2 << " = inttoptr i64 " << Addr2 << " to ptr\n";
        if (Op->Class == FEXCore::IR::RegClass::GPR) {
          std::string V1 = LoadGPROperand(Op->Value1);
          std::string V2 = LoadGPROperand(Op->Value2);
          if (Bits == 32) {
            std::string T1 = NextVal(), T2 = NextVal();
            OS << "  " << T1 << " = trunc i64 " << V1 << " to i32\n";
            OS << "  " << T2 << " = trunc i64 " << V2 << " to i32\n";
            OS << "  store i32 " << T1 << ", ptr " << Ptr1 << ", align 1\n";
            OS << "  store i32 " << T2 << ", ptr " << Ptr2 << ", align 1\n";
          } else {
            OS << "  store i64 " << V1 << ", ptr " << Ptr1 << ", align 1\n";
            OS << "  store i64 " << V2 << ", ptr " << Ptr2 << ", align 1\n";
          }
        } else if (UsesFPR) {
          std::string Vec1 = LoadFPROperand(Op->Value1);
          std::string Vec2 = LoadFPROperand(Op->Value2);
          if (Bits == 32) {
            std::string E1 = NextVal(), E2 = NextVal(), T1 = NextVal(), T2 = NextVal();
            OS << "  " << E1 << " = extractelement <2 x i64> " << Vec1 << ", i32 0\n";
            OS << "  " << E2 << " = extractelement <2 x i64> " << Vec2 << ", i32 0\n";
            OS << "  " << T1 << " = trunc i64 " << E1 << " to i32\n";
            OS << "  " << T2 << " = trunc i64 " << E2 << " to i32\n";
            OS << "  store i32 " << T1 << ", ptr " << Ptr1 << ", align 1\n";
            OS << "  store i32 " << T2 << ", ptr " << Ptr2 << ", align 1\n";
          } else if (Bits == 64) {
            std::string E1 = NextVal(), E2 = NextVal();
            OS << "  " << E1 << " = extractelement <2 x i64> " << Vec1 << ", i32 0\n";
            OS << "  " << E2 << " = extractelement <2 x i64> " << Vec2 << ", i32 0\n";
            OS << "  store i64 " << E1 << ", ptr " << Ptr1 << ", align 1\n";
            OS << "  store i64 " << E2 << ", ptr " << Ptr2 << ", align 1\n";
          } else {
            OS << "  store <2 x i64> " << Vec1 << ", ptr " << Ptr1 << ", align 1\n";
            OS << "  store <2 x i64> " << Vec2 << ", ptr " << Ptr2 << ", align 1\n";
          }
        }
        break;
      }

      case FEXCore::IR::OP_LOADMEMPAIR: {
        auto* Op = IROp->C<FEXCore::IR::IROp_LoadMemPair>();
        unsigned ElemBytes = OpSizeToBits(OpSize) / 8;
        if (ElemBytes == 0) ElemBytes = 8;
        std::string Base = LoadGPROperand(Op->Addr);
        std::string Addr1 = NextVal(), Addr2 = NextVal(), Ptr1 = NextVal(), Ptr2 = NextVal();
        OS << "  " << Addr1 << " = add i64 " << Base << ", " << static_cast<int64_t>(Op->Offset) << "\n";
        OS << "  " << Addr2 << " = add i64 " << Addr1 << ", " << ElemBytes << "\n";
        OS << "  " << Ptr1 << " = inttoptr i64 " << Addr1 << " to ptr\n";
        OS << "  " << Ptr2 << " = inttoptr i64 " << Addr2 << " to ptr\n";
        if (Op->Class == FEXCore::IR::RegClass::GPR) {
          unsigned LoadBits = (Bits == 32) ? 32 : 64;
          std::string V1 = NextVal(), V2 = NextVal();
          OS << "  " << V1 << " = load i" << LoadBits << ", ptr " << Ptr1 << ", align 1\n";
          OS << "  " << V2 << " = load i" << LoadBits << ", ptr " << Ptr2 << ", align 1\n";
          if (LoadBits < 64) {
            std::string Z1 = NextVal(), Z2 = NextVal();
            OS << "  " << Z1 << " = zext i32 " << V1 << " to i64\n";
            OS << "  " << Z2 << " = zext i32 " << V2 << " to i64\n";
            V1 = Z1; V2 = Z2;
          }
          StoreGPRWrapper(Op->OutValue1, V1);
          StoreGPRWrapper(Op->OutValue2, V2);
        } else if (UsesFPR) {
          if (Bits == 32 || Bits == 64) {
            std::string V1 = NextVal(), V2 = NextVal(), Z1 = V1, Z2 = V2, Vec1 = NextVal(), Vec2 = NextVal();
            OS << "  " << V1 << " = load i" << Bits << ", ptr " << Ptr1 << ", align 1\n";
            OS << "  " << V2 << " = load i" << Bits << ", ptr " << Ptr2 << ", align 1\n";
            if (Bits < 64) {
              Z1 = NextVal(); Z2 = NextVal();
              OS << "  " << Z1 << " = zext i32 " << V1 << " to i64\n";
              OS << "  " << Z2 << " = zext i32 " << V2 << " to i64\n";
            }
            OS << "  " << Vec1 << " = insertelement <2 x i64> zeroinitializer, i64 " << Z1 << ", i32 0\n";
            OS << "  " << Vec2 << " = insertelement <2 x i64> zeroinitializer, i64 " << Z2 << ", i32 0\n";
            StoreFPRWrapper(Op->OutValue1, Vec1);
            StoreFPRWrapper(Op->OutValue2, Vec2);
          } else {
            std::string Vec1 = NextVal(), Vec2 = NextVal();
            OS << "  " << Vec1 << " = load <2 x i64>, ptr " << Ptr1 << ", align 1\n";
            OS << "  " << Vec2 << " = load <2 x i64>, ptr " << Ptr2 << ", align 1\n";
            StoreFPRWrapper(Op->OutValue1, Vec1);
            StoreFPRWrapper(Op->OutValue2, Vec2);
          }
        }
        break;
      }

      case FEXCore::IR::OP_STOREMEMPAIR: {
        auto* Op = IROp->C<FEXCore::IR::IROp_StoreMemPair>();
        unsigned ElemBytes = OpSizeToBits(OpSize) / 8;
        if (ElemBytes == 0) ElemBytes = 8;
        std::string Base = LoadGPROperand(Op->Addr);
        std::string Addr1 = NextVal(), Addr2 = NextVal(), Ptr1 = NextVal(), Ptr2 = NextVal();
        OS << "  " << Addr1 << " = add i64 " << Base << ", " << static_cast<int64_t>(Op->Offset) << "\n";
        OS << "  " << Addr2 << " = add i64 " << Addr1 << ", " << ElemBytes << "\n";
        OS << "  " << Ptr1 << " = inttoptr i64 " << Addr1 << " to ptr\n";
        OS << "  " << Ptr2 << " = inttoptr i64 " << Addr2 << " to ptr\n";
        if (Op->Class == FEXCore::IR::RegClass::GPR) {
          std::string V1 = LoadGPROperand(Op->Value1);
          std::string V2 = LoadGPROperand(Op->Value2);
          if (Bits == 32) {
            std::string T1 = NextVal(), T2 = NextVal();
            OS << "  " << T1 << " = trunc i64 " << V1 << " to i32\n";
            OS << "  " << T2 << " = trunc i64 " << V2 << " to i32\n";
            OS << "  store i32 " << T1 << ", ptr " << Ptr1 << ", align 1\n";
            OS << "  store i32 " << T2 << ", ptr " << Ptr2 << ", align 1\n";
          } else {
            OS << "  store i64 " << V1 << ", ptr " << Ptr1 << ", align 1\n";
            OS << "  store i64 " << V2 << ", ptr " << Ptr2 << ", align 1\n";
          }
        } else if (UsesFPR) {
          std::string Vec1 = LoadFPROperand(Op->Value1);
          std::string Vec2 = LoadFPROperand(Op->Value2);
          if (Bits == 32) {
            std::string E1 = NextVal(), E2 = NextVal(), T1 = NextVal(), T2 = NextVal();
            OS << "  " << E1 << " = extractelement <2 x i64> " << Vec1 << ", i32 0\n";
            OS << "  " << E2 << " = extractelement <2 x i64> " << Vec2 << ", i32 0\n";
            OS << "  " << T1 << " = trunc i64 " << E1 << " to i32\n";
            OS << "  " << T2 << " = trunc i64 " << E2 << " to i32\n";
            OS << "  store i32 " << T1 << ", ptr " << Ptr1 << ", align 1\n";
            OS << "  store i32 " << T2 << ", ptr " << Ptr2 << ", align 1\n";
          } else if (Bits == 64) {
            std::string E1 = NextVal(), E2 = NextVal();
            OS << "  " << E1 << " = extractelement <2 x i64> " << Vec1 << ", i32 0\n";
            OS << "  " << E2 << " = extractelement <2 x i64> " << Vec2 << ", i32 0\n";
            OS << "  store i64 " << E1 << ", ptr " << Ptr1 << ", align 1\n";
            OS << "  store i64 " << E2 << ", ptr " << Ptr2 << ", align 1\n";
          } else {
            OS << "  store <2 x i64> " << Vec1 << ", ptr " << Ptr1 << ", align 1\n";
            OS << "  store <2 x i64> " << Vec2 << ", ptr " << Ptr2 << ", align 1\n";
          }
        }
        break;
      }

      case FEXCore::IR::OP_FORMCONTEXTADDRESS: {
        auto* Op = IROp->C<FEXCore::IR::IROp_FormContextAddress>();
        std::string Idx = LoadGPROperand(Op->Index);
        std::string Scaled = NextVal(), R = NextVal();
        OS << "  " << Scaled << " = mul i64 " << Idx << ", " << Op->Stride << "\n";
        OS << "  " << R << " = add i64 %state_ptr_int, " << Scaled << "\n";
        StoreGPRDest(CodeNode, R);
        break;
      }

      case FEXCore::IR::OP_CONTEXTCLEAR: {
        auto* Op = IROp->C<FEXCore::IR::IROp_ContextClear>();
        for (uint32_t Off = 0; Off + 8 <= Op->Size; Off += 8) {
          std::string Addr = NextVal(), Ptr = NextVal();
          OS << "  " << Addr << " = add i64 %state_ptr_int, " << (Op->Offset + Off) << "\n";
          OS << "  " << Ptr << " = inttoptr i64 " << Addr << " to ptr\n";
          OS << "  store i64 0, ptr " << Ptr << ", align 1\n";
        }
        break;
      }

      case FEXCore::IR::OP_ATOMICFETCHADD:
      case FEXCore::IR::OP_ATOMICFETCHSUB:
      case FEXCore::IR::OP_ATOMICFETCHAND:
      case FEXCore::IR::OP_ATOMICFETCHOR:
      case FEXCore::IR::OP_ATOMICFETCHXOR: {
        auto* Op = IROp->C<FEXCore::IR::IROp_AtomicFetchAdd>();
        std::string Addr = LoadGPROperand(Op->Addr);
        std::string Val = LoadGPROperand(Op->Value);
        std::string Ptr = NextVal();
        OS << "  " << Ptr << " = inttoptr i64 " << Addr << " to ptr\n";
        const char* RmwOp = "add";
        if (IROp->Op == FEXCore::IR::OP_ATOMICFETCHSUB) RmwOp = "sub";
        else if (IROp->Op == FEXCore::IR::OP_ATOMICFETCHAND) RmwOp = "and";
        else if (IROp->Op == FEXCore::IR::OP_ATOMICFETCHOR) RmwOp = "or";
        else if (IROp->Op == FEXCore::IR::OP_ATOMICFETCHXOR) RmwOp = "xor";
        unsigned RmwBits = (Bits <= 64 && Bits >= 8) ? Bits : 64;
        if (RmwBits < 64) {
          std::string VTr = NextVal(), OldTr = NextVal(), Old64 = NextVal();
          OS << "  " << VTr << " = trunc i64 " << Val << " to i" << RmwBits << "\n";
          OS << "  " << OldTr << " = atomicrmw " << RmwOp << " ptr " << Ptr << ", i" << RmwBits << " " << VTr << " seq_cst\n";
          OS << "  " << Old64 << " = zext i" << RmwBits << " " << OldTr << " to i64\n";
          StoreGPRDest(CodeNode, Old64);
        } else {
          std::string Old = NextVal();
          OS << "  " << Old << " = atomicrmw " << RmwOp << " ptr " << Ptr << ", i64 " << Val << " seq_cst\n";
          StoreGPRDest(CodeNode, Old);
        }
        break;
      }

      case FEXCore::IR::OP_CAS: {
        auto* Op = IROp->C<FEXCore::IR::IROp_CAS>();
        std::string Exp = LoadGPROperand(Op->Expected);
        std::string Des = LoadGPROperand(Op->Desired);
        std::string Addr = LoadGPROperand(Op->Addr);
        std::string Ptr = NextVal();
        OS << "  " << Ptr << " = inttoptr i64 " << Addr << " to ptr\n";
        if (Bits < 64 && Bits >= 8) {
          std::string ExpTr = NextVal(), DesTr = NextVal(), Pair = NextVal(), OldTr = NextVal(), Old64 = NextVal();
          OS << "  " << ExpTr << " = trunc i64 " << Exp << " to i" << Bits << "\n";
          OS << "  " << DesTr << " = trunc i64 " << Des << " to i" << Bits << "\n";
          OS << "  " << Pair << " = cmpxchg ptr " << Ptr << ", i" << Bits << " " << ExpTr << ", i" << Bits << " " << DesTr << " seq_cst seq_cst\n";
          OS << "  " << OldTr << " = extractvalue { i" << Bits << ", i1 } " << Pair << ", 0\n";
          OS << "  " << Old64 << " = zext i" << Bits << " " << OldTr << " to i64\n";
          StoreGPRDest(CodeNode, Old64);
        } else {
          std::string Pair = NextVal(), Old = NextVal();
          OS << "  " << Pair << " = cmpxchg ptr " << Ptr << ", i64 " << Exp << ", i64 " << Des << " seq_cst seq_cst\n";
          OS << "  " << Old << " = extractvalue { i64, i1 } " << Pair << ", 0\n";
          StoreGPRDest(CodeNode, MaskToOpSize(Old, OpSize));
        }
        break;
      }

      case FEXCore::IR::OP_ATOMICSWAP: {
        auto* Op = IROp->C<FEXCore::IR::IROp_AtomicSwap>();
        std::string Val = LoadGPROperand(Op->Value);
        std::string Addr = LoadGPROperand(Op->Addr);
        std::string Ptr = NextVal();
        OS << "  " << Ptr << " = inttoptr i64 " << Addr << " to ptr\n";
        if (Bits < 64 && Bits >= 8) {
          std::string VTr = NextVal(), OldTr = NextVal(), Old64 = NextVal();
          OS << "  " << VTr << " = trunc i64 " << Val << " to i" << Bits << "\n";
          OS << "  " << OldTr << " = atomicrmw xchg ptr " << Ptr << ", i" << Bits << " " << VTr << " seq_cst\n";
          OS << "  " << Old64 << " = zext i" << Bits << " " << OldTr << " to i64\n";
          StoreGPRDest(CodeNode, Old64);
        } else {
          std::string Old = NextVal();
          OS << "  " << Old << " = atomicrmw xchg ptr " << Ptr << ", i64 " << Val << " seq_cst\n";
          StoreGPRDest(CodeNode, Old);
        }
        break;
      }

      // Vector / NEON operations
      case FEXCore::IR::OP_PREFETCH: {
        break;
      }

      case FEXCore::IR::OP_FENCE:
      case FEXCore::IR::OP_YIELD:
      case FEXCore::IR::OP_CACHELINECLEAR:
      case FEXCore::IR::OP_CACHELINECLEAN:
      case FEXCore::IR::OP_CACHELINEZERO: {
        OS << "  fence seq_cst\n";
        break;
      }

      case FEXCore::IR::OP_MEMSET: {
        auto* Op = IROp->C<FEXCore::IR::IROp_MemSet>();
        unsigned ElemBytes = OpSizeToBits(Op->Size) / 8;
        if (ElemBytes == 0) ElemBytes = 1;
        std::string Addr = LoadGPROperand(Op->Addr);
        std::string Val = LoadGPROperand(Op->Value);
        std::string Len = LoadGPROperand(Op->Length);
        std::string Dir = LoadGPROperand(Op->Direction);
        std::string OutAddr = NextVal();
        const char* StrMn = (ElemBytes == 1) ? "strb ${1:w}" : (ElemBytes == 2) ? "strh ${1:w}" : (ElemBytes == 4) ? "str ${1:w}" : "str $1";
        OS << "  " << OutAddr << " = call i64 asm sideeffect \""
           << "mov x9, $2 ; mov x10, $3 ; lsl x11, $4, #" << (ElemBytes == 1 ? 0 : ElemBytes == 2 ? 1 : ElemBytes == 4 ? 2 : 3) << " ; "
           << "1: cbz x10, 2f ; " << StrMn << ", [x9] ; add x9, x9, x11 ; sub x10, x10, #1 ; b 1b ; 2: mov $0, x9\", "
           << "\"=&r,r,r,r,r,~{x9},~{x10},~{x11},~{memory}\"(i64 " << Val << ", i64 " << Addr << ", i64 " << Len << ", i64 " << Dir << ")\n";
        StoreGPRDest(CodeNode, OutAddr);
        break;
      }

      case FEXCore::IR::OP_MEMCPY: {
        auto* Op = IROp->C<FEXCore::IR::IROp_MemCpy>();
        unsigned ElemBytes = OpSizeToBits(Op->Size) / 8;
        if (ElemBytes == 0) ElemBytes = 1;
        std::string Dest = LoadGPROperand(Op->Dest);
        std::string Src = LoadGPROperand(Op->Src);
        std::string Len = LoadGPROperand(Op->Length);
        std::string Dir = LoadGPROperand(Op->Direction);
        std::string Pair = NextVal(), OutDst = NextVal(), OutSrc = NextVal();
        const char* LdrMn = (ElemBytes == 1) ? "ldrb w12" : (ElemBytes == 2) ? "ldrh w12" : (ElemBytes == 4) ? "ldr w12" : "ldr x12";
        const char* StrMn = (ElemBytes == 1) ? "strb w12" : (ElemBytes == 2) ? "strh w12" : (ElemBytes == 4) ? "str w12" : "str x12";
        OS << "  " << Pair << " = call { i64, i64 } asm sideeffect \""
           << "mov x9, $2 ; mov x10, $3 ; mov x11, $4 ; lsl x13, $5, #" << (ElemBytes == 1 ? 0 : ElemBytes == 2 ? 1 : ElemBytes == 4 ? 2 : 3) << " ; "
           << "1: cbz x11, 2f ; " << LdrMn << ", [x10] ; " << StrMn << ", [x9] ; add x9, x9, x13 ; add x10, x10, x13 ; sub x11, x11, #1 ; b 1b ; "
           << "2: mov $0, x9 ; mov $1, x10\", "
           << "\"=&r,=&r,r,r,r,r,~{x9},~{x10},~{x11},~{x12},~{x13},~{memory}\"(i64 " << Dest << ", i64 " << Src << ", i64 " << Len << ", i64 " << Dir << ")\n";
        OS << "  " << OutDst << " = extractvalue { i64, i64 } " << Pair << ", 0\n";
        OS << "  " << OutSrc << " = extractvalue { i64, i64 } " << Pair << ", 1\n";
        StoreGPRWrapper(Op->OutDstAddress, OutDst);
        StoreGPRWrapper(Op->OutSrcAddress, OutSrc);
        break;
      }

  default:
    return false;
  }
  return true;
}

} // namespace FEXCore::AOT

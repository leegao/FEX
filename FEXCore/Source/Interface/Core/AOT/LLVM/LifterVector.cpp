// SPDX-License-Identifier: MIT
#include "Interface/Core/AOT/LLVM/Lifter.h"

namespace FEXCore::AOT {

using LiftedFunctionIR = LLVMArm64ECAOTCompiler::LiftedFunctionIR;

bool LiftVectorOp(LifterContext& Ctx, FEXCore::IR::Ref CodeNode, const FEXCore::IR::IROp_Header* IROp) {
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
  auto MakeVec128Const = [&](uint64_t Lo, uint64_t Hi) { return Ctx.MakeVec128Const(Lo, Hi); };
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
  (void)ZeroUpperFPRBits; (void)MakeVec128Const; (void)MaskToOpSize; (void)ComputeEffectiveAddress;
  (void)PackNZCVFromAddSub; (void)EvaluateNZCVCond;

  switch (IROp->Op) {
      case FEXCore::IR::OP_VMOV: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VMov>();
        StoreFPRDest(CodeNode, ZeroUpperFPRBits(LoadFPROperand(Op->Source), Bits));
        break;
      }

      case FEXCore::IR::OP_LOADNAMEDVECTORCONSTANT: {
        auto* Op = IROp->C<FEXCore::IR::IROp_LoadNamedVectorConstant>();
        static constexpr uint64_t kNamedConsts[42][2] = {
          {0x0003000200010000ULL, 0x0007000600050004ULL},
          {0x000B000A00090008ULL, 0x000F000E000D000CULL},
          {0x0706050403020100ULL, 0x0F0E0D0C0B0A0908ULL},
          {0x0000000080000000ULL, 0x0000000080000000ULL},
          {0x0000000080000000ULL, 0x0000000080000000ULL},
          {0x8000000000000000ULL, 0x0000000000000000ULL},
          {0x8000000000000000ULL, 0x0000000000000000ULL},
          {0x8000000000000000ULL, 0x8000000000000000ULL},
          {0x8000000000000000ULL, 0x8000000000000000ULL},
          {0x0000000000000000ULL, 0x8000000000000000ULL},
          {0x0000000000000000ULL, 0x8000000000000000ULL},
          {0x0000000100000000ULL, 0x0000000300000002ULL},
          {0x040B0E010B0E0104ULL, 0x0C0306090306090CULL},
          {0x07060504FFFFFFFFULL, 0xFFFFFFFF0B0A0908ULL},
          {0x0706050403020100ULL, 0xFFFFFFFF0B0A0908ULL},
          {0xFFFFFFFF03020100ULL, 0x0F0E0D0CFFFFFFFFULL},
          {0x0706050403020100ULL, 0x0F0E0D0CFFFFFFFFULL},
          {0xFFFFFFFF03020100ULL, 0x0F0E0D0C0B0A0908ULL},
          {0x07060504FFFFFFFFULL, 0x0F0E0D0C0B0A0908ULL},
          {0x8040201008040201ULL, 0x8040201008040201ULL},
          {0x8040201008040201ULL, 0x8040201008040201ULL},
          {0x0706050403020100ULL, 0x1716151413121110ULL},
          {0x0F0E0D0C0B0A0908ULL, 0x1F1E1D1C1B1A1918ULL},
          {0x8000000000000000ULL, 0x0000000000003FFFULL},
          {0xD49A784BCD1B8AFEULL, 0x0000000000004000ULL},
          {0xB8AA3B295C17F0BCULL, 0x0000000000003FFFULL},
          {0xC90FDAA22168C235ULL, 0x0000000000004000ULL},
          {0x9A209A84FBCFF799ULL, 0x0000000000003FFDULL},
          {0xB17217F7D1CF79ACULL, 0x0000000000003FFEULL},
          {0x4F0000004F000000ULL, 0x4F0000004F000000ULL},
          {0x4F0000004F000000ULL, 0x4F0000004F000000ULL},
          {0x5F0000005F000000ULL, 0x5F0000005F000000ULL},
          {0x41E0000000000000ULL, 0x41E0000000000000ULL},
          {0x41E0000000000000ULL, 0x41E0000000000000ULL},
          {0x43E0000000000000ULL, 0x43E0000000000000ULL},
          {0x8000000080000000ULL, 0x8000000080000000ULL},
          {0x8000000000000000ULL, 0x8000000000000000ULL},
          {0x0000000000000000ULL, 0x0000000000008000ULL},
          {0x5A8279995A827999ULL, 0x5A8279995A827999ULL},
          {0x6ED9EBA16ED9EBA1ULL, 0x6ED9EBA16ED9EBA1ULL},
          {0x8F1BBCDC8F1BBCDCULL, 0x8F1BBCDC8F1BBCDCULL},
          {0xCA62C1D6CA62C1D6ULL, 0xCA62C1D6CA62C1D6ULL},
        };
        uint32_t Idx = static_cast<uint32_t>(Op->Constant);
        if (Idx < 42) {
          uint64_t Lo = kNamedConsts[Idx][0];
          uint64_t Hi = (Bits <= 64) ? 0ULL : kNamedConsts[Idx][1];
          StoreFPRDest(CodeNode, MakeVec128Const(Lo, Hi));
        } else {
          StoreFPRDest(CodeNode, "zeroinitializer");
        }
        break;
      }

      case FEXCore::IR::OP_LOADNAMEDVECTORINDEXEDCONSTANT: {
        auto* Op = IROp->C<FEXCore::IR::IROp_LoadNamedVectorIndexedConstant>();
        uint64_t Lo = 0, Hi = 0;
        const uint32_t Swiz = (Op->Index / 16u) & 0xFFu;
        switch (Op->Constant) {
        case FEXCore::IR::IndexNamedVectorConstant::INDEXED_NAMED_VECTOR_PSHUFLW: {
          static constexpr uint64_t WSel[4] = {0x0100ULL, 0x0302ULL, 0x0504ULL, 0x0706ULL};
          Lo = (WSel[(Swiz >> 0) & 3] << 0) | (WSel[(Swiz >> 2) & 3] << 16) |
               (WSel[(Swiz >> 4) & 3] << 32) | (WSel[(Swiz >> 6) & 3] << 48);
          Hi = 0x0f0e0d0c0b0a0908ULL;
          break;
        }
        case FEXCore::IR::IndexNamedVectorConstant::INDEXED_NAMED_VECTOR_PSHUFHW: {
          static constexpr uint64_t WSel[4] = {0x0908ULL, 0x0b0aULL, 0x0d0cULL, 0x0f0eULL};
          Lo = 0x0706050403020100ULL;
          Hi = (WSel[(Swiz >> 0) & 3] << 0) | (WSel[(Swiz >> 2) & 3] << 16) |
               (WSel[(Swiz >> 4) & 3] << 32) | (WSel[(Swiz >> 6) & 3] << 48);
          break;
        }
        case FEXCore::IR::IndexNamedVectorConstant::INDEXED_NAMED_VECTOR_PSHUFD: {
          static constexpr uint64_t WSel[4] = {0x03020100ULL, 0x07060504ULL, 0x0b0a0908ULL, 0x0f0e0d0cULL};
          Lo = (WSel[(Swiz >> 0) & 3] << 0) | (WSel[(Swiz >> 2) & 3] << 32);
          Hi = (WSel[(Swiz >> 4) & 3] << 0) | (WSel[(Swiz >> 6) & 3] << 32);
          break;
        }
        case FEXCore::IR::IndexNamedVectorConstant::INDEXED_NAMED_VECTOR_SHUFPS: {
          static constexpr uint64_t WSel1[4] = {0x03020100ULL, 0x07060504ULL, 0x0b0a0908ULL, 0x0f0e0d0cULL};
          static constexpr uint64_t WSel2[4] = {0x13121110ULL, 0x17161514ULL, 0x1b1a1918ULL, 0x1f1e1d1cULL};
          Lo = (WSel1[(Swiz >> 0) & 3] << 0) | (WSel1[(Swiz >> 2) & 3] << 32);
          Hi = (WSel2[(Swiz >> 4) & 3] << 0) | (WSel2[(Swiz >> 6) & 3] << 32);
          break;
        }
        case FEXCore::IR::IndexNamedVectorConstant::INDEXED_NAMED_VECTOR_DPPS_MASK: {
          uint64_t W0 = (Swiz & 1) ? 0xFFFFFFFFULL : 0ULL;
          uint64_t W1 = (Swiz & 2) ? 0xFFFFFFFFULL : 0ULL;
          uint64_t W2 = (Swiz & 4) ? 0xFFFFFFFFULL : 0ULL;
          uint64_t W3 = (Swiz & 8) ? 0xFFFFFFFFULL : 0ULL;
          Lo = W0 | (W1 << 32);
          Hi = W2 | (W3 << 32);
          break;
        }
        case FEXCore::IR::IndexNamedVectorConstant::INDEXED_NAMED_VECTOR_DPPD_MASK: {
          Lo = (Swiz & 1) ? ~0ULL : 0ULL;
          Hi = (Swiz & 2) ? ~0ULL : 0ULL;
          break;
        }
        case FEXCore::IR::IndexNamedVectorConstant::INDEXED_NAMED_VECTOR_PBLENDW: {
          static constexpr uint16_t WSel[8] = {0x0100, 0x0302, 0x0504, 0x0706, 0x0908, 0x0B0A, 0x0D0C, 0x0F0E};
          for (int j = 0; j < 4; ++j) {
            uint64_t VLo = ((Swiz >> j) & 1) ? WSel[j] : 0xFFFFULL;
            uint64_t VHi = ((Swiz >> (j + 4)) & 1) ? WSel[j + 4] : 0xFFFFULL;
            Lo |= (VLo << (j * 16));
            Hi |= (VHi << (j * 16));
          }
          break;
        }
        default: break;
        }
        if (Bits <= 64) Hi = 0;
        StoreFPRDest(CodeNode, MakeVec128Const(Lo, Hi));
        break;
      }

      case FEXCore::IR::OP_VAND: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VAnd>();
        std::string V1 = LoadFPROperand(Op->Vector1);
        std::string V2 = LoadFPROperand(Op->Vector2);
        std::string R = NextVal();
        OS << "  " << R << " = and <2 x i64> " << V1 << ", " << V2 << "\n";
        StoreFPRDest(CodeNode, ZeroUpperFPRBits(R, Bits));
        break;
      }

      case FEXCore::IR::OP_VOR: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VOr>();
        std::string V1 = LoadFPROperand(Op->Vector1);
        std::string V2 = LoadFPROperand(Op->Vector2);
        std::string R = NextVal();
        OS << "  " << R << " = or <2 x i64> " << V1 << ", " << V2 << "\n";
        StoreFPRDest(CodeNode, ZeroUpperFPRBits(R, Bits));
        break;
      }

      case FEXCore::IR::OP_VXOR: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VXor>();
        std::string V1 = LoadFPROperand(Op->Vector1);
        std::string V2 = LoadFPROperand(Op->Vector2);
        std::string R = NextVal();
        OS << "  " << R << " = xor <2 x i64> " << V1 << ", " << V2 << "\n";
        StoreFPRDest(CodeNode, ZeroUpperFPRBits(R, Bits));
        break;
      }

      case FEXCore::IR::OP_VANDN:
      case FEXCore::IR::OP_VORN: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VAndn>();
        std::string V1 = LoadFPROperand(Op->Vector1);
        std::string V2 = LoadFPROperand(Op->Vector2);
        std::string NotV2 = NextVal(), R = NextVal();
        OS << "  " << NotV2 << " = xor <2 x i64> " << V2 << ", <i64 -1, i64 -1>\n";
        const char* LogicOp = (IROp->Op == FEXCore::IR::OP_VANDN) ? "and" : "or";
        OS << "  " << R << " = " << LogicOp << " <2 x i64> " << V1 << ", " << NotV2 << "\n";
        StoreFPRDest(CodeNode, ZeroUpperFPRBits(R, Bits));
        break;
      }

      case FEXCore::IR::OP_VNOT: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VNot>();
        std::string V1 = LoadFPROperand(Op->Vector);
        std::string R = NextVal();
        OS << "  " << R << " = xor <2 x i64> " << V1 << ", <i64 -1, i64 -1>\n";
        StoreFPRDest(CodeNode, ZeroUpperFPRBits(R, Bits));
        break;
      }

      case FEXCore::IR::OP_VADD:
      case FEXCore::IR::OP_VSUB: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VAdd>();
        unsigned ElemBits = OpSizeToBits(IROp->ElementSize);
        if (ElemBits != 8 && ElemBits != 16 && ElemBits != 32 && ElemBits != 64) ElemBits = 32;
        const char* IntOp = (IROp->Op == FEXCore::IR::OP_VADD) ? "add" : "sub";
        std::string Res = Rellume.LiftSseBinOp(LoadFPROperand(Op->Vector1),
                                               LoadFPROperand(Op->Vector2),
                                               IntOp, false,
                                               rellume::x86_64::ResolveVecIntFacet(ElemBits));
        StoreFPRDest(CodeNode, ZeroUpperFPRBits(Res, Bits));
        break;
      }

      case FEXCore::IR::OP_VFADD:
      case FEXCore::IR::OP_VFSUB:
      case FEXCore::IR::OP_VFMUL: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VFAdd>();
        unsigned ElemBits = OpSizeToBits(IROp->ElementSize);
        const char* FpOp = (IROp->Op == FEXCore::IR::OP_VFADD) ? "fadd" :
                           (IROp->Op == FEXCore::IR::OP_VFSUB) ? "fsub" : "fmul";
        std::string Res = Rellume.LiftSseBinOp(LoadFPROperand(Op->Vector1),
                                               LoadFPROperand(Op->Vector2),
                                               FpOp, false,
                                               rellume::x86_64::ResolveVecFloatFacet(ElemBits));
        StoreFPRDest(CodeNode, ZeroUpperFPRBits(Res, Bits));
        break;
      }

      case FEXCore::IR::OP_VCASTFROMGPR: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VCastFromGPR>();
        std::string G = MaskToOpSize(LoadGPROperand(Op->Src), IROp->ElementSize);
        std::string R = NextVal();
        OS << "  " << R << " = insertelement <2 x i64> zeroinitializer, i64 " << G << ", i32 0\n";
        StoreFPRDest(CodeNode, R);
        break;
      }

      case FEXCore::IR::OP_VLOADTWOGPRS: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VLoadTwoGPRs>();
        std::string Lo = LoadGPROperand(Op->Lower);
        std::string Hi = LoadGPROperand(Op->Upper);
        std::string R0 = NextVal(), R1 = NextVal();
        OS << "  " << R0 << " = insertelement <2 x i64> zeroinitializer, i64 " << Lo << ", i32 0\n";
        OS << "  " << R1 << " = insertelement <2 x i64> " << R0 << ", i64 " << Hi << ", i32 1\n";
        StoreFPRDest(CodeNode, R1);
        break;
      }

      case FEXCore::IR::OP_VDUPFROMGPR: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VDupFromGPR>();
        std::string G = LoadGPROperand(Op->Src);
        unsigned ElemBits = OpSizeToBits(IROp->ElementSize);
        if (ElemBits != 8 && ElemBits != 16 && ElemBits != 32 && ElemBits != 64) ElemBits = 32;
        unsigned Lanes = 128 / ElemBits;
        std::string VecTy = "<" + std::to_string(Lanes) + " x i" + std::to_string(ElemBits) + ">";
        std::string GTr = G;
        if (ElemBits < 64) {
          GTr = NextVal();
          OS << "  " << GTr << " = trunc i64 " << G << " to i" << ElemBits << "\n";
        }
        std::string Ins0 = NextVal(), Shuf = NextVal(), Res = NextVal();
        OS << "  " << Ins0 << " = insertelement " << VecTy << " poison, i" << ElemBits << " " << GTr << ", i32 0\n";
        OS << "  " << Shuf << " = shufflevector " << VecTy << " " << Ins0 << ", " << VecTy << " poison, <" << Lanes << " x i32> zeroinitializer\n";
        OS << "  " << Res << " = bitcast " << VecTy << " " << Shuf << " to <2 x i64>\n";
        StoreFPRDest(CodeNode, ZeroUpperFPRBits(Res, Bits));
        break;
      }

      case FEXCore::IR::OP_FLOAT_FROMGPR_S: {
        auto* Op = IROp->C<FEXCore::IR::IROp_Float_FromGPR_S>();
        std::string G = LoadGPROperand(Op->Src);
        unsigned DstBits = OpSizeToBits(IROp->ElementSize);
        unsigned SrcBits = OpSizeToBits(Op->SrcElementSize);
        std::string GVal = G;
        if (SrcBits == 32) {
          GVal = NextVal();
          OS << "  " << GVal << " = trunc i64 " << G << " to i32\n";
        } else {
          SrcBits = 64;
        }
        if (DstBits == 64) {
          std::string Fp = NextVal(), Ins = NextVal(), Res = NextVal();
          OS << "  " << Fp << " = sitofp i" << SrcBits << " " << GVal << " to double\n";
          OS << "  " << Ins << " = insertelement <2 x double> zeroinitializer, double " << Fp << ", i32 0\n";
          OS << "  " << Res << " = bitcast <2 x double> " << Ins << " to <2 x i64>\n";
          StoreFPRDest(CodeNode, Res);
        } else {
          std::string Fp = NextVal(), Ins = NextVal(), Res = NextVal();
          OS << "  " << Fp << " = sitofp i" << SrcBits << " " << GVal << " to float\n";
          OS << "  " << Ins << " = insertelement <4 x float> zeroinitializer, float " << Fp << ", i32 0\n";
          OS << "  " << Res << " = bitcast <4 x float> " << Ins << " to <2 x i64>\n";
          StoreFPRDest(CodeNode, Res);
        }
        break;
      }

      case FEXCore::IR::OP_FLOAT_FTOF: {
        auto* Op = IROp->C<FEXCore::IR::IROp_Float_FToF>();
        std::string V = LoadFPROperand(Op->Scalar);
        unsigned DstBits = OpSizeToBits(IROp->ElementSize);
        unsigned SrcBits = OpSizeToBits(Op->SrcElementSize);
        if (DstBits == 64 && SrcBits == 32) {
          std::string BC = NextVal(), E = NextVal(), Cvt = NextVal(), Ins = NextVal(), Res = NextVal();
          OS << "  " << BC << " = bitcast <2 x i64> " << V << " to <4 x float>\n";
          OS << "  " << E << " = extractelement <4 x float> " << BC << ", i32 0\n";
          OS << "  " << Cvt << " = fpext float " << E << " to double\n";
          OS << "  " << Ins << " = insertelement <2 x double> zeroinitializer, double " << Cvt << ", i32 0\n";
          OS << "  " << Res << " = bitcast <2 x double> " << Ins << " to <2 x i64>\n";
          StoreFPRDest(CodeNode, Res);
        } else if (DstBits == 32 && SrcBits == 64) {
          std::string BC = NextVal(), E = NextVal(), Cvt = NextVal(), Ins = NextVal(), Res = NextVal();
          OS << "  " << BC << " = bitcast <2 x i64> " << V << " to <2 x double>\n";
          OS << "  " << E << " = extractelement <2 x double> " << BC << ", i32 0\n";
          OS << "  " << Cvt << " = fptrunc double " << E << " to float\n";
          OS << "  " << Ins << " = insertelement <4 x float> zeroinitializer, float " << Cvt << ", i32 0\n";
          OS << "  " << Res << " = bitcast <4 x float> " << Ins << " to <2 x i64>\n";
          StoreFPRDest(CodeNode, Res);
        } else {
          StoreFPRDest(CodeNode, ZeroUpperFPRBits(V, DstBits));
        }
        break;
      }

      case FEXCore::IR::OP_VECTORIMM: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VectorImm>();
        unsigned ElemBits = OpSizeToBits(IROp->ElementSize);
        if (ElemBits != 8 && ElemBits != 16 && ElemBits != 32 && ElemBits != 64) ElemBits = 8;
        uint64_t Val64 = 0;
        if (Op->Do64BitExpansion) {
          for (size_t i = 0; i < 8; ++i) {
            if ((Op->Immediate >> i) & 1) {
              Val64 |= (0xFFULL << (i * 8));
            }
          }
        } else {
          uint64_t ElemVal = (static_cast<uint64_t>(Op->Immediate) << Op->ShiftAmount);
          if (ElemBits < 64) ElemVal &= ((1ULL << ElemBits) - 1ULL);
          for (unsigned b = 0; b < 64; b += ElemBits) {
            Val64 |= (ElemVal << b);
          }
        }
        uint64_t Hi64 = (Bits <= 64) ? 0ULL : Val64;
        StoreFPRDest(CodeNode, MakeVec128Const(Val64, Hi64));
        break;
      }

      case FEXCore::IR::OP_VEXTRACTTOGPR: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VExtractToGPR>();
        std::string V = LoadFPROperand(Op->Vector);
        unsigned ElemBits = OpSizeToBits(IROp->ElementSize);
        if (ElemBits == 0) ElemBits = 64;
        unsigned Lanes = 128 / ElemBits;
        unsigned LaneIdx = Op->Index % Lanes;
        std::string VecTy = "<" + std::to_string(Lanes) + " x i" + std::to_string(ElemBits) + ">";
        std::string BC = NextVal(), Ext = NextVal();
        OS << "  " << BC << " = bitcast <2 x i64> " << V << " to " << VecTy << "\n";
        OS << "  " << Ext << " = extractelement " << VecTy << " " << BC << ", i32 " << LaneIdx << "\n";
        if (ElemBits < 64) {
          std::string Z = NextVal();
          OS << "  " << Z << " = zext i" << ElemBits << " " << Ext << " to i64\n";
          Ext = Z;
        }
        StoreGPRDest(CodeNode, MaskToOpSize(Ext, OpSize));
        break;
      }

      case FEXCore::IR::OP_VCMPGT:
      case FEXCore::IR::OP_VUCMPGT:
      case FEXCore::IR::OP_VCMPEQ: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VCMPGT>();
        std::string V1 = LoadFPROperand(Op->Vector1);
        std::string V2 = LoadFPROperand(Op->Vector2);
        unsigned ElemBits = OpSizeToBits(IROp->ElementSize);
        if (ElemBits != 8 && ElemBits != 16 && ElemBits != 32 && ElemBits != 64) ElemBits = 32;
        unsigned Lanes = 128 / ElemBits;
        std::string VecTy = "<" + std::to_string(Lanes) + " x i" + std::to_string(ElemBits) + ">";
        std::string BoolTy = "<" + std::to_string(Lanes) + " x i1>";
        const char* Pred = (IROp->Op == FEXCore::IR::OP_VCMPGT) ? "sgt" :
                           (IROp->Op == FEXCore::IR::OP_VUCMPGT) ? "ugt" : "eq";
        std::string BC1 = NextVal(), BC2 = NextVal(), Cmp = NextVal(), Ext = NextVal(), Res = NextVal();
        OS << "  " << BC1 << " = bitcast <2 x i64> " << V1 << " to " << VecTy << "\n";
        OS << "  " << BC2 << " = bitcast <2 x i64> " << V2 << " to " << VecTy << "\n";
        OS << "  " << Cmp << " = icmp " << Pred << " " << VecTy << " " << BC1 << ", " << BC2 << "\n";
        OS << "  " << Ext << " = sext " << BoolTy << " " << Cmp << " to " << VecTy << "\n";
        OS << "  " << Res << " = bitcast " << VecTy << " " << Ext << " to <2 x i64>\n";
        StoreFPRDest(CodeNode, ZeroUpperFPRBits(Res, Bits));
        break;
      }

      case FEXCore::IR::OP_VCMPLTZ:
      case FEXCore::IR::OP_VCMPEQZ:
      case FEXCore::IR::OP_VCMPGTZ: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VCMPLTZ>();
        std::string V1 = LoadFPROperand(Op->Vector);
        unsigned ElemBits = OpSizeToBits(IROp->ElementSize);
        if (ElemBits != 8 && ElemBits != 16 && ElemBits != 32 && ElemBits != 64) ElemBits = 32;
        unsigned Lanes = 128 / ElemBits;
        std::string VecTy = "<" + std::to_string(Lanes) + " x i" + std::to_string(ElemBits) + ">";
        std::string BoolTy = "<" + std::to_string(Lanes) + " x i1>";
        const char* Pred = (IROp->Op == FEXCore::IR::OP_VCMPLTZ) ? "slt" :
                           (IROp->Op == FEXCore::IR::OP_VCMPEQZ) ? "eq" : "sgt";
        std::string BC1 = NextVal(), Cmp = NextVal(), Ext = NextVal(), Res = NextVal();
        OS << "  " << BC1 << " = bitcast <2 x i64> " << V1 << " to " << VecTy << "\n";
        OS << "  " << Cmp << " = icmp " << Pred << " " << VecTy << " " << BC1 << ", zeroinitializer\n";
        OS << "  " << Ext << " = sext " << BoolTy << " " << Cmp << " to " << VecTy << "\n";
        OS << "  " << Res << " = bitcast " << VecTy << " " << Ext << " to <2 x i64>\n";
        StoreFPRDest(CodeNode, ZeroUpperFPRBits(Res, Bits));
        break;
      }

      case FEXCore::IR::OP_VUSHRI:
      case FEXCore::IR::OP_VSHLI: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VUShrI>();
        std::string V1 = LoadFPROperand(Op->Vector);
        unsigned ElemBits = OpSizeToBits(IROp->ElementSize);
        if (ElemBits != 8 && ElemBits != 16 && ElemBits != 32 && ElemBits != 64) ElemBits = 32;
        if (Op->BitShift >= ElemBits) {
          StoreFPRDest(CodeNode, "zeroinitializer");
          break;
        }
        unsigned Lanes = 128 / ElemBits;
        unsigned Sh = Op->BitShift;
        std::string VecTy = "<" + std::to_string(Lanes) + " x i" + std::to_string(ElemBits) + ">";
        std::string ShVec = "<";
        for (unsigned i = 0; i < Lanes; ++i) {
          if (i > 0) ShVec += ", ";
          ShVec += "i" + std::to_string(ElemBits) + " " + std::to_string(Sh);
        }
        ShVec += ">";
        const char* ShOp = (IROp->Op == FEXCore::IR::OP_VUSHRI) ? "lshr" : "shl";
        std::string BC1 = NextVal(), OpR = NextVal(), Res = NextVal();
        OS << "  " << BC1 << " = bitcast <2 x i64> " << V1 << " to " << VecTy << "\n";
        OS << "  " << OpR << " = " << ShOp << " " << VecTy << " " << BC1 << ", " << ShVec << "\n";
        OS << "  " << Res << " = bitcast " << VecTy << " " << OpR << " to <2 x i64>\n";
        StoreFPRDest(CodeNode, ZeroUpperFPRBits(Res, Bits));
        break;
      }

      case FEXCore::IR::OP_VADDP: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VAddP>();
        unsigned ElemBits = OpSizeToBits(IROp->ElementSize);
        std::string Res = Rellume.LiftSseBinOp(LoadFPROperand(Op->VectorLower),
                                               LoadFPROperand(Op->VectorUpper),
                                               "add", true,
                                               rellume::x86_64::ResolveVecIntFacet(ElemBits));
        StoreFPRDest(CodeNode, ZeroUpperFPRBits(Res, Bits));
        break;
      }

      case FEXCore::IR::OP_VFADDP: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VFAddP>();
        unsigned ElemBits = OpSizeToBits(IROp->ElementSize);
        std::string Res = Rellume.LiftSseBinOp(LoadFPROperand(Op->VectorLower),
                                               LoadFPROperand(Op->VectorUpper),
                                               "fadd", true,
                                               rellume::x86_64::ResolveVecFloatFacet(ElemBits));
        StoreFPRDest(CodeNode, ZeroUpperFPRBits(Res, Bits));
        break;
      }

      case FEXCore::IR::OP_VZIP:
      case FEXCore::IR::OP_VZIP2:
      case FEXCore::IR::OP_VUNZIP:
      case FEXCore::IR::OP_VUNZIP2: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VZip>();
        unsigned ElemBits = OpSizeToBits(IROp->ElementSize);
        bool HighHalf = (IROp->Op == FEXCore::IR::OP_VZIP2 || IROp->Op == FEXCore::IR::OP_VUNZIP2);
        bool IsDeinterleave = (IROp->Op == FEXCore::IR::OP_VUNZIP || IROp->Op == FEXCore::IR::OP_VUNZIP2);
        StoreFPRDest(CodeNode, Rellume.LiftSseUnpck(LoadFPROperand(Op->VectorLower),
                                                    LoadFPROperand(Op->VectorUpper),
                                                    ElemBits, HighHalf, IsDeinterleave, Bits));
        break;
      }

      case FEXCore::IR::OP_VFMIN:
      case FEXCore::IR::OP_VFMAX: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VFMin>();
        unsigned ElemBits = OpSizeToBits(IROp->ElementSize);
        const char* Pred = (IROp->Op == FEXCore::IR::OP_VFMIN) ? "olt" : "ogt";
        std::string Res = Rellume.LiftSseMinMax(LoadFPROperand(Op->Vector1),
                                                LoadFPROperand(Op->Vector2),
                                                "fcmp", Pred,
                                                rellume::x86_64::ResolveVecFloatFacet(ElemBits));
        StoreFPRDest(CodeNode, ZeroUpperFPRBits(Res, Bits));
        break;
      }

      case FEXCore::IR::OP_VSMIN:
      case FEXCore::IR::OP_VSMAX:
      case FEXCore::IR::OP_VUMIN:
      case FEXCore::IR::OP_VUMAX: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VSMin>();
        unsigned ElemBits = OpSizeToBits(IROp->ElementSize);
        const char* Pred = (IROp->Op == FEXCore::IR::OP_VSMIN) ? "slt" :
                           (IROp->Op == FEXCore::IR::OP_VSMAX) ? "sgt" :
                           (IROp->Op == FEXCore::IR::OP_VUMIN) ? "ult" : "ugt";
        std::string Res = Rellume.LiftSseMinMax(LoadFPROperand(Op->Vector1),
                                                LoadFPROperand(Op->Vector2),
                                                "icmp", Pred,
                                                rellume::x86_64::ResolveVecIntFacet(ElemBits));
        StoreFPRDest(CodeNode, ZeroUpperFPRBits(Res, Bits));
        break;
      }

      case FEXCore::IR::OP_VFSQRT: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VFSqrt>();
        std::string Res = Rellume.LiftSseSqrt(LoadFPROperand(Op->Vector), OpSizeToBits(IROp->ElementSize));
        StoreFPRDest(CodeNode, ZeroUpperFPRBits(Res, Bits));
        break;
      }

      case FEXCore::IR::OP_VABS: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VAbs>();
        std::string Res = Rellume.LiftSsePabs(LoadFPROperand(Op->Vector), OpSizeToBits(IROp->ElementSize));
        StoreFPRDest(CodeNode, ZeroUpperFPRBits(Res, Bits));
        break;
      }

      case FEXCore::IR::OP_VEXTR: {
        if (getenv("FEX_TRACE_VEC")) {
          auto* OpX = IROp->C<FEXCore::IR::IROp_VExtr>();
          fprintf(stderr, "[TRACE_VEXTR] Fn=0x%llx Bits=%u ElemBits=%u Idx=%u\n",
                  (unsigned long long)GuestEntryVA, Bits, OpSizeToBits(IROp->ElementSize), (unsigned)OpX->Index);
        }
        auto* Op = IROp->C<FEXCore::IR::IROp_VExtr>();
        unsigned ElemBytes = OpSizeToBits(IROp->ElementSize) / 8;
        if (ElemBytes == 0) ElemBytes = 1;
        unsigned OpBytes = (Bits == 64) ? 8 : 16;
        StoreFPRDest(CodeNode, Rellume.LiftSsePalignr(LoadFPROperand(Op->VectorUpper),
                                                      LoadFPROperand(Op->VectorLower),
                                                      Op->Index, ElemBytes, OpBytes));
        break;
      }

      case FEXCore::IR::OP_VFADDSCALARINSERT:
      case FEXCore::IR::OP_VFSUBSCALARINSERT:
      case FEXCore::IR::OP_VFMULSCALARINSERT:
      case FEXCore::IR::OP_VFDIVSCALARINSERT: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VFAddScalarInsert>();
        std::string V1 = LoadFPROperand(Op->Vector1);
        std::string V2 = LoadFPROperand(Op->Vector2);
        unsigned ElemBits = OpSizeToBits(IROp->ElementSize);
        const char* FpOp = (IROp->Op == FEXCore::IR::OP_VFADDSCALARINSERT) ? "fadd" :
                           (IROp->Op == FEXCore::IR::OP_VFSUBSCALARINSERT) ? "fsub" :
                           (IROp->Op == FEXCore::IR::OP_VFMULSCALARINSERT) ? "fmul" : "fdiv";
        if (ElemBits == 64) {
          std::string BC1 = NextVal(), BC2 = NextVal(), E1 = NextVal(), E2 = NextVal(), OpR = NextVal(), Ins = NextVal(), Res = NextVal();
          OS << "  " << BC1 << " = bitcast <2 x i64> " << V1 << " to <2 x double>\n";
          OS << "  " << BC2 << " = bitcast <2 x i64> " << V2 << " to <2 x double>\n";
          OS << "  " << E1 << " = extractelement <2 x double> " << BC1 << ", i32 0\n";
          OS << "  " << E2 << " = extractelement <2 x double> " << BC2 << ", i32 0\n";
          OS << "  " << OpR << " = " << FpOp << " double " << E1 << ", " << E2 << "\n";
          OS << "  " << Ins << " = insertelement <2 x double> " << BC1 << ", double " << OpR << ", i32 0\n";
          OS << "  " << Res << " = bitcast <2 x double> " << Ins << " to <2 x i64>\n";
          StoreFPRDest(CodeNode, Res);
        } else {
          std::string BC1 = NextVal(), BC2 = NextVal(), E1 = NextVal(), E2 = NextVal(), OpR = NextVal(), Ins = NextVal(), Res = NextVal();
          OS << "  " << BC1 << " = bitcast <2 x i64> " << V1 << " to <4 x float>\n";
          OS << "  " << BC2 << " = bitcast <2 x i64> " << V2 << " to <4 x float>\n";
          OS << "  " << E1 << " = extractelement <4 x float> " << BC1 << ", i32 0\n";
          OS << "  " << E2 << " = extractelement <4 x float> " << BC2 << ", i32 0\n";
          OS << "  " << OpR << " = " << FpOp << " float " << E1 << ", " << E2 << "\n";
          OS << "  " << Ins << " = insertelement <4 x float> " << BC1 << ", float " << OpR << ", i32 0\n";
          OS << "  " << Res << " = bitcast <4 x float> " << Ins << " to <2 x i64>\n";
          StoreFPRDest(CodeNode, Res);
        }
        break;
      }

      case FEXCore::IR::OP_VFCMPSCALARINSERT: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VFCMPScalarInsert>();
        std::string V1 = LoadFPROperand(Op->Vector1);
        std::string V2 = LoadFPROperand(Op->Vector2);
        unsigned ElemBits = OpSizeToBits(IROp->ElementSize);
        const char* Pred = "oeq";
        switch (Op->Op) {
        case FEXCore::IR::FloatCompareOp::EQ: Pred = "oeq"; break;
        case FEXCore::IR::FloatCompareOp::LT: Pred = "olt"; break;
        case FEXCore::IR::FloatCompareOp::LE: Pred = "ole"; break;
        case FEXCore::IR::FloatCompareOp::UNO: Pred = "uno"; break;
        case FEXCore::IR::FloatCompareOp::NEQ: Pred = "une"; break;
        case FEXCore::IR::FloatCompareOp::ORD: Pred = "ord"; break;
        }
        if (ElemBits == 64) {
          std::string BC1 = NextVal(), BC2 = NextVal(), E1 = NextVal(), E2 = NextVal(), Cmp = NextVal(), Mask = NextVal(), Ins = NextVal();
          OS << "  " << BC1 << " = bitcast <2 x i64> " << V1 << " to <2 x double>\n";
          OS << "  " << BC2 << " = bitcast <2 x i64> " << V2 << " to <2 x double>\n";
          OS << "  " << E1 << " = extractelement <2 x double> " << BC1 << ", i32 0\n";
          OS << "  " << E2 << " = extractelement <2 x double> " << BC2 << ", i32 0\n";
          OS << "  " << Cmp << " = fcmp " << Pred << " double " << E1 << ", " << E2 << "\n";
          OS << "  " << Mask << " = sext i1 " << Cmp << " to i64\n";
          OS << "  " << Ins << " = insertelement <2 x i64> " << V1 << ", i64 " << Mask << ", i32 0\n";
          StoreFPRDest(CodeNode, Ins);
        } else {
          std::string BC1 = NextVal(), BC2 = NextVal(), BCI = NextVal(), E1 = NextVal(), E2 = NextVal(), Cmp = NextVal(), Mask = NextVal(), Ins = NextVal(), Res = NextVal();
          OS << "  " << BC1 << " = bitcast <2 x i64> " << V1 << " to <4 x float>\n";
          OS << "  " << BC2 << " = bitcast <2 x i64> " << V2 << " to <4 x float>\n";
          OS << "  " << BCI << " = bitcast <2 x i64> " << V1 << " to <4 x i32>\n";
          OS << "  " << E1 << " = extractelement <4 x float> " << BC1 << ", i32 0\n";
          OS << "  " << E2 << " = extractelement <4 x float> " << BC2 << ", i32 0\n";
          OS << "  " << Cmp << " = fcmp " << Pred << " float " << E1 << ", " << E2 << "\n";
          OS << "  " << Mask << " = sext i1 " << Cmp << " to i32\n";
          OS << "  " << Ins << " = insertelement <4 x i32> " << BCI << ", i32 " << Mask << ", i32 0\n";
          OS << "  " << Res << " = bitcast <4 x i32> " << Ins << " to <2 x i64>\n";
          StoreFPRDest(CodeNode, Res);
        }
        break;
      }

      case FEXCore::IR::OP_VADDV: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VAddV>();
        std::string V = LoadFPROperand(Op->Vector);
        unsigned ElemBits = OpSizeToBits(IROp->ElementSize);
        if (ElemBits == 64) {
          std::string E0 = NextVal(), E1 = NextVal(), Sum = NextVal(), Res = NextVal();
          OS << "  " << E0 << " = extractelement <2 x i64> " << V << ", i32 0\n";
          OS << "  " << E1 << " = extractelement <2 x i64> " << V << ", i32 1\n";
          OS << "  " << Sum << " = add i64 " << E0 << ", " << E1 << "\n";
          OS << "  " << Res << " = insertelement <2 x i64> zeroinitializer, i64 " << Sum << ", i32 0\n";
          StoreFPRDest(CodeNode, Res);
        } else {
          if (ElemBits != 8 && ElemBits != 16 && ElemBits != 32) ElemBits = 32;
          unsigned Lanes = 128 / ElemBits;
          std::string VecTy = "<" + std::to_string(Lanes) + " x i" + std::to_string(ElemBits) + ">";
          std::string BC = NextVal(), Sum = NextVal(), Sum64 = NextVal(), Res = NextVal();
          OS << "  " << BC << " = bitcast <2 x i64> " << V << " to " << VecTy << "\n";
          OS << "  " << Sum << " = call i" << ElemBits << " @llvm.vector.reduce.add.v" << Lanes << "i" << ElemBits << "(" << VecTy << " " << BC << ")\n";
          OS << "  " << Sum64 << " = zext i" << ElemBits << " " << Sum << " to i64\n";
          OS << "  " << Res << " = insertelement <2 x i64> zeroinitializer, i64 " << Sum64 << ", i32 0\n";
          StoreFPRDest(CodeNode, Res);
        }
        break;
      }

      case FEXCore::IR::OP_VFADDV: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VFAddV>();
        std::string V = LoadFPROperand(Op->Vector);
        unsigned ElemBits = OpSizeToBits(IROp->ElementSize);
        if (ElemBits == 64) {
          std::string BC = NextVal(), E0 = NextVal(), E1 = NextVal(), Sum = NextVal(), Ins = NextVal(), Res = NextVal();
          OS << "  " << BC << " = bitcast <2 x i64> " << V << " to <2 x double>\n";
          OS << "  " << E0 << " = extractelement <2 x double> " << BC << ", i32 0\n";
          OS << "  " << E1 << " = extractelement <2 x double> " << BC << ", i32 1\n";
          OS << "  " << Sum << " = fadd double " << E0 << ", " << E1 << "\n";
          OS << "  " << Ins << " = insertelement <2 x double> zeroinitializer, double " << Sum << ", i32 0\n";
          OS << "  " << Res << " = bitcast <2 x double> " << Ins << " to <2 x i64>\n";
          StoreFPRDest(CodeNode, Res);
        } else {
          std::string BC = NextVal(), E0 = NextVal(), E1 = NextVal(), E2 = NextVal(), E3 = NextVal(), S01 = NextVal(), S23 = NextVal(), Sum = NextVal(), Ins = NextVal(), Res = NextVal();
          OS << "  " << BC << " = bitcast <2 x i64> " << V << " to <4 x float>\n";
          OS << "  " << E0 << " = extractelement <4 x float> " << BC << ", i32 0\n";
          OS << "  " << E1 << " = extractelement <4 x float> " << BC << ", i32 1\n";
          OS << "  " << E2 << " = extractelement <4 x float> " << BC << ", i32 2\n";
          OS << "  " << E3 << " = extractelement <4 x float> " << BC << ", i32 3\n";
          OS << "  " << S01 << " = fadd float " << E0 << ", " << E1 << "\n";
          OS << "  " << S23 << " = fadd float " << E2 << ", " << E3 << "\n";
          OS << "  " << Sum << " = fadd float " << S01 << ", " << S23 << "\n";
          OS << "  " << Ins << " = insertelement <4 x float> zeroinitializer, float " << Sum << ", i32 0\n";
          OS << "  " << Res << " = bitcast <4 x float> " << Ins << " to <2 x i64>\n";
          StoreFPRDest(CodeNode, Res);
        }
        break;
      }

      case FEXCore::IR::OP_VFRECP: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VFRecp>();
        std::string V = LoadFPROperand(Op->Vector);
        std::string BC = NextVal(), OpR = NextVal(), Res = NextVal();
        OS << "  " << BC << " = bitcast <2 x i64> " << V << " to <4 x float>\n";
        OS << "  " << OpR << " = fdiv <4 x float> <float 1.000000e+00, float 1.000000e+00, float 1.000000e+00, float 1.000000e+00>, " << BC << "\n";
        OS << "  " << Res << " = bitcast <4 x float> " << OpR << " to <2 x i64>\n";
        StoreFPRDest(CodeNode, ZeroUpperFPRBits(Res, Bits));
        break;
      }

      case FEXCore::IR::OP_VFRSQRT: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VFRSqrt>();
        std::string V = LoadFPROperand(Op->Vector);
        std::string BC = NextVal(), Sq = NextVal(), OpR = NextVal(), Res = NextVal();
        OS << "  " << BC << " = bitcast <2 x i64> " << V << " to <4 x float>\n";
        OS << "  " << Sq << " = call <4 x float> @llvm.sqrt.v4f32(<4 x float> " << BC << ")\n";
        OS << "  " << OpR << " = fdiv <4 x float> <float 1.000000e+00, float 1.000000e+00, float 1.000000e+00, float 1.000000e+00>, " << Sq << "\n";
        OS << "  " << Res << " = bitcast <4 x float> " << OpR << " to <2 x i64>\n";
        StoreFPRDest(CodeNode, ZeroUpperFPRBits(Res, Bits));
        break;
      }

      case FEXCore::IR::OP_VDUPELEMENT: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VDupElement>();
        std::string V = LoadFPROperand(Op->Vector);
        unsigned ElemBits = OpSizeToBits(IROp->ElementSize);
        if (ElemBits == 0 || ElemBits > 64) ElemBits = 32;
        unsigned Lanes = 128 / ElemBits;
        unsigned Idx = Op->Index % Lanes;
        std::string VecTy = "<" + std::to_string(Lanes) + " x i" + std::to_string(ElemBits) + ">";
        std::string BC = NextVal(), E = NextVal(), Ins0 = NextVal(), Shuf = NextVal(), Res = NextVal();
        OS << "  " << BC << " = bitcast <2 x i64> " << V << " to " << VecTy << "\n";
        OS << "  " << E << " = extractelement " << VecTy << " " << BC << ", i32 " << Idx << "\n";
        OS << "  " << Ins0 << " = insertelement " << VecTy << " poison, i" << ElemBits << " " << E << ", i32 0\n";
        OS << "  " << Shuf << " = shufflevector " << VecTy << " " << Ins0 << ", " << VecTy << " poison, <" << Lanes << " x i32> zeroinitializer\n";
        OS << "  " << Res << " = bitcast " << VecTy << " " << Shuf << " to <2 x i64>\n";
        StoreFPRDest(CodeNode, ZeroUpperFPRBits(Res, Bits));
        break;
      }

      case FEXCore::IR::OP_VSXTL:
      case FEXCore::IR::OP_VSXTL2:
      case FEXCore::IR::OP_VUXTL:
      case FEXCore::IR::OP_VUXTL2: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VSXTL>();
        bool IsSigned = (IROp->Op == FEXCore::IR::OP_VSXTL || IROp->Op == FEXCore::IR::OP_VSXTL2);
        bool HighHalf = (IROp->Op == FEXCore::IR::OP_VSXTL2 || IROp->Op == FEXCore::IR::OP_VUXTL2);
        StoreFPRDest(CodeNode, Rellume.LiftSsePmovx(LoadFPROperand(Op->Vector),
                                                    OpSizeToBits(IROp->ElementSize),
                                                    IsSigned, HighHalf));
        break;
      }

      case FEXCore::IR::OP_VUSHL:
      case FEXCore::IR::OP_VUSHR:
      case FEXCore::IR::OP_VSSHR: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VUShl>();
        const char* ShOp = (IROp->Op == FEXCore::IR::OP_VUSHL) ? "shl" :
                           (IROp->Op == FEXCore::IR::OP_VUSHR) ? "lshr" : "ashr";
        std::string Res = Rellume.LiftSsePshiftElement(LoadFPROperand(Op->Vector),
                                                       LoadFPROperand(Op->ShiftVector),
                                                       ShOp, OpSizeToBits(IROp->ElementSize));
        StoreFPRDest(CodeNode, ZeroUpperFPRBits(Res, Bits));
        break;
      }

      case FEXCore::IR::OP_VUSHLS:
      case FEXCore::IR::OP_VUSHRS:
      case FEXCore::IR::OP_VSSHRS: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VUShlS>();
        unsigned ElemBits = OpSizeToBits(IROp->ElementSize);
        if (ElemBits != 8 && ElemBits != 16 && ElemBits != 32 && ElemBits != 64) ElemBits = 32;
        unsigned Lanes = 128 / ElemBits;
        std::string VecTy = "<" + std::to_string(Lanes) + " x i" + std::to_string(ElemBits) + ">";
        std::string ShS = LoadFPROperand(Op->ShiftScalar);
        std::string BCS = NextVal(), E0 = NextVal(), Ins0 = NextVal(), Shuf = NextVal(), ShVec = NextVal();
        OS << "  " << BCS << " = bitcast <2 x i64> " << ShS << " to " << VecTy << "\n";
        OS << "  " << E0 << " = extractelement " << VecTy << " " << BCS << ", i32 0\n";
        OS << "  " << Ins0 << " = insertelement " << VecTy << " poison, i" << ElemBits << " " << E0 << ", i32 0\n";
        OS << "  " << Shuf << " = shufflevector " << VecTy << " " << Ins0 << ", " << VecTy << " poison, <" << Lanes << " x i32> zeroinitializer\n";
        OS << "  " << ShVec << " = bitcast " << VecTy << " " << Shuf << " to <2 x i64>\n";
        const char* ShOp = (IROp->Op == FEXCore::IR::OP_VUSHLS) ? "shl" :
                           (IROp->Op == FEXCore::IR::OP_VUSHRS) ? "lshr" : "ashr";
        std::string Res = Rellume.LiftSsePshiftElement(LoadFPROperand(Op->Vector), ShVec, ShOp, ElemBits);
        StoreFPRDest(CodeNode, ZeroUpperFPRBits(Res, Bits));
        break;
      }

      case FEXCore::IR::OP_VFCMPEQ:
      case FEXCore::IR::OP_VFCMPNEQ:
      case FEXCore::IR::OP_VFCMPLT:
      case FEXCore::IR::OP_VFCMPGT:
      case FEXCore::IR::OP_VFCMPLE:
      case FEXCore::IR::OP_VFCMPORD:
      case FEXCore::IR::OP_VFCMPUNO: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VFCMPLT>();
        std::string V1 = LoadFPROperand(Op->Vector1);
        std::string V2 = LoadFPROperand(Op->Vector2);
        unsigned ElemBits = OpSizeToBits(IROp->ElementSize);
        const char* Pred = (IROp->Op == FEXCore::IR::OP_VFCMPEQ) ? "oeq" :
                           (IROp->Op == FEXCore::IR::OP_VFCMPNEQ) ? "une" :
                           (IROp->Op == FEXCore::IR::OP_VFCMPLT) ? "olt" :
                           (IROp->Op == FEXCore::IR::OP_VFCMPGT) ? "ogt" :
                           (IROp->Op == FEXCore::IR::OP_VFCMPLE) ? "ole" :
                           (IROp->Op == FEXCore::IR::OP_VFCMPORD) ? "ord" : "uno";
        if (ElemBits == 64) {
          std::string BC1 = NextVal(), BC2 = NextVal(), Cmp = NextVal(), Ext = NextVal();
          OS << "  " << BC1 << " = bitcast <2 x i64> " << V1 << " to <2 x double>\n";
          OS << "  " << BC2 << " = bitcast <2 x i64> " << V2 << " to <2 x double>\n";
          OS << "  " << Cmp << " = fcmp " << Pred << " <2 x double> " << BC1 << ", " << BC2 << "\n";
          OS << "  " << Ext << " = sext <2 x i1> " << Cmp << " to <2 x i64>\n";
          StoreFPRDest(CodeNode, ZeroUpperFPRBits(Ext, Bits));
        } else {
          std::string BC1 = NextVal(), BC2 = NextVal(), Cmp = NextVal(), Ext = NextVal(), Res = NextVal();
          OS << "  " << BC1 << " = bitcast <2 x i64> " << V1 << " to <4 x float>\n";
          OS << "  " << BC2 << " = bitcast <2 x i64> " << V2 << " to <4 x float>\n";
          OS << "  " << Cmp << " = fcmp " << Pred << " <4 x float> " << BC1 << ", " << BC2 << "\n";
          OS << "  " << Ext << " = sext <4 x i1> " << Cmp << " to <4 x i32>\n";
          OS << "  " << Res << " = bitcast <4 x i32> " << Ext << " to <2 x i64>\n";
          StoreFPRDest(CodeNode, ZeroUpperFPRBits(Res, Bits));
        }
        break;
      }

      case FEXCore::IR::OP_VECTOR_STOF: {
        auto* Op = IROp->C<FEXCore::IR::IROp_Vector_SToF>();
        std::string V = LoadFPROperand(Op->Vector);
        unsigned ElemBits = OpSizeToBits(IROp->ElementSize);
        if (ElemBits == 64) {
          std::string Fp = NextVal(), Res = NextVal();
          OS << "  " << Fp << " = sitofp <2 x i64> " << V << " to <2 x double>\n";
          OS << "  " << Res << " = bitcast <2 x double> " << Fp << " to <2 x i64>\n";
          StoreFPRDest(CodeNode, Res);
        } else {
          std::string BC = NextVal(), Fp = NextVal(), Res = NextVal();
          OS << "  " << BC << " = bitcast <2 x i64> " << V << " to <4 x i32>\n";
          OS << "  " << Fp << " = sitofp <4 x i32> " << BC << " to <4 x float>\n";
          OS << "  " << Res << " = bitcast <4 x float> " << Fp << " to <2 x i64>\n";
          StoreFPRDest(CodeNode, Res);
        }
        break;
      }

      case FEXCore::IR::OP_VECTOR_FTOF: {
        auto* Op = IROp->C<FEXCore::IR::IROp_Vector_FToF>();
        std::string V = LoadFPROperand(Op->Vector);
        unsigned DstBits = OpSizeToBits(IROp->ElementSize);
        if (DstBits == 64) {
          std::string BC = NextVal(), Low = NextVal(), Ext = NextVal(), Res = NextVal();
          OS << "  " << BC << " = bitcast <2 x i64> " << V << " to <4 x float>\n";
          OS << "  " << Low << " = shufflevector <4 x float> " << BC << ", <4 x float> poison, <2 x i32> <i32 0, i32 1>\n";
          OS << "  " << Ext << " = fpext <2 x float> " << Low << " to <2 x double>\n";
          OS << "  " << Res << " = bitcast <2 x double> " << Ext << " to <2 x i64>\n";
          StoreFPRDest(CodeNode, Res);
        } else {
          std::string BC = NextVal(), Tr = NextVal(), Pad = NextVal(), Res = NextVal();
          OS << "  " << BC << " = bitcast <2 x i64> " << V << " to <2 x double>\n";
          OS << "  " << Tr << " = fptrunc <2 x double> " << BC << " to <2 x float>\n";
          OS << "  " << Pad << " = shufflevector <2 x float> " << Tr << ", <2 x float> zeroinitializer, <4 x i32> <i32 0, i32 1, i32 2, i32 3>\n";
          OS << "  " << Res << " = bitcast <4 x float> " << Pad << " to <2 x i64>\n";
          StoreFPRDest(CodeNode, Res);
        }
        break;
      }

      case FEXCore::IR::OP_VINSELEMENT: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VInsElement>();
        std::string DV = LoadFPROperand(Op->DestVector);
        std::string SV = LoadFPROperand(Op->SrcVector);
        unsigned ElemBits = OpSizeToBits(IROp->ElementSize);
        if (ElemBits == 0 || ElemBits > 64) ElemBits = 64;
        unsigned Lanes = 128 / ElemBits;
        unsigned DIdx = Op->DestIdx % Lanes;
        unsigned SIdx = Op->SrcIdx % Lanes;
        std::string VecTy = "<" + std::to_string(Lanes) + " x i" + std::to_string(ElemBits) + ">";
        std::string BCD = NextVal(), BCS = NextVal(), Ext = NextVal(), Ins = NextVal(), Res = NextVal();
        OS << "  " << BCD << " = bitcast <2 x i64> " << DV << " to " << VecTy << "\n";
        OS << "  " << BCS << " = bitcast <2 x i64> " << SV << " to " << VecTy << "\n";
        OS << "  " << Ext << " = extractelement " << VecTy << " " << BCS << ", i32 " << SIdx << "\n";
        OS << "  " << Ins << " = insertelement " << VecTy << " " << BCD << ", i" << ElemBits << " " << Ext << ", i32 " << DIdx << "\n";
        OS << "  " << Res << " = bitcast " << VecTy << " " << Ins << " to <2 x i64>\n";
        StoreFPRDest(CodeNode, Res);
        break;
      }

      case FEXCore::IR::OP_VINSGPR: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VInsGPR>();
        std::string DV = LoadFPROperand(Op->DestVector);
        std::string G = LoadGPROperand(Op->Src);
        unsigned ElemBits = OpSizeToBits(IROp->ElementSize);
        if (ElemBits == 0 || ElemBits > 64) ElemBits = 64;
        unsigned Lanes = 128 / ElemBits;
        unsigned DIdx = Op->DestIdx % Lanes;
        std::string VecTy = "<" + std::to_string(Lanes) + " x i" + std::to_string(ElemBits) + ">";
        std::string BCD = NextVal(), GVal = G, Ins = NextVal(), Res = NextVal();
        OS << "  " << BCD << " = bitcast <2 x i64> " << DV << " to " << VecTy << "\n";
        if (ElemBits < 64) {
          GVal = NextVal();
          OS << "  " << GVal << " = trunc i64 " << G << " to i" << ElemBits << "\n";
        }
        OS << "  " << Ins << " = insertelement " << VecTy << " " << BCD << ", i" << ElemBits << " " << GVal << ", i32 " << DIdx << "\n";
        OS << "  " << Res << " = bitcast " << VecTy << " " << Ins << " to <2 x i64>\n";
        StoreFPRDest(CodeNode, Res);
        break;
      }

      case FEXCore::IR::OP_VLOADVECTORELEMENT: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VLoadVectorElement>();
        std::string DV = LoadFPROperand(Op->DstSrc);
        std::string Addr = LoadGPROperand(Op->Addr);
        std::string Ptr = NextVal();
        OS << "  " << Ptr << " = inttoptr i64 " << Addr << " to ptr\n";
        unsigned ElemBits = OpSizeToBits(IROp->ElementSize);
        if (ElemBits >= 128) {
          std::string Val = NextVal();
          OS << "  " << Val << " = load <2 x i64>, ptr " << Ptr << ", align 1\n";
          StoreFPRDest(CodeNode, Val);
        } else {
          if (ElemBits == 0 || ElemBits > 64) ElemBits = 64;
          unsigned Lanes = 128 / ElemBits;
          unsigned Idx = Op->Index % Lanes;
          std::string VecTy = "<" + std::to_string(Lanes) + " x i" + std::to_string(ElemBits) + ">";
          std::string BCD = NextVal(), Ld = NextVal(), Ins = NextVal(), Res = NextVal();
          OS << "  " << BCD << " = bitcast <2 x i64> " << DV << " to " << VecTy << "\n";
          OS << "  " << Ld << " = load i" << ElemBits << ", ptr " << Ptr << ", align 1\n";
          OS << "  " << Ins << " = insertelement " << VecTy << " " << BCD << ", i" << ElemBits << " " << Ld << ", i32 " << Idx << "\n";
          OS << "  " << Res << " = bitcast " << VecTy << " " << Ins << " to <2 x i64>\n";
          StoreFPRDest(CodeNode, Res);
        }
        break;
      }

      case FEXCore::IR::OP_VSTOREVECTORELEMENT: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VStoreVectorElement>();
        std::string V = LoadFPROperand(Op->Value);
        std::string Addr = LoadGPROperand(Op->Addr);
        std::string Ptr = NextVal();
        OS << "  " << Ptr << " = inttoptr i64 " << Addr << " to ptr\n";
        unsigned ElemBits = OpSizeToBits(IROp->ElementSize);
        if (ElemBits >= 128) {
          OS << "  store <2 x i64> " << V << ", ptr " << Ptr << ", align 1\n";
        } else {
          if (ElemBits == 0 || ElemBits > 64) ElemBits = 64;
          unsigned Lanes = 128 / ElemBits;
          unsigned Idx = Op->Index % Lanes;
          std::string VecTy = "<" + std::to_string(Lanes) + " x i" + std::to_string(ElemBits) + ">";
          std::string BC = NextVal(), Ext = NextVal();
          OS << "  " << BC << " = bitcast <2 x i64> " << V << " to " << VecTy << "\n";
          OS << "  " << Ext << " = extractelement " << VecTy << " " << BC << ", i32 " << Idx << "\n";
          OS << "  store i" << ElemBits << " " << Ext << ", ptr " << Ptr << ", align 1\n";
        }
        break;
      }

      case FEXCore::IR::OP_VFMINSCALARINSERT:
      case FEXCore::IR::OP_VFMAXSCALARINSERT: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VFMinScalarInsert>();
        std::string V1 = LoadFPROperand(Op->Vector1);
        std::string V2 = LoadFPROperand(Op->Vector2);
        unsigned ElemBits = OpSizeToBits(IROp->ElementSize);
        const char* Pred = (IROp->Op == FEXCore::IR::OP_VFMINSCALARINSERT) ? "olt" : "ogt";
        std::string BaseVec = Op->ZeroUpperBits ? "zeroinitializer" : V1;
        if (ElemBits == 64) {
          std::string BC1 = NextVal(), BC2 = NextVal(), BCB = NextVal(), E1 = NextVal(), E2 = NextVal(), Cmp = NextVal(), Sel = NextVal(), Ins = NextVal(), Res = NextVal();
          OS << "  " << BC1 << " = bitcast <2 x i64> " << V1 << " to <2 x double>\n";
          OS << "  " << BC2 << " = bitcast <2 x i64> " << V2 << " to <2 x double>\n";
          OS << "  " << BCB << " = bitcast <2 x i64> " << BaseVec << " to <2 x double>\n";
          OS << "  " << E1 << " = extractelement <2 x double> " << BC1 << ", i32 0\n";
          OS << "  " << E2 << " = extractelement <2 x double> " << BC2 << ", i32 0\n";
          OS << "  " << Cmp << " = fcmp " << Pred << " double " << E1 << ", " << E2 << "\n";
          OS << "  " << Sel << " = select i1 " << Cmp << ", double " << E1 << ", double " << E2 << "\n";
          OS << "  " << Ins << " = insertelement <2 x double> " << BCB << ", double " << Sel << ", i32 0\n";
          OS << "  " << Res << " = bitcast <2 x double> " << Ins << " to <2 x i64>\n";
          StoreFPRDest(CodeNode, Res);
        } else {
          std::string BC1 = NextVal(), BC2 = NextVal(), BCB = NextVal(), E1 = NextVal(), E2 = NextVal(), Cmp = NextVal(), Sel = NextVal(), Ins = NextVal(), Res = NextVal();
          OS << "  " << BC1 << " = bitcast <2 x i64> " << V1 << " to <4 x float>\n";
          OS << "  " << BC2 << " = bitcast <2 x i64> " << V2 << " to <4 x float>\n";
          OS << "  " << BCB << " = bitcast <2 x i64> " << BaseVec << " to <4 x float>\n";
          OS << "  " << E1 << " = extractelement <4 x float> " << BC1 << ", i32 0\n";
          OS << "  " << E2 << " = extractelement <4 x float> " << BC2 << ", i32 0\n";
          OS << "  " << Cmp << " = fcmp " << Pred << " float " << E1 << ", " << E2 << "\n";
          OS << "  " << Sel << " = select i1 " << Cmp << ", float " << E1 << ", float " << E2 << "\n";
          OS << "  " << Ins << " = insertelement <4 x float> " << BCB << ", float " << Sel << ", i32 0\n";
          OS << "  " << Res << " = bitcast <4 x float> " << Ins << " to <2 x i64>\n";
          StoreFPRDest(CodeNode, Res);
        }
        break;
      }

      case FEXCore::IR::OP_VFSQRTSCALARINSERT: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VFSqrtScalarInsert>();
        std::string V1 = LoadFPROperand(Op->Vector1);
        std::string V2 = LoadFPROperand(Op->Vector2);
        unsigned ElemBits = OpSizeToBits(IROp->ElementSize);
        std::string BaseVec = Op->ZeroUpperBits ? "zeroinitializer" : V1;
        if (ElemBits == 64) {
          std::string BC2 = NextVal(), BCB = NextVal(), E2 = NextVal(), Sq = NextVal(), Ins = NextVal(), Res = NextVal();
          OS << "  " << BC2 << " = bitcast <2 x i64> " << V2 << " to <2 x double>\n";
          OS << "  " << BCB << " = bitcast <2 x i64> " << BaseVec << " to <2 x double>\n";
          OS << "  " << E2 << " = extractelement <2 x double> " << BC2 << ", i32 0\n";
          OS << "  " << Sq << " = call double @llvm.sqrt.f64(double " << E2 << ")\n";
          OS << "  " << Ins << " = insertelement <2 x double> " << BCB << ", double " << Sq << ", i32 0\n";
          OS << "  " << Res << " = bitcast <2 x double> " << Ins << " to <2 x i64>\n";
          StoreFPRDest(CodeNode, Res);
        } else {
          std::string BC2 = NextVal(), BCB = NextVal(), E2 = NextVal(), Sq = NextVal(), Ins = NextVal(), Res = NextVal();
          OS << "  " << BC2 << " = bitcast <2 x i64> " << V2 << " to <4 x float>\n";
          OS << "  " << BCB << " = bitcast <2 x i64> " << BaseVec << " to <4 x float>\n";
          OS << "  " << E2 << " = extractelement <4 x float> " << BC2 << ", i32 0\n";
          OS << "  " << Sq << " = call float @llvm.sqrt.f32(float " << E2 << ")\n";
          OS << "  " << Ins << " = insertelement <4 x float> " << BCB << ", float " << Sq << ", i32 0\n";
          OS << "  " << Res << " = bitcast <4 x float> " << Ins << " to <2 x i64>\n";
          StoreFPRDest(CodeNode, Res);
        }
        break;
      }

      case FEXCore::IR::OP_VFTOFSCALARINSERT: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VFToFScalarInsert>();
        std::string V1 = LoadFPROperand(Op->Vector1);
        std::string V2 = LoadFPROperand(Op->Vector2);
        unsigned DstBits = OpSizeToBits(IROp->ElementSize);
        unsigned SrcBits = OpSizeToBits(Op->SrcElementSize);
        std::string BaseVec = Op->ZeroUpperBits ? "zeroinitializer" : V1;
        if (DstBits == 64 && SrcBits == 32) {
          std::string BC2 = NextVal(), BCB = NextVal(), E2 = NextVal(), Cvt = NextVal(), Ins = NextVal(), Res = NextVal();
          OS << "  " << BC2 << " = bitcast <2 x i64> " << V2 << " to <4 x float>\n";
          OS << "  " << BCB << " = bitcast <2 x i64> " << BaseVec << " to <2 x double>\n";
          OS << "  " << E2 << " = extractelement <4 x float> " << BC2 << ", i32 0\n";
          OS << "  " << Cvt << " = fpext float " << E2 << " to double\n";
          OS << "  " << Ins << " = insertelement <2 x double> " << BCB << ", double " << Cvt << ", i32 0\n";
          OS << "  " << Res << " = bitcast <2 x double> " << Ins << " to <2 x i64>\n";
          StoreFPRDest(CodeNode, Res);
        } else if (DstBits == 32 && SrcBits == 64) {
          std::string BC2 = NextVal(), BCB = NextVal(), E2 = NextVal(), Cvt = NextVal(), Ins = NextVal(), Res = NextVal();
          OS << "  " << BC2 << " = bitcast <2 x i64> " << V2 << " to <2 x double>\n";
          OS << "  " << BCB << " = bitcast <2 x i64> " << BaseVec << " to <4 x float>\n";
          OS << "  " << E2 << " = extractelement <2 x double> " << BC2 << ", i32 0\n";
          OS << "  " << Cvt << " = fptrunc double " << E2 << " to float\n";
          OS << "  " << Ins << " = insertelement <4 x float> " << BCB << ", float " << Cvt << ", i32 0\n";
          OS << "  " << Res << " = bitcast <4 x float> " << Ins << " to <2 x i64>\n";
          StoreFPRDest(CodeNode, Res);
        } else {
          StoreFPRDest(CodeNode, V1);
        }
        break;
      }

      case FEXCore::IR::OP_VSTOFGPRINSERT: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VSToFGPRInsert>();
        std::string V1 = LoadFPROperand(Op->Vector);
        std::string G = LoadGPROperand(Op->Src);
        unsigned DstBits = OpSizeToBits(IROp->ElementSize);
        unsigned SrcBits = OpSizeToBits(Op->SrcElementSize);
        std::string BaseVec = Op->ZeroUpperBits ? "zeroinitializer" : V1;
        std::string GVal = G;
        if (SrcBits == 32) {
          GVal = NextVal();
          OS << "  " << GVal << " = trunc i64 " << G << " to i32\n";
        } else {
          SrcBits = 64;
        }
        if (DstBits == 64) {
          std::string BCB = NextVal(), Cvt = NextVal(), Ins = NextVal(), Res = NextVal();
          OS << "  " << BCB << " = bitcast <2 x i64> " << BaseVec << " to <2 x double>\n";
          OS << "  " << Cvt << " = sitofp i" << SrcBits << " " << GVal << " to double\n";
          OS << "  " << Ins << " = insertelement <2 x double> " << BCB << ", double " << Cvt << ", i32 0\n";
          OS << "  " << Res << " = bitcast <2 x double> " << Ins << " to <2 x i64>\n";
          StoreFPRDest(CodeNode, Res);
        } else {
          std::string BCB = NextVal(), Cvt = NextVal(), Ins = NextVal(), Res = NextVal();
          OS << "  " << BCB << " = bitcast <2 x i64> " << BaseVec << " to <4 x float>\n";
          OS << "  " << Cvt << " = sitofp i" << SrcBits << " " << GVal << " to float\n";
          OS << "  " << Ins << " = insertelement <4 x float> " << BCB << ", float " << Cvt << ", i32 0\n";
          OS << "  " << Res << " = bitcast <4 x float> " << Ins << " to <2 x i64>\n";
          StoreFPRDest(CodeNode, Res);
        }
        break;
      }

      case FEXCore::IR::OP_VSTOFVECTORINSERT: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VSToFVectorInsert>();
        std::string V1 = LoadFPROperand(Op->Vector1);
        std::string V2 = LoadFPROperand(Op->Vector2);
        unsigned DstBits = OpSizeToBits(IROp->ElementSize);
        unsigned SrcBits = OpSizeToBits(Op->SrcElementSize);
        std::string BaseVec = Op->ZeroUpperBits ? "zeroinitializer" : V1;
        if (Op->HasTwoElements && DstBits == 32 && SrcBits == 32) {
          std::string BC2 = NextVal(), BCB = NextVal(), E0 = NextVal(), E1 = NextVal(), F0 = NextVal(), F1 = NextVal(), Ins0 = NextVal(), Ins1 = NextVal(), Res = NextVal();
          OS << "  " << BC2 << " = bitcast <2 x i64> " << V2 << " to <4 x i32>\n";
          OS << "  " << BCB << " = bitcast <2 x i64> " << BaseVec << " to <4 x float>\n";
          OS << "  " << E0 << " = extractelement <4 x i32> " << BC2 << ", i32 0\n";
          OS << "  " << E1 << " = extractelement <4 x i32> " << BC2 << ", i32 1\n";
          OS << "  " << F0 << " = sitofp i32 " << E0 << " to float\n";
          OS << "  " << F1 << " = sitofp i32 " << E1 << " to float\n";
          OS << "  " << Ins0 << " = insertelement <4 x float> " << BCB << ", float " << F0 << ", i32 0\n";
          OS << "  " << Ins1 << " = insertelement <4 x float> " << Ins0 << ", float " << F1 << ", i32 1\n";
          OS << "  " << Res << " = bitcast <4 x float> " << Ins1 << " to <2 x i64>\n";
          StoreFPRDest(CodeNode, Res);
        } else if (DstBits == 64) {
          std::string BC2 = NextVal(), BCB = NextVal(), E0 = NextVal(), F0 = NextVal(), Ins0 = NextVal(), Res = NextVal();
          if (SrcBits == 32) {
            OS << "  " << BC2 << " = bitcast <2 x i64> " << V2 << " to <4 x i32>\n";
            OS << "  " << E0 << " = extractelement <4 x i32> " << BC2 << ", i32 0\n";
            OS << "  " << F0 << " = sitofp i32 " << E0 << " to double\n";
          } else {
            OS << "  " << E0 << " = extractelement <2 x i64> " << V2 << ", i32 0\n";
            OS << "  " << F0 << " = sitofp i64 " << E0 << " to double\n";
          }
          OS << "  " << BCB << " = bitcast <2 x i64> " << BaseVec << " to <2 x double>\n";
          OS << "  " << Ins0 << " = insertelement <2 x double> " << BCB << ", double " << F0 << ", i32 0\n";
          OS << "  " << Res << " = bitcast <2 x double> " << Ins0 << " to <2 x i64>\n";
          StoreFPRDest(CodeNode, Res);
        } else {
          std::string BC2 = NextVal(), BCB = NextVal(), E0 = NextVal(), F0 = NextVal(), Ins0 = NextVal(), Res = NextVal();
          OS << "  " << BC2 << " = bitcast <2 x i64> " << V2 << " to <4 x i32>\n";
          OS << "  " << BCB << " = bitcast <2 x i64> " << BaseVec << " to <4 x float>\n";
          OS << "  " << E0 << " = extractelement <4 x i32> " << BC2 << ", i32 0\n";
          OS << "  " << F0 << " = sitofp i32 " << E0 << " to float\n";
          OS << "  " << Ins0 << " = insertelement <4 x float> " << BCB << ", float " << F0 << ", i32 0\n";
          OS << "  " << Res << " = bitcast <4 x float> " << Ins0 << " to <2 x i64>\n";
          StoreFPRDest(CodeNode, Res);
        }
        break;
      }

      case FEXCore::IR::OP_FLOAT_TOGPR_ZS:
      case FEXCore::IR::OP_FLOAT_TOGPR_S: {
        auto* Op = IROp->C<FEXCore::IR::IROp_Float_ToGPR_ZS>();
        std::string V = LoadFPROperand(Op->Scalar);
        unsigned SrcBits = OpSizeToBits(Op->SrcElementSize);
        unsigned DstBits = (Bits == 32) ? 32 : 64;
        std::string Res64 = NextVal();
        if (SrcBits == 64) {
          std::string BC = NextVal(), E = NextVal(), Cvt = NextVal();
          OS << "  " << BC << " = bitcast <2 x i64> " << V << " to <2 x double>\n";
          OS << "  " << E << " = extractelement <2 x double> " << BC << ", i32 0\n";
          if (DstBits == 32) {
            OS << "  " << Cvt << " = call i32 asm \"fcvtzs ${0:w}, ${1:d}\", \"=r,w\"(double " << E << ")\n";
            OS << "  " << Res64 << " = zext i32 " << Cvt << " to i64\n";
          } else {
            OS << "  " << Res64 << " = call i64 asm \"fcvtzs $0, ${1:d}\", \"=r,w\"(double " << E << ")\n";
          }
        } else {
          std::string BC = NextVal(), E = NextVal(), Cvt = NextVal();
          OS << "  " << BC << " = bitcast <2 x i64> " << V << " to <4 x float>\n";
          OS << "  " << E << " = extractelement <4 x float> " << BC << ", i32 0\n";
          if (DstBits == 32) {
            OS << "  " << Cvt << " = call i32 asm \"fcvtzs ${0:w}, ${1:s}\", \"=r,w\"(float " << E << ")\n";
            OS << "  " << Res64 << " = zext i32 " << Cvt << " to i64\n";
          } else {
            OS << "  " << Res64 << " = call i64 asm \"fcvtzs $0, ${1:s}\", \"=r,w\"(float " << E << ")\n";
          }
        }
        StoreGPRDest(CodeNode, Res64);
        break;
      }

      case FEXCore::IR::OP_VECTOR_FTOZS:
      case FEXCore::IR::OP_VECTOR_FTOS: {
        auto* Op = IROp->C<FEXCore::IR::IROp_Vector_FToZS>();
        std::string V = LoadFPROperand(Op->Vector);
        unsigned ElemBits = OpSizeToBits(IROp->ElementSize);
        std::string Res = NextVal();
        if (ElemBits == 64) {
          OS << "  " << Res << " = call <2 x i64> asm \"fcvtzs $0.2d, $1.2d\", \"=w,w\"(<2 x i64> " << V << ")\n";
        } else {
          OS << "  " << Res << " = call <2 x i64> asm \"fcvtzs $0.4s, $1.4s\", \"=w,w\"(<2 x i64> " << V << ")\n";
        }
        StoreFPRDest(CodeNode, Res);
        break;
      }

      case FEXCore::IR::OP_VSSHRI: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VSShrI>();
        std::string V1 = LoadFPROperand(Op->Vector);
        unsigned ElemBits = OpSizeToBits(IROp->ElementSize);
        if (ElemBits == 0 || ElemBits > 64) ElemBits = 32;
        unsigned Lanes = 128 / ElemBits;
        unsigned Sh = (Op->BitShift >= ElemBits) ? (ElemBits - 1) : Op->BitShift;
        std::string VecTy = "<" + std::to_string(Lanes) + " x i" + std::to_string(ElemBits) + ">";
        std::string ShVec = "<";
        for (unsigned i = 0; i < Lanes; ++i) {
          if (i > 0) ShVec += ", ";
          ShVec += "i" + std::to_string(ElemBits) + " " + std::to_string(Sh);
        }
        ShVec += ">";
        std::string BC1 = NextVal(), OpR = NextVal(), Res = NextVal();
        OS << "  " << BC1 << " = bitcast <2 x i64> " << V1 << " to " << VecTy << "\n";
        OS << "  " << OpR << " = ashr " << VecTy << " " << BC1 << ", " << ShVec << "\n";
        OS << "  " << Res << " = bitcast " << VecTy << " " << OpR << " to <2 x i64>\n";
        StoreFPRDest(CodeNode, Res);
        break;
      }

      case FEXCore::IR::OP_VUQADD:
      case FEXCore::IR::OP_VUQSUB:
      case FEXCore::IR::OP_VSQADD:
      case FEXCore::IR::OP_VSQSUB: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VUQAdd>();
        std::string V1 = LoadFPROperand(Op->Vector1);
        std::string V2 = LoadFPROperand(Op->Vector2);
        unsigned ElemBits = OpSizeToBits(IROp->ElementSize);
        if (ElemBits != 8 && ElemBits != 16) ElemBits = 8;
        unsigned Lanes = 128 / ElemBits;
        std::string VecTy = "<" + std::to_string(Lanes) + " x i" + std::to_string(ElemBits) + ">";
        const char* Intr = (IROp->Op == FEXCore::IR::OP_VUQADD) ? "uadd.sat" :
                           (IROp->Op == FEXCore::IR::OP_VUQSUB) ? "usub.sat" :
                           (IROp->Op == FEXCore::IR::OP_VSQADD) ? "sadd.sat" : "ssub.sat";
        std::string IntrName = std::string("@llvm.") + Intr + ".v" + std::to_string(Lanes) + "i" + std::to_string(ElemBits);
        std::string BC1 = NextVal(), BC2 = NextVal(), OpR = NextVal(), Res = NextVal();
        OS << "  " << BC1 << " = bitcast <2 x i64> " << V1 << " to " << VecTy << "\n";
        OS << "  " << BC2 << " = bitcast <2 x i64> " << V2 << " to " << VecTy << "\n";
        OS << "  " << OpR << " = call " << VecTy << " " << IntrName << "(" << VecTy << " " << BC1 << ", " << VecTy << " " << BC2 << ")\n";
        OS << "  " << Res << " = bitcast " << VecTy << " " << OpR << " to <2 x i64>\n";
        StoreFPRDest(CodeNode, Res);
        break;
      }

      case FEXCore::IR::OP_VSQXTUNPAIR:
      case FEXCore::IR::OP_VSQXTNPAIR: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VSQXTUNPair>();
        std::string VL = LoadFPROperand(Op->VectorLower);
        std::string VU = LoadFPROperand(Op->VectorUpper);
        unsigned ElemBits = OpSizeToBits(IROp->ElementSize);
        bool IsUnsigned = (IROp->Op == FEXCore::IR::OP_VSQXTUNPAIR);
        std::string Res = NextVal();
        const char* Mn1 = IsUnsigned ? "sqxtun" : "sqxtn";
        const char* Mn2 = IsUnsigned ? "sqxtun2" : "sqxtn2";
        const char* Arr1 = (ElemBits == 8) ? "8b, $1.8h" : (ElemBits == 16) ? "4h, $1.4s" : "2s, $1.2d";
        const char* Arr2 = (ElemBits == 8) ? "16b, $2.8h" : (ElemBits == 16) ? "8h, $2.4s" : "4s, $2.2d";
        OS << "  " << Res << " = call <2 x i64> asm \"" << Mn1 << " $0." << Arr1 << " ; " << Mn2 << " $0." << Arr2 << "\", \"=&w,w,w\"(<2 x i64> " << VL << ", <2 x i64> " << VU << ")\n";
        StoreFPRDest(CodeNode, Res);
        break;
      }

      case FEXCore::IR::OP_VFDIV: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VFDiv>();
        std::string V1 = LoadFPROperand(Op->Vector1);
        std::string V2 = LoadFPROperand(Op->Vector2);
        unsigned ElemBits = OpSizeToBits(IROp->ElementSize);
        std::string BC1 = NextVal(), BC2 = NextVal(), OpR = NextVal(), Res = NextVal();
        if (ElemBits == 64) {
          OS << "  " << BC1 << " = bitcast <2 x i64> " << V1 << " to <2 x double>\n";
          OS << "  " << BC2 << " = bitcast <2 x i64> " << V2 << " to <2 x double>\n";
          OS << "  " << OpR << " = fdiv <2 x double> " << BC1 << ", " << BC2 << "\n";
          OS << "  " << Res << " = bitcast <2 x double> " << OpR << " to <2 x i64>\n";
        } else {
          OS << "  " << BC1 << " = bitcast <2 x i64> " << V1 << " to <4 x float>\n";
          OS << "  " << BC2 << " = bitcast <2 x i64> " << V2 << " to <4 x float>\n";
          OS << "  " << OpR << " = fdiv <4 x float> " << BC1 << ", " << BC2 << "\n";
          OS << "  " << Res << " = bitcast <4 x float> " << OpR << " to <2 x i64>\n";
        }
        StoreFPRDest(CodeNode, Res);
        break;
      }

      case FEXCore::IR::OP_VMUL: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VMul>();
        std::string V1 = LoadFPROperand(Op->Vector1);
        std::string V2 = LoadFPROperand(Op->Vector2);
        unsigned ElemBits = OpSizeToBits(IROp->ElementSize);
        if (ElemBits == 0 || ElemBits > 64) ElemBits = 32;
        unsigned Lanes = 128 / ElemBits;
        std::string VecTy = "<" + std::to_string(Lanes) + " x i" + std::to_string(ElemBits) + ">";
        std::string BC1 = NextVal(), BC2 = NextVal(), OpR = NextVal(), Res = NextVal();
        OS << "  " << BC1 << " = bitcast <2 x i64> " << V1 << " to " << VecTy << "\n";
        OS << "  " << BC2 << " = bitcast <2 x i64> " << V2 << " to " << VecTy << "\n";
        OS << "  " << OpR << " = mul " << VecTy << " " << BC1 << ", " << BC2 << "\n";
        OS << "  " << Res << " = bitcast " << VecTy << " " << OpR << " to <2 x i64>\n";
        StoreFPRDest(CodeNode, Res);
        break;
      }

      case FEXCore::IR::OP_VUMULH: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VUMulH>();
        std::string V1 = LoadFPROperand(Op->Vector1);
        std::string V2 = LoadFPROperand(Op->Vector2);
        std::string BC1 = NextVal(), BC2 = NextVal(), Z1 = NextVal(), Z2 = NextVal(), M = NextVal(), Sh = NextVal(), Tr = NextVal(), Res = NextVal();
        OS << "  " << BC1 << " = bitcast <2 x i64> " << V1 << " to <8 x i16>\n";
        OS << "  " << BC2 << " = bitcast <2 x i64> " << V2 << " to <8 x i16>\n";
        OS << "  " << Z1 << " = zext <8 x i16> " << BC1 << " to <8 x i32>\n";
        OS << "  " << Z2 << " = zext <8 x i16> " << BC2 << " to <8 x i32>\n";
        OS << "  " << M << " = mul <8 x i32> " << Z1 << ", " << Z2 << "\n";
        OS << "  " << Sh << " = lshr <8 x i32> " << M << ", <i32 16, i32 16, i32 16, i32 16, i32 16, i32 16, i32 16, i32 16>\n";
        OS << "  " << Tr << " = trunc <8 x i32> " << Sh << " to <8 x i16>\n";
        OS << "  " << Res << " = bitcast <8 x i16> " << Tr << " to <2 x i64>\n";
        StoreFPRDest(CodeNode, Res);
        break;
      }

      case FEXCore::IR::OP_VUMULL:
      case FEXCore::IR::OP_VSMULL:
      case FEXCore::IR::OP_VUMULL2:
      case FEXCore::IR::OP_VSMULL2: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VUMull>();
        std::string V1 = LoadFPROperand(Op->Vector1);
        std::string V2 = LoadFPROperand(Op->Vector2);
        unsigned ElemBits = OpSizeToBits(IROp->ElementSize);
        bool IsSigned = (IROp->Op == FEXCore::IR::OP_VSMULL || IROp->Op == FEXCore::IR::OP_VSMULL2);
        bool IsHigh = (IROp->Op == FEXCore::IR::OP_VUMULL2 || IROp->Op == FEXCore::IR::OP_VSMULL2);
        const char* Mn = IsSigned ? (IsHigh ? "smull2" : "smull") : (IsHigh ? "umull2" : "umull");
        const char* Arr = (ElemBits == 16) ? (IsHigh ? "8h, $1.16b, $2.16b" : "8h, $1.8b, $2.8b") :
                          (ElemBits == 32) ? (IsHigh ? "4s, $1.8h, $2.8h" : "4s, $1.4h, $2.4h") :
                                             (IsHigh ? "2d, $1.4s, $2.4s" : "2d, $1.2s, $2.2s");
        std::string Res = NextVal();
        OS << "  " << Res << " = call <2 x i64> asm \"" << Mn << " $0." << Arr << "\", \"=w,w,w\"(<2 x i64> " << V1 << ", <2 x i64> " << V2 << ")\n";
        StoreFPRDest(CodeNode, Res);
        break;
      }

      case FEXCore::IR::OP_VUABDL:
      case FEXCore::IR::OP_VUABDL2: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VUABDL>();
        std::string V1 = LoadFPROperand(Op->Vector1);
        std::string V2 = LoadFPROperand(Op->Vector2);
        unsigned ElemBits = OpSizeToBits(IROp->ElementSize);
        bool IsHigh = (IROp->Op == FEXCore::IR::OP_VUABDL2);
        const char* Mn = IsHigh ? "uabdl2" : "uabdl";
        const char* Arr = (ElemBits == 16) ? (IsHigh ? "8h, $1.16b, $2.16b" : "8h, $1.8b, $2.8b") :
                          (ElemBits == 32) ? (IsHigh ? "4s, $1.8h, $2.8h" : "4s, $1.4h, $2.4h") :
                                             (IsHigh ? "2d, $1.4s, $2.4s" : "2d, $1.2s, $2.2s");
        std::string Res = NextVal();
        OS << "  " << Res << " = call <2 x i64> asm \"" << Mn << " $0." << Arr << "\", \"=w,w,w\"(<2 x i64> " << V1 << ", <2 x i64> " << V2 << ")\n";
        StoreFPRDest(CodeNode, Res);
        break;
      }

      case FEXCore::IR::OP_VURAVG: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VURAvg>();
        std::string V1 = LoadFPROperand(Op->Vector1);
        std::string V2 = LoadFPROperand(Op->Vector2);
        unsigned ElemBits = OpSizeToBits(IROp->ElementSize);
        const char* Arr = (ElemBits == 8) ? "16b" : (ElemBits == 16) ? "8h" : "4s";
        std::string Res = NextVal();
        OS << "  " << Res << " = call <2 x i64> asm \"urhadd $0." << Arr << ", $1." << Arr << ", $2." << Arr << "\", \"=w,w,w\"(<2 x i64> " << V1 << ", <2 x i64> " << V2 << ")\n";
        StoreFPRDest(CodeNode, Res);
        break;
      }

      case FEXCore::IR::OP_VREV64: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VRev64>();
        std::string V1 = LoadFPROperand(Op->Vector);
        unsigned ElemBits = OpSizeToBits(IROp->ElementSize);
        const char* Arr = (ElemBits == 8) ? "16b" : (ElemBits == 16) ? "8h" : "4s";
        std::string Res = NextVal();
        OS << "  " << Res << " = call <2 x i64> asm \"rev64 $0." << Arr << ", $1." << Arr << "\", \"=w,w\"(<2 x i64> " << V1 << ")\n";
        StoreFPRDest(CodeNode, ZeroUpperFPRBits(Res, Bits));
        break;
      }

      case FEXCore::IR::OP_VREV32: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VRev32>();
        std::string V1 = LoadFPROperand(Op->Vector);
        unsigned ElemBits = OpSizeToBits(IROp->ElementSize);
        const char* Arr = (ElemBits == 8) ? "16b" : "8h";
        std::string Res = NextVal();
        OS << "  " << Res << " = call <2 x i64> asm \"rev32 $0." << Arr << ", $1." << Arr << "\", \"=w,w\"(<2 x i64> " << V1 << ")\n";
        StoreFPRDest(CodeNode, ZeroUpperFPRBits(Res, Bits));
        break;
      }

      case FEXCore::IR::OP_VTRN:
      case FEXCore::IR::OP_VTRN2: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VTrn>();
        std::string V1 = LoadFPROperand(Op->VectorLower);
        std::string V2 = LoadFPROperand(Op->VectorUpper);
        unsigned ElemBits = OpSizeToBits(IROp->ElementSize);
        const char* Mn = (IROp->Op == FEXCore::IR::OP_VTRN2) ? "trn2" : "trn1";
        const char* Arr = (ElemBits == 8) ? "16b" : (ElemBits == 16) ? "8h" : (ElemBits == 32) ? "4s" : "2d";
        std::string Res = NextVal();
        OS << "  " << Res << " = call <2 x i64> asm \"" << Mn << " $0." << Arr << ", $1." << Arr << ", $2." << Arr << "\", \"=w,w,w\"(<2 x i64> " << V1 << ", <2 x i64> " << V2 << ")\n";
        StoreFPRDest(CodeNode, ZeroUpperFPRBits(Res, Bits));
        break;
      }

      case FEXCore::IR::OP_VTBL1: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VTBL1>();
        std::string VT = LoadFPROperand(Op->VectorTable);
        std::string VI = LoadFPROperand(Op->VectorIndices);
        std::string BCT = NextVal(), BCI = NextVal(), Tbl = NextVal(), Res = NextVal();
        OS << "  " << BCT << " = bitcast <2 x i64> " << VT << " to <16 x i8>\n";
        OS << "  " << BCI << " = bitcast <2 x i64> " << VI << " to <16 x i8>\n";
        OS << "  " << Tbl << " = call <16 x i8> @llvm.aarch64.neon.tbl1.v16i8(<16 x i8> " << BCT << ", <16 x i8> " << BCI << ")\n";
        OS << "  " << Res << " = bitcast <16 x i8> " << Tbl << " to <2 x i64>\n";
        StoreFPRDest(CodeNode, ZeroUpperFPRBits(Res, Bits));
        break;
      }

      case FEXCore::IR::OP_VTBL2: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VTBL2>();
        std::string VT1 = LoadFPROperand(Op->VectorTable1);
        std::string VT2 = LoadFPROperand(Op->VectorTable2);
        std::string VI = LoadFPROperand(Op->VectorIndices);
        std::string BCT1 = NextVal(), BCT2 = NextVal(), BCI = NextVal(), Tbl = NextVal(), Res = NextVal();
        OS << "  " << BCT1 << " = bitcast <2 x i64> " << VT1 << " to <16 x i8>\n";
        OS << "  " << BCT2 << " = bitcast <2 x i64> " << VT2 << " to <16 x i8>\n";
        OS << "  " << BCI << " = bitcast <2 x i64> " << VI << " to <16 x i8>\n";
        OS << "  " << Tbl << " = call <16 x i8> @llvm.aarch64.neon.tbl2.v16i8(<16 x i8> " << BCT1 << ", <16 x i8> " << BCT2 << ", <16 x i8> " << BCI << ")\n";
        OS << "  " << Res << " = bitcast <16 x i8> " << Tbl << " to <2 x i64>\n";
        StoreFPRDest(CodeNode, ZeroUpperFPRBits(Res, Bits));
        break;
      }

      case FEXCore::IR::OP_VTBX1: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VTBX1>();
        std::string VSD = LoadFPROperand(Op->VectorSrcDst);
        std::string VT = LoadFPROperand(Op->VectorTable);
        std::string VI = LoadFPROperand(Op->VectorIndices);
        std::string BCSD = NextVal(), BCT = NextVal(), BCI = NextVal(), Tbx = NextVal(), Res = NextVal();
        OS << "  " << BCSD << " = bitcast <2 x i64> " << VSD << " to <16 x i8>\n";
        OS << "  " << BCT << " = bitcast <2 x i64> " << VT << " to <16 x i8>\n";
        OS << "  " << BCI << " = bitcast <2 x i64> " << VI << " to <16 x i8>\n";
        OS << "  " << Tbx << " = call <16 x i8> @llvm.aarch64.neon.tbx1.v16i8(<16 x i8> " << BCSD << ", <16 x i8> " << BCT << ", <16 x i8> " << BCI << ")\n";
        OS << "  " << Res << " = bitcast <16 x i8> " << Tbx << " to <2 x i64>\n";
        StoreFPRDest(CodeNode, ZeroUpperFPRBits(Res, Bits));
        break;
      }

      case FEXCore::IR::OP_VBLENDIMM: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VBlendImm>();
        std::string VL = LoadFPROperand(Op->LHS);
        std::string VR = LoadFPROperand(Op->RHS);
        unsigned ElemBits = OpSizeToBits(IROp->ElementSize);
        if (ElemBits != 8 && ElemBits != 16 && ElemBits != 32 && ElemBits != 64) ElemBits = 32;
        unsigned Lanes = 128 / ElemBits;
        std::string VecTy = "<" + std::to_string(Lanes) + " x i" + std::to_string(ElemBits) + ">";
        std::string MaskStr = "<";
        for (unsigned i = 0; i < Lanes; ++i) {
          if (i) MaskStr += ", ";
          bool PickR = ((Op->Selector >> i) & 1) != 0;
          MaskStr += "i32 " + std::to_string(PickR ? (Lanes + i) : i);
        }
        MaskStr += ">";
        std::string BCL = NextVal(), BCR = NextVal(), Shuf = NextVal(), Res = NextVal();
        OS << "  " << BCL << " = bitcast <2 x i64> " << VL << " to " << VecTy << "\n";
        OS << "  " << BCR << " = bitcast <2 x i64> " << VR << " to " << VecTy << "\n";
        OS << "  " << Shuf << " = shufflevector " << VecTy << " " << BCL << ", " << VecTy << " " << BCR << ", <" << Lanes << " x i32> " << MaskStr << "\n";
        OS << "  " << Res << " = bitcast " << VecTy << " " << Shuf << " to <2 x i64>\n";
        StoreFPRDest(CodeNode, ZeroUpperFPRBits(Res, Bits));
        break;
      }

      case FEXCore::IR::OP_VNEG: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VNeg>();
        std::string V = LoadFPROperand(Op->Vector);
        unsigned ElemBits = OpSizeToBits(IROp->ElementSize);
        if (ElemBits != 8 && ElemBits != 16 && ElemBits != 32 && ElemBits != 64) ElemBits = 32;
        unsigned Lanes = 128 / ElemBits;
        std::string VecTy = "<" + std::to_string(Lanes) + " x i" + std::to_string(ElemBits) + ">";
        std::string BC = NextVal(), Neg = NextVal(), Res = NextVal();
        OS << "  " << BC << " = bitcast <2 x i64> " << V << " to " << VecTy << "\n";
        OS << "  " << Neg << " = sub " << VecTy << " zeroinitializer, " << BC << "\n";
        OS << "  " << Res << " = bitcast " << VecTy << " " << Neg << " to <2 x i64>\n";
        StoreFPRDest(CodeNode, ZeroUpperFPRBits(Res, Bits));
        break;
      }

      case FEXCore::IR::OP_VFNEG: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VFNeg>();
        std::string V = LoadFPROperand(Op->Vector);
        unsigned ElemBits = OpSizeToBits(IROp->ElementSize);
        std::string BC = NextVal(), Neg = NextVal(), Res = NextVal();
        if (ElemBits == 64) {
          OS << "  " << BC << " = bitcast <2 x i64> " << V << " to <2 x double>\n";
          OS << "  " << Neg << " = fneg <2 x double> " << BC << "\n";
          OS << "  " << Res << " = bitcast <2 x double> " << Neg << " to <2 x i64>\n";
        } else {
          OS << "  " << BC << " = bitcast <2 x i64> " << V << " to <4 x float>\n";
          OS << "  " << Neg << " = fneg <4 x float> " << BC << "\n";
          OS << "  " << Res << " = bitcast <4 x float> " << Neg << " to <2 x i64>\n";
        }
        StoreFPRDest(CodeNode, ZeroUpperFPRBits(Res, Bits));
        break;
      }

      case FEXCore::IR::OP_VFABS: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VFAbs>();
        std::string V = LoadFPROperand(Op->Vector);
        unsigned ElemBits = OpSizeToBits(IROp->ElementSize);
        std::string BC = NextVal(), Abs = NextVal(), Res = NextVal();
        if (ElemBits == 64) {
          OS << "  " << BC << " = bitcast <2 x i64> " << V << " to <2 x double>\n";
          OS << "  " << Abs << " = call <2 x double> @llvm.fabs.v2f64(<2 x double> " << BC << ")\n";
          OS << "  " << Res << " = bitcast <2 x double> " << Abs << " to <2 x i64>\n";
        } else {
          OS << "  " << BC << " = bitcast <2 x i64> " << V << " to <4 x float>\n";
          OS << "  " << Abs << " = call <4 x float> @llvm.fabs.v4f32(<4 x float> " << BC << ")\n";
          OS << "  " << Res << " = bitcast <4 x float> " << Abs << " to <2 x i64>\n";
        }
        StoreFPRDest(CodeNode, ZeroUpperFPRBits(Res, Bits));
        break;
      }

      case FEXCore::IR::OP_VPOPCOUNT: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VPopcount>();
        std::string V = LoadFPROperand(Op->Vector);
        std::string BC = NextVal(), Cnt = NextVal(), Res = NextVal();
        OS << "  " << BC << " = bitcast <2 x i64> " << V << " to <16 x i8>\n";
        OS << "  " << Cnt << " = call <16 x i8> @llvm.ctpop.v16i8(<16 x i8> " << BC << ")\n";
        OS << "  " << Res << " = bitcast <16 x i8> " << Cnt << " to <2 x i64>\n";
        StoreFPRDest(CodeNode, ZeroUpperFPRBits(Res, Bits));
        break;
      }

      case FEXCore::IR::OP_VFCOPYSIGN: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VFCopySign>();
        std::string V1 = LoadFPROperand(Op->Vector1);
        std::string V2 = LoadFPROperand(Op->Vector2);
        unsigned ElemBits = OpSizeToBits(IROp->ElementSize);
        std::string BC1 = NextVal(), BC2 = NextVal(), Cs = NextVal(), Res = NextVal();
        if (ElemBits == 64) {
          OS << "  " << BC1 << " = bitcast <2 x i64> " << V1 << " to <2 x double>\n";
          OS << "  " << BC2 << " = bitcast <2 x i64> " << V2 << " to <2 x double>\n";
          OS << "  " << Cs << " = call <2 x double> @llvm.copysign.v2f64(<2 x double> " << BC1 << ", <2 x double> " << BC2 << ")\n";
          OS << "  " << Res << " = bitcast <2 x double> " << Cs << " to <2 x i64>\n";
        } else {
          OS << "  " << BC1 << " = bitcast <2 x i64> " << V1 << " to <4 x float>\n";
          OS << "  " << BC2 << " = bitcast <2 x i64> " << V2 << " to <4 x float>\n";
          OS << "  " << Cs << " = call <4 x float> @llvm.copysign.v4f32(<4 x float> " << BC1 << ", <4 x float> " << BC2 << ")\n";
          OS << "  " << Res << " = bitcast <4 x float> " << Cs << " to <2 x i64>\n";
        }
        StoreFPRDest(CodeNode, ZeroUpperFPRBits(Res, Bits));
        break;
      }

      case FEXCore::IR::OP_VFMLA:
      case FEXCore::IR::OP_VFMLS:
      case FEXCore::IR::OP_VFNMLA:
      case FEXCore::IR::OP_VFNMLS: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VFMLA>();
        std::string V1 = LoadFPROperand(Op->Vector1);
        std::string V2 = LoadFPROperand(Op->Vector2);
        std::string VA = LoadFPROperand(Op->Addend);
        unsigned ElemBits = OpSizeToBits(IROp->ElementSize);
        bool NegProd = (IROp->Op == FEXCore::IR::OP_VFNMLA || IROp->Op == FEXCore::IR::OP_VFNMLS);
        bool NegAdd  = (IROp->Op == FEXCore::IR::OP_VFMLS  || IROp->Op == FEXCore::IR::OP_VFNMLS);
        const char* VecTy = (ElemBits == 64) ? "<2 x double>" : "<4 x float>";
        const char* Intr  = (ElemBits == 64) ? "@llvm.fma.v2f64" : "@llvm.fma.v4f32";
        std::string BC1 = NextVal(), BC2 = NextVal(), BCA = NextVal();
        OS << "  " << BC1 << " = bitcast <2 x i64> " << V1 << " to " << VecTy << "\n";
        OS << "  " << BC2 << " = bitcast <2 x i64> " << V2 << " to " << VecTy << "\n";
        OS << "  " << BCA << " = bitcast <2 x i64> " << VA << " to " << VecTy << "\n";
        if (NegProd) {
          std::string N1 = NextVal();
          OS << "  " << N1 << " = fneg " << VecTy << " " << BC1 << "\n";
          BC1 = N1;
        }
        if (NegAdd) {
          std::string NA = NextVal();
          OS << "  " << NA << " = fneg " << VecTy << " " << BCA << "\n";
          BCA = NA;
        }
        std::string Fma = NextVal(), Res = NextVal();
        OS << "  " << Fma << " = call " << VecTy << " " << Intr << "(" << VecTy << " " << BC1 << ", " << VecTy << " " << BC2 << ", " << VecTy << " " << BCA << ")\n";
        OS << "  " << Res << " = bitcast " << VecTy << " " << Fma << " to <2 x i64>\n";
        StoreFPRDest(CodeNode, ZeroUpperFPRBits(Res, Bits));
        break;
      }

      case FEXCore::IR::OP_VFMLASCALARINSERT:
      case FEXCore::IR::OP_VFMLSSCALARINSERT:
      case FEXCore::IR::OP_VFNMLASCALARINSERT:
      case FEXCore::IR::OP_VFNMLSSCALARINSERT: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VFMLAScalarInsert>();
        std::string VU = LoadFPROperand(Op->Upper);
        std::string V1 = LoadFPROperand(Op->Vector1);
        std::string V2 = LoadFPROperand(Op->Vector2);
        std::string VA = LoadFPROperand(Op->Addend);
        unsigned ElemBits = OpSizeToBits(IROp->ElementSize);
        bool NegProd = (IROp->Op == FEXCore::IR::OP_VFNMLASCALARINSERT || IROp->Op == FEXCore::IR::OP_VFNMLSSCALARINSERT);
        bool NegAdd  = (IROp->Op == FEXCore::IR::OP_VFMLSSCALARINSERT  || IROp->Op == FEXCore::IR::OP_VFNMLSSCALARINSERT);
        const char* VecTy = (ElemBits == 64) ? "<2 x double>" : "<4 x float>";
        const char* ScTy  = (ElemBits == 64) ? "double" : "float";
        const char* Intr  = (ElemBits == 64) ? "@llvm.fma.f64" : "@llvm.fma.f32";
        std::string BCU = NextVal(), BC1 = NextVal(), BC2 = NextVal(), BCA = NextVal();
        std::string E1 = NextVal(), E2 = NextVal(), EA = NextVal();
        OS << "  " << BCU << " = bitcast <2 x i64> " << VU << " to " << VecTy << "\n";
        OS << "  " << BC1 << " = bitcast <2 x i64> " << V1 << " to " << VecTy << "\n";
        OS << "  " << BC2 << " = bitcast <2 x i64> " << V2 << " to " << VecTy << "\n";
        OS << "  " << BCA << " = bitcast <2 x i64> " << VA << " to " << VecTy << "\n";
        OS << "  " << E1 << " = extractelement " << VecTy << " " << BC1 << ", i32 0\n";
        OS << "  " << E2 << " = extractelement " << VecTy << " " << BC2 << ", i32 0\n";
        OS << "  " << EA << " = extractelement " << VecTy << " " << BCA << ", i32 0\n";
        if (NegProd) {
          std::string N1 = NextVal();
          OS << "  " << N1 << " = fneg " << ScTy << " " << E1 << "\n";
          E1 = N1;
        }
        if (NegAdd) {
          std::string NA = NextVal();
          OS << "  " << NA << " = fneg " << ScTy << " " << EA << "\n";
          EA = NA;
        }
        std::string Fma = NextVal(), Ins = NextVal(), Res = NextVal();
        OS << "  " << Fma << " = call " << ScTy << " " << Intr << "(" << ScTy << " " << E1 << ", " << ScTy << " " << E2 << ", " << ScTy << " " << EA << ")\n";
        OS << "  " << Ins << " = insertelement " << VecTy << " " << BCU << ", " << ScTy << " " << Fma << ", i32 0\n";
        OS << "  " << Res << " = bitcast " << VecTy << " " << Ins << " to <2 x i64>\n";
        StoreFPRDest(CodeNode, Res);
        break;
      }

      case FEXCore::IR::OP_VFRSQRTSCALARINSERT:
      case FEXCore::IR::OP_VFRECPSCALARINSERT: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VFRSqrtScalarInsert>();
        std::string V1 = LoadFPROperand(Op->Vector1);
        std::string V2 = LoadFPROperand(Op->Vector2);
        unsigned ElemBits = OpSizeToBits(IROp->ElementSize);
        std::string BaseVec = Op->ZeroUpperBits ? "zeroinitializer" : V1;
        bool IsRsqrt = (IROp->Op == FEXCore::IR::OP_VFRSQRT || IROp->Op == FEXCore::IR::OP_VFRSQRTSCALARINSERT);
        const char* VecTy = (ElemBits == 64) ? "<2 x double>" : "<4 x float>";
        const char* ScTy  = (ElemBits == 64) ? "double" : "float";
        std::string BC2 = NextVal(), BCB = NextVal(), E2 = NextVal(), Den = E2, Div = NextVal(), Ins = NextVal(), Res = NextVal();
        OS << "  " << BC2 << " = bitcast <2 x i64> " << V2 << " to " << VecTy << "\n";
        OS << "  " << BCB << " = bitcast <2 x i64> " << BaseVec << " to " << VecTy << "\n";
        OS << "  " << E2 << " = extractelement " << VecTy << " " << BC2 << ", i32 0\n";
        if (IsRsqrt) {
          Den = NextVal();
          OS << "  " << Den << " = call " << ScTy << " @llvm.sqrt." << (ElemBits == 64 ? "f64" : "f32") << "(" << ScTy << " " << E2 << ")\n";
        }
        OS << "  " << Div << " = fdiv " << ScTy << " 1.000000e+00, " << Den << "\n";
        OS << "  " << Ins << " = insertelement " << VecTy << " " << BCB << ", " << ScTy << " " << Div << ", i32 0\n";
        OS << "  " << Res << " = bitcast " << VecTy << " " << Ins << " to <2 x i64>\n";
        StoreFPRDest(CodeNode, Res);
        break;
      }

      case FEXCore::IR::OP_VECTOR_FTOI:
      case FEXCore::IR::OP_VECTOR_FTOISIZED: {
        auto* Op = IROp->C<FEXCore::IR::IROp_Vector_FToI>();
        std::string V = LoadFPROperand(Op->Vector);
        unsigned ElemBits = OpSizeToBits(IROp->ElementSize);
        const char* Intr = "nearbyint";
        if (IROp->Op == FEXCore::IR::OP_VECTOR_FTOI) {
          switch (Op->Round) {
          case FEXCore::IR::RoundMode::Nearest: Intr = "nearbyint"; break;
          case FEXCore::IR::RoundMode::NegInfinity: Intr = "floor"; break;
          case FEXCore::IR::RoundMode::PosInfinity: Intr = "ceil"; break;
          case FEXCore::IR::RoundMode::TowardsZero: Intr = "trunc"; break;
          case FEXCore::IR::RoundMode::Host: Intr = "rint"; break;
          }
        } else {
          auto* OpS = IROp->C<FEXCore::IR::IROp_Vector_FToISized>();
          Intr = OpS->HostRound ? "rint" : "trunc";
        }
        std::string BC = NextVal(), Rnd = NextVal(), Res = NextVal();
        if (ElemBits == 64) {
          OS << "  " << BC << " = bitcast <2 x i64> " << V << " to <2 x double>\n";
          OS << "  " << Rnd << " = call <2 x double> @llvm." << Intr << ".v2f64(<2 x double> " << BC << ")\n";
          OS << "  " << Res << " = bitcast <2 x double> " << Rnd << " to <2 x i64>\n";
        } else {
          OS << "  " << BC << " = bitcast <2 x i64> " << V << " to <4 x float>\n";
          OS << "  " << Rnd << " = call <4 x float> @llvm." << Intr << ".v4f32(<4 x float> " << BC << ")\n";
          OS << "  " << Res << " = bitcast <4 x float> " << Rnd << " to <2 x i64>\n";
        }
        StoreFPRDest(CodeNode, ZeroUpperFPRBits(Res, Bits));
        break;
      }

      case FEXCore::IR::OP_VFTOISCALARINSERT: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VFToIScalarInsert>();
        std::string V1 = LoadFPROperand(Op->Vector1);
        std::string V2 = LoadFPROperand(Op->Vector2);
        unsigned ElemBits = OpSizeToBits(IROp->ElementSize);
        std::string BaseVec = Op->ZeroUpperBits ? "zeroinitializer" : V1;
        const char* Intr = "nearbyint";
        switch (Op->Round) {
        case FEXCore::IR::RoundMode::Nearest: Intr = "nearbyint"; break;
        case FEXCore::IR::RoundMode::NegInfinity: Intr = "floor"; break;
        case FEXCore::IR::RoundMode::PosInfinity: Intr = "ceil"; break;
        case FEXCore::IR::RoundMode::TowardsZero: Intr = "trunc"; break;
        case FEXCore::IR::RoundMode::Host: Intr = "rint"; break;
        }
        const char* VecTy = (ElemBits == 64) ? "<2 x double>" : "<4 x float>";
        const char* ScTy  = (ElemBits == 64) ? "double" : "float";
        const char* Suf   = (ElemBits == 64) ? "f64" : "f32";
        std::string BC2 = NextVal(), BCB = NextVal(), E2 = NextVal(), Rnd = NextVal(), Ins = NextVal(), Res = NextVal();
        OS << "  " << BC2 << " = bitcast <2 x i64> " << V2 << " to " << VecTy << "\n";
        OS << "  " << BCB << " = bitcast <2 x i64> " << BaseVec << " to " << VecTy << "\n";
        OS << "  " << E2 << " = extractelement " << VecTy << " " << BC2 << ", i32 0\n";
        OS << "  " << Rnd << " = call " << ScTy << " @llvm." << Intr << "." << Suf << "(" << ScTy << " " << E2 << ")\n";
        OS << "  " << Ins << " = insertelement " << VecTy << " " << BCB << ", " << ScTy << " " << Rnd << ", i32 0\n";
        OS << "  " << Res << " = bitcast " << VecTy << " " << Ins << " to <2 x i64>\n";
        StoreFPRDest(CodeNode, Res);
        break;
      }

      case FEXCore::IR::OP_VECTOR_F64TOI32: {
        auto* Op = IROp->C<FEXCore::IR::IROp_Vector_F64ToI32>();
        std::string V = LoadFPROperand(Op->Vector);
        const char* Intr = "trunc";
        switch (Op->Round) {
        case FEXCore::IR::RoundMode::Nearest: Intr = "nearbyint"; break;
        case FEXCore::IR::RoundMode::NegInfinity: Intr = "floor"; break;
        case FEXCore::IR::RoundMode::PosInfinity: Intr = "ceil"; break;
        case FEXCore::IR::RoundMode::TowardsZero: Intr = "trunc"; break;
        case FEXCore::IR::RoundMode::Host: Intr = "rint"; break;
        }
        std::string BC = NextVal(), Rnd = NextVal(), Res = NextVal();
        OS << "  " << BC << " = bitcast <2 x i64> " << V << " to <2 x double>\n";
        OS << "  " << Rnd << " = call <2 x double> @llvm." << Intr << ".v2f64(<2 x double> " << BC << ")\n";
        OS << "  " << Res << " = call <2 x i64> asm \"fcvtzs $0.2d, $1.2d ; sqxtn $0.2s, $0.2d\", \"=w,w\"(<2 x double> " << Rnd << ")\n";
        StoreFPRDest(CodeNode, ZeroUpperFPRBits(Res, 64));
        break;
      }

      case FEXCore::IR::OP_VFCVTL2: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VFCVTL2>();
        std::string V = LoadFPROperand(Op->Vector);
        unsigned DstBits = OpSizeToBits(IROp->ElementSize);
        std::string Res = NextVal();
        const char* Arr = (DstBits == 64) ? "2d, $1.4s" : "4s, $1.8h";
        OS << "  " << Res << " = call <2 x i64> asm \"fcvtl2 $0." << Arr << "\", \"=w,w\"(<2 x i64> " << V << ")\n";
        StoreFPRDest(CodeNode, Res);
        break;
      }

      case FEXCore::IR::OP_VFCVTN2: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VFCVTN2>();
        std::string VL = LoadFPROperand(Op->VectorLower);
        std::string VU = LoadFPROperand(Op->VectorUpper);
        unsigned DstBits = OpSizeToBits(IROp->ElementSize);
        std::string Res = NextVal();
        const char* Arr = (DstBits == 32) ? "4s, $2.2d" : "8h, $2.4s";
        OS << "  " << Res << " = call <2 x i64> asm \"mov $0.16b, $1.16b ; fcvtn2 $0." << Arr << "\", \"=&w,w,w\"(<2 x i64> " << VL << ", <2 x i64> " << VU << ")\n";
        StoreFPRDest(CodeNode, Res);
        break;
      }

      case FEXCore::IR::OP_VSQXTN:
      case FEXCore::IR::OP_VSQXTUN: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VSQXTN>();
        std::string V = LoadFPROperand(Op->Vector);
        unsigned ElemBits = OpSizeToBits(IROp->ElementSize);
        const char* Mn = (IROp->Op == FEXCore::IR::OP_VSQXTUN) ? "sqxtun" : "sqxtn";
        const char* Arr = (ElemBits == 8) ? "8b, $1.8h" : (ElemBits == 16) ? "4h, $1.4s" : "2s, $1.2d";
        std::string Res = NextVal();
        OS << "  " << Res << " = call <2 x i64> asm \"" << Mn << " $0." << Arr << "\", \"=w,w\"(<2 x i64> " << V << ")\n";
        StoreFPRDest(CodeNode, ZeroUpperFPRBits(Res, 64));
        break;
      }

      case FEXCore::IR::OP_VSQXTN2:
      case FEXCore::IR::OP_VSQXTUN2: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VSQXTN2>();
        std::string VL = LoadFPROperand(Op->VectorLower);
        std::string VU = LoadFPROperand(Op->VectorUpper);
        unsigned ElemBits = OpSizeToBits(IROp->ElementSize);
        const char* Mn = (IROp->Op == FEXCore::IR::OP_VSQXTUN2) ? "sqxtun2" : "sqxtn2";
        const char* Arr = (ElemBits == 8) ? "16b, $2.8h" : (ElemBits == 16) ? "8h, $2.4s" : "4s, $2.2d";
        std::string Res = NextVal();
        OS << "  " << Res << " = call <2 x i64> asm \"mov $0.16b, $1.16b ; " << Mn << " $0." << Arr << "\", \"=&w,w,w\"(<2 x i64> " << VL << ", <2 x i64> " << VU << ")\n";
        StoreFPRDest(CodeNode, Res);
        break;
      }

      case FEXCore::IR::OP_VUSHRNI: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VUShrNI>();
        std::string V = LoadFPROperand(Op->Vector);
        unsigned DstBits = OpSizeToBits(IROp->ElementSize);
        if ( DstBits != 8 && DstBits != 16 && DstBits != 32 ) DstBits = 16;
        unsigned SrcBits = DstBits * 2;
        unsigned Lanes = 128 / SrcBits;
        unsigned Sh = (Op->BitShift >= SrcBits) ? (SrcBits - 1) : Op->BitShift;
        std::string SrcVecTy = "<" + std::to_string(Lanes) + " x i" + std::to_string(SrcBits) + ">";
        std::string DstHalfTy = "<" + std::to_string(Lanes) + " x i" + std::to_string(DstBits) + ">";
        std::string BC = NextVal(), Shifted = BC, Tr = NextVal(), Z64 = NextVal(), Res = NextVal();
        OS << "  " << BC << " = bitcast <2 x i64> " << V << " to " << SrcVecTy << "\n";
        if (Sh > 0) {
          Shifted = NextVal();
          std::string ShVec = "<";
          for (unsigned i = 0; i < Lanes; ++i) {
            if (i) ShVec += ", ";
            ShVec += "i" + std::to_string(SrcBits) + " " + std::to_string(Sh);
          }
          ShVec += ">";
          OS << "  " << Shifted << " = lshr " << SrcVecTy << " " << BC << ", " << ShVec << "\n";
        }
        OS << "  " << Tr << " = trunc " << SrcVecTy << " " << Shifted << " to " << DstHalfTy << "\n";
        OS << "  " << Z64 << " = bitcast " << DstHalfTy << " " << Tr << " to i64\n";
        OS << "  " << Res << " = insertelement <2 x i64> zeroinitializer, i64 " << Z64 << ", i32 0\n";
        StoreFPRDest(CodeNode, Res);
        break;
      }

      case FEXCore::IR::OP_VSSHLL:
      case FEXCore::IR::OP_VSSHLL2: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VSSHLL>();
        bool HighHalf = (IROp->Op == FEXCore::IR::OP_VSSHLL2);
        unsigned DstBits = OpSizeToBits(IROp->ElementSize);
        if (DstBits != 16 && DstBits != 32 && DstBits != 64) DstBits = 32;
        std::string Ext = Rellume.LiftSsePmovx(LoadFPROperand(Op->Vector), DstBits, true, HighHalf);
        if (Op->BitShift > 0) {
          unsigned Lanes = 128 / DstBits;
          std::string VecTy = "<" + std::to_string(Lanes) + " x i" + std::to_string(DstBits) + ">";
          std::string ShVec = "<";
          for (unsigned i = 0; i < Lanes; ++i) {
            if (i) ShVec += ", ";
            ShVec += "i" + std::to_string(DstBits) + " " + std::to_string(Op->BitShift);
          }
          ShVec += ">";
          std::string BC = NextVal(), Sh = NextVal(), Res = NextVal();
          OS << "  " << BC << " = bitcast <2 x i64> " << Ext << " to " << VecTy << "\n";
          OS << "  " << Sh << " = shl " << VecTy << " " << BC << ", " << ShVec << "\n";
          OS << "  " << Res << " = bitcast " << VecTy << " " << Sh << " to <2 x i64>\n";
          Ext = Res;
        }
        StoreFPRDest(CodeNode, Ext);
        break;
      }

      case FEXCore::IR::OP_VSMULH: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VSMulH>();
        std::string V1 = LoadFPROperand(Op->Vector1);
        std::string V2 = LoadFPROperand(Op->Vector2);
        std::string BC1 = NextVal(), BC2 = NextVal(), S1 = NextVal(), S2 = NextVal(), M = NextVal(), Sh = NextVal(), Tr = NextVal(), Res = NextVal();
        OS << "  " << BC1 << " = bitcast <2 x i64> " << V1 << " to <8 x i16>\n";
        OS << "  " << BC2 << " = bitcast <2 x i64> " << V2 << " to <8 x i16>\n";
        OS << "  " << S1 << " = sext <8 x i16> " << BC1 << " to <8 x i32>\n";
        OS << "  " << S2 << " = sext <8 x i16> " << BC2 << " to <8 x i32>\n";
        OS << "  " << M << " = mul <8 x i32> " << S1 << ", " << S2 << "\n";
        OS << "  " << Sh << " = lshr <8 x i32> " << M << ", <i32 16, i32 16, i32 16, i32 16, i32 16, i32 16, i32 16, i32 16>\n";
        OS << "  " << Tr << " = trunc <8 x i32> " << Sh << " to <8 x i16>\n";
        OS << "  " << Res << " = bitcast <8 x i16> " << Tr << " to <2 x i64>\n";
        StoreFPRDest(CodeNode, ZeroUpperFPRBits(Res, Bits));
        break;
      }

      case FEXCore::IR::OP_VBROADCASTFROMMEM: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VBroadcastFromMem>();
        std::string Addr = LoadGPROperand(Op->Address);
        std::string Ptr = NextVal();
        OS << "  " << Ptr << " = inttoptr i64 " << Addr << " to ptr\n";
        unsigned ElemBits = OpSizeToBits(IROp->ElementSize);
        if (ElemBits >= 128) {
          std::string V = NextVal();
          OS << "  " << V << " = load <2 x i64>, ptr " << Ptr << ", align 1\n";
          StoreFPRDest(CodeNode, V);
        } else {
          if (ElemBits != 8 && ElemBits != 16 && ElemBits != 32 && ElemBits != 64) ElemBits = 32;
          unsigned Lanes = 128 / ElemBits;
          std::string VecTy = "<" + std::to_string(Lanes) + " x i" + std::to_string(ElemBits) + ">";
          std::string Ld = NextVal(), Ins0 = NextVal(), Shuf = NextVal(), Res = NextVal();
          OS << "  " << Ld << " = load i" << ElemBits << ", ptr " << Ptr << ", align 1\n";
          OS << "  " << Ins0 << " = insertelement " << VecTy << " poison, i" << ElemBits << " " << Ld << ", i32 0\n";
          OS << "  " << Shuf << " = shufflevector " << VecTy << " " << Ins0 << ", " << VecTy << " poison, <" << Lanes << " x i32> zeroinitializer\n";
          OS << "  " << Res << " = bitcast " << VecTy << " " << Shuf << " to <2 x i64>\n";
          StoreFPRDest(CodeNode, ZeroUpperFPRBits(Res, Bits));
        }
        break;
      }

      case FEXCore::IR::OP_VLOADNONTEMPORAL: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VLoadNonTemporal>();
        std::string Base = LoadGPROperand(Op->Addr);
        std::string Addr = NextVal(), Ptr = NextVal(), Vec = NextVal();
        OS << "  " << Addr << " = add i64 " << Base << ", " << static_cast<int64_t>(Op->Offset) << "\n";
        OS << "  " << Ptr << " = inttoptr i64 " << Addr << " to ptr\n";
        OS << "  " << Vec << " = load <2 x i64>, ptr " << Ptr << ", align 1\n";
        StoreFPRDest(CodeNode, Vec);
        break;
      }

      case FEXCore::IR::OP_VSTORENONTEMPORAL: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VStoreNonTemporal>();
        std::string Base = LoadGPROperand(Op->Addr);
        std::string Vec = LoadFPROperand(Op->Value);
        std::string Addr = NextVal(), Ptr = NextVal();
        OS << "  " << Addr << " = add i64 " << Base << ", " << static_cast<int64_t>(Op->Offset) << "\n";
        OS << "  " << Ptr << " = inttoptr i64 " << Addr << " to ptr\n";
        OS << "  store <2 x i64> " << Vec << ", ptr " << Ptr << ", align 1\n";
        break;
      }

      case FEXCore::IR::OP_VSTORENONTEMPORALPAIR: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VStoreNonTemporalPair>();
        std::string Base = LoadGPROperand(Op->Addr);
        std::string V1 = LoadFPROperand(Op->ValueLow);
        std::string V2 = LoadFPROperand(Op->ValueHigh);
        std::string Addr1 = NextVal(), Addr2 = NextVal(), Ptr1 = NextVal(), Ptr2 = NextVal();
        OS << "  " << Addr1 << " = add i64 " << Base << ", " << static_cast<int64_t>(Op->Offset) << "\n";
        OS << "  " << Addr2 << " = add i64 " << Addr1 << ", 16\n";
        OS << "  " << Ptr1 << " = inttoptr i64 " << Addr1 << " to ptr\n";
        OS << "  " << Ptr2 << " = inttoptr i64 " << Addr2 << " to ptr\n";
        OS << "  store <2 x i64> " << V1 << ", ptr " << Ptr1 << ", align 1\n";
        OS << "  store <2 x i64> " << V2 << ", ptr " << Ptr2 << ", align 1\n";
        break;
      }

      case FEXCore::IR::OP_VBSL: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VBSL>();
        std::string VM = LoadFPROperand(Op->VectorMask);
        std::string VT = LoadFPROperand(Op->VectorTrue);
        std::string VF = LoadFPROperand(Op->VectorFalse);
        std::string NotM = NextVal(), TPart = NextVal(), FPart = NextVal(), Res = NextVal();
        OS << "  " << NotM << " = xor <2 x i64> " << VM << ", <i64 -1, i64 -1>\n";
        OS << "  " << TPart << " = and <2 x i64> " << VT << ", " << VM << "\n";
        OS << "  " << FPart << " = and <2 x i64> " << VF << ", " << NotM << "\n";
        OS << "  " << Res << " = or <2 x i64> " << TPart << ", " << FPart << "\n";
        StoreFPRDest(CodeNode, ZeroUpperFPRBits(Res, Bits));
        break;
      }

  default:
    return false;
  }
  return true;
}

} // namespace FEXCore::AOT

// SPDX-License-Identifier: MIT AND LGPL-2.1-or-later
/*
 * Rellume x86-64 -> LLVM IR Lifter Integration for FEX-Emu Arm64EC AOT
 *
 * Adapted from Rellume (https://github.com/aengelke/rellume):
 *   (c) 2016-2019, Alexis Engelke <alexis.engelke@googlemail.com>
 *   (c) 2020, Dominik Okwieka <dominik.okwieka@t-online.de>
 *
 * Provides Rellume's typed Facet model (src/x86-64/lifter-operand.cc),
 * arithmetic & overflow-intrinsic flag calculations (src/x86-64/lifter-flags.cc),
 * general-purpose 128-bit div/mul, funnel-shift, and bit-manipulation lifters
 * (src/x86-64/lifter-gp.cc), and SSE/vector lifters (src/x86-64/lifter-sse.cc).
 */

#pragma once

#include <FEXCore/IR/IR.h>
#include "Interface/IR/IR.h"

#include <cstdint>
#include <functional>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace rellume::x86_64 {

enum class Facet {
  I,
  I8,
  I8H,
  I16,
  I32,
  I64,
  I128,
  PTR,
  F32,
  F64,
  V16I8,
  V8I16,
  V4I32,
  V2I64,
  V4F32,
  V2F64,
  V2F32,
  V2I32,
  V4I16,
  V8I8,
  V4I8,
  V2I8,
  V2I16,
};

enum class Condition {
  O = 0, NO = 1, C = 2, NC = 3, Z = 4, NZ = 5, BE = 6, A = 7,
  S = 8, NS = 9, P = 10, NP = 11, L = 12, GE = 13, LE = 14, G = 15,
};

inline Facet ResolveIntFacet(unsigned Bits) {
  switch (Bits) {
  case 8: return Facet::I8;
  case 16: return Facet::I16;
  case 32: return Facet::I32;
  case 128: return Facet::I128;
  default: return Facet::I64;
  }
}

inline Facet ResolveVecIntFacet(unsigned ElemBits) {
  switch (ElemBits) {
  case 8: return Facet::V16I8;
  case 16: return Facet::V8I16;
  case 64: return Facet::V2I64;
  default: return Facet::V4I32;
  }
}

inline Facet ResolveVecFloatFacet(unsigned ElemBits) {
  return (ElemBits == 64) ? Facet::V2F64 : Facet::V4F32;
}

inline std::string FacetTypeStr(Facet F) {
  switch (F) {
  case Facet::I8:
  case Facet::I8H: return "i8";
  case Facet::I16: return "i16";
  case Facet::I32: return "i32";
  case Facet::I64: return "i64";
  case Facet::I128: return "i128";
  case Facet::PTR: return "ptr";
  case Facet::F32: return "float";
  case Facet::F64: return "double";
  case Facet::V16I8: return "<16 x i8>";
  case Facet::V8I16: return "<8 x i16>";
  case Facet::V4I32: return "<4 x i32>";
  case Facet::V2I64: return "<2 x i64>";
  case Facet::V4F32: return "<4 x float>";
  case Facet::V2F64: return "<2 x double>";
  case Facet::V2F32: return "<2 x float>";
  case Facet::V2I32: return "<2 x i32>";
  case Facet::V4I16: return "<4 x i16>";
  case Facet::V8I8: return "<8 x i8>";
  case Facet::V4I8: return "<4 x i8>";
  case Facet::V2I8: return "<2 x i8>";
  case Facet::V2I16: return "<2 x i16>";
  default: return "i64";
  }
}

inline unsigned FacetLanes(Facet F) {
  switch (F) {
  case Facet::V16I8: return 16;
  case Facet::V8I16:
  case Facet::V8I8: return 8;
  case Facet::V4I32:
  case Facet::V4F32:
  case Facet::V4I16:
  case Facet::V4I8: return 4;
  case Facet::V2I64:
  case Facet::V2F64:
  case Facet::V2F32:
  case Facet::V2I32:
  case Facet::V2I16:
  case Facet::V2I8: return 2;
  default: return 1;
  }
}

inline unsigned FacetElemBits(Facet F) {
  switch (F) {
  case Facet::I8:
  case Facet::I8H:
  case Facet::V16I8:
  case Facet::V8I8:
  case Facet::V4I8:
  case Facet::V2I8: return 8;
  case Facet::I16:
  case Facet::V8I16:
  case Facet::V4I16:
  case Facet::V2I16: return 16;
  case Facet::I32:
  case Facet::F32:
  case Facet::V4I32:
  case Facet::V4F32:
  case Facet::V2F32:
  case Facet::V2I32: return 32;
  case Facet::I128: return 128;
  default: return 64;
  }
}

inline void EmitIntrinsicDeclarations(std::ostringstream& ModIR) {
  ModIR << "declare i16 @llvm.bswap.i16(i16)\n";
  ModIR << "declare i32 @llvm.bswap.i32(i32)\n";
  ModIR << "declare i64 @llvm.bswap.i64(i64)\n";
  ModIR << "declare i8  @llvm.bitreverse.i8(i8)\n";
  ModIR << "declare i16 @llvm.bitreverse.i16(i16)\n";
  ModIR << "declare i32 @llvm.bitreverse.i32(i32)\n";
  ModIR << "declare i64 @llvm.bitreverse.i64(i64)\n";
  ModIR << "declare i16 @llvm.cttz.i16(i16, i1 immarg)\n";
  ModIR << "declare i32 @llvm.cttz.i32(i32, i1 immarg)\n";
  ModIR << "declare i64 @llvm.cttz.i64(i64, i1 immarg)\n";
  ModIR << "declare i16 @llvm.ctlz.i16(i16, i1 immarg)\n";
  ModIR << "declare i32 @llvm.ctlz.i32(i32, i1 immarg)\n";
  ModIR << "declare i64 @llvm.ctlz.i64(i64, i1 immarg)\n";
  ModIR << "declare i8  @llvm.ctpop.i8(i8)\n";
  ModIR << "declare i16 @llvm.ctpop.i16(i16)\n";
  ModIR << "declare i32 @llvm.ctpop.i32(i32)\n";
  ModIR << "declare i64 @llvm.ctpop.i64(i64)\n";
  ModIR << "declare i8  @llvm.fshl.i8(i8, i8, i8)\n";
  ModIR << "declare i16 @llvm.fshl.i16(i16, i16, i16)\n";
  ModIR << "declare i32 @llvm.fshl.i32(i32, i32, i32)\n";
  ModIR << "declare i64 @llvm.fshl.i64(i64, i64, i64)\n";
  ModIR << "declare i8  @llvm.fshr.i8(i8, i8, i8)\n";
  ModIR << "declare i16 @llvm.fshr.i16(i16, i16, i16)\n";
  ModIR << "declare i32 @llvm.fshr.i32(i32, i32, i32)\n";
  ModIR << "declare i64 @llvm.fshr.i64(i64, i64, i64)\n";
  ModIR << "declare { i8,  i1 } @llvm.sadd.with.overflow.i8(i8, i8)\n";
  ModIR << "declare { i16, i1 } @llvm.sadd.with.overflow.i16(i16, i16)\n";
  ModIR << "declare { i32, i1 } @llvm.sadd.with.overflow.i32(i32, i32)\n";
  ModIR << "declare { i64, i1 } @llvm.sadd.with.overflow.i64(i64, i64)\n";
  ModIR << "declare { i8,  i1 } @llvm.ssub.with.overflow.i8(i8, i8)\n";
  ModIR << "declare { i16, i1 } @llvm.ssub.with.overflow.i16(i16, i16)\n";
  ModIR << "declare { i32, i1 } @llvm.ssub.with.overflow.i32(i32, i32)\n";
  ModIR << "declare { i64, i1 } @llvm.ssub.with.overflow.i64(i64, i64)\n";
  ModIR << "declare float  @llvm.sqrt.f32(float)\n";
  ModIR << "declare double @llvm.sqrt.f64(double)\n";
  ModIR << "declare <4 x float>  @llvm.sqrt.v4f32(<4 x float>)\n";
  ModIR << "declare <2 x double> @llvm.sqrt.v2f64(<2 x double>)\n";
  ModIR << "declare <16 x i8> @llvm.sadd.sat.v16i8(<16 x i8>, <16 x i8>)\n";
  ModIR << "declare <8 x i16> @llvm.sadd.sat.v8i16(<8 x i16>, <8 x i16>)\n";
  ModIR << "declare <16 x i8> @llvm.uadd.sat.v16i8(<16 x i8>, <16 x i8>)\n";
  ModIR << "declare <8 x i16> @llvm.uadd.sat.v8i16(<8 x i16>, <8 x i16>)\n";
  ModIR << "declare <16 x i8> @llvm.ssub.sat.v16i8(<16 x i8>, <16 x i8>)\n";
  ModIR << "declare <8 x i16> @llvm.ssub.sat.v8i16(<8 x i16>, <8 x i16>)\n";
  ModIR << "declare <16 x i8> @llvm.usub.sat.v16i8(<16 x i8>, <16 x i8>)\n";
  ModIR << "declare <8 x i16> @llvm.usub.sat.v8i16(<8 x i16>, <8 x i16>)\n";
  ModIR << "declare i32 @llvm.vector.reduce.add.v4i32(<4 x i32>)\n";
  ModIR << "declare i16 @llvm.vector.reduce.add.v8i16(<8 x i16>)\n";
  ModIR << "declare i8  @llvm.vector.reduce.add.v16i8(<16 x i8>)\n";
  ModIR << "declare <16 x i8> @llvm.aarch64.neon.tbl1.v16i8(<16 x i8>, <16 x i8>)\n";
  ModIR << "declare <16 x i8> @llvm.aarch64.neon.tbl2.v16i8(<16 x i8>, <16 x i8>, <16 x i8>)\n";
  ModIR << "declare <16 x i8> @llvm.aarch64.neon.tbx1.v16i8(<16 x i8>, <16 x i8>, <16 x i8>)\n";
  ModIR << "declare <16 x i8> @llvm.ctpop.v16i8(<16 x i8>)\n";
  ModIR << "declare float  @llvm.fabs.f32(float)\n";
  ModIR << "declare double @llvm.fabs.f64(double)\n";
  ModIR << "declare <4 x float>  @llvm.fabs.v4f32(<4 x float>)\n";
  ModIR << "declare <2 x double> @llvm.fabs.v2f64(<2 x double>)\n";
  ModIR << "declare <4 x float>  @llvm.copysign.v4f32(<4 x float>, <4 x float>)\n";
  ModIR << "declare <2 x double> @llvm.copysign.v2f64(<2 x double>, <2 x double>)\n";
  ModIR << "declare float  @llvm.fma.f32(float, float, float)\n";
  ModIR << "declare double @llvm.fma.f64(double, double, double)\n";
  ModIR << "declare <4 x float>  @llvm.fma.v4f32(<4 x float>, <4 x float>, <4 x float>)\n";
  ModIR << "declare <2 x double> @llvm.fma.v2f64(<2 x double>, <2 x double>, <2 x double>)\n";
  ModIR << "declare float  @llvm.rint.f32(float)\n";
  ModIR << "declare double @llvm.rint.f64(double)\n";
  ModIR << "declare <4 x float>  @llvm.rint.v4f32(<4 x float>)\n";
  ModIR << "declare <2 x double> @llvm.rint.v2f64(<2 x double>)\n";
  ModIR << "declare float  @llvm.nearbyint.f32(float)\n";
  ModIR << "declare double @llvm.nearbyint.f64(double)\n";
  ModIR << "declare <4 x float>  @llvm.nearbyint.v4f32(<4 x float>)\n";
  ModIR << "declare <2 x double> @llvm.nearbyint.v2f64(<2 x double>)\n";
  ModIR << "declare float  @llvm.floor.f32(float)\n";
  ModIR << "declare double @llvm.floor.f64(double)\n";
  ModIR << "declare <4 x float>  @llvm.floor.v4f32(<4 x float>)\n";
  ModIR << "declare <2 x double> @llvm.floor.v2f64(<2 x double>)\n";
  ModIR << "declare float  @llvm.ceil.f32(float)\n";
  ModIR << "declare double @llvm.ceil.f64(double)\n";
  ModIR << "declare <4 x float>  @llvm.ceil.v4f32(<4 x float>)\n";
  ModIR << "declare <2 x double> @llvm.ceil.v2f64(<2 x double>)\n";
  ModIR << "declare float  @llvm.trunc.f32(float)\n";
  ModIR << "declare double @llvm.trunc.f64(double)\n";
  ModIR << "declare <4 x float>  @llvm.trunc.v4f32(<4 x float>)\n";
  ModIR << "declare <2 x double> @llvm.trunc.v2f64(<2 x double>)\n\n";
}

class Lifter {
public:
  using NextValFn = std::function<std::string()>;

  Lifter(std::ostringstream& OS_, NextValFn NextVal_)
    : OS(OS_), NextVal(std::move(NextVal_)) {}

  // =========================================================================
  // 1. Rellume Flag Calculations (src/x86-64/lifter-flags.cc)
  // =========================================================================

  // Computes AArch64 NZCV (N[31], Z[30], C[29], V[28]) using Rellume's
  // overflow intrinsics and arithmetic comparisons.
  void FlagCalcAddSub(const std::string& Lhs64, const std::string& Rhs64,
                      const std::string& Res64, unsigned Bits, bool IsSub) {
    if (Bits == 0 || Bits > 64) Bits = 64;
    std::string Ty = "i" + std::to_string(Bits);
    std::string Lhs = Lhs64, Rhs = Rhs64, Res = Res64;
    if (Bits < 64) {
      Lhs = NextVal(); Rhs = NextVal(); Res = NextVal();
      OS << "  " << Lhs << " = trunc i64 " << Lhs64 << " to " << Ty << "\n";
      OS << "  " << Rhs << " = trunc i64 " << Rhs64 << " to " << Ty << "\n";
      OS << "  " << Res << " = trunc i64 " << Res64 << " to " << Ty << "\n";
    }

    // SF = Res <s 0, ZF = (Res == 0)
    std::string SfBit = NextVal(), ZfBit = NextVal(), CfBit = NextVal(), OfBit = NextVal();
    OS << "  " << SfBit << " = icmp slt " << Ty << " " << Res << ", 0\n";
    OS << "  " << ZfBit << " = icmp eq " << Ty << " " << Res << ", 0\n";

    if (IsSub) {
      // AArch64 SUBS sets C=1 when NO borrow occurred (Lhs >=u Rhs)
      OS << "  " << CfBit << " = icmp uge " << Ty << " " << Lhs << ", " << Rhs << "\n";
      // Rellume FlagCalcSub: OF = (SF != (Lhs <s Rhs))
      std::string LhsLtRhs = NextVal();
      OS << "  " << LhsLtRhs << " = icmp slt " << Ty << " " << Lhs << ", " << Rhs << "\n";
      OS << "  " << OfBit << " = icmp ne i1 " << SfBit << ", " << LhsLtRhs << "\n";
    } else {
      // Rellume FlagCalcAdd: CF = (Res <u Lhs), OF via @llvm.sadd.with.overflow
      OS << "  " << CfBit << " = icmp ult " << Ty << " " << Res << ", " << Lhs << "\n";
      std::string Packed = NextVal();
      OS << "  " << Packed << " = call { " << Ty << ", i1 } @llvm.sadd.with.overflow." << Ty
         << "(" << Ty << " " << Lhs << ", " << Ty << " " << Rhs << ")\n";
      OS << "  " << OfBit << " = extractvalue { " << Ty << ", i1 } " << Packed << ", 1\n";
    }

    PackNZCVBits(SfBit, ZfBit, CfBit, OfBit);
  }

  void FlagCalcSAPLogic(const std::string& Res64, unsigned Bits) {
    if (Bits == 0 || Bits > 64) Bits = 64;
    std::string Ty = "i" + std::to_string(Bits);
    std::string Res = Res64;
    if (Bits < 64) {
      Res = NextVal();
      OS << "  " << Res << " = trunc i64 " << Res64 << " to " << Ty << "\n";
    }
    std::string SfBit = NextVal(), ZfBit = NextVal();
    OS << "  " << SfBit << " = icmp slt " << Ty << " " << Res << ", 0\n";
    OS << "  " << ZfBit << " = icmp eq " << Ty << " " << Res << ", 0\n";
    PackNZCVBits(SfBit, ZfBit, "false", "false");
  }

  void PackNZCVBits(const std::string& NBit, const std::string& ZBit,
                    const std::string& CBit, const std::string& VBit) {
    std::string N64 = NextVal(), Z64 = NextVal(), C64 = NextVal(), V64 = NextVal();
    std::string NS = NextVal(), ZS = NextVal(), CS = NextVal(), VS = NextVal();
    std::string NZ = NextVal(), NZC = NextVal(), NZCV = NextVal();
    OS << "  " << N64 << " = zext i1 " << NBit << " to i64\n";
    OS << "  " << Z64 << " = zext i1 " << ZBit << " to i64\n";
    OS << "  " << C64 << " = zext i1 " << CBit << " to i64\n";
    OS << "  " << V64 << " = zext i1 " << VBit << " to i64\n";
    OS << "  " << NS << " = shl i64 " << N64 << ", 31\n";
    OS << "  " << ZS << " = shl i64 " << Z64 << ", 30\n";
    OS << "  " << CS << " = shl i64 " << C64 << ", 29\n";
    OS << "  " << VS << " = shl i64 " << V64 << ", 28\n";
    OS << "  " << NZ << " = or i64 " << NS << ", " << ZS << "\n";
    OS << "  " << NZC << " = or i64 " << NZ << ", " << CS << "\n";
    OS << "  " << NZCV << " = or i64 " << NZC << ", " << VS << "\n";
    OS << "  store i64 " << NZCV << ", ptr %nzcv_reg, align 8\n";
  }

  // Rellume Parity calculation using @llvm.ctpop.i8 (src/x86-64/lifter-flags.cc)
  std::string LiftParity(const std::string& Raw64, bool Invert) {
    std::string B8 = NextVal(), Pop8 = NextVal(), Pop64 = NextVal(), Bit0 = NextVal(), Res = NextVal();
    OS << "  " << B8 << " = trunc i64 " << Raw64 << " to i8\n";
    OS << "  " << Pop8 << " = call i8 @llvm.ctpop.i8(i8 " << B8 << ")\n";
    OS << "  " << Pop64 << " = zext i8 " << Pop8 << " to i64\n";
    OS << "  " << Bit0 << " = and i64 " << Pop64 << ", 1\n";
    OS << "  " << Res << " = xor i64 " << Bit0 << ", " << (Invert ? 0 : 1) << "\n";
    return Res;
  }

  // =========================================================================
  // 2. Rellume General-Purpose Lifters (src/x86-64/lifter-gp.cc)
  // =========================================================================

  // Rellume LiftDiv (src/x86-64/lifter-gp.cc:318-378):
  // Supports 8/16/32/64-bit signed (IDIV) and unsigned (DIV) division,
  // including double-width DX:AX / EDX:EAX / RDX:RAX dividends when Upper is present.
  std::pair<std::string, std::string> LiftDiv(const std::string& Lower64,
                                              const std::string& Upper64,
                                              bool HasUpper,
                                              const std::string& Divisor64,
                                              unsigned Bits,
                                              bool IsSigned) {
    if (Bits < 8 || Bits > 64) Bits = 64;
    const char* ExtOp = IsSigned ? "sext" : "zext";
    const char* DivOp = IsSigned ? "sdiv" : "udiv";
    const char* RemOp = IsSigned ? "srem" : "urem";

    if (HasUpper && Bits >= 16) {
      unsigned WideBits = Bits * 2; // 32, 64, or 128
      std::string NarrowTy = "i" + std::to_string(Bits);
      std::string WideTy = "i" + std::to_string(WideBits);
      std::string LowN = Lower64, HighN = Upper64, DivN = Divisor64;
      if (Bits < 64) {
        LowN = NextVal(); HighN = NextVal(); DivN = NextVal();
        OS << "  " << LowN << " = trunc i64 " << Lower64 << " to " << NarrowTy << "\n";
        OS << "  " << HighN << " = trunc i64 " << Upper64 << " to " << NarrowTy << "\n";
        OS << "  " << DivN << " = trunc i64 " << Divisor64 << " to " << NarrowTy << "\n";
      }
      std::string LowW = NextVal(), HighW = NextVal(), HighSh = NextVal(), Dividend = NextVal();
      std::string DivW = NextVal(), IsZero = NextVal(), SafeDiv = NextVal();
      std::string QuotW = NextVal(), RemW = NextVal(), QuotN = NextVal(), RemN = NextVal();
      OS << "  " << LowW << " = zext " << NarrowTy << " " << LowN << " to " << WideTy << "\n";
      OS << "  " << HighW << " = zext " << NarrowTy << " " << HighN << " to " << WideTy << "\n";
      OS << "  " << HighSh << " = shl " << WideTy << " " << HighW << ", " << Bits << "\n";
      OS << "  " << Dividend << " = or " << WideTy << " " << LowW << ", " << HighSh << "\n";
      OS << "  " << DivW << " = " << ExtOp << " " << NarrowTy << " " << DivN << " to " << WideTy << "\n";
      OS << "  " << IsZero << " = icmp eq " << WideTy << " " << DivW << ", 0\n";
      OS << "  " << SafeDiv << " = select i1 " << IsZero << ", " << WideTy << " 1, " << WideTy << " " << DivW << "\n";
      OS << "  " << QuotW << " = " << DivOp << " " << WideTy << " " << Dividend << ", " << SafeDiv << "\n";
      OS << "  " << RemW << " = " << RemOp << " " << WideTy << " " << Dividend << ", " << SafeDiv << "\n";
      OS << "  " << QuotN << " = trunc " << WideTy << " " << QuotW << " to " << NarrowTy << "\n";
      OS << "  " << RemN << " = trunc " << WideTy << " " << RemW << " to " << NarrowTy << "\n";
      if (Bits < 64) {
        std::string Quot64 = NextVal(), Rem64 = NextVal();
        OS << "  " << Quot64 << " = zext " << NarrowTy << " " << QuotN << " to i64\n";
        OS << "  " << Rem64 << " = zext " << NarrowTy << " " << RemN << " to i64\n";
        return {Quot64, Rem64};
      }
      return {QuotN, RemN};
    }

    // Single-register dividend (Upper already folded by FEX RA or 8-bit division)
    std::string A = Lower64, B = Divisor64;
    if (Bits < 64) {
      std::string NarrowTy = "i" + std::to_string(Bits);
      std::string AT = NextVal(), BT = NextVal();
      A = NextVal(); B = NextVal();
      OS << "  " << AT << " = trunc i64 " << Lower64 << " to " << NarrowTy << "\n";
      OS << "  " << BT << " = trunc i64 " << Divisor64 << " to " << NarrowTy << "\n";
      OS << "  " << A << " = " << ExtOp << " " << NarrowTy << " " << AT << " to i64\n";
      OS << "  " << B << " = " << ExtOp << " " << NarrowTy << " " << BT << " to i64\n";
    }
    std::string IsZero = NextVal(), SafeB = NextVal(), Quot = NextVal(), Rem = NextVal();
    OS << "  " << IsZero << " = icmp eq i64 " << B << ", 0\n";
    if (IsSigned) {
      // Guard INT64_MIN / -1 signed overflow UB in LLVM IR
      std::string IsMin = NextVal(), IsNeg1 = NextVal(), IsOv = NextVal(), Bad = NextVal();
      OS << "  " << IsMin << " = icmp eq i64 " << A << ", -9223372036854775808\n";
      OS << "  " << IsNeg1 << " = icmp eq i64 " << B << ", -1\n";
      OS << "  " << IsOv << " = and i1 " << IsMin << ", " << IsNeg1 << "\n";
      OS << "  " << Bad << " = or i1 " << IsZero << ", " << IsOv << "\n";
      OS << "  " << SafeB << " = select i1 " << Bad << ", i64 1, i64 " << B << "\n";
    } else {
      OS << "  " << SafeB << " = select i1 " << IsZero << ", i64 1, i64 " << B << "\n";
    }
    OS << "  " << Quot << " = " << DivOp << " i64 " << A << ", " << SafeB << "\n";
    OS << "  " << Rem << " = " << RemOp << " i64 " << A << ", " << SafeB << "\n";
    if (Bits < 64) {
      uint64_t Mask = (1ULL << Bits) - 1ULL;
      std::string QM = NextVal(), RM = NextVal();
      OS << "  " << QM << " = and i64 " << Quot << ", " << Mask << "\n";
      OS << "  " << RM << " = and i64 " << Rem << ", " << Mask << "\n";
      return {QM, RM};
    }
    return {Quot, Rem};
  }

  // Rellume LiftRotate / LiftShiftdouble via @llvm.fshr / @llvm.fshl (src/x86-64/lifter-gp.cc:227-269)
  std::string LiftFunnelShift(const std::string& Hi64, const std::string& Lo64,
                              const std::string& Shift64, unsigned Bits, bool IsLeft) {
    if (Bits != 8 && Bits != 16 && Bits != 32 && Bits != 64) Bits = 64;
    const char* Intrin = IsLeft ? "fshl" : "fshr";
    std::string Ty = "i" + std::to_string(Bits);
    if (Bits < 64) {
      std::string H = NextVal(), L = NextVal(), S = NextVal(), R = NextVal(), R64 = NextVal();
      OS << "  " << H << " = trunc i64 " << Hi64 << " to " << Ty << "\n";
      OS << "  " << L << " = trunc i64 " << Lo64 << " to " << Ty << "\n";
      OS << "  " << S << " = trunc i64 " << Shift64 << " to " << Ty << "\n";
      OS << "  " << R << " = call " << Ty << " @llvm." << Intrin << "." << Ty
         << "(" << Ty << " " << H << ", " << Ty << " " << L << ", " << Ty << " " << S << ")\n";
      OS << "  " << R64 << " = zext " << Ty << " " << R << " to i64\n";
      return R64;
    }
    std::string R = NextVal();
    OS << "  " << R << " = call i64 @llvm." << Intrin << ".i64(i64 " << Hi64 << ", i64 " << Lo64 << ", i64 " << Shift64 << ")\n";
    return R;
  }

  // =========================================================================
  // 3. Rellume SSE / Vector Lifters (src/x86-64/lifter-sse.cc)
  // =========================================================================

  std::string CastVecFromI64x2(const std::string& V, Facet F) {
    if (F == Facet::V2I64) return V;
    std::string R = NextVal();
    OS << "  " << R << " = bitcast <2 x i64> " << V << " to " << FacetTypeStr(F) << "\n";
    return R;
  }

  std::string CastVecToI64x2(const std::string& V, Facet F) {
    if (F == Facet::V2I64) return V;
    std::string R = NextVal();
    OS << "  " << R << " = bitcast " << FacetTypeStr(F) << " " << V << " to <2 x i64>\n";
    return R;
  }

  // Rellume horzToVert (src/x86-64/lifter-sse.cc:184-196)
  std::pair<std::string, std::string> HorzToVert(const std::string& Op1,
                                                 const std::string& Op2,
                                                 Facet F) {
    unsigned Lanes = FacetLanes(F);
    std::string Ty = FacetTypeStr(F);
    std::string MaskTy = "<" + std::to_string(Lanes) + " x i32>";
    std::string EvenMask = "<", OddMask = "<";
    for (unsigned i = 0; i < Lanes; ++i) {
      if (i) { EvenMask += ", "; OddMask += ", "; }
      EvenMask += "i32 " + std::to_string(2 * i);
      OddMask += "i32 " + std::to_string(2 * i + 1);
    }
    EvenMask += ">";
    OddMask += ">";
    std::string S1 = NextVal(), S2 = NextVal();
    OS << "  " << S1 << " = shufflevector " << Ty << " " << Op1 << ", " << Ty << " " << Op2
       << ", " << MaskTy << " " << EvenMask << "\n";
    OS << "  " << S2 << " = shufflevector " << Ty << " " << Op1 << ", " << Ty << " " << Op2
       << ", " << MaskTy << " " << OddMask << "\n";
    return {S1, S2};
  }

  // Rellume LiftSseBinOp (src/x86-64/lifter-sse.cc:198-213)
  std::string LiftSseBinOp(const std::string& V1_64x2, const std::string& V2_64x2,
                           const char* LLVMBinOp, bool Horz, Facet F) {
    std::string Op1 = CastVecFromI64x2(V1_64x2, F);
    std::string Op2 = CastVecFromI64x2(V2_64x2, F);
    if (Horz) {
      std::tie(Op1, Op2) = HorzToVert(Op1, Op2, F);
    }
    std::string R = NextVal();
    OS << "  " << R << " = " << LLVMBinOp << " " << FacetTypeStr(F) << " " << Op1 << ", " << Op2 << "\n";
    return CastVecToI64x2(R, F);
  }

  // Rellume LiftSseMinmax / LiftSsePminmax (src/x86-64/lifter-sse.cc:269-275, 577-583)
  std::string LiftSseMinMax(const std::string& V1_64x2, const std::string& V2_64x2,
                            const char* CmpInst, const char* Pred, Facet F) {
    std::string Op1 = CastVecFromI64x2(V1_64x2, F);
    std::string Op2 = CastVecFromI64x2(V2_64x2, F);
    std::string Ty = FacetTypeStr(F);
    std::string Cmp = NextVal(), Sel = NextVal();
    OS << "  " << Cmp << " = " << CmpInst << " " << Pred << " " << Ty << " " << Op1 << ", " << Op2 << "\n";
    OS << "  " << Sel << " = select <" << FacetLanes(F) << " x i1> " << Cmp << ", "
       << Ty << " " << Op1 << ", " << Ty << " " << Op2 << "\n";
    return CastVecToI64x2(Sel, F);
  }

  // Rellume LiftSseSqrt (src/x86-64/lifter-sse.cc:277-280)
  std::string LiftSseSqrt(const std::string& V_64x2, unsigned ElemBits) {
    Facet F = ResolveVecFloatFacet(ElemBits);
    std::string Op1 = CastVecFromI64x2(V_64x2, F);
    std::string R = NextVal();
    if (ElemBits == 64) {
      OS << "  " << R << " = call <2 x double> @llvm.sqrt.v2f64(<2 x double> " << Op1 << ")\n";
    } else {
      OS << "  " << R << " = call <4 x float> @llvm.sqrt.v4f32(<4 x float> " << Op1 << ")\n";
    }
    return CastVecToI64x2(R, F);
  }

  // Rellume LiftSseUnpck (src/x86-64/lifter-sse.cc:308-331) for VZIP / VZIP2 / VUNZIP / VUNZIP2
  std::string LiftSseUnpck(const std::string& V1_64x2, const std::string& V2_64x2,
                           unsigned ElemBits, bool HighHalf, bool IsDeinterleave, unsigned OpBits = 128) {
    Facet F = ResolveVecIntFacet(ElemBits);
    unsigned Lanes = FacetLanes(F);
    std::string Op1 = CastVecFromI64x2(V1_64x2, F);
    std::string Op2 = CastVecFromI64x2(V2_64x2, F);
    std::string Ty = FacetTypeStr(F);
    std::string MaskTy = "<" + std::to_string(Lanes) + " x i32>";
    std::string Mask = "<";
    unsigned ActiveLanes = (OpBits == 64 && Lanes >= 2) ? (Lanes / 2) : Lanes;
    for (unsigned i = 0; i < Lanes; ++i) {
      if (i) Mask += ", ";
      unsigned Idx = 0;
      if (!IsDeinterleave) {
        unsigned Pair = (HighHalf ? (ActiveLanes / 2) : 0) + (i / 2);
        Idx = (i & 1) ? (Lanes + Pair) : Pair;
      } else {
        if (OpBits == 64 && Lanes >= 2) {
          if (i < ActiveLanes / 2) {
            Idx = 2 * i + (HighHalf ? 1 : 0);
          } else if (i < ActiveLanes) {
            Idx = Lanes + 2 * (i - ActiveLanes / 2) + (HighHalf ? 1 : 0);
          } else {
            Idx = 0;
          }
        } else {
          Idx = 2 * i + (HighHalf ? 1 : 0);
        }
      }
      Mask += "i32 " + std::to_string(Idx);
    }
    Mask += ">";
    std::string Shuf = NextVal();
    OS << "  " << Shuf << " = shufflevector " << Ty << " " << Op1 << ", " << Ty << " " << Op2
       << ", " << MaskTy << " " << Mask << "\n";
    std::string Res64x2 = CastVecToI64x2(Shuf, F);
    if (OpBits == 64) {
      std::string ZeroHi = NextVal();
      OS << "  " << ZeroHi << " = insertelement <2 x i64> " << Res64x2 << ", i64 0, i32 1\n";
      return ZeroHi;
    }
    return Res64x2;
  }

  // Rellume LiftSsePshiftElement (src/x86-64/lifter-sse.cc:356-389)
  std::string LiftSsePshiftElement(const std::string& V_64x2, const std::string& ShiftVec_64x2,
                                   const char* ShOp, unsigned ElemBits) {
    if (ElemBits != 8 && ElemBits != 16 && ElemBits != 32 && ElemBits != 64) ElemBits = 32;
    Facet F = ResolveVecIntFacet(ElemBits);
    unsigned Lanes = FacetLanes(F);
    std::string Ty = FacetTypeStr(F);
    std::string V1 = CastVecFromI64x2(V_64x2, F);
    std::string V2 = CastVecFromI64x2(ShiftVec_64x2, F);

    std::string MaxShiftVec = "<", ZeroVec = "zeroinitializer", ElemBitsVec = "<";
    for (unsigned i = 0; i < Lanes; ++i) {
      if (i) { MaxShiftVec += ", "; ElemBitsVec += ", "; }
      MaxShiftVec += "i" + std::to_string(ElemBits) + " " + std::to_string(ElemBits - 1);
      ElemBitsVec += "i" + std::to_string(ElemBits) + " " + std::to_string(ElemBits);
    }
    MaxShiftVec += ">";
    ElemBitsVec += ">";

    bool IsArith = (std::string(ShOp) == "ashr");
    if (IsArith) {
      std::string Cmp = NextVal(), SafeSh = NextVal(), Res = NextVal();
      OS << "  " << Cmp << " = icmp ugt " << Ty << " " << V2 << ", " << MaxShiftVec << "\n";
      OS << "  " << SafeSh << " = select <" << Lanes << " x i1> " << Cmp << ", "
         << Ty << " " << MaxShiftVec << ", " << Ty << " " << V2 << "\n";
      OS << "  " << Res << " = ashr " << Ty << " " << V1 << ", " << SafeSh << "\n";
      return CastVecToI64x2(Res, F);
    } else {
      std::string InRange = NextVal(), SafeSh = NextVal(), Shifted = NextVal(), Res = NextVal();
      OS << "  " << InRange << " = icmp ult " << Ty << " " << V2 << ", " << ElemBitsVec << "\n";
      OS << "  " << SafeSh << " = select <" << Lanes << " x i1> " << InRange << ", "
         << Ty << " " << V2 << ", " << Ty << " zeroinitializer\n";
      OS << "  " << Shifted << " = " << ShOp << " " << Ty << " " << V1 << ", " << SafeSh << "\n";
      OS << "  " << Res << " = select <" << Lanes << " x i1> " << InRange << ", "
         << Ty << " " << Shifted << ", " << Ty << " zeroinitializer\n";
      return CastVecToI64x2(Res, F);
    }
  }

  // Rellume LiftSsePmovx (src/x86-64/lifter-sse.cc:609-614) for VSXTL / VUXTL / VSXTL2 / VUXTL2
  std::string LiftSsePmovx(const std::string& V_64x2, unsigned DstBits, bool IsSigned, bool HighHalf = false) {
    if (DstBits != 16 && DstBits != 32 && DstBits != 64) DstBits = 64;
    unsigned SrcBits = DstBits / 2;
    unsigned DstLanes = 128 / DstBits;
    unsigned SrcLanes = 128 / SrcBits;
    const char* ExtOp = IsSigned ? "sext" : "zext";
    std::string SrcVecTy = "<" + std::to_string(SrcLanes) + " x i" + std::to_string(SrcBits) + ">";
    std::string HalfVecTy = "<" + std::to_string(DstLanes) + " x i" + std::to_string(SrcBits) + ">";
    std::string DstVecTy = "<" + std::to_string(DstLanes) + " x i" + std::to_string(DstBits) + ">";
    std::string MaskTy = "<" + std::to_string(DstLanes) + " x i32>";
    std::string MaskStr = "<";
    unsigned BaseIdx = HighHalf ? DstLanes : 0;
    for (unsigned i = 0; i < DstLanes; ++i) {
      if (i) MaskStr += ", ";
      MaskStr += "i32 " + std::to_string(BaseIdx + i);
    }
    MaskStr += ">";
    std::string BC = NextVal(), Half = NextVal(), Ext = NextVal(), Res = NextVal();
    OS << "  " << BC << " = bitcast <2 x i64> " << V_64x2 << " to " << SrcVecTy << "\n";
    OS << "  " << Half << " = shufflevector " << SrcVecTy << " " << BC << ", " << SrcVecTy
       << " poison, " << MaskTy << " " << MaskStr << "\n";
    OS << "  " << Ext << " = " << ExtOp << " " << HalfVecTy << " " << Half << " to " << DstVecTy << "\n";
    OS << "  " << Res << " = bitcast " << DstVecTy << " " << Ext << " to <2 x i64>\n";
    return Res;
  }

  // Rellume LiftSsePabs (src/x86-64/lifter-sse.cc:585-591)
  std::string LiftSsePabs(const std::string& V_64x2, unsigned ElemBits) {
    if (ElemBits != 8 && ElemBits != 16 && ElemBits != 32 && ElemBits != 64) ElemBits = 32;
    Facet F = ResolveVecIntFacet(ElemBits);
    unsigned Lanes = FacetLanes(F);
    std::string Ty = FacetTypeStr(F);
    std::string Src = CastVecFromI64x2(V_64x2, F);
    std::string Neg = NextVal(), Cmp = NextVal(), Sel = NextVal();
    OS << "  " << Neg << " = sub " << Ty << " zeroinitializer, " << Src << "\n";
    OS << "  " << Cmp << " = icmp sge " << Ty << " " << Src << ", zeroinitializer\n";
    OS << "  " << Sel << " = select <" << Lanes << " x i1> " << Cmp << ", "
       << Ty << " " << Src << ", " << Ty << " " << Neg << "\n";
    return CastVecToI64x2(Sel, F);
  }

  // Rellume LiftSsePalignr / FEX VExtr (VectorOps.cpp:3173-3219):
  // LowerBits = Op->VectorUpper (Vn, bytes 0..OpBytes-1)
  // UpperBits = Op->VectorLower (Vm, bytes OpBytes..2*OpBytes-1)
  std::string LiftSsePalignr(const std::string& LowerBits_64x2, const std::string& UpperBits_64x2,
                             unsigned Index, unsigned ElemBytes = 1, unsigned OpBytes = 16) {
    if (ElemBytes == 0) ElemBytes = 1;
    if (OpBytes != 8) OpBytes = 16;
    std::string LoVec = LowerBits_64x2;
    std::string HiVec = UpperBits_64x2;
    if (Index >= OpBytes) {
      LoVec = HiVec;
      HiVec = "zeroinitializer";
      Index -= OpBytes;
    }
    unsigned CopyFromByte = (Index * ElemBytes) & (OpBytes - 1);
    if (OpBytes == 16) {
      if (CopyFromByte == 0) return LoVec;
      std::string SLo = CastVecFromI64x2(LoVec, Facet::V16I8);
      std::string SHi = CastVecFromI64x2(HiVec, Facet::V16I8);
      std::string Mask = "<";
      for (unsigned i = 0; i < 16; ++i) {
        if (i) Mask += ", ";
        Mask += "i32 " + std::to_string(CopyFromByte + i);
      }
      Mask += ">";
      std::string Shuf = NextVal();
      OS << "  " << Shuf << " = shufflevector <16 x i8> " << SLo << ", <16 x i8> " << SHi
         << ", <16 x i32> " << Mask << "\n";
      return CastVecToI64x2(Shuf, Facet::V16I8);
    } else {
      std::string SLo = CastVecFromI64x2(LoVec, Facet::V16I8);
      std::string SHi = CastVecFromI64x2(HiVec, Facet::V16I8);
      std::string Mask = "<";
      for (unsigned i = 0; i < 16; ++i) {
        if (i) Mask += ", ";
        if (i < 8) {
          unsigned b = CopyFromByte + i;
          unsigned srcIdx = (b < 8) ? b : (16 + (b - 8));
          Mask += "i32 " + std::to_string(srcIdx);
        } else {
          Mask += "i32 0";
        }
      }
      Mask += ">";
      std::string Shuf = NextVal();
      OS << "  " << Shuf << " = shufflevector <16 x i8> " << SLo << ", <16 x i8> " << SHi
         << ", <16 x i32> " << Mask << "\n";
      std::string Res64x2 = CastVecToI64x2(Shuf, Facet::V16I8);
      std::string ZeroHi = NextVal();
      OS << "  " << ZeroHi << " = insertelement <2 x i64> " << Res64x2 << ", i64 0, i32 1\n";
      return ZeroHi;
    }
  }

private:
  std::ostringstream& OS;
  NextValFn NextVal;
};

} // namespace rellume::x86_64

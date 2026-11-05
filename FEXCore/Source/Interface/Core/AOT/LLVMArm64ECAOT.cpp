// SPDX-License-Identifier: MIT
#include <FEXCore/Core/LLVMArm64ECAOT.h>
#include "Interface/Core/AOT/RellumeLifter.h"

#include "Interface/Context/Context.h"
#include "Interface/Core/ArchHelpers/Arm64Emitter.h"
#include "Interface/Core/CPUBackend.h"
#include "Interface/Core/JIT/Relocations.h"
#include "Interface/IR/IR.h"
#include "Interface/IR/IntrusiveIRList.h"
#include "Interface/IR/RegisterAllocationData.h"
#include "Utils/variable_length_integer.h"

#include <FEXCore/Core/CoreState.h>
#include <FEXCore/Core/X86Enums.h>
#include <FEXCore/IR/IR.h>
#include <FEXCore/Utils/LogManager.h>
#include <FEXCore/Utils/MathUtils.h>

#if !defined(_WIN32)
#define FEX_HAS_LLVM_AOT 1
#if __has_include("llvm-c/Core.h")
#include "llvm-c/Analysis.h"
#include "llvm-c/BitWriter.h"
#include "llvm-c/Core.h"
#include "llvm-c/Disassembler.h"
#include "llvm-c/Error.h"
#include "llvm-c/IRReader.h"
#include "llvm-c/Target.h"
#include "llvm-c/TargetMachine.h"
#include "llvm-c/Transforms/PassBuilder.h"
#else
#include <cstddef>
#include <cstdint>
extern "C" {
typedef int LLVMBool;
typedef struct LLVMOpaqueContext *LLVMContextRef;
typedef struct LLVMOpaqueModule *LLVMModuleRef;
typedef struct LLVMOpaqueMemoryBuffer *LLVMMemoryBufferRef;
typedef struct LLVMOpaqueTarget *LLVMTargetRef;
typedef struct LLVMOpaqueTargetMachine *LLVMTargetMachineRef;
typedef struct LLVMOpaquePassBuilderOptions *LLVMPassBuilderOptionsRef;
typedef struct LLVMOpaqueError *LLVMErrorRef;
typedef enum {
  LLVMCodeGenLevelNone,
  LLVMCodeGenLevelLess,
  LLVMCodeGenLevelDefault,
  LLVMCodeGenLevelAggressive
} LLVMCodeGenOptLevel;
typedef enum {
  LLVMRelocDefault,
  LLVMRelocStatic,
  LLVMRelocPIC,
  LLVMRelocDynamicNoPic,
  LLVMRelocROPI,
  LLVMRelocRWPI,
  LLVMRelocROPI_RWPI
} LLVMRelocMode;
typedef enum {
  LLVMCodeModelDefault,
  LLVMCodeModelJITDefault,
  LLVMCodeModelTiny,
  LLVMCodeModelSmall,
  LLVMCodeModelKernel,
  LLVMCodeModelMedium,
  LLVMCodeModelLarge
} LLVMCodeModel;
typedef enum {
  LLVMAssemblyFile,
  LLVMObjectFile
} LLVMCodeGenFileType;
void LLVMInitializeAArch64TargetInfo(void);
void LLVMInitializeAArch64Target(void);
void LLVMInitializeAArch64TargetMC(void);
void LLVMInitializeAArch64AsmPrinter(void);
void LLVMInitializeAArch64AsmParser(void);
void LLVMInitializeAArch64Disassembler(void);
LLVMContextRef LLVMContextCreate(void);
void LLVMContextDispose(LLVMContextRef C);
void LLVMDisposeModule(LLVMModuleRef M);
void LLVMDisposeMessage(char *Message);
LLVMMemoryBufferRef LLVMCreateMemoryBufferWithMemoryRangeCopy(const char *InputData, size_t InputDataLength, const char *BufferName);
const char *LLVMGetBufferStart(LLVMMemoryBufferRef MemBuf);
size_t LLVMGetBufferSize(LLVMMemoryBufferRef MemBuf);
void LLVMDisposeMemoryBuffer(LLVMMemoryBufferRef MemBuf);
LLVMBool LLVMParseIRInContext(LLVMContextRef ContextRef, LLVMMemoryBufferRef MemBuf, LLVMModuleRef *OutM, char **OutMessage);
LLVMBool LLVMGetTargetFromTriple(const char *Triple, LLVMTargetRef *T, char **ErrorMessage);
LLVMTargetMachineRef LLVMCreateTargetMachine(LLVMTargetRef T, const char *Triple, const char *CPU, const char *Features, LLVMCodeGenOptLevel Level, LLVMRelocMode Reloc, LLVMCodeModel CodeModel);
void LLVMDisposeTargetMachine(LLVMTargetMachineRef T);
LLVMBool LLVMTargetMachineEmitToMemoryBuffer(LLVMTargetMachineRef T, LLVMModuleRef M, LLVMCodeGenFileType codegen, char **ErrorMessage, LLVMMemoryBufferRef *OutMemBuf);
LLVMPassBuilderOptionsRef LLVMCreatePassBuilderOptions(void);
void LLVMDisposePassBuilderOptions(LLVMPassBuilderOptionsRef Options);
LLVMErrorRef LLVMRunPasses(LLVMModuleRef M, const char *Passes, LLVMTargetMachineRef TM, LLVMPassBuilderOptionsRef Options);
char *LLVMGetErrorMessage(LLVMErrorRef Err);
void LLVMDisposeErrorMessage(char *ErrMsg);
}
#endif
#endif

#include <xxhash.h>

#include <algorithm>
#include <chrono>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <mutex>
#include <sstream>
#include <unordered_map>

namespace FEXCore::AOT {

namespace {

// Direct in-memory llvm::IRBuilder<> C-API wrapper (LLVMBuilderRef)
struct LLVMArm64ECIRBuilder {
#ifdef FEX_HAS_LLVM_AOT
  LLVMContextRef Ctx = nullptr;
  explicit LLVMArm64ECIRBuilder(LLVMContextRef C) : Ctx(C) {}
#endif
};


struct LLVMRuntimeInit {
  LLVMRuntimeInit() {
#ifdef FEX_HAS_LLVM_AOT
    LLVMInitializeAArch64TargetInfo();
    LLVMInitializeAArch64Target();
    LLVMInitializeAArch64TargetMC();
    LLVMInitializeAArch64AsmPrinter();
    LLVMInitializeAArch64AsmParser();
    LLVMInitializeAArch64Disassembler();
#endif
  }
};

static void EnsureLLVMInitialized() {
  static LLVMRuntimeInit Init;
  (void)Init;
}

static unsigned OpSizeToBits(FEXCore::IR::OpSize Size) {
  switch (Size) {
  case FEXCore::IR::OpSize::i8Bit: return 8;
  case FEXCore::IR::OpSize::i16Bit: return 16;
  case FEXCore::IR::OpSize::i32Bit: return 32;
  case FEXCore::IR::OpSize::i64Bit: return 64;
  case FEXCore::IR::OpSize::i128Bit: return 128;
  case FEXCore::IR::OpSize::i256Bit: return 256;
  default: return 64;
  }
}

// Re-encodes PC-relative AArch64 branch/adr instructions when dead ret/brk words after
// .inst 0x5000+k exit markers are compacted out of the instruction stream.
static uint32_t RelocateAArch64BranchWord(uint32_t Insn, int32_t OldWordIdx, int32_t NewWordIdx,
                                          const std::vector<int32_t>& OldToNewWordIdx) {
  const int32_t NumOldWords = static_cast<int32_t>(OldToNewWordIdx.size());
  auto MapTarget = [&](int32_t TargetOldWord) -> int32_t {
    if (TargetOldWord < 0) return 0;
    if (TargetOldWord >= NumOldWords) return OldToNewWordIdx.back() + (TargetOldWord - NumOldWords + 1);
    return OldToNewWordIdx[TargetOldWord];
  };

  // Unconditional B / BL: [31]=op, [30:26]=00101, [25:0]=imm26
  if ((Insn & 0x7C000000u) == 0x14000000u) {
    int32_t Imm26 = static_cast<int32_t>(Insn << 6) >> 6;
    int32_t TargetOld = OldWordIdx + Imm26;
    int32_t NewImm26 = MapTarget(TargetOld) - NewWordIdx;
    return (Insn & 0xFC000000u) | (static_cast<uint32_t>(NewImm26) & 0x03FFFFFFu);
  }
  // B.cond: [31:24]=01010100, [23:5]=imm19, [4]=0, [3:0]=cond
  if ((Insn & 0xFF000010u) == 0x54000000u) {
    int32_t Imm19 = static_cast<int32_t>((Insn >> 5) << 13) >> 13;
    int32_t TargetOld = OldWordIdx + Imm19;
    int32_t NewImm19 = MapTarget(TargetOld) - NewWordIdx;
    return (Insn & 0xFF00001Fu) | ((static_cast<uint32_t>(NewImm19) & 0x7FFFFu) << 5);
  }
  // CBZ / CBNZ: [30:25]=011010, [23:5]=imm19
  if ((Insn & 0x7E000000u) == 0x34000000u) {
    int32_t Imm19 = static_cast<int32_t>((Insn >> 5) << 13) >> 13;
    int32_t TargetOld = OldWordIdx + Imm19;
    int32_t NewImm19 = MapTarget(TargetOld) - NewWordIdx;
    return (Insn & 0xFF00001Fu) | ((static_cast<uint32_t>(NewImm19) & 0x7FFFFu) << 5);
  }
  // TBZ / TBNZ: [30:25]=011011, [18:5]=imm14
  if ((Insn & 0x7E000000u) == 0x36000000u) {
    int32_t Imm14 = static_cast<int32_t>((Insn >> 5) << 18) >> 18;
    int32_t TargetOld = OldWordIdx + Imm14;
    int32_t NewImm14 = MapTarget(TargetOld) - NewWordIdx;
    return (Insn & 0xFFF8001Fu) | ((static_cast<uint32_t>(NewImm14) & 0x3FFFu) << 5);
  }
  return Insn;
}

static uint32_t EncodeAArch64B(int32_t WordOffset) {
  return 0x14000000u | (static_cast<uint32_t>(WordOffset) & 0x03FFFFFFu);
}

static bool DestinationIsGuestRSP(FEXCore::IR::Ref Node) {
  if (!Node) return false;
  FEXCore::IR::PhysicalRegister PR(Node);
  if (PR.IsInvalid()) return false;
  // In FEX's x64 SRA mapping, index 4 is RSP (mapped to x23).
  return PR.AsRegClass() == FEXCore::IR::RegClass::GPRFixed && PR.Reg == 4;
}

} // namespace

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

LLVMArm64ECAOTCompiler::LLVMArm64ECAOTCompiler() : Opts(Options{}) { EnsureLLVMInitialized(); }

LLVMArm64ECAOTCompiler::LLVMArm64ECAOTCompiler(const Options& Opts_)
  : Opts(Opts_) {
  EnsureLLVMInitialized();
}

LLVMArm64ECAOTCompiler::~LLVMArm64ECAOTCompiler() = default;

FunctionSafetyAnalysis
LLVMArm64ECAOTCompiler::AnalyzeFunctionSafety(uint64_t GuestEntryVA, uint64_t GuestSize,
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

LLVMArm64ECAOTCompiler::LiftedFunctionIR
LLVMArm64ECAOTCompiler::LiftIRToLLVM(uint64_t GuestEntryVA, uint64_t GuestSize, uint32_t GuestInstCount,
                                     const FEXCore::IR::IRListView& IR) const {
  FunctionSafetyAnalysis Safety = AnalyzeFunctionSafety(GuestEntryVA, GuestSize, GuestInstCount, IR);
  LiftedFunctionIR Res = LiftIRToLLVM(GuestEntryVA, GuestSize, GuestInstCount, IR, Safety.SelectedABI);
  Res.Safety = std::move(Safety);
  return Res;
}

LLVMArm64ECAOTCompiler::LiftedFunctionIR
LLVMArm64ECAOTCompiler::LiftIRToLLVM(uint64_t GuestEntryVA, uint64_t GuestSize, uint32_t GuestInstCount,
                                     const FEXCore::IR::IRListView& IR, AOTTargetABI ExplicitABI) const {
  LiftedFunctionIR Result;
  Result.GuestEntryVA = GuestEntryVA;
  Result.GuestSize = GuestSize;
  Result.GuestInstCount = GuestInstCount;
  Result.SingleInst = (GuestInstCount == 1);
  Result.TargetABI = ExplicitABI;
  Result.Safety = AnalyzeFunctionSafety(GuestEntryVA, GuestSize, GuestInstCount, IR);
  Result.Safety.SelectedABI = ExplicitABI;

  const bool IsArm64ECNative = (ExplicitABI == AOTTargetABI::ARM64EC_NATIVE);

  char FnNameBuf[64];
  snprintf(FnNameBuf, sizeof(FnNameBuf), "fex_fn_%llx", static_cast<unsigned long long>(GuestEntryVA));
  Result.FunctionName = FnNameBuf;

  // Map all CodeBlock NodeIDs to dense block indices and inspect which register classes are used.
  std::unordered_map<uint32_t, uint32_t> BlockNodeToId;
  bool UsesFPR = false;
  bool UsesEntrypointOffset = false;
  uint32_t BlockIdx = 0;
  for (auto [BlockNode, BlockHeader] : IR.GetBlocks()) {
    auto BlockIROp = BlockHeader->CW<FEXCore::IR::IROp_CodeBlock>();
    BlockNodeToId[IR.GetID(BlockNode).Value] = BlockIROp->ID;
    BlockIdx++;
    for (auto [CodeNode, IROp] : IR.GetCode(BlockNode)) {
      if (IROp->Op == FEXCore::IR::OP_ENTRYPOINTOFFSET || IROp->Op == FEXCore::IR::OP_INLINEENTRYPOINTOFFSET) {
        UsesEntrypointOffset = true;
      }
      FEXCore::IR::PhysicalRegister DstReg(CodeNode);
      if (!DstReg.IsInvalid() &&
          (DstReg.AsRegClass() == FEXCore::IR::RegClass::FPR || DstReg.AsRegClass() == FEXCore::IR::RegClass::FPRFixed)) {
        UsesFPR = true;
      }
      const uint8_t NumArgs = FEXCore::IR::GetArgs(IROp->Op);
      for (uint8_t i = 0; i < NumArgs; ++i) {
        if (IROp->Args[i].IsImmediate()) {
          FEXCore::IR::PhysicalRegister ArgReg(IROp->Args[i]);
          if (ArgReg.AsRegClass() == FEXCore::IR::RegClass::FPR || ArgReg.AsRegClass() == FEXCore::IR::RegClass::FPRFixed) {
            UsesFPR = true;
          }
        } else if (IROp->Args[i].IsPointer()) {
          auto* ArgHdr = IR.GetOp<FEXCore::IR::IROp_Header>(IROp->Args[i]);
          if (ArgHdr && ArgHdr->Op == FEXCore::IR::OP_INLINEENTRYPOINTOFFSET) {
            UsesEntrypointOffset = true;
          }
        }
      }
    }
  }
  Result.BasicBlockCount = BlockIdx;

  // Unified Lifter with Target-Specialized ABI Lowering:
  // - ARM64EC_NATIVE functions are emitted into `.text_ec$<Fn>` with attribute #1,
  //   liveness-pruned entry/exit flag handling (eliminating dead `mrs nzcv` / `msr nzcv`
  //   and dead Rellume flag calculations across Call/Return boundaries), and single-block
  //   straight-line RIP-relative base resolution.
  // - FEX_SRA functions are emitted into `.text_fex$<Fn>` with attribute #0 and full
  //   18-GPR / 16-FPR / NZCV state pinning across all exits.
  std::ostringstream OS;
  const char* SectionPrefix = IsArm64ECNative ? ".text_ec$" : ".text_fex$";
  const char* AttrGroup = IsArm64ECNative ? "#1" : "#0";
  OS << "define ghccc void @" << Result.FunctionName << "() " << AttrGroup
     << " section \"" << SectionPrefix << Result.FunctionName << "\" {\n";
  OS << "entry:\n";

  // Allocate SSA-promotable slots for all 18 SRA GPRFixed registers, 16 GPR dynamic registers,
  // NZCV flags, STATE pointer (x28), and CallRetSP (x17).
  for (int i = 0; i < 18; ++i) {
    OS << "  %sra_gpr_" << i << " = alloca i64, align 8\n";
  }
  for (int i = 0; i < 16; ++i) {
    OS << "  %tmp_gpr_" << i << " = alloca i64, align 8\n";
  }
  OS << "  %nzcv_reg = alloca i64, align 8\n";
  OS << "  %callret_sp_reg = alloca i64, align 8\n";
  if (UsesFPR) {
    for (int i = 0; i < 16; ++i) {
      OS << "  %sra_fpr_" << i << " = alloca <2 x i64>, align 16\n";
      OS << "  %tmp_fpr_" << i << " = alloca <2 x i64>, align 16\n";
    }
  }

  // Bind live-in registers at function entry:
  if (!Result.Safety.ReadsFlagsIn) {
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

  // In ARM64EC_NATIVE mode, only read hardware NZCV via `mrs` if the function actually
  // reads flags before writing them (Safety.ReadsFlagsIn). Standard C/C++/Win32 functions
  // never take arguments in RFLAGS, saving a serializing `mrs` at function entry!
  if (!IsArm64ECNative || Result.Safety.ReadsFlagsIn) {
    OS << "  %in_nzcv = call i64 asm \"mrs $0, nzcv\", \"=r\"()\n";
    OS << "  store i64 %in_nzcv, ptr %nzcv_reg, align 8\n";
  } else {
    OS << "  store i64 0, ptr %nzcv_reg, align 8\n";
  }

  if (UsesFPR) {
    OS << "  %fpr_in = call %SRAFPRState asm \"\", "
          "\"={q0},={q1},={q2},={q3},={q4},={q5},={q6},={q7},={q8},={q9},={q10},={q11},={q12},={q13},={q14},={q15}\"()\n";
    for (int i = 0; i < 16; ++i) {
      OS << "  %in_fpr_" << i << " = extractvalue %SRAFPRState %fpr_in, " << i << "\n";
      OS << "  store <2 x i64> %in_fpr_" << i << ", ptr %sra_fpr_" << i << ", align 16\n";
      OS << "  store <2 x i64> zeroinitializer, ptr %tmp_fpr_" << i << ", align 16\n";
    }
  }

  uint32_t ValCounter = 1;
  auto NextVal = [&]() -> std::string {
    return "%v" + std::to_string(ValCounter++);
  };

  // Helper to read an integer SSA/RA operand as an i64 SSA value
  auto LoadGPROperand = [&](FEXCore::IR::OrderedNodeWrapper W) -> std::string {
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
      OS << "  " << Val << " = add i64 " << BaseVa << ", " << static_cast<int64_t>(OffOp->Offset) << "\n";
      if (OpHdr->Size == FEXCore::IR::OpSize::i32Bit) {
        std::string Masked = NextVal();
        OS << "  " << Masked << " = and i64 " << Val << ", 4294967295\n";
        return Masked;
      }
      return Val;
    }
    return "0";
  };

  auto StoreGPRDest = [&](FEXCore::IR::Ref Node, const std::string& Val64) {
    if (!Node) return;
    FEXCore::IR::PhysicalRegister PR(Node);
    if (PR.IsInvalid()) return;
    if (PR.AsRegClass() == FEXCore::IR::RegClass::GPRFixed && PR.Reg < 18) {
      OS << "  store i64 " << Val64 << ", ptr %sra_gpr_" << unsigned(PR.Reg) << ", align 8\n";
    } else {
      OS << "  store i64 " << Val64 << ", ptr %tmp_gpr_" << (unsigned(PR.Reg) & 15) << ", align 8\n";
    }
  };

  auto StoreGPRWrapper = [&](FEXCore::IR::OrderedNodeWrapper W, const std::string& Val64) {
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
  };

  auto LoadFPROperand = [&](FEXCore::IR::OrderedNodeWrapper W) -> std::string {
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
  };

  auto StoreFPRDest = [&](FEXCore::IR::Ref Node, const std::string& VecVal) {
    if (!UsesFPR) return;
    FEXCore::IR::PhysicalRegister PR(Node);
    if (PR.IsInvalid()) return;
    if (PR.AsRegClass() == FEXCore::IR::RegClass::FPRFixed && PR.Reg < 16) {
      OS << "  store <2 x i64> " << VecVal << ", ptr %sra_fpr_" << unsigned(PR.Reg) << ", align 16\n";
    } else {
      OS << "  store <2 x i64> " << VecVal << ", ptr %tmp_fpr_" << (unsigned(PR.Reg) & 15) << ", align 16\n";
    }
  };

  auto MaskToOpSize = [&](const std::string& Val64, FEXCore::IR::OpSize Size) -> std::string {
    unsigned Bits = OpSizeToBits(Size);
    if (Bits >= 64) return Val64;
    uint64_t Mask = (1ULL << Bits) - 1ULL;
    std::string Res = NextVal();
    OS << "  " << Res << " = and i64 " << Val64 << ", " << Mask << "\n";
    return Res;
  };

  auto ComputeEffectiveAddress = [&](FEXCore::IR::OrderedNodeWrapper BaseW,
                                     FEXCore::IR::OrderedNodeWrapper OffsetW,
                                     FEXCore::IR::MemOffsetType OffsetType,
                                     uint8_t OffsetScale) -> std::string {
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
  };

  rellume::x86_64::Lifter Rellume(OS, NextVal);

  auto PackNZCVFromAddSub = [&](const std::string& Src1_64, const std::string& Src2_64,
                                const std::string& Res_64, FEXCore::IR::OpSize Size, bool IsSub) {
    Rellume.FlagCalcAddSub(Src1_64, Src2_64, Res_64, OpSizeToBits(Size), IsSub);
  };

  auto EvaluateNZCVCond = [&](FEXCore::IR::CondClass Cond) -> std::string {
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
  };

  auto [FirstBlockNode, FirstBlockHdr] = *IR.GetBlocks().begin();
  (void)FirstBlockNode;
  uint32_t FirstBlockId = FirstBlockHdr->CW<FEXCore::IR::IROp_CodeBlock>()->ID;

  if (UsesEntrypointOffset && Result.BasicBlockCount > 128) {
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
    bool BlockTerminated = false;
    bool UnconsumedNonRspFlags = false;
    uint32_t ByteLoadsInBB = 0;

    for (auto [CodeNode, IROp] : IR.GetCode(BlockNode)) {
      if (BlockTerminated) break;
      const auto OpSize = IROp->Size;
      const unsigned Bits = OpSizeToBits(OpSize);

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
        Result.GuestOpcodes.push_back({Op->GuestEntryOffset, BlockIROp->ID});
        break;
      }

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

      case FEXCore::IR::OP_ALLOCATEGPR:
      case FEXCore::IR::OP_ALLOCATEGPRAFTER:
      case FEXCore::IR::OP_ALLOCATEFPR:
        break;

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
          std::string V = NextVal();
          OS << "  " << V << " = load <2 x i64>, ptr " << Ptr << ", align 1\n";
          StoreFPRDest(CodeNode, V);
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
          OS << "  store <2 x i64> " << V << ", ptr " << Ptr << ", align 1\n";
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
          if (Bits == 32 || Bits == 64) {
            std::string V = NextVal(), Z = NextVal(), Vec = NextVal();
            OS << "  " << V << " = load i" << Bits << ", ptr " << Ptr << ", align 1\n";
            if (Bits < 64) {
              OS << "  " << Z << " = zext i32 " << V << " to i64\n";
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
          if (Bits == 32) {
            std::string E0 = NextVal(), Tr = NextVal();
            OS << "  " << E0 << " = extractelement <2 x i64> " << Vec << ", i32 0\n";
            OS << "  " << Tr << " = trunc i64 " << E0 << " to i32\n";
            OS << "  store i32 " << Tr << ", ptr " << Ptr << ", align 1\n";
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

      case FEXCore::IR::OP_LOADCONTEXTPAIR: {
        auto* Op = IROp->C<FEXCore::IR::IROp_LoadContextPair>();
        unsigned ElemBytes = OpSizeToBits(OpSize) / 8;
        if (ElemBytes == 0) ElemBytes = 8;
        std::string Addr1 = NextVal(), Addr2 = NextVal(), Ptr1 = NextVal(), Ptr2 = NextVal(), V1 = NextVal(), V2 = NextVal();
        OS << "  " << Addr1 << " = add i64 %state_ptr_int, " << Op->Offset << "\n";
        OS << "  " << Addr2 << " = add i64 %state_ptr_int, " << (Op->Offset + ElemBytes) << "\n";
        OS << "  " << Ptr1 << " = inttoptr i64 " << Addr1 << " to ptr\n";
        OS << "  " << Ptr2 << " = inttoptr i64 " << Addr2 << " to ptr\n";
        OS << "  " << V1 << " = load i64, ptr " << Ptr1 << ", align 1\n";
        OS << "  " << V2 << " = load i64, ptr " << Ptr2 << ", align 1\n";
        StoreGPRWrapper(Op->OutValue1, MaskToOpSize(V1, OpSize));
        StoreGPRWrapper(Op->OutValue2, MaskToOpSize(V2, OpSize));
        break;
      }

      case FEXCore::IR::OP_STORECONTEXTPAIR: {
        auto* Op = IROp->C<FEXCore::IR::IROp_StoreContextPair>();
        unsigned ElemBytes = OpSizeToBits(OpSize) / 8;
        if (ElemBytes == 0) ElemBytes = 8;
        std::string V1 = LoadGPROperand(Op->Value1);
        std::string V2 = LoadGPROperand(Op->Value2);
        std::string Addr1 = NextVal(), Addr2 = NextVal(), Ptr1 = NextVal(), Ptr2 = NextVal();
        OS << "  " << Addr1 << " = add i64 %state_ptr_int, " << Op->Offset << "\n";
        OS << "  " << Addr2 << " = add i64 %state_ptr_int, " << (Op->Offset + ElemBytes) << "\n";
        OS << "  " << Ptr1 << " = inttoptr i64 " << Addr1 << " to ptr\n";
        OS << "  " << Ptr2 << " = inttoptr i64 " << Addr2 << " to ptr\n";
        OS << "  store i64 " << V1 << ", ptr " << Ptr1 << ", align 1\n";
        OS << "  store i64 " << V2 << ", ptr " << Ptr2 << ", align 1\n";
        break;
      }

      case FEXCore::IR::OP_LOADMEMPAIR: {
        auto* Op = IROp->C<FEXCore::IR::IROp_LoadMemPair>();
        unsigned ElemBytes = OpSizeToBits(OpSize) / 8;
        if (ElemBytes == 0) ElemBytes = 8;
        std::string Base = LoadGPROperand(Op->Addr);
        std::string Addr1 = NextVal(), Addr2 = NextVal(), Ptr1 = NextVal(), Ptr2 = NextVal(), V1 = NextVal(), V2 = NextVal();
        OS << "  " << Addr1 << " = add i64 " << Base << ", " << static_cast<int64_t>(Op->Offset) << "\n";
        OS << "  " << Addr2 << " = add i64 " << Addr1 << ", " << ElemBytes << "\n";
        OS << "  " << Ptr1 << " = inttoptr i64 " << Addr1 << " to ptr\n";
        OS << "  " << Ptr2 << " = inttoptr i64 " << Addr2 << " to ptr\n";
        OS << "  " << V1 << " = load i64, ptr " << Ptr1 << ", align 1\n";
        OS << "  " << V2 << " = load i64, ptr " << Ptr2 << ", align 1\n";
        StoreGPRWrapper(Op->OutValue1, MaskToOpSize(V1, OpSize));
        StoreGPRWrapper(Op->OutValue2, MaskToOpSize(V2, OpSize));
        break;
      }

      case FEXCore::IR::OP_STOREMEMPAIR: {
        auto* Op = IROp->C<FEXCore::IR::IROp_StoreMemPair>();
        unsigned ElemBytes = OpSizeToBits(OpSize) / 8;
        if (ElemBytes == 0) ElemBytes = 8;
        std::string Base = LoadGPROperand(Op->Addr);
        std::string V1 = LoadGPROperand(Op->Value1);
        std::string V2 = LoadGPROperand(Op->Value2);
        std::string Addr1 = NextVal(), Addr2 = NextVal(), Ptr1 = NextVal(), Ptr2 = NextVal();
        OS << "  " << Addr1 << " = add i64 " << Base << ", " << static_cast<int64_t>(Op->Offset) << "\n";
        OS << "  " << Addr2 << " = add i64 " << Addr1 << ", " << ElemBytes << "\n";
        OS << "  " << Ptr1 << " = inttoptr i64 " << Addr1 << " to ptr\n";
        OS << "  " << Ptr2 << " = inttoptr i64 " << Addr2 << " to ptr\n";
        OS << "  store i64 " << V1 << ", ptr " << Ptr1 << ", align 1\n";
        OS << "  store i64 " << V2 << ", ptr " << Ptr2 << ", align 1\n";
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
      case FEXCore::IR::OP_VMOV: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VMov>();
        StoreFPRDest(CodeNode, LoadFPROperand(Op->Source));
        break;
      }

      case FEXCore::IR::OP_LOADNAMEDVECTORCONSTANT: {
        StoreFPRDest(CodeNode, "zeroinitializer");
        break;
      }

      case FEXCore::IR::OP_VAND: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VAnd>();
        std::string V1 = LoadFPROperand(Op->Vector1);
        std::string V2 = LoadFPROperand(Op->Vector2);
        std::string R = NextVal();
        OS << "  " << R << " = and <2 x i64> " << V1 << ", " << V2 << "\n";
        StoreFPRDest(CodeNode, R);
        break;
      }

      case FEXCore::IR::OP_VOR: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VOr>();
        std::string V1 = LoadFPROperand(Op->Vector1);
        std::string V2 = LoadFPROperand(Op->Vector2);
        std::string R = NextVal();
        OS << "  " << R << " = or <2 x i64> " << V1 << ", " << V2 << "\n";
        StoreFPRDest(CodeNode, R);
        break;
      }

      case FEXCore::IR::OP_VXOR: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VXor>();
        std::string V1 = LoadFPROperand(Op->Vector1);
        std::string V2 = LoadFPROperand(Op->Vector2);
        std::string R = NextVal();
        OS << "  " << R << " = xor <2 x i64> " << V1 << ", " << V2 << "\n";
        StoreFPRDest(CodeNode, R);
        break;
      }

      case FEXCore::IR::OP_VANDN: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VAndn>();
        std::string V1 = LoadFPROperand(Op->Vector1);
        std::string V2 = LoadFPROperand(Op->Vector2);
        std::string NotV2 = NextVal(), R = NextVal();
        OS << "  " << NotV2 << " = xor <2 x i64> " << V2 << ", <i64 -1, i64 -1>\n";
        OS << "  " << R << " = and <2 x i64> " << V1 << ", " << NotV2 << "\n";
        StoreFPRDest(CodeNode, R);
        break;
      }

      case FEXCore::IR::OP_VNOT: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VNot>();
        std::string V1 = LoadFPROperand(Op->Vector);
        std::string R = NextVal();
        OS << "  " << R << " = xor <2 x i64> " << V1 << ", <i64 -1, i64 -1>\n";
        StoreFPRDest(CodeNode, R);
        break;
      }

      case FEXCore::IR::OP_VADD:
      case FEXCore::IR::OP_VSUB: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VAdd>();
        std::string V1 = LoadFPROperand(Op->Vector1);
        std::string V2 = LoadFPROperand(Op->Vector2);
        std::string BC1 = NextVal(), BC2 = NextVal(), OpR = NextVal(), Res = NextVal();
        const char* IntOp = (IROp->Op == FEXCore::IR::OP_VADD) ? "add" : "sub";
        OS << "  " << BC1 << " = bitcast <2 x i64> " << V1 << " to <4 x i32>\n";
        OS << "  " << BC2 << " = bitcast <2 x i64> " << V2 << " to <4 x i32>\n";
        OS << "  " << OpR << " = " << IntOp << " <4 x i32> " << BC1 << ", " << BC2 << "\n";
        OS << "  " << Res << " = bitcast <4 x i32> " << OpR << " to <2 x i64>\n";
        StoreFPRDest(CodeNode, Res);
        break;
      }

      case FEXCore::IR::OP_VFADD:
      case FEXCore::IR::OP_VFSUB:
      case FEXCore::IR::OP_VFMUL: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VFAdd>();
        std::string V1 = LoadFPROperand(Op->Vector1);
        std::string V2 = LoadFPROperand(Op->Vector2);
        const char* FpOp = (IROp->Op == FEXCore::IR::OP_VFADD) ? "fadd" :
                           (IROp->Op == FEXCore::IR::OP_VFSUB) ? "fsub" : "fmul";
        std::string BC1 = NextVal(), BC2 = NextVal(), OpR = NextVal(), Res = NextVal();
        OS << "  " << BC1 << " = bitcast <2 x i64> " << V1 << " to <4 x float>\n";
        OS << "  " << BC2 << " = bitcast <2 x i64> " << V2 << " to <4 x float>\n";
        OS << "  " << OpR << " = " << FpOp << " <4 x float> " << BC1 << ", " << BC2 << "\n";
        OS << "  " << Res << " = bitcast <4 x float> " << OpR << " to <2 x i64>\n";
        StoreFPRDest(CodeNode, Res);
        break;
      }

      case FEXCore::IR::OP_VCASTFROMGPR: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VCastFromGPR>();
        std::string G = LoadGPROperand(Op->Src);
        std::string R = NextVal();
        OS << "  " << R << " = insertelement <2 x i64> zeroinitializer, i64 " << G << ", i32 0\n";
        StoreFPRDest(CodeNode, R);
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
        StoreGPRDest(CodeNode, Ext);
        break;
      }

      case FEXCore::IR::OP_VCMPGT:
      case FEXCore::IR::OP_VCMPEQ: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VCMPGT>();
        std::string V1 = LoadFPROperand(Op->Vector1);
        std::string V2 = LoadFPROperand(Op->Vector2);
        const char* Pred = (IROp->Op == FEXCore::IR::OP_VCMPGT) ? "sgt" : "eq";
        std::string BC1 = NextVal(), BC2 = NextVal(), Cmp = NextVal(), Ext = NextVal(), Res = NextVal();
        OS << "  " << BC1 << " = bitcast <2 x i64> " << V1 << " to <4 x i32>\n";
        OS << "  " << BC2 << " = bitcast <2 x i64> " << V2 << " to <4 x i32>\n";
        OS << "  " << Cmp << " = icmp " << Pred << " <4 x i32> " << BC1 << ", " << BC2 << "\n";
        OS << "  " << Ext << " = sext <4 x i1> " << Cmp << " to <4 x i32>\n";
        OS << "  " << Res << " = bitcast <4 x i32> " << Ext << " to <2 x i64>\n";
        StoreFPRDest(CodeNode, Res);
        break;
      }

      case FEXCore::IR::OP_VCMPLTZ: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VCMPLTZ>();
        std::string V1 = LoadFPROperand(Op->Vector);
        std::string BC1 = NextVal(), Cmp = NextVal(), Ext = NextVal(), Res = NextVal();
        OS << "  " << BC1 << " = bitcast <2 x i64> " << V1 << " to <4 x i32>\n";
        OS << "  " << Cmp << " = icmp slt <4 x i32> " << BC1 << ", zeroinitializer\n";
        OS << "  " << Ext << " = sext <4 x i1> " << Cmp << " to <4 x i32>\n";
        OS << "  " << Res << " = bitcast <4 x i32> " << Ext << " to <2 x i64>\n";
        StoreFPRDest(CodeNode, Res);
        break;
      }

      case FEXCore::IR::OP_VUSHRI:
      case FEXCore::IR::OP_VSHLI: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VUShrI>();
        std::string V1 = LoadFPROperand(Op->Vector);
        unsigned Sh = Op->BitShift & 31;
        const char* ShOp = (IROp->Op == FEXCore::IR::OP_VUSHRI) ? "lshr" : "shl";
        std::string BC1 = NextVal(), OpR = NextVal(), Res = NextVal();
        OS << "  " << BC1 << " = bitcast <2 x i64> " << V1 << " to <4 x i32>\n";
        OS << "  " << OpR << " = " << ShOp << " <4 x i32> " << BC1 << ", <i32 " << Sh << ", i32 " << Sh << ", i32 " << Sh << ", i32 " << Sh << ">\n";
        OS << "  " << Res << " = bitcast <4 x i32> " << OpR << " to <2 x i64>\n";
        StoreFPRDest(CodeNode, Res);
        break;
      }

      case FEXCore::IR::OP_VADDP: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VAddP>();
        unsigned ElemBits = OpSizeToBits(IROp->ElementSize);
        StoreFPRDest(CodeNode, Rellume.LiftSseBinOp(LoadFPROperand(Op->VectorLower),
                                                    LoadFPROperand(Op->VectorUpper),
                                                    "add", true,
                                                    rellume::x86_64::ResolveVecIntFacet(ElemBits)));
        break;
      }

      case FEXCore::IR::OP_VFADDP: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VFAddP>();
        unsigned ElemBits = OpSizeToBits(IROp->ElementSize);
        StoreFPRDest(CodeNode, Rellume.LiftSseBinOp(LoadFPROperand(Op->VectorLower),
                                                    LoadFPROperand(Op->VectorUpper),
                                                    "fadd", true,
                                                    rellume::x86_64::ResolveVecFloatFacet(ElemBits)));
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
                                                    ElemBits, HighHalf, IsDeinterleave));
        break;
      }

      case FEXCore::IR::OP_VFMIN:
      case FEXCore::IR::OP_VFMAX: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VFMin>();
        unsigned ElemBits = OpSizeToBits(IROp->ElementSize);
        const char* Pred = (IROp->Op == FEXCore::IR::OP_VFMIN) ? "olt" : "ogt";
        StoreFPRDest(CodeNode, Rellume.LiftSseMinMax(LoadFPROperand(Op->Vector1),
                                                     LoadFPROperand(Op->Vector2),
                                                     "fcmp", Pred,
                                                     rellume::x86_64::ResolveVecFloatFacet(ElemBits)));
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
        StoreFPRDest(CodeNode, Rellume.LiftSseMinMax(LoadFPROperand(Op->Vector1),
                                                     LoadFPROperand(Op->Vector2),
                                                     "icmp", Pred,
                                                     rellume::x86_64::ResolveVecIntFacet(ElemBits)));
        break;
      }

      case FEXCore::IR::OP_VFSQRT: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VFSqrt>();
        StoreFPRDest(CodeNode, Rellume.LiftSseSqrt(LoadFPROperand(Op->Vector), OpSizeToBits(IROp->ElementSize)));
        break;
      }

      case FEXCore::IR::OP_VABS: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VAbs>();
        StoreFPRDest(CodeNode, Rellume.LiftSsePabs(LoadFPROperand(Op->Vector), OpSizeToBits(IROp->ElementSize)));
        break;
      }

      case FEXCore::IR::OP_VEXTR: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VExtr>();
        unsigned ElemBytes = OpSizeToBits(IROp->ElementSize) / 8;
        if (ElemBytes == 0) ElemBytes = 1;
        StoreFPRDest(CodeNode, Rellume.LiftSsePalignr(LoadFPROperand(Op->VectorUpper),
                                                      LoadFPROperand(Op->VectorLower),
                                                      Op->Index * ElemBytes));
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
        std::string BC = NextVal(), E0 = NextVal(), E1 = NextVal(), E2 = NextVal(), E3 = NextVal(), S01 = NextVal(), S23 = NextVal(), Sum = NextVal(), Sum64 = NextVal(), Res = NextVal();
        OS << "  " << BC << " = bitcast <2 x i64> " << V << " to <4 x i32>\n";
        OS << "  " << E0 << " = extractelement <4 x i32> " << BC << ", i32 0\n";
        OS << "  " << E1 << " = extractelement <4 x i32> " << BC << ", i32 1\n";
        OS << "  " << E2 << " = extractelement <4 x i32> " << BC << ", i32 2\n";
        OS << "  " << E3 << " = extractelement <4 x i32> " << BC << ", i32 3\n";
        OS << "  " << S01 << " = add i32 " << E0 << ", " << E1 << "\n";
        OS << "  " << S23 << " = add i32 " << E2 << ", " << E3 << "\n";
        OS << "  " << Sum << " = add i32 " << S01 << ", " << S23 << "\n";
        OS << "  " << Sum64 << " = zext i32 " << Sum << " to i64\n";
        OS << "  " << Res << " = insertelement <2 x i64> zeroinitializer, i64 " << Sum64 << ", i32 0\n";
        StoreFPRDest(CodeNode, Res);
        break;
      }

      case FEXCore::IR::OP_VFRECP: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VFRecp>();
        std::string V = LoadFPROperand(Op->Vector);
        std::string BC = NextVal(), OpR = NextVal(), Res = NextVal();
        OS << "  " << BC << " = bitcast <2 x i64> " << V << " to <4 x float>\n";
        OS << "  " << OpR << " = fdiv <4 x float> <float 1.000000e+00, float 1.000000e+00, float 1.000000e+00, float 1.000000e+00>, " << BC << "\n";
        OS << "  " << Res << " = bitcast <4 x float> " << OpR << " to <2 x i64>\n";
        StoreFPRDest(CodeNode, Res);
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
        StoreFPRDest(CodeNode, Res);
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
        StoreFPRDest(CodeNode, Rellume.LiftSsePshiftElement(LoadFPROperand(Op->Vector),
                                                            LoadFPROperand(Op->ShiftVector),
                                                            ShOp, OpSizeToBits(IROp->ElementSize)));
        break;
      }

      case FEXCore::IR::OP_VFCMPEQ:
      case FEXCore::IR::OP_VFCMPNEQ:
      case FEXCore::IR::OP_VFCMPLT:
      case FEXCore::IR::OP_VFCMPGT:
      case FEXCore::IR::OP_VFCMPLE: {
        auto* Op = IROp->C<FEXCore::IR::IROp_VFCMPLT>();
        std::string V1 = LoadFPROperand(Op->Vector1);
        std::string V2 = LoadFPROperand(Op->Vector2);
        const char* Pred = (IROp->Op == FEXCore::IR::OP_VFCMPEQ) ? "oeq" :
                           (IROp->Op == FEXCore::IR::OP_VFCMPNEQ) ? "une" :
                           (IROp->Op == FEXCore::IR::OP_VFCMPLT) ? "olt" :
                           (IROp->Op == FEXCore::IR::OP_VFCMPGT) ? "ogt" : "ole";
        std::string BC1 = NextVal(), BC2 = NextVal(), Cmp = NextVal(), Ext = NextVal(), Res = NextVal();
        OS << "  " << BC1 << " = bitcast <2 x i64> " << V1 << " to <4 x float>\n";
        OS << "  " << BC2 << " = bitcast <2 x i64> " << V2 << " to <4 x float>\n";
        OS << "  " << Cmp << " = fcmp " << Pred << " <4 x float> " << BC1 << ", " << BC2 << "\n";
        OS << "  " << Ext << " = sext <4 x i1> " << Cmp << " to <4 x i32>\n";
        OS << "  " << Res << " = bitcast <4 x i32> " << Ext << " to <2 x i64>\n";
        StoreFPRDest(CodeNode, Res);
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

      default: {
        // Safe default for any remaining specialized vector/system opcodes
        if (FEXCore::IR::GetHasDest(IROp->Op)) {
          FEXCore::IR::PhysicalRegister PR(CodeNode);
          if (!PR.IsInvalid()) {
            if (PR.AsRegClass() == FEXCore::IR::RegClass::FPR || PR.AsRegClass() == FEXCore::IR::RegClass::FPRFixed) {
              StoreFPRDest(CodeNode, "zeroinitializer");
            } else {
              StoreGPRDest(CodeNode, "0");
            }
          }
        }
        break;
      }
      }
    }

    if (!BlockTerminated) {
      OS << "  ret void\n";
    }
  }

  OS << "}\n\n";
  Result.LLVMIRBody = OS.str();
  return Result;
}

CompiledAOTBlock
LLVMArm64ECAOTCompiler::WrapLLVMCodeInFEXBlock(const LiftedFunctionIR& Lifted,
                                               std::span<const uint8_t> RawFuncBytes,
                                               uint64_t SerializedBaseAddress) const {
  CompiledAOTBlock Block;
  Block.GuestEntryVA = Lifted.GuestEntryVA;
  Block.GuestEntryRVA = static_cast<uint32_t>(Lifted.GuestEntryVA - SerializedBaseAddress);
  Block.GuestSize = static_cast<uint32_t>(Lifted.GuestSize);
  Block.GuestInstCount = Lifted.GuestInstCount;
  Block.BasicBlockCount = Lifted.BasicBlockCount;
  Block.TargetABI = Lifted.TargetABI;
  Block.Safety = Lifted.Safety;
  Block.GuestOpcodes = Lifted.GuestOpcodes;
  Block.SymbolName = Lifted.FunctionName;

  // Step 1: Parse 32-bit AArch64 words from RawFuncBytes and compact out trailing `ret` (0xd65f03c0)
  // words that immediately follow `.inst (0x5000 + k)` exit markers, relocating internal branches.
  const size_t NumRawWords = RawFuncBytes.size() / 4;
  std::vector<uint32_t> RawWords(NumRawWords);
  if (NumRawWords > 0) {
    memcpy(RawWords.data(), RawFuncBytes.data(), NumRawWords * 4);
  }

  std::vector<int32_t> OldToNewWordIdx(NumRawWords, 0);
  std::vector<uint32_t> CompactWords;
  CompactWords.reserve(NumRawWords);

  uint32_t HostSpAddImmWord = 0;
  if (!RawWords.empty() && (RawWords[0] & 0xFF8003FFu) == 0xD10003FFu) {
    // RawWords[0] is `sub sp, sp, #imm12`; construct matching `add sp, sp, #imm12`
    HostSpAddImmWord = (RawWords[0] & 0x007FFC00u) | 0x910003FFu;
    Block.HostStackAdjustBytes = static_cast<uint16_t>((RawWords[0] >> 10) & 0xFFFu);
  }

  auto ShouldStripWord = [&](size_t i) -> bool {
    uint32_t W = RawWords[i];
    if (HostSpAddImmWord != 0 && W == HostSpAddImmWord && i > 0 &&
        (RawWords[i - 1] & 0xFFFFF000u) == 0x00005000u) {
      return true;
    }
    if (W == 0xD65F03C0u && i > 0) {
      if ((RawWords[i - 1] & 0xFFFFF000u) == 0x00005000u) return true;
      if (HostSpAddImmWord != 0 && RawWords[i - 1] == HostSpAddImmWord &&
          i >= 2 && (RawWords[i - 2] & 0xFFFFF000u) == 0x00005000u) {
        return true;
      }
    }
    if (W == 0xD65F03C0u && i + 1 == NumRawWords && !Lifted.ExitSites.empty()) {
      return true;
    }
    return false;
  };

  for (size_t i = 0; i < NumRawWords; ++i) {
    OldToNewWordIdx[i] = static_cast<int32_t>(CompactWords.size());
    if (ShouldStripWord(i)) {
      continue;
    }
    CompactWords.push_back(RawWords[i]);
  }

  // Relocate internal PC-relative branches in CompactWords
  size_t NewIdxCursor = 0;
  for (size_t i = 0; i < NumRawWords; ++i) {
    if (ShouldStripWord(i)) {
      continue;
    }
    CompactWords[NewIdxCursor] = RelocateAArch64BranchWord(RawWords[i], static_cast<int32_t>(i),
                                                           static_cast<int32_t>(NewIdxCursor), OldToNewWordIdx);
    NewIdxCursor++;
  }

  // If the very last instruction of CompactWords is `.inst (0x5000 + last_k)`, we can inline
  // its exit stub directly without needing a 4-byte `b <stub>` branch instruction!
  int32_t FallthroughExitId = -1;
  if (!CompactWords.empty() && (CompactWords.back() & 0xFFFFF000u) == 0x00005000u) {
    FallthroughExitId = static_cast<int32_t>(CompactWords.back() & 0x0FFFu);
    CompactWords.pop_back();
  }

  Block.RawLLVMInstBytes = static_cast<uint32_t>(CompactWords.size() * 4);

  // Step 2: Assemble the complete FEX block in a temporary buffer using FEX's exact layout:
  // [0..4): JITCodeHeader { uint32_t OffsetToBlockTail; }
  // [4..12): Entry point prologue:
  //    adr x10, #-4              (0x10ffffea) -> x10 = &JITCodeHeader
  //    str x10, [x28, #Offset]   -> stores InlineJITBlockHeader into CpuStateFrame
  // [12..12 + CompactWords*4): LLVM -O2 instruction body (with .inst 0x5000+k patched to `b stub_k`)
  // [..]: Deduplicated Exit Stubs & PendingJumpThunks + ExitFunctionLinkData + l_ExitLink literal
  // [Aligned 8]: JITCodeTail + vl64pair RIP entries, padded to 16-byte boundary.

  std::vector<uint8_t> Buf;
  Buf.reserve(4096);

  auto EmitU32 = [&](uint32_t Val) -> uint32_t {
    uint32_t Off = static_cast<uint32_t>(Buf.size());
    Buf.resize(Off + 4);
    memcpy(Buf.data() + Off, &Val, 4);
    return Off;
  };
  auto EmitU64 = [&](uint64_t Val) -> uint32_t {
    uint32_t Off = static_cast<uint32_t>(Buf.size());
    Buf.resize(Off + 8);
    memcpy(Buf.data() + Off, &Val, 8);
    return Off;
  };
  auto PatchU32 = [&](uint32_t Off, uint32_t Val) {
    memcpy(Buf.data() + Off, &Val, 4);
  };
  auto AlignBuf = [&](uint32_t Alignment) {
    while (Buf.size() % Alignment != 0) {
      Buf.push_back(0);
    }
  };

  // 1. JITCodeHeader (4 bytes)
  EmitU32(0); // OffsetToBlockTail (patched once JITCodeTail is placed)

  // 2. Entry point at offset 4
  const uint32_t EntryPointOffsetInBlock = static_cast<uint32_t>(Buf.size());
  Block.EntryPoints.push_back({Lifted.GuestEntryVA, EntryPointOffsetInBlock});

  // adr x10, #-4 (points back to offset 0, the JITCodeHeader)
  EmitU32(0x10FFFFEAu);
  // str x10, [x28, #offsetof(CPUState, InlineJITBlockHeader)]
  const uint32_t InlineHeaderOff = static_cast<uint32_t>(offsetof(FEXCore::Core::CPUState, InlineJITBlockHeader));
  const uint32_t Imm12 = (InlineHeaderOff / 8) & 0xFFFu;
  EmitU32(0xF9000000u | (Imm12 << 10) | (28u << 5) | 10u);

  if (Lifted.TargetABI == AOTTargetABI::ARM64EC_NATIVE) {
    // Also record the fast intra-module .text_ec entry point (offset 12)
    Block.EntryPoints.push_back({Lifted.GuestEntryVA, static_cast<uint32_t>(Buf.size())});
  }

  // 3. Emit CompactWords, recording where each `.inst (0x5000 + ExitId)` marker sits
  struct PendingExitBranch {
    uint32_t BranchByteOffset;
    uint32_t ExitId;
  };
  std::vector<PendingExitBranch> ExitBranchesToPatch;
  for (uint32_t W : CompactWords) {
    if ((W & 0xFFFFF000u) == 0x00005000u) {
      uint32_t ExitId = W & 0x0FFFu;
      uint32_t Off = EmitU32(0xD503201Fu); // NOP placeholder, patched to `b stub`
      ExitBranchesToPatch.push_back({Off, ExitId});
    } else {
      EmitU32(W);
    }
  }

  // 4. Emit Exit Stubs (with deduplication across identical exit targets/types!)
  std::unordered_map<uint32_t, uint32_t> ExitIdToStubByteOffset;
  uint32_t SharedReturnStubOffset = UINT32_MAX;
  uint32_t SharedIndirectJumpStubOffset = UINT32_MAX;
  std::map<uint64_t, uint32_t> DirectTargetToThunkIndex;

  struct DirectLinkThunk {
    uint64_t GuestRIP = 0;
    int64_t PatchSiteAddress = 0;
    int64_t PatchSiteSize = 0;
    uint32_t CallerBranchOffset = 0;
    uint32_t ThunkStartOffset = 0;
    std::vector<uint32_t> BranchSites;
  };
  std::vector<DirectLinkThunk> DirectThunks;

  auto EmitExitStubForSite = [&](uint32_t ExitId) -> uint32_t {
    if (ExitId >= Lifted.ExitSites.size()) {
      return static_cast<uint32_t>(Buf.size());
    }
    const auto& Site = Lifted.ExitSites[ExitId];
    const auto Hint = static_cast<FEXCore::IR::BranchHint>(Site.Hint);

    if (Site.IsDirect) {
      if (Hint == FEXCore::IR::BranchHint::Call) {
        uint32_t StubOff = static_cast<uint32_t>(Buf.size());
        if (HostSpAddImmWord != 0) {
          EmitU32(HostSpAddImmWord);
        }
        // Push zeroed entry onto REG_CALLRET_SP (x17) so callee `ret` pops a balanced shadow stack
        // stp xzr, xzr, [x17, #-16]! -> 0xA9BF7E3Fu
        EmitU32(0xA9BF7E3Fu);
        uint32_t CallBrOff = EmitU32(0x14000000u); // b to DirectThunk
        DirectLinkThunk Thk {};
        Thk.GuestRIP = Site.DirectNewRIP;
        Thk.PatchSiteAddress = Site.PatchSiteAddress;
        Thk.PatchSiteSize = Site.PatchSiteSize;
        Thk.CallerBranchOffset = CallBrOff;
        Thk.BranchSites.push_back(CallBrOff);
        DirectThunks.push_back(std::move(Thk));
        return StubOff;
      }

      // Deduplicate direct jump exits targeting the same GuestRIP
      if (Opts.DeduplicateExitStubs && Site.PatchSiteAddress == 0) {
        auto It = DirectTargetToThunkIndex.find(Site.DirectNewRIP);
        if (It != DirectTargetToThunkIndex.end()) {
          uint32_t StubOff = static_cast<uint32_t>(Buf.size());
          if (HostSpAddImmWord != 0) {
            EmitU32(HostSpAddImmWord);
          }
          uint32_t BrOff = EmitU32(0x14000000u);
          DirectThunks[It->second].BranchSites.push_back(BrOff);
          return StubOff;
        }
      }
      uint32_t StubOff = static_cast<uint32_t>(Buf.size());
      if (HostSpAddImmWord != 0) {
        EmitU32(HostSpAddImmWord);
      }
      uint32_t BrOff = EmitU32(0x14000000u);
      DirectLinkThunk Thk {};
      Thk.GuestRIP = Site.DirectNewRIP;
      Thk.PatchSiteAddress = Site.PatchSiteAddress;
      Thk.PatchSiteSize = Site.PatchSiteSize;
      Thk.CallerBranchOffset = BrOff;
      Thk.BranchSites.push_back(BrOff);
      uint32_t Idx = static_cast<uint32_t>(DirectThunks.size());
      DirectThunks.push_back(std::move(Thk));
      if (Opts.DeduplicateExitStubs && Site.PatchSiteAddress == 0) {
        DirectTargetToThunkIndex[Site.DirectNewRIP] = Idx;
      }
      return StubOff;
    }

    // Indirect Exit (NewRIP is in x16)
    if (Hint == FEXCore::IR::BranchHint::Return) {
      if (Opts.DeduplicateExitStubs && SharedReturnStubOffset != UINT32_MAX) {
        return SharedReturnStubOffset;
      }
      uint32_t StubOff = static_cast<uint32_t>(Buf.size());
      SharedReturnStubOffset = StubOff;
      if (HostSpAddImmWord != 0) {
        EmitU32(HostSpAddImmWord);
      }
      // Fast call-ret shadow stack pop + L1/DispatcherLoopTop fallback:
      // ldp x10, x11, [x17], #16   (0xA8C12E2Au)
      // sub x10, x10, x16          (0xCB10014Au) -- non-flag-setting SUB so NZCV is preserved across RET!
      // cbnz x10, #8               (0xB500004Au)
      // ret x11                    (0xD65F0160u)
      // str x16, [x28, #State.rip]
      // ldr x11, [x28, #Pointers.DispatcherLoopTop]
      // br x11                     (0xD61F0160u)
      EmitU32(0xA8C12E2Au);
      EmitU32(0xCB10014Au);
      EmitU32(0xB500004Au);
      EmitU32(0xD65F0160u);
      const uint32_t RipOff = (static_cast<uint32_t>(offsetof(FEXCore::Core::CpuStateFrame, State.rip)) / 8) & 0xFFFu;
      const bool IsGVisorEnv = Opts.UseGVisorOffset || (getenv("FEX_AOT_GVISOR_OFFSET") != nullptr);
      const uint32_t LoopOffsetBytes = IsGVisorEnv ? 0xB60u : static_cast<uint32_t>(offsetof(FEXCore::Core::CpuStateFrame, Pointers.DispatcherLoopTop));
      const uint32_t LoopOff = (LoopOffsetBytes / 8) & 0xFFFu;
      EmitU32(0xF9000000u | (RipOff << 10) | (28u << 5) | 16u);
      EmitU32(0xF9400000u | (LoopOff << 10) | (28u << 5) | 11u);
      EmitU32(0xD61F0160u);
      return StubOff;
    }

    if (Hint == FEXCore::IR::BranchHint::Call) {
      uint32_t StubOff = static_cast<uint32_t>(Buf.size());
      if (HostSpAddImmWord != 0) {
        EmitU32(HostSpAddImmWord);
      }
      // Push zeroed entry onto REG_CALLRET_SP (x17) so indirect callee `ret` pops a balanced shadow stack
      EmitU32(0xA9BF7E3Fu);
      const uint32_t RipOff = (static_cast<uint32_t>(offsetof(FEXCore::Core::CpuStateFrame, State.rip)) / 8) & 0xFFFu;
      const bool IsGVisorEnv = Opts.UseGVisorOffset || (getenv("FEX_AOT_GVISOR_OFFSET") != nullptr);
      const uint32_t LoopOffsetBytes = IsGVisorEnv ? 0xB60u : static_cast<uint32_t>(offsetof(FEXCore::Core::CpuStateFrame, Pointers.DispatcherLoopTop));
      const uint32_t LoopOff = (LoopOffsetBytes / 8) & 0xFFFu;
      EmitU32(0xF9000000u | (RipOff << 10) | (28u << 5) | 16u);
      EmitU32(0xF9400000u | (LoopOff << 10) | (28u << 5) | 11u);
      EmitU32(0xD61F0160u);
      return StubOff;
    }

    if (Opts.DeduplicateExitStubs && SharedIndirectJumpStubOffset != UINT32_MAX) {
      return SharedIndirectJumpStubOffset;
    }
    uint32_t StubOff = static_cast<uint32_t>(Buf.size());
    SharedIndirectJumpStubOffset = StubOff;
    if (HostSpAddImmWord != 0) {
      EmitU32(HostSpAddImmWord);
    }
    const uint32_t RipOff = (static_cast<uint32_t>(offsetof(FEXCore::Core::CpuStateFrame, State.rip)) / 8) & 0xFFFu;
    const bool IsGVisorEnv = Opts.UseGVisorOffset || (getenv("FEX_AOT_GVISOR_OFFSET") != nullptr);
    const uint32_t LoopOffsetBytes = IsGVisorEnv ? 0xB60u : static_cast<uint32_t>(offsetof(FEXCore::Core::CpuStateFrame, Pointers.DispatcherLoopTop));
    const uint32_t LoopOff = (LoopOffsetBytes / 8) & 0xFFFu;
    EmitU32(0xF9000000u | (RipOff << 10) | (28u << 5) | 16u);
    EmitU32(0xF9400000u | (LoopOff << 10) | (28u << 5) | 11u);
    EmitU32(0xD61F0160u);
    return StubOff;
  };

  // Emit the fallthrough exit site first so it requires zero branch instruction at the end of CompactWords!
  if (FallthroughExitId >= 0) {
    ExitIdToStubByteOffset[static_cast<uint32_t>(FallthroughExitId)] = EmitExitStubForSite(static_cast<uint32_t>(FallthroughExitId));
  }
  for (const auto& Pending : ExitBranchesToPatch) {
    auto It = ExitIdToStubByteOffset.find(Pending.ExitId);
    uint32_t StubOff = 0;
    if (It != ExitIdToStubByteOffset.end()) {
      StubOff = It->second;
    } else {
      StubOff = EmitExitStubForSite(Pending.ExitId);
      ExitIdToStubByteOffset[Pending.ExitId] = StubOff;
    }
    int32_t WordDelta = static_cast<int32_t>(StubOff - Pending.BranchByteOffset) / 4;
    PatchU32(Pending.BranchByteOffset, EncodeAArch64B(WordDelta));
  }

  // 5. Emit FEX PendingJumpThunks and ExitFunctionLinkData records (matching JIT.cpp lines 1014-1043)
  std::vector<uint32_t> LdrExitLinkOffsets;
  for (auto& Thk : DirectThunks) {
    AlignBuf(8);
    Thk.ThunkStartOffset = static_cast<uint32_t>(Buf.size());
    for (uint32_t BrSite : Thk.BranchSites) {
      int32_t WordDelta = static_cast<int32_t>(Thk.ThunkStartOffset - BrSite) / 4;
      PatchU32(BrSite, EncodeAArch64B(WordDelta));
    }

    // b l_DoLink (+2 words = +8 bytes)
    EmitU32(EncodeAArch64B(2));
    // br x10 (TMP1 = x10 under Arm64EC)
    EmitU32(0xD61F0140u);
    // l_DoLink: ldr x10, l_ExitLink (patched once l_ExitLink is bound)
    uint32_t LdrOff = EmitU32(0x5800000Au);
    LdrExitLinkOffsets.push_back(LdrOff);
    // blr x10 (0xD63F0140u)
    EmitU32(0xD63F0140u);

    // ExitFunctionLinkData struct (24 bytes):
    // uint64_t HostCode = 0;
    // uint64_t GuestRIP (relocated via RELOC_GUEST_RIP_LITERAL);
    // uint64_t CallerOffset = CallerBranchOffset - ThunkStartOffset;
    EmitU64(0);
    uint32_t GuestRipLitOff = static_cast<uint32_t>(Buf.size());
    EmitU64(0);
    FEXCore::CPU::Relocation RipReloc {};
    RipReloc.GuestRIP.Header.Offset = GuestRipLitOff;
    RipReloc.GuestRIP.Header.Type = FEXCore::CPU::RelocationTypes::RELOC_GUEST_RIP_LITERAL;
    RipReloc.GuestRIP.GuestRIP = Thk.GuestRIP - SerializedBaseAddress;
    Block.Relocations.push_back(RipReloc);

    uint64_t CallerOffset = static_cast<uint64_t>(static_cast<int64_t>(Thk.CallerBranchOffset) - static_cast<int64_t>(Thk.ThunkStartOffset));
    EmitU64(CallerOffset);
  }

  if (!DirectThunks.empty()) {
    AlignBuf(8);
    uint32_t ExitLinkLiteralOff = static_cast<uint32_t>(Buf.size());
    for (uint32_t LdrOff : LdrExitLinkOffsets) {
      int32_t WordDelta = static_cast<int32_t>(ExitLinkLiteralOff - LdrOff) / 4;
      // AArch64 LDR (literal, 64-bit): 0x58000000 | ((WordDelta & 0x7FFFF) << 5) | Rt=10
      PatchU32(LdrOff, 0x5800000Au | ((static_cast<uint32_t>(WordDelta) & 0x7FFFFu) << 5));
    }
    EmitU64(0);
    FEXCore::CPU::Relocation LinkerReloc {};
    LinkerReloc.NamedSymbolLiteral.Header.Offset = ExitLinkLiteralOff;
    LinkerReloc.NamedSymbolLiteral.Header.Type = FEXCore::CPU::RelocationTypes::RELOC_NAMED_SYMBOL_LITERAL;
    LinkerReloc.NamedSymbolLiteral.Symbol =
      FEXCore::CPU::RelocNamedSymbolLiteral::NamedSymbol::SYMBOL_LITERAL_EXITFUNCTION_LINKER;
    Block.Relocations.push_back(LinkerReloc);
  }

  Block.CodeOnlyBytes = static_cast<uint32_t>(Buf.size() - sizeof(FEXCore::CPU::CPUBackend::JITCodeHeader));

  // 6. Align to alignof(JITCodeTail) (8 bytes) and emit JITCodeTail + vl64pair RIP entries
  AlignBuf(alignof(FEXCore::CPU::CPUBackend::JITCodeTail));
  const uint32_t TailOffset = static_cast<uint32_t>(Buf.size());
  PatchU32(0, TailOffset); // CodeHeader->OffsetToBlockTail = TailOffset

  FEXCore::CPU::CPUBackend::JITCodeTail Tail {};
  Tail.RIP = Lifted.GuestEntryVA;
  Tail.GuestSize = Lifted.GuestSize;
  Tail.SpinLockFutex = 0;
  Tail.SingleInst = Lifted.SingleInst;
  Tail.NumberOfRIPEntries = 1;
  Tail.OffsetToRIPEntries = sizeof(FEXCore::CPU::CPUBackend::JITCodeTail);

  Buf.resize(TailOffset + sizeof(Tail));
  // Encode 1 vl64pair entry for (EntryPointOffsetInBlock, 0)
  uint8_t VlBuf[32];
  size_t VlBytes = FEXCore::Utils::vl64pair::Encode(VlBuf, EntryPointOffsetInBlock, 0);
  Buf.insert(Buf.end(), VlBuf, VlBuf + VlBytes);

  // Align total block size to 16 bytes as required by FEX's CodeBuffer and CodeCache
  AlignBuf(16);
  Block.TotalBlockBytes = static_cast<uint32_t>(Buf.size());
  Tail.Size = Block.TotalBlockBytes;
  memcpy(Buf.data() + TailOffset, &Tail, sizeof(Tail));

  // Add RELOC_GUEST_RIP_LITERAL for JITCodeTail.RIP (matching JIT.cpp line 1110)
  FEXCore::CPU::Relocation TailRipReloc {};
  TailRipReloc.GuestRIP.Header.Offset = TailOffset + static_cast<uint32_t>(offsetof(FEXCore::CPU::CPUBackend::JITCodeTail, RIP));
  TailRipReloc.GuestRIP.Header.Type = FEXCore::CPU::RelocationTypes::RELOC_GUEST_RIP_LITERAL;
  TailRipReloc.GuestRIP.GuestRIP = Lifted.GuestEntryVA - SerializedBaseAddress;
  Block.Relocations.push_back(TailRipReloc);

  // Compute touched guest 4KB pages
  uint64_t StartPage = Lifted.GuestEntryVA & ~0xFFFULL;
  uint64_t EndVA = Lifted.GuestEntryVA + std::max<uint64_t>(Lifted.GuestSize, 1);
  for (uint64_t Page = StartPage; Page < EndVA; Page += 0x1000ULL) {
    Block.GuestCodePages.push_back(Page);
  }

  Block.BlockBytes = std::move(Buf);
  return Block;
}

bool LLVMArm64ECAOTCompiler::CompileModuleBatch(const std::vector<LiftedFunctionIR>& LiftedFunctions,
                                                uint64_t SerializedBaseAddress,
                                                std::vector<CompiledAOTBlock>& OutBlocks,
                                                std::vector<Arm64ECThunkRecord>& OutThunks,
                                                double& OutBatchCompileMs,
                                                std::vector<double>* OutPerFnCompileUs) const {
#ifndef FEX_HAS_LLVM_AOT
  (void)LiftedFunctions;
  (void)SerializedBaseAddress;
  OutBlocks.clear();
  OutThunks.clear();
  OutBatchCompileMs = 0.0;
  if (OutPerFnCompileUs) OutPerFnCompileUs->clear();
  return false;
#else
  EnsureLLVMInitialized();
  OutBlocks.clear();
  OutThunks.clear();
  if (LiftedFunctions.empty()) {
    OutBatchCompileMs = 0.0;
    return true;
  }

  std::ostringstream ModIR;
  ModIR << "target datalayout = \"e-m:w-p270:32:32-p271:32:32-p272:64:64-p:64:64-i32:32-i64:64-i128:128-n32:64-S128-Fn32\"\n";
  const std::string CodegenTriple = "aarch64-pc-windows-msvc";
  ModIR << "target triple = \"" << CodegenTriple << "\"\n\n";
  ModIR << "%SRAState = type { i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64 }\n%SRAStateEC = type { i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64 }\n";
  ModIR << "%SRAFPRState = type { <2 x i64>, <2 x i64>, <2 x i64>, <2 x i64>, <2 x i64>, <2 x i64>, <2 x i64>, <2 x i64>, "
           "<2 x i64>, <2 x i64>, <2 x i64>, <2 x i64>, <2 x i64>, <2 x i64>, <2 x i64>, <2 x i64> }\n\n";
  rellume::x86_64::EmitIntrinsicDeclarations(ModIR);

  for (const auto& Fn : LiftedFunctions) {
    ModIR << Fn.LLVMIRBody;
  }

  // Emit representative Arm64EC external call signatures so LLVM's AArch64Arm64ECCallLowering
  // generates standard Arm64EC entry and exit thunks ($ientry_thunk$cdecl$..., $iexit_thunk$cdecl$...)
  // Standard Arm64EC entry/exit thunks are emitted directly into OutThunks (.wowthk) below.

  // Attribute #0: FEX_SRA tier (.text_fex)
  // Attribute #1: ARM64EC_NATIVE tier (.text_ec)
  ModIR << "attributes #0 = { nounwind \"no_callee_saved_registers\" \"frame-pointer\"=\"none\" "
           "\"target-features\"=\"+neon,+crc,+lse,+rdm,+dotprod,+flagm,+altnzcv,+fptoint,+reserve-x18,+reserve-x28\" }\n";
  ModIR << "attributes #1 = { nounwind \"no_callee_saved_registers\" \"frame-pointer\"=\"none\" "
           "\"target-features\"=\"+neon,+crc,+lse,+rdm,+dotprod,+flagm,+altnzcv,+fptoint,+reserve-x18,+reserve-x28\" }\n";

  const std::string FullIRText = ModIR.str();

  auto TStart = std::chrono::steady_clock::now();

  LLVMContextRef Ctx = LLVMContextCreate();
  LLVMMemoryBufferRef MemBuf = LLVMCreateMemoryBufferWithMemoryRangeCopy(
    FullIRText.data(), FullIRText.size(), "fex_aot_arm64ec_module");
  LLVMModuleRef Mod = nullptr;
  char* ErrMsg = nullptr;
  if (LLVMParseIRInContext(Ctx, MemBuf, &Mod, &ErrMsg) != 0) {
    fprintf(stderr, "LLVMParseIRInContext failed: %s\n", ErrMsg ? ErrMsg : "unknown");
    LogMan::Msg::EFmt("LLVMParseIRInContext failed: {}", ErrMsg ? ErrMsg : "unknown");
    if (ErrMsg) LLVMDisposeMessage(ErrMsg);
    LLVMContextDispose(Ctx);
    return false;
  }

  LLVMTargetRef Target = nullptr;
  if (LLVMGetTargetFromTriple(CodegenTriple.c_str(), &Target, &ErrMsg) != 0) {
    LogMan::Msg::EFmt("LLVMGetTargetFromTriple failed: {}", ErrMsg ? ErrMsg : "unknown");
    if (ErrMsg) LLVMDisposeMessage(ErrMsg);
    LLVMDisposeModule(Mod);
    LLVMContextDispose(Ctx);
    return false;
  }

  LLVMTargetMachineRef TM = LLVMCreateTargetMachine(
    Target, CodegenTriple.c_str(), Opts.CpuArch.c_str(), "",
    LLVMCodeGenLevelAggressive, LLVMRelocPIC, LLVMCodeModelDefault);

  LLVMPassBuilderOptionsRef PBOpts = LLVMCreatePassBuilderOptions();
  LLVMErrorRef PassErr = LLVMRunPasses(Mod, Opts.OptPipeline.c_str(), TM, PBOpts);
  LLVMDisposePassBuilderOptions(PBOpts);
  if (PassErr) {
    char* Msg = LLVMGetErrorMessage(PassErr);
    LogMan::Msg::EFmt("LLVMRunPasses({}) failed: {}", Opts.OptPipeline, Msg ? Msg : "unknown");
    if (Msg) LLVMDisposeErrorMessage(Msg);
    LLVMDisposeTargetMachine(TM);
    LLVMDisposeModule(Mod);
    LLVMContextDispose(Ctx);
    return false;
  }

  LLVMMemoryBufferRef ObjBuf = nullptr;
  if (LLVMTargetMachineEmitToMemoryBuffer(TM, Mod, LLVMObjectFile, &ErrMsg, &ObjBuf) != 0) {
    LogMan::Msg::EFmt("LLVMTargetMachineEmitToMemoryBuffer failed: {}", ErrMsg ? ErrMsg : "unknown");
    if (ErrMsg) LLVMDisposeMessage(ErrMsg);
    LLVMDisposeTargetMachine(TM);
    LLVMDisposeModule(Mod);
    LLVMContextDispose(Ctx);
    return false;
  }

  auto TEnd = std::chrono::steady_clock::now();
  OutBatchCompileMs = std::chrono::duration<double, std::milli>(TEnd - TStart).count();

  // Extract compiled per-function sections (.text_ec$*, .text_fex$*) and .wowthk$aa thunks from the emitted COFF object
  const uint8_t* ObjData = reinterpret_cast<const uint8_t*>(LLVMGetBufferStart(ObjBuf));
  const size_t ObjSize = LLVMGetBufferSize(ObjBuf);

  #pragma pack(push, 1)
  struct RawCOFFFileHeader {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
  };
  struct RawCOFFSectionHeader {
    char Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
  };
  struct RawCOFFSymbol {
    union {
      char ShortName[8];
      struct {
        uint32_t Zeroes;
        uint32_t Offset;
      } LongName;
    } Name;
    uint32_t Value;
    int16_t SectionNumber;
    uint16_t Type;
    uint8_t StorageClass;
    uint8_t NumberOfAuxSymbols;
  };
  #pragma pack(pop)

  if (ObjSize < sizeof(RawCOFFFileHeader)) {
    LLVMDisposeMemoryBuffer(ObjBuf);
    LLVMDisposeTargetMachine(TM);
    LLVMDisposeModule(Mod);
    LLVMContextDispose(Ctx);
    return false;
  }

  const auto* FileHdr = reinterpret_cast<const RawCOFFFileHeader*>(ObjData);
  const size_t SecTableOff = sizeof(RawCOFFFileHeader) + FileHdr->SizeOfOptionalHeader;
  if (SecTableOff + size_t(FileHdr->NumberOfSections) * sizeof(RawCOFFSectionHeader) > ObjSize) {
    LLVMDisposeMemoryBuffer(ObjBuf);
    LLVMDisposeTargetMachine(TM);
    LLVMDisposeModule(Mod);
    LLVMContextDispose(Ctx);
    return false;
  }

  const auto* SecHdrs = reinterpret_cast<const RawCOFFSectionHeader*>(ObjData + SecTableOff);
  const size_t SymTableOff = FileHdr->PointerToSymbolTable;
  const size_t StrTableOff = SymTableOff + size_t(FileHdr->NumberOfSymbols) * sizeof(RawCOFFSymbol);
  const char* StrTable = (StrTableOff + 4 <= ObjSize)
                           ? reinterpret_cast<const char*>(ObjData + StrTableOff)
                           : nullptr;
  const size_t StrTableMax = (StrTableOff <= ObjSize) ? (ObjSize - StrTableOff) : 0;

  auto GetCOFFSymName = [&](const RawCOFFSymbol& Sym) -> std::string {
    if (Sym.Name.LongName.Zeroes == 0) {
      uint32_t Off = Sym.Name.LongName.Offset;
      if (StrTable && Off < StrTableMax) {
        return std::string(StrTable + Off);
      }
      return {};
    }
    return std::string(Sym.Name.ShortName, strnlen(Sym.Name.ShortName, 8));
  };

  struct SymEntry {
    std::string Name;
    int16_t SecNum;
    uint32_t Value;
    uint8_t StorageClass;
    uint16_t Type;
  };
  std::vector<SymEntry> ParsedSyms;
  std::map<int16_t, std::vector<uint32_t>> SecSymbolOffsets;

  if (SymTableOff + size_t(FileHdr->NumberOfSymbols) * sizeof(RawCOFFSymbol) <= ObjSize) {
    const auto* Syms = reinterpret_cast<const RawCOFFSymbol*>(ObjData + SymTableOff);
    for (uint32_t i = 0; i < FileHdr->NumberOfSymbols; ++i) {
      const RawCOFFSymbol& S = Syms[i];
      std::string SName = GetCOFFSymName(S);
      if (S.SectionNumber > 0 && S.SectionNumber <= int16_t(FileHdr->NumberOfSections)) {
        if (!SName.empty() && !(S.StorageClass == 3 && S.Value == 0 && S.Type == 0)) {
          ParsedSyms.push_back({SName, S.SectionNumber, S.Value, S.StorageClass, S.Type});
          SecSymbolOffsets[S.SectionNumber].push_back(S.Value);
        }
      }
      i += S.NumberOfAuxSymbols;
    }
  }

  for (auto& [SecIdx, Offs] : SecSymbolOffsets) {
    std::sort(Offs.begin(), Offs.end());
    Offs.erase(std::unique(Offs.begin(), Offs.end()), Offs.end());
  }

  std::unordered_map<std::string, std::vector<uint8_t>> ExtractedFuncBytes;
  for (const auto& Sym : ParsedSyms) {
    const RawCOFFSectionHeader& Sec = SecHdrs[Sym.SecNum - 1];
    if (Sec.PointerToRawData + Sec.SizeOfRawData > ObjSize) continue;
    if (Sym.Value >= Sec.SizeOfRawData) continue;

    uint32_t EndOffset = Sec.SizeOfRawData;
    const auto& Offs = SecSymbolOffsets[Sym.SecNum];
    auto UpperIt = std::upper_bound(Offs.begin(), Offs.end(), Sym.Value);
    if (UpperIt != Offs.end() && *UpperIt <= Sec.SizeOfRawData) {
      EndOffset = *UpperIt;
    }

    const uint8_t* Ptr = ObjData + Sec.PointerToRawData + Sym.Value;
    const size_t Len = EndOffset - Sym.Value;

    if (Sym.Name.starts_with("#fex_fn_")) {
      std::string BaseFn = Sym.Name.substr(1); // strip leading '#'
      ExtractedFuncBytes[BaseFn] = std::vector<uint8_t>(Ptr, Ptr + Len);
    } else if (Sym.Name.starts_with("fex_fn_") && !ExtractedFuncBytes.contains(Sym.Name)) {
      ExtractedFuncBytes[Sym.Name] = std::vector<uint8_t>(Ptr, Ptr + Len);
    } else if (Sym.Name.starts_with("$ientry_thunk$") || Sym.Name.starts_with("$iexit_thunk$")) {
      Arm64ECThunkRecord Thk {};
      Thk.Name = Sym.Name;
      Thk.Bytes.assign(Ptr, Ptr + Len);
      Thk.IsEntryThunk = Sym.Name.starts_with("$ientry_thunk$");
      OutThunks.push_back(std::move(Thk));
    }
  }

  // Add our hybrid FEX<->Arm64EC dispatch & SEH helper thunks to OutThunks (.wowthk section):
  // 1. __fex_ec_to_sra_adapter: Synchronizes Arm64EC stack/registers and dispatches to FEX DispatcherLoopTop (0xB60)
  // 2. __fex_sra_to_ec_adapter: Synchronizes FEX SRA x23 -> sp and invokes target Arm64EC function in x11
  // 3. __os_arm64x_check_icall_cfg: Indirect call target validator for hybrid .text_ec / .text_fex targets
  if (Opts.EmitArm64ECThunks) {
    Arm64ECThunkRecord IEntry {};
    IEntry.Name = "$ientry_thunk$cdecl$i8$i8i8";
    IEntry.IsEntryThunk = true;
    uint32_t EntryWords[4] = {
      0xAA0803E0u, // mov x0, x8
      0xAA1703FFu, // mov sp, x23
      0xD63F0120u, // blr x9
      0xD65F03C0u  // ret
    };
    IEntry.Bytes.resize(sizeof(EntryWords));
    memcpy(IEntry.Bytes.data(), EntryWords, sizeof(EntryWords));
    OutThunks.push_back(std::move(IEntry));

    Arm64ECThunkRecord IExit {};
    IExit.Name = "$iexit_thunk$cdecl$i8$i8i8";
    IExit.IsEntryThunk = false;
    uint32_t ExitWords[4] = {
      0x910003F7u, // mov x23, sp
      0xD63F0120u, // blr x9
      0xAA0003E8u, // mov x8, x0
      0xD65F03C0u  // ret
    };
    IExit.Bytes.resize(sizeof(ExitWords));
    memcpy(IExit.Bytes.data(), ExitWords, sizeof(ExitWords));
    OutThunks.push_back(std::move(IExit));
  }
  {
    Arm64ECThunkRecord EcToSra {};
    EcToSra.Name = "__fex_ec_to_sra_adapter";
    EcToSra.IsEntryThunk = false;
    const uint32_t RipOff = (static_cast<uint32_t>(offsetof(FEXCore::Core::CpuStateFrame, State.rip)) / 8) & 0xFFFu;
    const bool IsGVisorEnv = Opts.UseGVisorOffset || (getenv("FEX_AOT_GVISOR_OFFSET") != nullptr);
    const uint32_t LoopOffsetBytes = IsGVisorEnv ? 0xB60u : static_cast<uint32_t>(offsetof(FEXCore::Core::CpuStateFrame, Pointers.DispatcherLoopTop));
    const uint32_t LoopOff = (LoopOffsetBytes / 8) & 0xFFFu;
    uint32_t Words1[4] = {
      0xA9BF7E3Fu, // stp xzr, xzr, [x17, #-16]!
      0xF9000000u | (RipOff << 10) | (28u << 5) | 16u, // str x16, [x28, #State.rip]
      0xF9400000u | (LoopOff << 10) | (28u << 5) | 11u, // ldr x11, [x28, #Pointers.DispatcherLoopTop]
      0xD61F0160u  // br x11
    };
    EcToSra.Bytes.resize(sizeof(Words1));
    memcpy(EcToSra.Bytes.data(), Words1, sizeof(Words1));
    OutThunks.push_back(std::move(EcToSra));

    Arm64ECThunkRecord SraToEc {};
    SraToEc.Name = "__fex_sra_to_ec_adapter";
    SraToEc.IsEntryThunk = true;
    const uint32_t EnterEcOff = (0xB70u / 8u) & 0xFFFu;
    uint32_t Words2[3] = {
      0x910002E9u, // mov x9, x23 (preserve guest RSP)
      0xF9400000u | (EnterEcOff << 10) | (28u << 5) | 11u, // ldr x11, [x28, #Pointers.DispatcherLoopTopEnterEC]
      0xD61F0160u  // br x11
    };
    SraToEc.Bytes.resize(sizeof(Words2));
    memcpy(SraToEc.Bytes.data(), Words2, sizeof(Words2));
    OutThunks.push_back(std::move(SraToEc));

    Arm64ECThunkRecord IcallCfg {};
    IcallCfg.Name = "__os_arm64x_check_icall_cfg";
    IcallCfg.IsEntryThunk = false;
    uint32_t Words3[2] = {
      0xAA0B03F0u, // mov x16, x11
      0xD65F03C0u  // ret
    };
    IcallCfg.Bytes.resize(sizeof(Words3));
    memcpy(IcallCfg.Bytes.data(), Words3, sizeof(Words3));
    OutThunks.push_back(std::move(IcallCfg));
  }

  OutBlocks.reserve(LiftedFunctions.size());
  if (OutPerFnCompileUs) {
    OutPerFnCompileUs->assign(LiftedFunctions.size(), (OutBatchCompileMs * 1000.0) / double(LiftedFunctions.size()));
  }

  for (size_t i = 0; i < LiftedFunctions.size(); ++i) {
    const auto& Lifted = LiftedFunctions[i];
    auto It = ExtractedFuncBytes.find(Lifted.FunctionName);
    std::span<const uint8_t> RawSpan;
    if (It != ExtractedFuncBytes.end()) {
      RawSpan = It->second;
    }
    OutBlocks.push_back(WrapLLVMCodeInFEXBlock(Lifted, RawSpan, SerializedBaseAddress));
  }

  LLVMDisposeMemoryBuffer(ObjBuf);
  LLVMDisposeTargetMachine(TM);
  LLVMDisposeModule(Mod);
  LLVMContextDispose(Ctx);
  return true;
#endif
}

} // namespace FEXCore::AOT

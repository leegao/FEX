// SPDX-License-Identifier: MIT
#pragma once

#include <FEXCore/Core/LLVMArm64ECAOT.h>
#include <FEXCore/Core/CoreState.h>
#include <FEXCore/Core/X86Enums.h>
#include <FEXCore/IR/IR.h>
#include <FEXCore/Utils/CompilerDefs.h>
#include <FEXCore/Utils/LogManager.h>
#include <FEXCore/Utils/MathUtils.h>

#include "Interface/Context/Context.h"
#include "Interface/Core/ArchHelpers/Arm64Emitter.h"
#include "Interface/Core/CPUBackend.h"
#include "Interface/Core/JIT/Relocations.h"
#include "Interface/IR/IR.h"
#include "Interface/IR/IntrusiveIRList.h"
#include "Interface/IR/RegisterAllocationData.h"
#include "Utils/variable_length_integer.h"

#include <xxhash.h>

#include <algorithm>
#include <chrono>
#include <cinttypes>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <mutex>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

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

namespace FEXCore::AOT {

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

inline void EnsureLLVMInitialized() {
  static LLVMRuntimeInit Init;
  (void)Init;
}

inline unsigned OpSizeToBits(FEXCore::IR::OpSize Size) {
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

inline uint32_t EncodeAArch64B(int32_t WordOffset) {
  return 0x14000000u | (static_cast<uint32_t>(WordOffset) & 0x03FFFFFFu);
}

inline bool DestinationIsGuestRSP(FEXCore::IR::Ref Node) {
  if (!Node) return false;
  FEXCore::IR::PhysicalRegister PR(Node);
  if (PR.IsInvalid()) return false;
  // In FEX's x64 SRA mapping, index 4 is RSP (mapped to x23).
  return PR.AsRegClass() == FEXCore::IR::RegClass::GPRFixed && PR.Reg == 4;
}

} // namespace FEXCore::AOT

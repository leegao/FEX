// SPDX-License-Identifier: MIT
#include "Interface/Core/AOT/LLVM/CompilationEngine.h"
#include "Interface/Core/AOT/LLVM/BlockWrapper.h"
#include "Interface/Core/AOT/LLVM/Internal.h"
#include "Interface/Core/AOT/RellumeLifter.h"

#include <FEXCore/Core/CoreState.h>
#include <FEXCore/Utils/LogManager.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <sstream>
#include <unordered_map>

namespace FEXCore::AOT {

CompilationEngine::CompilationEngine(const LLVMArm64ECAOTCompiler::Options& Opts_)
  : Opts(Opts_) {}

void CompilationEngine::GenerateArm64ECThunks(std::vector<Arm64ECThunkRecord>& OutThunks) const {
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
}

bool CompilationEngine::CompileBatch(const std::vector<LLVMArm64ECAOTCompiler::LiftedFunctionIR>& LiftedFunctions,
                                     uint64_t SerializedBaseAddress,
                                     std::vector<CompiledAOTBlock>& OutBlocks,
                                     std::vector<Arm64ECThunkRecord>& OutThunks,
                                     double& OutBatchCompileMs,
                                     std::vector<double>* OutPerFnCompileUs) const {
  constexpr size_t kMaxChunkSize = 250;
  if (LiftedFunctions.size() > kMaxChunkSize) {
    OutBlocks.clear();
    OutThunks.clear();
    OutBatchCompileMs = 0.0;
    if (OutPerFnCompileUs) OutPerFnCompileUs->clear();

    for (size_t start = 0; start < LiftedFunctions.size(); start += kMaxChunkSize) {
      size_t count = std::min(kMaxChunkSize, LiftedFunctions.size() - start);
      std::vector<LLVMArm64ECAOTCompiler::LiftedFunctionIR> Chunk(LiftedFunctions.begin() + start, LiftedFunctions.begin() + start + count);
      std::vector<CompiledAOTBlock> ChunkBlocks;
      std::vector<Arm64ECThunkRecord> ChunkThunks;
      double ChunkMs = 0.0;
      std::vector<double> ChunkPerFnUs;
      if (!CompileSingleModuleChunk(Chunk, SerializedBaseAddress, ChunkBlocks, ChunkThunks, ChunkMs, &ChunkPerFnUs)) {
        return false;
      }
      OutBlocks.insert(OutBlocks.end(), std::make_move_iterator(ChunkBlocks.begin()), std::make_move_iterator(ChunkBlocks.end()));
      if (start == 0) {
        OutThunks = std::move(ChunkThunks);
      }
      OutBatchCompileMs += ChunkMs;
      if (OutPerFnCompileUs) {
        OutPerFnCompileUs->insert(OutPerFnCompileUs->end(), ChunkPerFnUs.begin(), ChunkPerFnUs.end());
      }
    }
    return true;
  }
  return CompileSingleModuleChunk(LiftedFunctions, SerializedBaseAddress, OutBlocks, OutThunks, OutBatchCompileMs, OutPerFnCompileUs);
}

bool CompilationEngine::CompileSingleModuleChunk(const std::vector<LLVMArm64ECAOTCompiler::LiftedFunctionIR>& LiftedFunctions,
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
  struct RawCOFFRelocation {
    uint32_t VirtualAddress;
    uint32_t SymbolTableIndex;
    uint16_t Type;
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
  std::unordered_map<std::string, std::vector<COFFConstPoolReloc>> ExtractedFuncRelocs;
  const auto* RawSyms = (SymTableOff + size_t(FileHdr->NumberOfSymbols) * sizeof(RawCOFFSymbol) <= ObjSize)
                          ? reinterpret_cast<const RawCOFFSymbol*>(ObjData + SymTableOff)
                          : nullptr;
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

    auto ExtractSecRelocs = [&]() -> std::vector<COFFConstPoolReloc> {
      std::vector<COFFConstPoolReloc> RelList;
      if (!RawSyms || Sec.NumberOfRelocations == 0) return RelList;
      if (Sec.PointerToRelocations + size_t(Sec.NumberOfRelocations) * sizeof(RawCOFFRelocation) > ObjSize) {
        return RelList;
      }
      const auto* Relocs = reinterpret_cast<const RawCOFFRelocation*>(ObjData + Sec.PointerToRelocations);
      for (uint16_t r = 0; r < Sec.NumberOfRelocations; ++r) {
        const RawCOFFRelocation& Rel = Relocs[r];
        if (Rel.VirtualAddress < Sym.Value || Rel.VirtualAddress + 4 > EndOffset) continue;
        if (Rel.SymbolTableIndex >= FileHdr->NumberOfSymbols) continue;
        const RawCOFFSymbol& TSym = RawSyms[Rel.SymbolTableIndex];
        if (TSym.SectionNumber <= 0 || TSym.SectionNumber > int16_t(FileHdr->NumberOfSections)) continue;
        if (TSym.SectionNumber == Sym.SecNum) continue;
        const RawCOFFSectionHeader& TSec = SecHdrs[TSym.SectionNumber - 1];
        if (TSec.SizeOfRawData == 0 || TSec.PointerToRawData + TSec.SizeOfRawData > ObjSize) continue;
        COFFConstPoolReloc CPR {};
        CPR.OldWordIdx = (Rel.VirtualAddress - Sym.Value) / 4;
        CPR.Type = Rel.Type;
        CPR.TargetSecNum = static_cast<uint16_t>(TSym.SectionNumber);
        CPR.TargetSymOffset = TSym.Value;
        CPR.SecBytes.assign(ObjData + TSec.PointerToRawData,
                            ObjData + TSec.PointerToRawData + TSec.SizeOfRawData);
        RelList.push_back(std::move(CPR));
      }
      return RelList;
    };

    if (Sym.Name.starts_with("#fex_fn_")) {
      std::string BaseFn = Sym.Name.substr(1); // strip leading '#'
      ExtractedFuncBytes[BaseFn] = std::vector<uint8_t>(Ptr, Ptr + Len);
      ExtractedFuncRelocs[BaseFn] = ExtractSecRelocs();
    } else if (Sym.Name.starts_with("fex_fn_") && !ExtractedFuncBytes.contains(Sym.Name)) {
      ExtractedFuncBytes[Sym.Name] = std::vector<uint8_t>(Ptr, Ptr + Len);
      ExtractedFuncRelocs[Sym.Name] = ExtractSecRelocs();
    } else if (Sym.Name.starts_with("$ientry_thunk$") || Sym.Name.starts_with("$iexit_thunk$")) {
      Arm64ECThunkRecord Thk {};
      Thk.Name = Sym.Name;
      Thk.Bytes.assign(Ptr, Ptr + Len);
      Thk.IsEntryThunk = Sym.Name.starts_with("$ientry_thunk$");
      OutThunks.push_back(std::move(Thk));
    }
  }

  // Add our hybrid FEX<->Arm64EC dispatch & SEH helper thunks to OutThunks (.wowthk section)
  GenerateArm64ECThunks(OutThunks);

  OutBlocks.reserve(LiftedFunctions.size());
  if (OutPerFnCompileUs) {
    OutPerFnCompileUs->assign(LiftedFunctions.size(), (OutBatchCompileMs * 1000.0) / double(LiftedFunctions.size()));
  }

  BlockWrapper Wrapper(Opts);
  for (size_t i = 0; i < LiftedFunctions.size(); ++i) {
    const auto& Lifted = LiftedFunctions[i];
    auto It = ExtractedFuncBytes.find(Lifted.FunctionName);
    std::span<const uint8_t> RawSpan;
    if (It != ExtractedFuncBytes.end()) {
      RawSpan = It->second;
    }
    std::span<const COFFConstPoolReloc> RelSpan;
    auto RelIt = ExtractedFuncRelocs.find(Lifted.FunctionName);
    if (RelIt != ExtractedFuncRelocs.end()) {
      RelSpan = RelIt->second;
    }
    OutBlocks.push_back(Wrapper.Wrap(Lifted, RawSpan, SerializedBaseAddress, RelSpan));
  }

  LLVMDisposeMemoryBuffer(ObjBuf);
  LLVMDisposeTargetMachine(TM);
  LLVMDisposeModule(Mod);
  LLVMContextDispose(Ctx);
  return true;
#endif
}

} // namespace FEXCore::AOT

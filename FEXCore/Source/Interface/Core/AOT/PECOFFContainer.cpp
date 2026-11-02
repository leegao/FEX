// SPDX-License-Identifier: MIT
#include <FEXCore/Core/LLVMArm64ECAOT.h>

#include "Interface/Core/CPUBackend.h"
#include "Interface/Core/JIT/Relocations.h"
#include <FEXCore/Utils/MathUtils.h>
#include <git_version.h>

#if !defined(_WIN32)
#define FEX_HAS_LLVM_AOT 1
#if __has_include("llvm-c/Disassembler.h")
#include "llvm-c/Disassembler.h"
#include "llvm-c/Target.h"
#else
#include <cstddef>
#include <cstdint>
extern "C" {
typedef void* LLVMDisasmContextRef;
typedef int (*LLVMOpInfoCallback)(void*, uint64_t, uint64_t, uint64_t, uint64_t, int, void*);
typedef const char* (*LLVMSymbolLookupCallback)(void*, uint64_t, uint64_t*, uint64_t, const char**);
void LLVMInitializeAArch64TargetInfo(void);
void LLVMInitializeAArch64TargetMC(void);
void LLVMInitializeAArch64Disassembler(void);
LLVMDisasmContextRef LLVMCreateDisasm(const char* TripleName, void* DisInfo, int TagType,
                                      LLVMOpInfoCallback GetOpInfo, LLVMSymbolLookupCallback SymbolLookUp);
size_t LLVMDisasmInstruction(LLVMDisasmContextRef DC, uint8_t* Bytes, uint64_t BytesSize,
                             uint64_t PC, char* OutString, size_t OutStringSize);
void LLVMDisasmDispose(LLVMDisasmContextRef DC);
}
#endif
#endif

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <map>
#include <sstream>

namespace FEXCore::AOT {

namespace {

constexpr uint32_t PE_PAGE_SIZE = 0x1000;
constexpr uint16_t IMAGE_FILE_MACHINE_ARM64EC_VAL = 0xA641;

struct __attribute__((packed)) RawCodeCacheHeader {
  std::array<char, 4> Magic = {'F', 'X', 'C', 'C'};
  uint32_t FormatVersion = 2;
  uint8_t FEXVersion[20] = {};
  uint32_t NumBlocks = 0;
  uint32_t NumCodePages = 0;
  uint32_t CodeBufferSize = 0;
  uint32_t NumRelocations = 0;
  uint32_t Flags = 0;
  uint64_t SerializedBaseAddress = 0;
};
static_assert(sizeof(RawCodeCacheHeader) == 56, "RawCodeCacheHeader size mismatch");

struct __attribute__((packed)) PEDosHeader {
  uint16_t e_magic = 0x5A4D; // "MZ"
  uint16_t e_cblp = 0x0090;
  uint16_t e_cp = 0x0003;
  uint16_t e_crlc = 0;
  uint16_t e_cparhdr = 0x0004;
  uint16_t e_minalloc = 0;
  uint16_t e_maxalloc = 0xFFFF;
  uint16_t e_ss = 0;
  uint16_t e_sp = 0x00B8;
  uint16_t e_csum = 0;
  uint16_t e_ip = 0;
  uint16_t e_cs = 0;
  uint16_t e_lfarlc = 0x0040;
  uint16_t e_ovno = 0;
  uint16_t e_res[4] = {};
  uint16_t e_oemid = 0;
  uint16_t e_oeminfo = 0;
  uint16_t e_res2[10] = {};
  uint32_t e_lfanew = 0x0100;
};
static_assert(sizeof(PEDosHeader) == 64);

struct __attribute__((packed)) PEFileHeader {
  uint16_t Machine = 0x8664; // IMAGE_FILE_MACHINE_AMD64 (with CHPEMetadata -> ARM64EC 0xA641)
  uint16_t NumberOfSections = 0;
  uint32_t TimeDateStamp = 0;
  uint32_t PointerToSymbolTable = 0;
  uint32_t NumberOfSymbols = 0;
  uint16_t SizeOfOptionalHeader = 240;
  uint16_t Characteristics = 0x2022; // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE | DLL
};

struct __attribute__((packed)) PEDataDirectory {
  uint32_t VirtualAddress = 0;
  uint32_t Size = 0;
};

struct __attribute__((packed)) PEOptionalHeader64 {
  uint16_t Magic = 0x020B; // PE32+
  uint8_t MajorLinkerVersion = 14;
  uint8_t MinorLinkerVersion = 40;
  uint32_t SizeOfCode = 0;
  uint32_t SizeOfInitializedData = 0;
  uint32_t SizeOfUninitializedData = 0;
  uint32_t AddressOfEntryPoint = 0;
  uint32_t BaseOfCode = 0;
  uint64_t ImageBase = 0x180000000ULL;
  uint32_t SectionAlignment = PE_PAGE_SIZE;
  uint32_t FileAlignment = PE_PAGE_SIZE;
  uint16_t MajorOperatingSystemVersion = 10;
  uint16_t MinorOperatingSystemVersion = 0;
  uint16_t MajorImageVersion = 1;
  uint16_t MinorImageVersion = 0;
  uint16_t MajorSubsystemVersion = 10;
  uint16_t MinorSubsystemVersion = 0;
  uint32_t Win32VersionValue = 0;
  uint32_t SizeOfImage = 0;
  uint32_t SizeOfHeaders = PE_PAGE_SIZE;
  uint32_t CheckSum = 0;
  uint16_t Subsystem = 3; // IMAGE_SUBSYSTEM_WINDOWS_CUI
  uint16_t DllCharacteristics = 0x8160; // HIGH_ENTROPY_VA | DYNAMIC_BASE | NX_COMPAT | TERMINAL_SERVICE_AWARE
  uint64_t SizeOfStackReserve = 0x100000;
  uint64_t SizeOfStackCommit = 0x1000;
  uint64_t SizeOfHeapReserve = 0x100000;
  uint64_t SizeOfHeapCommit = 0x1000;
  uint32_t LoaderFlags = 0;
  uint32_t NumberOfRvaAndSizes = 16;
  PEDataDirectory DataDirectories[16] = {};
};
static_assert(sizeof(PEOptionalHeader64) == 240);

struct __attribute__((packed)) PENtHeaders64 {
  uint32_t Signature = 0x00004550; // "PE\0\0"
  PEFileHeader FileHeader {};
  PEOptionalHeader64 OptionalHeader {};
};

struct __attribute__((packed)) PESectionHeader {
  char Name[8] = {};
  uint32_t VirtualSize = 0;
  uint32_t VirtualAddress = 0;
  uint32_t SizeOfRawData = 0;
  uint32_t PointerToRawData = 0;
  uint32_t PointerToRelocations = 0;
  uint32_t PointerToLinenumbers = 0;
  uint16_t NumberOfRelocations = 0;
  uint16_t NumberOfLinenumbers = 0;
  uint32_t Characteristics = 0;
};
static_assert(sizeof(PESectionHeader) == 40);

struct __attribute__((packed)) PEExportDirectory {
  uint32_t Characteristics = 0;
  uint32_t TimeDateStamp = 0;
  uint16_t MajorVersion = 1;
  uint16_t MinorVersion = 0;
  uint32_t NameRVA = 0;
  uint32_t OrdinalBase = 1;
  uint32_t AddressTableEntries = 0;
  uint32_t NumberOfNamePointers = 0;
  uint32_t ExportAddressTableRVA = 0;
  uint32_t NamePointerRVA = 0;
  uint32_t OrdinalTableRVA = 0;
};
static_assert(sizeof(PEExportDirectory) == 40);

struct __attribute__((packed)) PERuntimeFunction {
  uint32_t BeginAddress = 0;
  uint32_t EndAddress = 0;
  uint32_t UnwindInfoAddress = 0;
};

struct __attribute__((packed)) COFFSymbol18 {
  union {
    char ShortName[8];
    struct {
      uint32_t Zeroes;
      uint32_t Offset;
    } LongName;
  } Name;
  uint32_t Value = 0;
  int16_t SectionNumber = 0;
  uint16_t Type = 0;
  uint8_t StorageClass = 0;
  uint8_t NumberOfAuxSymbols = 0;
};
static_assert(sizeof(COFFSymbol18) == 18);

// Standard PE Load Configuration 64 + Arm64EC CHPEv2 structures
struct __attribute__((packed)) PELoadConfiguration64 {
  uint32_t Size = 0;
  uint32_t TimeDateStamp = 0;
  uint16_t MajorVersion = 0;
  uint16_t MinorVersion = 0;
  uint32_t GlobalFlagsClear = 0;
  uint32_t GlobalFlagsSet = 0;
  uint32_t CriticalSectionDefaultTimeout = 0;
  uint64_t DeCommitFreeBlockThreshold = 0;
  uint64_t DeCommitTotalFreeThreshold = 0;
  uint64_t LockPrefixTable = 0;
  uint64_t MaximumAllocationSize = 0;
  uint64_t VirtualMemoryThreshold = 0;
  uint64_t ProcessAffinityMask = 0;
  uint32_t ProcessHeapFlags = 0;
  uint16_t CSDVersion = 0;
  uint16_t DependentLoadFlags = 0;
  uint64_t EditList = 0;
  uint64_t SecurityCookie = 0;
  uint64_t SEHandlerTable = 0;
  uint64_t SEHandlerCount = 0;
  uint64_t GuardCFCheckFunctionPointer = 0;
  uint64_t GuardCFDispatchFunctionPointer = 0;
  uint64_t GuardCFFunctionTable = 0;
  uint64_t GuardCFFunctionCount = 0;
  uint32_t GuardFlags = 0;
  uint16_t CodeIntegrityFlags = 0;
  uint16_t CodeIntegrityCatalog = 0;
  uint32_t CodeIntegrityCatalogOffset = 0;
  uint32_t CodeIntegrityReserved = 0;
  uint64_t GuardAddressTakenIatEntryTable = 0;
  uint64_t GuardAddressTakenIatEntryCount = 0;
  uint64_t GuardLongJumpTargetTable = 0;
  uint64_t GuardLongJumpTargetCount = 0;
  uint64_t DynamicValueRelocTable = 0;
  uint64_t CHPEMetadataPointer = 0;
  uint64_t GuardRFFailureRoutine = 0;
  uint64_t GuardRFFailureRoutineFunctionPointer = 0;
  uint32_t DynamicValueRelocTableOffset = 0;
  uint16_t DynamicValueRelocTableSection = 0;
  uint16_t Reserved2 = 0;
  uint64_t GuardRFVerifyStackPointerFunctionPointer = 0;
  uint32_t HotPatchTableOffset = 0;
  uint32_t Reserved3 = 0;
  uint64_t EnclaveConfigurationPointer = 0;
  uint64_t VolatileMetadataPointer = 0;
  uint64_t GuardEHContinuationTable = 0;
  uint64_t GuardEHContinuationCount = 0;
  uint64_t GuardXFGCheckFunctionPointer = 0;
  uint64_t GuardXFGDispatchFunctionPointer = 0;
  uint64_t GuardXFGTableDispatchFunctionPointer = 0;
  uint64_t CastGuardOsDeterminedFailureMode = 0;
};
static_assert(sizeof(PELoadConfiguration64) == 312);

struct __attribute__((packed)) PEChpeMetadata {
  uint32_t Version = 2;
  uint32_t CodeMap = 0;
  uint32_t CodeMapCount = 0;
  uint32_t CodeRangesToEntryPoints = 0;
  uint32_t RedirectionMetadata = 0;
  uint32_t __os_arm64x_dispatch_call_no_redirect = 0;
  uint32_t __os_arm64x_dispatch_ret = 0;
  uint32_t __os_arm64x_dispatch_call = 0;
  uint32_t __os_arm64x_dispatch_icall = 0;
  uint32_t __os_arm64x_dispatch_icall_cfg = 0;
  uint32_t AlternateEntryPoint = 0;
  uint32_t AuxiliaryIAT = 0;
  uint32_t CodeRangesToEntryPointsCount = 0;
  uint32_t RedirectionMetadataCount = 0;
  uint32_t GetX64InformationFunctionPointer = 0;
  uint32_t SetX64InformationFunctionPointer = 0;
  uint32_t ExtraRFETable = 0;
  uint32_t ExtraRFETableSize = 0;
  uint32_t __os_arm64x_dispatch_fptr = 0;
  uint32_t AuxiliaryIATCopy = 0;
  uint32_t AuxiliaryDelayloadIAT = 0;
  uint32_t AuxiliaryDelayloadIATCopy = 0;
  uint32_t HybridImageInfoBitfield = 0;
};
static_assert(sizeof(PEChpeMetadata) == 92);

struct __attribute__((packed)) PEChpeRangeEntry {
  uint32_t StartOffset = 0;
  uint32_t Length = 0;
};
static constexpr uint32_t CHPE_RANGE_TYPE_ARM64EC = 1u;

struct __attribute__((packed)) PEChpeRedirectionEntry {
  uint32_t Source = 0;
  uint32_t Destination = 0;
};

static uint32_t AlignUpU32(uint32_t Val, uint32_t Align) {
  return (Val + Align - 1u) & ~(Align - 1u);
}

// Applies ForStorage relocations on a copy of CodeBuffer (matching CodeCache.cpp::SaveData)
// so that NamedSymbolLiterals are zeroed and GuestRIPLiterals contain SerializedBaseAddress + Offset.
static void PrepareCodeBufferForStorage(uint64_t SerializedBaseAddress,
                                        std::vector<uint8_t>& CodeBuffer,
                                        const std::vector<FEXCore::CPU::Relocation>& Relocations) {
  for (const auto& Reloc : Relocations) {
    if (Reloc.Header.Offset + 8 > CodeBuffer.size()) continue;
    switch (Reloc.Header.Type) {
    case FEXCore::CPU::RelocationTypes::RELOC_NAMED_SYMBOL_LITERAL: {
      uint64_t Zero = 0;
      memcpy(CodeBuffer.data() + Reloc.Header.Offset, &Zero, 8);
      break;
    }
    case FEXCore::CPU::RelocationTypes::RELOC_GUEST_RIP_LITERAL: {
      uint64_t Val = SerializedBaseAddress + Reloc.GuestRIP.GuestRIP;
      memcpy(CodeBuffer.data() + Reloc.Header.Offset, &Val, 8);
      break;
    }
    default:
      break;
    }
  }
}

} // namespace

bool BuildDualPECOFFAndFXCCContainer(
    const FEXAOTPEManifest& BaseManifest,
    const std::vector<CompiledAOTBlock>& Blocks,
    const std::vector<Arm64ECThunkRecord>& Thunks,
    std::vector<uint8_t>& OutDualPECOFF,
    std::vector<uint8_t>& OutRawFXCC) {
  OutDualPECOFF.clear();
  OutRawFXCC.clear();
  if (Blocks.empty()) {
    return false;
  }

  // Sort blocks deterministically by GuestEntryRVA
  std::vector<const CompiledAOTBlock*> SortedBlocks;
  SortedBlocks.reserve(Blocks.size());
  for (const auto& B : Blocks) {
    SortedBlocks.push_back(&B);
  }
  std::sort(SortedBlocks.begin(), SortedBlocks.end(),
            [](const CompiledAOTBlock* A, const CompiledAOTBlock* B) { return A->GuestEntryVA < B->GuestEntryVA; });

  // Assemble the page-aligned CodeBuffer (.text section) and combined Relocations + CodePages map
  std::vector<uint8_t> CodeBuffer;
  std::vector<FEXCore::CPU::Relocation> AllRelocations;
  std::map<uint64_t, std::vector<uint64_t>> PageIndexToEntrypoints;

  struct BlockPlacement {
    const CompiledAOTBlock* Block;
    uint32_t BlockBeginOffset;
    uint32_t EntryPointOffset;
  };
  std::vector<BlockPlacement> Placements;
  Placements.reserve(SortedBlocks.size());

  for (const CompiledAOTBlock* B : SortedBlocks) {
    while (CodeBuffer.size() % 16 != 0) {
      CodeBuffer.push_back(0);
    }
    uint32_t BaseOff = static_cast<uint32_t>(CodeBuffer.size());
    uint32_t EntryOff = BaseOff + (B->EntryPoints.empty() ? 4u : B->EntryPoints[0].second);
    Placements.push_back({B, BaseOff, EntryOff});

    CodeBuffer.insert(CodeBuffer.end(), B->BlockBytes.begin(), B->BlockBytes.end());

    for (auto Reloc : B->Relocations) {
      Reloc.Header.Offset += BaseOff;
      AllRelocations.push_back(Reloc);
    }
    for (uint64_t PageVA : B->GuestCodePages) {
      uint64_t PageIdx = PageVA >> 12;
      PageIndexToEntrypoints[PageIdx].push_back(B->GuestEntryVA);
    }
  }

  // Sort relocations by Offset as required by CodeCache::LoadCache binary search (line 732)
  std::sort(AllRelocations.begin(), AllRelocations.end(),
            [](const FEXCore::CPU::Relocation& A, const FEXCore::CPU::Relocation& B) {
              return A.Header.Offset < B.Header.Offset;
            });

  // Pad CodeBuffer to 4KB page boundary
  uint32_t CodeBufferAlignedSize = AlignUpU32(static_cast<uint32_t>(CodeBuffer.size()), PE_PAGE_SIZE);
  CodeBuffer.resize(CodeBufferAlignedSize, 0);

  PrepareCodeBufferForStorage(BaseManifest.SourceImageBase, CodeBuffer, AllRelocations);

  // Build FXCC Header + BlockList + Relocations (.fxmeta section)
  RawCodeCacheHeader FxHdr {};
  std::copy(GIT_HASH.begin(), GIT_HASH.end(), FxHdr.FEXVersion);
  FxHdr.NumBlocks = static_cast<uint32_t>(Placements.size());
  FxHdr.NumCodePages = static_cast<uint32_t>(PageIndexToEntrypoints.size());
  FxHdr.CodeBufferSize = CodeBufferAlignedSize;
  FxHdr.NumRelocations = static_cast<uint32_t>(AllRelocations.size());
  FxHdr.Flags = BaseManifest.HeaderFlags;
  FxHdr.SerializedBaseAddress = BaseManifest.SourceImageBase;

  std::vector<uint8_t> FxMeta;
  auto AppendBytes = [](std::vector<uint8_t>& Vec, const void* Data, size_t Len) {
    const auto* Ptr = static_cast<const uint8_t*>(Data);
    Vec.insert(Vec.end(), Ptr, Ptr + Len);
  };

  AppendBytes(FxMeta, &FxHdr, sizeof(FxHdr));

  for (const auto& P : Placements) {
    uint64_t GuestRel = P.Block->GuestEntryVA - BaseManifest.SourceImageBase;
    uint64_t HostOff = P.EntryPointOffset;
    uint64_t NumPages = P.Block->GuestCodePages.size();
    AppendBytes(FxMeta, &GuestRel, sizeof(GuestRel));
    AppendBytes(FxMeta, &HostOff, sizeof(HostOff));
    AppendBytes(FxMeta, &NumPages, sizeof(NumPages));
    for (uint64_t PageVA : P.Block->GuestCodePages) {
      uint64_t PageRel = PageVA - BaseManifest.SourceImageBase;
      AppendBytes(FxMeta, &PageRel, sizeof(PageRel));
    }
  }

  if (!AllRelocations.empty()) {
    AppendBytes(FxMeta, AllRelocations.data(), AllRelocations.size() * sizeof(FEXCore::CPU::Relocation));
  }

  uint32_t FxMetaAlignedSize = AlignUpU32(static_cast<uint32_t>(FxMeta.size()), PE_PAGE_SIZE);
  FxMeta.resize(FxMetaAlignedSize, 0);

  // Build FXCC CodePages table (.fxpage section)
  std::vector<uint8_t> FxPages;
  for (const auto& [PageIdx, EntryVAs] : PageIndexToEntrypoints) {
    uint64_t PageRel = (PageIdx << 12) - BaseManifest.SourceImageBase;
    uint64_t NumEntries = EntryVAs.size();
    AppendBytes(FxPages, &PageRel, sizeof(PageRel));
    AppendBytes(FxPages, &NumEntries, sizeof(NumEntries));
    for (uint64_t EntryVA : EntryVAs) {
      uint64_t EntryRel = EntryVA - BaseManifest.SourceImageBase;
      AppendBytes(FxPages, &EntryRel, sizeof(EntryRel));
    }
  }
  uint32_t FxPagesUnalignedSize = static_cast<uint32_t>(FxPages.size());
  uint32_t FxPagesAlignedSize = AlignUpU32(std::max<uint32_t>(FxPagesUnalignedSize, 16u), PE_PAGE_SIZE);

  // 1. Construct OutRawFXCC (exact raw FXCC v2 stream: FxMeta + CodeBuffer + unpadded FxPages)
  OutRawFXCC.reserve(FxMeta.size() + CodeBuffer.size() + FxPagesUnalignedSize);
  OutRawFXCC.insert(OutRawFXCC.end(), FxMeta.begin(), FxMeta.end());
  OutRawFXCC.insert(OutRawFXCC.end(), CodeBuffer.begin(), CodeBuffer.end());
  OutRawFXCC.insert(OutRawFXCC.end(), FxPages.begin(), FxPages.end());

  // Pad FxPages to page boundary for PE section alignment
  FxPages.resize(FxPagesAlignedSize, 0);

  // 2. Build .wowthk section containing LLVM-generated Arm64EC entry/exit thunks
  std::vector<uint8_t> WowThk;
  struct ThunkPlacement {
    std::string Name;
    uint32_t OffsetInSection;
    uint32_t Size;
  };
  std::vector<ThunkPlacement> ThunkPlacements;
  for (const auto& T : Thunks) {
    while (WowThk.size() % 16 != 0) WowThk.push_back(0);
    uint32_t Off = static_cast<uint32_t>(WowThk.size());
    WowThk.insert(WowThk.end(), T.Bytes.begin(), T.Bytes.end());
    ThunkPlacements.push_back({T.Name, Off, static_cast<uint32_t>(T.Bytes.size())});
  }
  if (WowThk.empty()) {
    // Emit a default Arm64EC fast-return stub if no external thunks were passed
    uint32_t RetInsn = 0xD65F03C0u;
    AppendBytes(WowThk, &RetInsn, 4);
    ThunkPlacements.push_back({"$ientry_thunk$cdecl$v$v", 0, 4});
  }
  uint32_t WowThkRawSize = static_cast<uint32_t>(WowThk.size());
  uint32_t WowThkAlignedSize = AlignUpU32(WowThkRawSize, PE_PAGE_SIZE);
  WowThk.resize(WowThkAlignedSize, 0);

  // Compute section RVAs (identical to FileOffsets because SectionAlignment == FileAlignment == 0x1000!)
  const uint32_t SecFxMetaRVA  = PE_PAGE_SIZE; // 0x1000
  const uint32_t SecTextRVA    = SecFxMetaRVA + FxMetaAlignedSize;
  const uint32_t SecFxPageRVA  = SecTextRVA + CodeBufferAlignedSize;
  const uint32_t SecWowThkRVA  = SecFxPageRVA + FxPagesAlignedSize;

  // 3. Build .pdata section (PERuntimeFunction entries for every compiled function + unwind info)
  std::vector<uint8_t> PData;
  const uint32_t NumRuntimeFns = static_cast<uint32_t>(Placements.size() + ThunkPlacements.size());
  const uint32_t UnwindDataOffsetInPData = NumRuntimeFns * sizeof(PERuntimeFunction);
  for (const auto& P : Placements) {
    PERuntimeFunction RF {};
    RF.BeginAddress = SecTextRVA + P.EntryPointOffset;
    RF.EndAddress = SecTextRVA + P.BlockBeginOffset + P.Block->CodeOnlyBytes + 4;
    RF.UnwindInfoAddress = 0; // Patched once SecPDataRVA is known
    AppendBytes(PData, &RF, sizeof(RF));
  }
  for (const auto& TP : ThunkPlacements) {
    PERuntimeFunction RF {};
    RF.BeginAddress = SecWowThkRVA + TP.OffsetInSection;
    RF.EndAddress = SecWowThkRVA + TP.OffsetInSection + TP.Size;
    RF.UnwindInfoAddress = 0;
    AppendBytes(PData, &RF, sizeof(RF));
  }
  // Minimal 8-byte unwind info record at UnwindDataOffsetInPData
  uint8_t UnwindRecord[8] = {0x01, 0x00, 0x00, 0x00, 0xE4, 0x00, 0x00, 0x00};
  AppendBytes(PData, UnwindRecord, sizeof(UnwindRecord));
  uint32_t PDataRawSize = static_cast<uint32_t>(PData.size());
  uint32_t PDataAlignedSize = AlignUpU32(PDataRawSize, PE_PAGE_SIZE);
  PData.resize(PDataAlignedSize, 0);

  const uint32_t SecPDataRVA = SecWowThkRVA + WowThkAlignedSize;
  // Patch UnwindInfoAddress RVA in PData
  for (uint32_t i = 0; i < NumRuntimeFns; ++i) {
    auto* RF = reinterpret_cast<PERuntimeFunction*>(PData.data() + i * sizeof(PERuntimeFunction));
    RF->UnwindInfoAddress = SecPDataRVA + UnwindDataOffsetInPData;
  }

  // 4. Build .rdata section containing:
  //    - PELoadConfiguration64 (at offset 0 of .rdata)
  //    - PEChpeMetadata (Arm64EC CHPEv2 metadata)
  //    - PEChpeRangeEntry array (marking .text and .wowthk as CHPE_RANGE_TYPE_ARM64EC)
  //    - PEChpeRedirectionEntry array (mapping GuestEntryRVA -> Arm64EC RVA in .text)
  //    - FEXAOTPEManifest
  //    - PE Export Directory (.edata) exporting all compiled functions and Arm64EC thunks
  const uint32_t SecRDataRVA = SecPDataRVA + PDataAlignedSize;
  std::vector<uint8_t> RData;

  PELoadConfiguration64 LoadCfg {};
  memset(&LoadCfg, 0, sizeof(LoadCfg));
  LoadCfg.Size = sizeof(LoadCfg);

  PEChpeMetadata ChpeMeta {};
  memset(&ChpeMeta, 0, sizeof(ChpeMeta));
  ChpeMeta.Version = 2;
  ChpeMeta.ExtraRFETable = SecPDataRVA;
  ChpeMeta.ExtraRFETableSize = NumRuntimeFns * sizeof(PERuntimeFunction);

  const uint32_t LoadCfgOff = 0;
  RData.resize(sizeof(LoadCfg), 0);
  while (RData.size() % 16 != 0) RData.push_back(0);

  const uint32_t ChpeMetaOff = static_cast<uint32_t>(RData.size());
  LoadCfg.CHPEMetadataPointer = 0x180000000ULL + SecRDataRVA + ChpeMetaOff;
  RData.resize(ChpeMetaOff + sizeof(ChpeMeta), 0);

  // Emit chpe_range_entry table (2 entries: .text as Arm64EC, .wowthk as Arm64EC)
  const uint32_t ChpeCodeMapOff = static_cast<uint32_t>(RData.size());
  PEChpeRangeEntry RangeEntries[2] {};
  RangeEntries[0].StartOffset = SecTextRVA | CHPE_RANGE_TYPE_ARM64EC;
  RangeEntries[0].Length = CodeBufferAlignedSize;
  RangeEntries[1].StartOffset = SecWowThkRVA | CHPE_RANGE_TYPE_ARM64EC;
  RangeEntries[1].Length = WowThkAlignedSize;
  AppendBytes(RData, RangeEntries, sizeof(RangeEntries));

  // Emit chpe_redirection_entry table (mapping each guest RVA -> Arm64EC .text RVA)
  const uint32_t ChpeRedirOff = static_cast<uint32_t>(RData.size());
  for (const auto& P : Placements) {
    PEChpeRedirectionEntry Redir {};
    Redir.Source = P.Block->GuestEntryRVA;
    Redir.Destination = SecTextRVA + P.EntryPointOffset;
    AppendBytes(RData, &Redir, sizeof(Redir));
  }

  ChpeMeta.CodeMap = SecRDataRVA + ChpeCodeMapOff;
  ChpeMeta.CodeMapCount = 2;
  ChpeMeta.RedirectionMetadata = SecRDataRVA + ChpeRedirOff;
  ChpeMeta.RedirectionMetadataCount = static_cast<uint32_t>(Placements.size());

  memcpy(RData.data() + LoadCfgOff, &LoadCfg, sizeof(LoadCfg));
  memcpy(RData.data() + ChpeMetaOff, &ChpeMeta, sizeof(ChpeMeta));

  while (RData.size() % 16 != 0) RData.push_back(0);

  // Embed FEXAOTPEManifest in .rdata as well as DOS stub
  FEXAOTPEManifest FinalManifest = BaseManifest;
  FinalManifest.FxccStreamFileOffset = SecFxMetaRVA;
  FinalManifest.FxccTextFileOffset = SecTextRVA;
  FinalManifest.FxccPageFileOffset = SecFxPageRVA;
  AppendBytes(RData, &FinalManifest, sizeof(FinalManifest));

  while (RData.size() % 16 != 0) RData.push_back(0);

  // Build PE Export Directory inside .rdata
  struct ExportItem {
    std::string Name;
    uint32_t TargetRVA;
  };
  std::vector<ExportItem> Exports;
  for (const auto& P : Placements) {
    Exports.push_back({"#" + P.Block->SymbolName, SecTextRVA + P.EntryPointOffset});
    Exports.push_back({P.Block->SymbolName, SecTextRVA + P.EntryPointOffset});
  }
  for (const auto& TP : ThunkPlacements) {
    Exports.push_back({TP.Name, SecWowThkRVA + TP.OffsetInSection});
  }
  std::sort(Exports.begin(), Exports.end(),
            [](const ExportItem& A, const ExportItem& B) { return A.Name < B.Name; });

  const uint32_t ExportDirOff = static_cast<uint32_t>(RData.size());
  const uint32_t NumExports = static_cast<uint32_t>(Exports.size());
  RData.resize(ExportDirOff + sizeof(PEExportDirectory), 0);

  const uint32_t EatOff = static_cast<uint32_t>(RData.size());
  for (uint32_t i = 0; i < NumExports; ++i) {
    AppendBytes(RData, &Exports[i].TargetRVA, 4);
  }
  const uint32_t NamePtrTableOff = static_cast<uint32_t>(RData.size());
  RData.resize(NamePtrTableOff + NumExports * 4, 0);

  const uint32_t OrdinalTableOff = static_cast<uint32_t>(RData.size());
  for (uint16_t i = 0; i < NumExports; ++i) {
    AppendBytes(RData, &i, 2);
  }

  const uint32_t DllNameOff = static_cast<uint32_t>(RData.size());
  const std::string DllNameStr = "fex_aot_arm64ec.dll";
  AppendBytes(RData, DllNameStr.c_str(), DllNameStr.size() + 1);

  for (uint32_t i = 0; i < NumExports; ++i) {
    uint32_t StrRVA = SecRDataRVA + static_cast<uint32_t>(RData.size());
    memcpy(RData.data() + NamePtrTableOff + i * 4, &StrRVA, 4);
    AppendBytes(RData, Exports[i].Name.c_str(), Exports[i].Name.size() + 1);
  }

  PEExportDirectory ExpDir {};
  ExpDir.TimeDateStamp = BaseManifest.SourceTimeDateStamp;
  ExpDir.NameRVA = SecRDataRVA + DllNameOff;
  ExpDir.OrdinalBase = 1;
  ExpDir.AddressTableEntries = NumExports;
  ExpDir.NumberOfNamePointers = NumExports;
  ExpDir.ExportAddressTableRVA = SecRDataRVA + EatOff;
  ExpDir.NamePointerRVA = SecRDataRVA + NamePtrTableOff;
  ExpDir.OrdinalTableRVA = SecRDataRVA + OrdinalTableOff;
  memcpy(RData.data() + ExportDirOff, &ExpDir, sizeof(ExpDir));

  uint32_t ExportDirTotalSize = static_cast<uint32_t>(RData.size()) - ExportDirOff;
  uint32_t RDataRawSize = static_cast<uint32_t>(RData.size());
  uint32_t RDataAlignedSize = AlignUpU32(RDataRawSize, PE_PAGE_SIZE);
  RData.resize(RDataAlignedSize, 0);

  // 5. Build .reloc section (PE Base Relocation block covering LoadCfg.CHPEMetadataPointer)
  const uint32_t SecRelocRVA = SecRDataRVA + RDataAlignedSize;
  std::vector<uint8_t> RelocSec;
  uint32_t RelocPageRVA = SecRDataRVA;
  uint32_t RelocBlockSize = 12; // 8-byte header + two 2-byte entries
  AppendBytes(RelocSec, &RelocPageRVA, 4);
  AppendBytes(RelocSec, &RelocBlockSize, 4);
  uint16_t RelocEntry1 = static_cast<uint16_t>((10u << 12) | ((LoadCfgOff + offsetof(PELoadConfiguration64, CHPEMetadataPointer)) & 0xFFFu));
  uint16_t RelocEntryPad = 0; // IMAGE_REL_BASED_ABSOLUTE padding
  AppendBytes(RelocSec, &RelocEntry1, 2);
  AppendBytes(RelocSec, &RelocEntryPad, 2);
  uint32_t RelocRawSize = static_cast<uint32_t>(RelocSec.size());
  uint32_t RelocAlignedSize = AlignUpU32(RelocRawSize, PE_PAGE_SIZE);
  RelocSec.resize(RelocAlignedSize, 0);

  const uint32_t TotalImageSize = SecRelocRVA + RelocAlignedSize;

  // 6. Build COFF Symbol Table and String Table (placed at end of file after .reloc)
  std::vector<COFFSymbol18> SymTab;
  std::vector<char> StrTab(4, 0); // First 4 bytes of COFF string table hold total byte size

  auto AddCOFFSymbol = [&](const std::string& Name, uint32_t Value, int16_t SectionNum, uint16_t Type, uint8_t StorageClass) {
    COFFSymbol18 Sym {};
    if (Name.size() <= 8) {
      memcpy(Sym.Name.ShortName, Name.data(), Name.size());
    } else {
      Sym.Name.LongName.Zeroes = 0;
      Sym.Name.LongName.Offset = static_cast<uint32_t>(StrTab.size());
      StrTab.insert(StrTab.end(), Name.begin(), Name.end());
      StrTab.push_back('\0');
    }
    Sym.Value = Value;
    Sym.SectionNumber = SectionNum;
    Sym.Type = Type;
    Sym.StorageClass = StorageClass;
    Sym.NumberOfAuxSymbols = 0;
    SymTab.push_back(Sym);
  };

  for (const auto& P : Placements) {
    AddCOFFSymbol("#" + P.Block->SymbolName, P.EntryPointOffset, 2 /* .text */, 0x20 /* DTYPE_FUNCTION */, 2 /* IMAGE_SYM_CLASS_EXTERNAL */);
    AddCOFFSymbol(P.Block->SymbolName, P.EntryPointOffset, 2 /* .text */, 0x20, 2);
  }
  for (const auto& TP : ThunkPlacements) {
    AddCOFFSymbol(TP.Name, TP.OffsetInSection, 4 /* .wowthk */, 0x20, 2);
  }
  uint32_t StrTabTotalSize = static_cast<uint32_t>(StrTab.size());
  memcpy(StrTab.data(), &StrTabTotalSize, 4);

  const uint32_t SymTabFileOffset = TotalImageSize;

  // 7. Assemble Page 0 (0x0000 .. 0x0FFF): DOS Header + FEXAOTPEManifest + NT Headers + 7 Section Headers
  std::vector<uint8_t> HeaderPage(PE_PAGE_SIZE, 0);
  PEDosHeader DosHdr {};
  memcpy(HeaderPage.data(), &DosHdr, sizeof(DosHdr));
  memcpy(HeaderPage.data() + 0x40, &FinalManifest, sizeof(FinalManifest));

  PENtHeaders64 NtHdr {};
  NtHdr.FileHeader.Machine = 0x8664; // AMD64 + CHPEMetadata => Arm64EC (0xA641)
  NtHdr.FileHeader.NumberOfSections = 7;
  NtHdr.FileHeader.TimeDateStamp = BaseManifest.SourceTimeDateStamp;
  NtHdr.FileHeader.PointerToSymbolTable = SymTabFileOffset;
  NtHdr.FileHeader.NumberOfSymbols = static_cast<uint32_t>(SymTab.size());
  NtHdr.FileHeader.SizeOfOptionalHeader = sizeof(PEOptionalHeader64);
  NtHdr.FileHeader.Characteristics = 0x2022;

  NtHdr.OptionalHeader.SizeOfCode = CodeBufferAlignedSize + WowThkAlignedSize;
  NtHdr.OptionalHeader.SizeOfInitializedData = FxMetaAlignedSize + FxPagesAlignedSize + PDataAlignedSize + RDataAlignedSize + RelocAlignedSize;
  NtHdr.OptionalHeader.AddressOfEntryPoint = SecTextRVA + Placements[0].EntryPointOffset;
  NtHdr.OptionalHeader.BaseOfCode = SecTextRVA;
  NtHdr.OptionalHeader.ImageBase = 0x180000000ULL;
  NtHdr.OptionalHeader.SizeOfImage = TotalImageSize;
  NtHdr.OptionalHeader.SizeOfHeaders = PE_PAGE_SIZE;

  // Data Directories:
  // 0: Export Directory
  NtHdr.OptionalHeader.DataDirectories[0] = {SecRDataRVA + ExportDirOff, ExportDirTotalSize};
  // 3: Exception Directory (.pdata)
  NtHdr.OptionalHeader.DataDirectories[3] = {SecPDataRVA, NumRuntimeFns * static_cast<uint32_t>(sizeof(PERuntimeFunction))};
  // 5: Base Relocation Directory (.reloc)
  NtHdr.OptionalHeader.DataDirectories[5] = {SecRelocRVA, RelocRawSize};
  // 10: Load Configuration Directory (CHPEv2 Arm64EC metadata)
  NtHdr.OptionalHeader.DataDirectories[10] = {SecRDataRVA + LoadCfgOff, sizeof(LoadCfg)};

  memcpy(HeaderPage.data() + DosHdr.e_lfanew, &NtHdr, sizeof(NtHdr));

  PESectionHeader SecHdrs7[7] {};
  auto SetSec = [](PESectionHeader& S, const char* Name, uint32_t VSize, uint32_t RVA, uint32_t RawSize, uint32_t Flags) {
    memset(S.Name, 0, 8);
    strncpy(S.Name, Name, 8);
    S.VirtualSize = VSize;
    S.VirtualAddress = RVA;
    S.SizeOfRawData = RawSize;
    S.PointerToRawData = RVA; // 1:1 RVA == FileOffset
    S.Characteristics = Flags;
  };

  constexpr uint32_t SCN_READ_DATA = 0x40000040u; // INITIALIZED_DATA | MEM_READ
  constexpr uint32_t SCN_EXEC_CODE = 0x60000020u; // CNT_CODE | MEM_EXECUTE | MEM_READ
  constexpr uint32_t SCN_RELOC     = 0x42000040u; // INITIALIZED_DATA | MEM_DISCARDABLE | MEM_READ

  SetSec(SecHdrs7[0], ".fxmeta", FxMetaAlignedSize, SecFxMetaRVA, FxMetaAlignedSize, SCN_READ_DATA);
  SetSec(SecHdrs7[1], ".text",   CodeBufferAlignedSize, SecTextRVA, CodeBufferAlignedSize, SCN_EXEC_CODE);
  SetSec(SecHdrs7[2], ".fxpage", FxPagesAlignedSize, SecFxPageRVA, FxPagesAlignedSize, SCN_READ_DATA);
  SetSec(SecHdrs7[3], ".wowthk", WowThkRawSize, SecWowThkRVA, WowThkAlignedSize, SCN_EXEC_CODE);
  SetSec(SecHdrs7[4], ".pdata",  PDataRawSize, SecPDataRVA, PDataAlignedSize, SCN_READ_DATA);
  SetSec(SecHdrs7[5], ".rdata",  RDataRawSize, SecRDataRVA, RDataAlignedSize, SCN_READ_DATA);
  SetSec(SecHdrs7[6], ".reloc",  RelocRawSize, SecRelocRVA, RelocAlignedSize, SCN_RELOC);

  memcpy(HeaderPage.data() + DosHdr.e_lfanew + sizeof(NtHdr), SecHdrs7, sizeof(SecHdrs7));

  // Concatenate all sections + COFF Symbol Table + COFF String Table into OutDualPECOFF
  OutDualPECOFF.reserve(TotalImageSize + SymTab.size() * sizeof(COFFSymbol18) + StrTab.size());
  OutDualPECOFF.insert(OutDualPECOFF.end(), HeaderPage.begin(), HeaderPage.end());
  OutDualPECOFF.insert(OutDualPECOFF.end(), FxMeta.begin(), FxMeta.end());
  OutDualPECOFF.insert(OutDualPECOFF.end(), CodeBuffer.begin(), CodeBuffer.end());
  OutDualPECOFF.insert(OutDualPECOFF.end(), FxPages.begin(), FxPages.end());
  OutDualPECOFF.insert(OutDualPECOFF.end(), WowThk.begin(), WowThk.end());
  OutDualPECOFF.insert(OutDualPECOFF.end(), PData.begin(), PData.end());
  OutDualPECOFF.insert(OutDualPECOFF.end(), RData.begin(), RData.end());
  OutDualPECOFF.insert(OutDualPECOFF.end(), RelocSec.begin(), RelocSec.end());

  const auto* SymBytes = reinterpret_cast<const uint8_t*>(SymTab.data());
  OutDualPECOFF.insert(OutDualPECOFF.end(), SymBytes, SymBytes + SymTab.size() * sizeof(COFFSymbol18));
  OutDualPECOFF.insert(OutDualPECOFF.end(), reinterpret_cast<const uint8_t*>(StrTab.data()),
                       reinterpret_cast<const uint8_t*>(StrTab.data()) + StrTab.size());

  return true;
}

bool AuditPECOFFContainer(std::span<const uint8_t> ContainerBytes,
                          std::string& OutReport,
                          bool DisassembleAll) {
  if (ContainerBytes.size() < PE_PAGE_SIZE) {
    OutReport = "Error: Container smaller than 4096 bytes\n";
    return false;
  }

  PEDosHeader Dos {};
  memcpy(&Dos, ContainerBytes.data(), sizeof(Dos));
  if (Dos.e_magic != 0x5A4D || Dos.e_lfanew + sizeof(PENtHeaders64) > ContainerBytes.size()) {
    OutReport = "Error: Invalid DOS/NT header in PE/COFF container\n";
    return false;
  }

  PENtHeaders64 Nt {};
  memcpy(&Nt, ContainerBytes.data() + Dos.e_lfanew, sizeof(Nt));
  if (Nt.Signature != 0x00004550 || Nt.OptionalHeader.Magic != 0x020B) {
    OutReport = "Error: Invalid PE32+ signature in PE/COFF container\n";
    return false;
  }

  const size_t SecHdrOff = Dos.e_lfanew + sizeof(PENtHeaders64);
  const uint16_t NumSecs = Nt.FileHeader.NumberOfSections;
  if (SecHdrOff + NumSecs * sizeof(PESectionHeader) > ContainerBytes.size()) {
    OutReport = "Error: Section headers exceed container size\n";
    return false;
  }

  const auto* Secs = reinterpret_cast<const PESectionHeader*>(ContainerBytes.data() + SecHdrOff);

  const PELoadConfiguration64* LoadCfg = nullptr;
  const PEChpeMetadata* Chpe = nullptr;
  const auto LoadCfgDir = Nt.OptionalHeader.DataDirectories[10];
  if (LoadCfgDir.VirtualAddress && LoadCfgDir.VirtualAddress + sizeof(PELoadConfiguration64) <= ContainerBytes.size()) {
    LoadCfg = reinterpret_cast<const PELoadConfiguration64*>(ContainerBytes.data() + LoadCfgDir.VirtualAddress);
    if (LoadCfg->CHPEMetadataPointer >= Nt.OptionalHeader.ImageBase) {
      uint64_t ChpeRVA = LoadCfg->CHPEMetadataPointer - Nt.OptionalHeader.ImageBase;
      if (ChpeRVA + sizeof(PEChpeMetadata) <= ContainerBytes.size()) {
        Chpe = reinterpret_cast<const PEChpeMetadata*>(ContainerBytes.data() + ChpeRVA);
      }
    }
  }

  const uint16_t EffectiveMachine = (Nt.FileHeader.Machine == 0x8664 && Chpe != nullptr)
                                      ? IMAGE_FILE_MACHINE_ARM64EC_VAL
                                      : Nt.FileHeader.Machine;

  std::ostringstream OS;
  OS << "=== PE/COFF Arm64EC + FEX FXCC Dual Container Audit ===\n";
  OS << "Container Size         : " << ContainerBytes.size() << " bytes\n";
  OS << "COFF Effective Machine : 0x" << std::hex << EffectiveMachine << std::dec
     << (EffectiveMachine == IMAGE_FILE_MACHINE_ARM64EC_VAL ? " (IMAGE_FILE_MACHINE_ARM64EC)" : "") << "\n";
  OS << "CHPEv2 Metadata Present: " << (Chpe ? "YES (Version " + std::to_string(Chpe->Version) + ")" : "NO") << "\n";
  if (Chpe) {
    OS << "  CHPE CodeMap RVA     : 0x" << std::hex << uint32_t(Chpe->CodeMap) << " (" << std::dec << uint32_t(Chpe->CodeMapCount) << " ranges)\n";
    OS << "  CHPE Redirection RVA : 0x" << std::hex << uint32_t(Chpe->RedirectionMetadata)
       << " (" << std::dec << uint32_t(Chpe->RedirectionMetadataCount) << " x64->Arm64EC entries)\n";
    OS << "  CHPE ExtraRFETable   : 0x" << std::hex << uint32_t(Chpe->ExtraRFETable)
       << " (" << std::dec << uint32_t(Chpe->ExtraRFETableSize) << " bytes)\n";
  }
  if (LoadCfg) {
    OS << "LoadConfig64 Size      : " << uint32_t(LoadCfg->Size) << " bytes (CHPEMetadataPointer = 0x"
       << std::hex << uint64_t(LoadCfg->CHPEMetadataPointer) << std::dec << ")\n";
  }

  // Verify embedded FEXAOTPEManifest at offset 0x40
  FEXAOTPEManifest Manifest {};
  memcpy(&Manifest, ContainerBytes.data() + 0x40, sizeof(Manifest));
  if (memcmp(Manifest.Magic, "FXPE", 4) == 0) {
    OS << "\n--- Embedded FEXAOTPEManifest (FXPE) ---\n";
    OS << "  SourceFileId         : 0x" << std::hex << Manifest.SourceFileId << "\n";
    OS << "  CodeCacheConfigId    : 0x" << Manifest.CodeCacheConfigId << "\n";
    OS << "  SourceImageBase      : 0x" << Manifest.SourceImageBase << "\n";
    OS << "  SourceSizeOfImage    : 0x" << Manifest.SourceSizeOfImage << "\n";
    OS << "  SourceTimeDateStamp  : 0x" << Manifest.SourceTimeDateStamp << "\n";
    OS << "  SourceTextXXH3       : 0x" << Manifest.SourceTextXXH3 << "\n";
    OS << "  FxccStreamFileOffset : 0x" << Manifest.FxccStreamFileOffset << "\n";
    OS << "  FxccTextFileOffset   : 0x" << Manifest.FxccTextFileOffset << "\n";
    OS << "  FxccPageFileOffset   : 0x" << Manifest.FxccPageFileOffset << std::dec << "\n";
  }

  // Verify FXCC CodeCacheHeader at Manifest.FxccStreamFileOffset
  if (Manifest.FxccStreamFileOffset + sizeof(RawCodeCacheHeader) <= ContainerBytes.size()) {
    RawCodeCacheHeader FxHdr {};
    memcpy(&FxHdr, ContainerBytes.data() + Manifest.FxccStreamFileOffset, sizeof(FxHdr));
    OS << "\n--- Embedded FEX CodeCacheHeader (FXCC v" << FxHdr.FormatVersion << ") ---\n";
    OS << "  Magic                : " << std::string_view(FxHdr.Magic.data(), 4) << "\n";
    OS << "  NumBlocks            : " << FxHdr.NumBlocks << "\n";
    OS << "  NumCodePages         : " << FxHdr.NumCodePages << "\n";
    OS << "  CodeBufferSize       : " << FxHdr.CodeBufferSize << " bytes\n";
    OS << "  NumRelocations       : " << FxHdr.NumRelocations << "\n";
    OS << "  Flags                : 0x" << std::hex << FxHdr.Flags << std::dec << " (LLVM_AOT_O2 | PE_COFF_CONTAINER | PROTECTED_AOT)\n";
  }

  // List PE Sections
  OS << "\n--- PE32+ Sections (" << NumSecs << ") ---\n";
#ifdef FEX_HAS_LLVM_AOT
  const uint8_t* TextData = nullptr;
  size_t TextSize = 0;
  uint64_t TextRVA = 0;
  const uint8_t* WowThkData = nullptr;
  size_t WowThkSize = 0;
  uint64_t WowThkRVA = 0;
#endif

  for (uint16_t i = 0; i < NumSecs; ++i) {
    const auto& S = Secs[i];
    std::string SName(S.Name, strnlen(S.Name, 8));
    size_t SSize = S.SizeOfRawData;
    uint64_t SRVA = S.VirtualAddress;
    char Line[160];
    snprintf(Line, sizeof(Line), "  %-10s RVA: 0x%08llx  RawSize: %8zu bytes\n",
             SName.c_str(), static_cast<unsigned long long>(SRVA), SSize);
    OS << Line;
#ifdef FEX_HAS_LLVM_AOT
    if (S.PointerToRawData + SSize <= ContainerBytes.size()) {
      if (SName == ".text") {
        TextData = ContainerBytes.data() + S.PointerToRawData;
        TextSize = SSize;
        TextRVA = SRVA;
      } else if (SName == ".wowthk") {
        WowThkData = ContainerBytes.data() + S.PointerToRawData;
        WowThkSize = SSize;
        WowThkRVA = SRVA;
      }
    }
#endif
  }

  OS << "\nCOFF Symbol Table      : " << Nt.FileHeader.NumberOfSymbols << " symbols\n";

#ifdef FEX_HAS_LLVM_AOT
  LLVMInitializeAArch64TargetInfo();
  LLVMInitializeAArch64TargetMC();
  LLVMInitializeAArch64Disassembler();

  LLVMDisasmContextRef Disasm = LLVMCreateDisasm("aarch64-pc-windows-msvc", nullptr, 0, nullptr, nullptr);
  if (Disasm && TextData && TextSize > 0) {
    OS << "\n--- Sample AArch64 Disassembly from .text (RVA 0x" << std::hex << TextRVA << std::dec << ") ---\n";
    size_t MaxOff = DisassembleAll ? TextSize : std::min<size_t>(TextSize, 96);
    for (size_t Off = 4; Off + 4 <= MaxOff; Off += 4) {
      uint32_t Word = 0;
      memcpy(&Word, TextData + Off, 4);
      if (Word == 0) continue;
      char OutStr[128] = {};
      size_t InstLen = LLVMDisasmInstruction(
        Disasm,
        const_cast<uint8_t*>(TextData + Off),
        4, TextRVA + Off, OutStr, sizeof(OutStr));
      char Line[192];
      snprintf(Line, sizeof(Line), "  0x%08llx: %08x  %s\n",
               static_cast<unsigned long long>(TextRVA + Off), Word,
               InstLen ? OutStr : "\t.word");
      OS << Line;
    }
  }
  if (Disasm && WowThkData && WowThkSize > 0) {
    OS << "\n--- Arm64EC Entry/Exit Thunk Disassembly from .wowthk (RVA 0x" << std::hex << WowThkRVA << std::dec << ") ---\n";
    size_t MaxOff = std::min<size_t>(WowThkSize, 80);
    for (size_t Off = 0; Off + 4 <= MaxOff; Off += 4) {
      uint32_t Word = 0;
      memcpy(&Word, WowThkData + Off, 4);
      if (Word == 0) break;
      char OutStr[128] = {};
      LLVMDisasmInstruction(
        Disasm,
        const_cast<uint8_t*>(WowThkData + Off),
        4, WowThkRVA + Off, OutStr, sizeof(OutStr));
      char Line[192];
      snprintf(Line, sizeof(Line), "  0x%08llx: %08x  %s\n",
               static_cast<unsigned long long>(WowThkRVA + Off), Word, OutStr);
      OS << Line;
    }
  }
  if (Disasm) {
    LLVMDisasmDispose(Disasm);
  }
#else
  (void)DisassembleAll;
#endif

  OutReport = OS.str();
  return EffectiveMachine == IMAGE_FILE_MACHINE_ARM64EC_VAL && Chpe != nullptr && memcmp(Manifest.Magic, "FXPE", 4) == 0;
}

} // namespace FEXCore::AOT

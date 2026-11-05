// SPDX-License-Identifier: MIT
/*
 * fex-aot-pe: Offline Optimizing LLVM-Arm64EC (-O2) Dual-Tier AOT Compiler (.text_ec + .text_fex),
 *             Dual PE/COFF + FXCC Packager, Auditor, Runtime Interop Verifier, and Benchmark Tool.
 *
 * Supports both x86-64 host cross-compilation and native aarch64 (Linux / Android / Wine) execution.
 */

#include <FEXCore/Core/LLVMArm64ECAOT.h>

#include "Interface/Context/Context.h"
#include "Interface/Core/LookupCache.h"
#include "Interface/Core/Frontend.h"
#include "Interface/Core/OpcodeDispatcher.h"
#include "Interface/Core/JIT/DebugData.h"
#include "Interface/IR/IR.h"
#include "Interface/IR/IntrusiveIRList.h"

#include <FEXCore/Config/Config.h>
#include <FEXCore/Core/CodeCache.h>
#include <FEXCore/Core/Context.h>
#include <FEXCore/Core/CoreState.h>
#include <FEXCore/Core/SignalDelegator.h>
#include <FEXCore/HLE/SyscallHandler.h>
#include <FEXCore/HLE/SourcecodeResolver.h>
#include <FEXCore/Utils/Allocator.h>
#include <FEXCore/Utils/LogManager.h>

#include <xxhash.h>

#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include <execinfo.h>
#include <signal.h>

static void segv_handler(int sig) {
  void* bt[48];
  int n = backtrace(bt, 48);
  backtrace_symbols_fd(bt, n, 2);
  _exit(128 + sig);
}
static void CustomMsgHandler(LogMan::DebugLevels Level, const char* Message) {
  fprintf(stderr, "[FEX %s] %s\n", LogMan::DebugLevelStr(Level), Message);
}
static void AssertHandler(const char* Message) {
  fprintf(stderr, "[FEX ASSERT] %s\n", Message);
}

namespace {

// Standalone SHA-256 implementation for deterministic per-binary content hashing
struct SimpleSHA256 {
  static void Compute(const uint8_t* Data, size_t Len, uint8_t Out[32]) {
    static constexpr uint32_t K[64] = {
      0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
      0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
      0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
      0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
      0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfc1u & 0xffffffffu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
      0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
      0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
      0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
    };
    auto Ror32 = [](uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); };
    uint32_t H[8] = {
      0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
      0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
    };
    uint64_t BitLen = static_cast<uint64_t>(Len) * 8ULL;
    size_t PaddedLen = ((Len + 9 + 63) / 64) * 64;
    std::vector<uint8_t> Buf(PaddedLen, 0);
    if (Len > 0) memcpy(Buf.data(), Data, Len);
    Buf[Len] = 0x80;
    for (int i = 0; i < 8; ++i) {
      Buf[PaddedLen - 1 - i] = static_cast<uint8_t>((BitLen >> (i * 8)) & 0xFFu);
    }
    for (size_t Off = 0; Off < PaddedLen; Off += 64) {
      uint32_t W[64];
      for (int i = 0; i < 16; ++i) {
        W[i] = (uint32_t(Buf[Off + i * 4]) << 24) |
               (uint32_t(Buf[Off + i * 4 + 1]) << 16) |
               (uint32_t(Buf[Off + i * 4 + 2]) << 8) |
               uint32_t(Buf[Off + i * 4 + 3]);
      }
      for (int i = 16; i < 64; ++i) {
        uint32_t s0 = Ror32(W[i - 15], 7) ^ Ror32(W[i - 15], 18) ^ (W[i - 15] >> 3);
        uint32_t s1 = Ror32(W[i - 2], 17) ^ Ror32(W[i - 2], 19) ^ (W[i - 2] >> 10);
        W[i] = W[i - 16] + s0 + W[i - 7] + s1;
      }
      uint32_t a = H[0], b = H[1], c = H[2], d = H[3];
      uint32_t e = H[4], f = H[5], g = H[6], h = H[7];
      for (int i = 0; i < 64; ++i) {
        uint32_t S1 = Ror32(e, 6) ^ Ror32(e, 11) ^ Ror32(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t temp1 = h + S1 + ch + K[i] + W[i];
        uint32_t S0 = Ror32(a, 2) ^ Ror32(a, 13) ^ Ror32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = S0 + maj;
        h = g; g = f; f = e; e = d + temp1;
        d = c; c = b; b = a; a = temp1 + temp2;
      }
      H[0] += a; H[1] += b; H[2] += c; H[3] += d;
      H[4] += e; H[5] += f; H[6] += g; H[7] += h;
    }
    for (int i = 0; i < 8; ++i) {
      Out[i * 4 + 0] = static_cast<uint8_t>((H[i] >> 24) & 0xFFu);
      Out[i * 4 + 1] = static_cast<uint8_t>((H[i] >> 16) & 0xFFu);
      Out[i * 4 + 2] = static_cast<uint8_t>((H[i] >> 8) & 0xFFu);
      Out[i * 4 + 3] = static_cast<uint8_t>(H[i] & 0xFFu);
    }
  }
};

struct DosHeader {
  uint16_t e_magic;
  uint16_t e_cblp[29];
  uint32_t e_lfanew;
};

struct FileHeader {
  uint16_t Machine;
  uint16_t NumberOfSections;
  uint32_t TimeDateStamp;
  uint32_t PointerToSymbolTable;
  uint32_t NumberOfSymbols;
  uint16_t SizeOfOptionalHeader;
  uint16_t Characteristics;
};

struct DataDirectory {
  uint32_t VirtualAddress;
  uint32_t Size;
};

struct OptionalHeader64 {
  uint16_t Magic;
  uint8_t MajorLinkerVersion;
  uint8_t MinorLinkerVersion;
  uint32_t SizeOfCode;
  uint32_t SizeOfInitializedData;
  uint32_t SizeOfUninitializedData;
  uint32_t AddressOfEntryPoint;
  uint32_t BaseOfCode;
  uint64_t ImageBase;
  uint32_t SectionAlignment;
  uint32_t FileAlignment;
  uint16_t MajorOperatingSystemVersion;
  uint16_t MinorOperatingSystemVersion;
  uint16_t MajorImageVersion;
  uint16_t MinorImageVersion;
  uint16_t MajorSubsystemVersion;
  uint16_t MinorSubsystemVersion;
  uint32_t Win32VersionValue;
  uint32_t SizeOfImage;
  uint32_t SizeOfHeaders;
  uint32_t CheckSum;
  uint16_t Subsystem;
  uint16_t DllCharacteristics;
  uint64_t SizeOfStackReserve;
  uint64_t SizeOfStackCommit;
  uint64_t SizeOfHeapReserve;
  uint64_t SizeOfHeapCommit;
  uint32_t LoaderFlags;
  uint32_t NumberOfRvaAndSizes;
  DataDirectory DataDirectories[16];
};

struct NtHeaders64 {
  uint32_t Signature;
  FileHeader FileHdr;
  OptionalHeader64 OptHdr;
};

struct SectionHeader {
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

struct RuntimeFunction {
  uint32_t BeginAddress;
  uint32_t EndAddress;
  uint32_t UnwindInfoAddress;
};

class OfflineSignalDelegator final : public FEXCore::SignalDelegator {};

class OfflineSyscallHandler final : public FEXCore::HLE::SyscallHandler {
public:
  OfflineSyscallHandler(uint64_t Base, uint64_t Size, FEXCore::ExecutableFileInfo& Info)
    : SectionInfo {Info, Base, Base, Base + Size} {}

  void HandleSyscall(FEXCore::Core::CpuStateFrame*) override {}

  FEXCore::HLE::ExecutableRangeInfo QueryGuestExecutableRange(FEXCore::Core::InternalThreadState*, uint64_t Address) override {
    if (Address >= SectionInfo.BeginVA && Address < SectionInfo.EndVA) {
      return {SectionInfo.BeginVA, SectionInfo.EndVA - SectionInfo.BeginVA, false};
    }
    return {0, 0, false};
  }

  std::optional<FEXCore::ExecutableFileSectionInfo> LookupExecutableFileSection(FEXCore::Core::InternalThreadState*, uint64_t Address) override {
    if (Address >= SectionInfo.BeginVA && Address < SectionInfo.EndVA) {
      return SectionInfo;
    }
    return std::nullopt;
  }

  FEXCore::ExecutableFileSectionInfo SectionInfo;
};

static std::string ToLowerStr(std::string_view S) {
  std::string Out(S);
  std::transform(Out.begin(), Out.end(), Out.begin(), [](unsigned char c) { return std::tolower(c); });
  return Out;
}

static bool CompileAndPackagePEBinary(const std::string& Path,
                                      const std::string& OutputDir,
                                      bool VerifyInterop,
                                      bool RunAudit,
                                      bool ForceAllSRA,
                                      bool EmitFexJit,
                                      FEXCore::AOT::PEModuleAOTResult& OutResult) {
  OutResult = {};
  OutResult.SourcePath = Path;
  OutResult.BaseName = ToLowerStr(std::filesystem::path(Path).filename().string());

  std::ifstream InFile(Path, std::ios::binary | std::ios::ate);
  if (!InFile) {
    std::cerr << "Error: Failed to open PE binary: " << Path << "\n";
    return false;
  }
  size_t FileSize = static_cast<size_t>(InFile.tellg());
  InFile.seekg(0, std::ios::beg);
  std::vector<uint8_t> RawBytes(FileSize);
  InFile.read(reinterpret_cast<char*>(RawBytes.data()), FileSize);
  InFile.close();

  if (RawBytes.size() < sizeof(DosHeader)) {
    std::cerr << "Error: File too small to be a PE binary: " << Path << "\n";
    return false;
  }
  const auto* Dos = reinterpret_cast<const DosHeader*>(RawBytes.data());
  if (Dos->e_magic != 0x5A4D || Dos->e_lfanew + sizeof(NtHeaders64) > RawBytes.size()) {
    std::cerr << "Error: Invalid DOS/NT header in: " << Path << "\n";
    return false;
  }
  const auto* Nt = reinterpret_cast<const NtHeaders64*>(RawBytes.data() + Dos->e_lfanew);
  if (Nt->Signature != 0x00004550 || Nt->OptHdr.Magic != 0x020B) {
    std::cerr << "Error: Only 64-bit PE32+ binaries are supported: " << Path << "\n";
    return false;
  }

  const auto* Secs = reinterpret_cast<const SectionHeader*>(
    reinterpret_cast<const uint8_t*>(&Nt->OptHdr) + Nt->FileHdr.SizeOfOptionalHeader);

  const uint64_t ImgBase = Nt->OptHdr.ImageBase;
  const uint64_t ImgSize = (static_cast<uint64_t>(Nt->OptHdr.SizeOfImage) + 0xFFFULL) & ~0xFFFULL;

  // Populate FEXAOTPEManifest for per-binary identification and cache invalidation
  OutResult.Manifest.SourceImageBase = ImgBase;
  OutResult.Manifest.SourceSizeOfImage = Nt->OptHdr.SizeOfImage;
  OutResult.Manifest.SourceTimeDateStamp = Nt->FileHdr.TimeDateStamp;
  OutResult.Manifest.SourceFileId = FEXCore::AOT::ComputePEFileId(
    OutResult.BaseName, Nt->FileHdr.TimeDateStamp, Nt->OptHdr.SizeOfImage);
  SimpleSHA256::Compute(RawBytes.data(), RawBytes.size(), OutResult.Manifest.SourceSHA256);

  void* Mapped = mmap(reinterpret_cast<void*>(ImgBase), ImgSize,
                      PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
  if (Mapped == MAP_FAILED) {
    perror("mmap PE image");
    return false;
  }

  memcpy(Mapped, RawBytes.data(), std::min<size_t>(Nt->OptHdr.SizeOfHeaders, RawBytes.size()));
  uint64_t TextBegin = 0, TextEnd = 0;
  for (int i = 0; i < Nt->FileHdr.NumberOfSections; ++i) {
    const auto& S = Secs[i];
    if (S.PointerToRawData && S.SizeOfRawData && S.VirtualAddress + S.SizeOfRawData <= ImgSize) {
      size_t CopyLen = std::min<size_t>(S.SizeOfRawData, S.VirtualSize ? S.VirtualSize : S.SizeOfRawData);
      memcpy(static_cast<uint8_t*>(Mapped) + S.VirtualAddress, RawBytes.data() + S.PointerToRawData, CopyLen);
    }
    if (strncmp(S.Name, ".text", 5) == 0) {
      TextBegin = ImgBase + S.VirtualAddress;
      TextEnd = TextBegin + S.VirtualSize;
      OutResult.Manifest.SourceTextXXH3 = XXH3_64bits(
        static_cast<const uint8_t*>(Mapped) + S.VirtualAddress, S.VirtualSize);
    }
  }

  // Discover functions and basic blocks from:
  // 1. PE AddressOfEntryPoint
  // 2. PE .pdata Exception Directory (RUNTIME_FUNCTION entries)
  // 3. PE .text direct CALL rel32 target scan
  // 4. Transitive FEX Frontend::Decoder ExternalBranches CFG discovery
  std::set<uint64_t> Seeds;
  std::map<uint64_t, uint32_t> FunctionEndRVAs;
  if (Nt->OptHdr.AddressOfEntryPoint) {
    Seeds.insert(ImgBase + Nt->OptHdr.AddressOfEntryPoint);
  }
  size_t g_MaxFunctionsCap = 1000;
  if (const char* EnvMax = getenv("FEX_AOT_MAX_FUNCTIONS")) {
    size_t V = std::strtoull(EnvMax, nullptr, 10);
    if (V > 0) g_MaxFunctionsCap = V;
  }
  const auto PDataDir = Nt->OptHdr.DataDirectories[3];
  size_t PDataTotalCount = 0;
  if (PDataDir.VirtualAddress && PDataDir.Size && PDataDir.VirtualAddress + PDataDir.Size <= ImgSize) {
    const auto* RF = reinterpret_cast<const RuntimeFunction*>(static_cast<const uint8_t*>(Mapped) + PDataDir.VirtualAddress);
    size_t Count = PDataDir.Size / sizeof(RuntimeFunction);
    PDataTotalCount = Count;
    if (Count > 2000 && !getenv("FEX_AOT_MAX_FUNCTIONS")) {
      g_MaxFunctionsCap = 64;
    }
    size_t Step = (Count > g_MaxFunctionsCap) ? std::max<size_t>(1, Count / g_MaxFunctionsCap) : 1;
    for (size_t i = 0; i < Count; i += Step) {
      if (RF[i].BeginAddress) {
        uint64_t EntryVA = ImgBase + RF[i].BeginAddress;
        Seeds.insert(EntryVA);
        FunctionEndRVAs[EntryVA] = RF[i].EndAddress;
        if (Seeds.size() >= g_MaxFunctionsCap) break;
      }
    }
  }
  const uint64_t ScanEnd = (PDataTotalCount > g_MaxFunctionsCap || (TextEnd - TextBegin) > (2ULL << 20))
                           ? std::min<uint64_t>(TextEnd, TextBegin + (256ULL << 10))
                           : TextEnd;
  for (uint64_t P = TextBegin; P + 5 <= ScanEnd && Seeds.size() < g_MaxFunctionsCap; ++P) {
    const uint8_t* Ins = reinterpret_cast<const uint8_t*>(P);
    if (Ins[0] == 0xE8) {
      int32_t Disp = *reinterpret_cast<const int32_t*>(Ins + 1);
      uint64_t Target = P + 5 + Disp;
      if (Target >= TextBegin && Target < TextEnd) {
        const uint8_t* TPtr = reinterpret_cast<const uint8_t*>(Target);
        if ((P == TextBegin || TPtr[-1] == 0xCC || TPtr[-1] == 0xC3) &&
            (TPtr[0] == 0x48 || TPtr[0] == 0x40 || TPtr[0] == 0x4C || TPtr[0] == 0x55 ||
             TPtr[0] == 0x53 || TPtr[0] == 0x56 || TPtr[0] == 0x57 || TPtr[0] == 0x33 || TPtr[0] == 0xE9)) {
          Seeds.insert(Target);
        }
      }
    }
  }

  // Initialize FEXCore Context & Thread for IR generation and FEX-JIT baseline compilation
  FEXCore::HostFeatures Features;
  auto CtxUnique = FEXCore::Context::Context::CreateNewContext(Features);
  auto* CTX = static_cast<FEXCore::Context::ContextImpl*>(CtxUnique.get());
  OfflineSignalDelegator SigDelegator;
  FEXCore::ExecutableFileInfo FileInfo {nullptr, OutResult.Manifest.SourceFileId, OutResult.BaseName.c_str()};
  // Parse PE Base Relocation Directory (DataDirectories[5]) into FileInfo.Relocations so OpDispatcher emits
  // OP_INLINEENTRYPOINTOFFSET for relocated 64-bit immediates when CacheGenerating is active.
  if (Nt->OptHdr.NumberOfRvaAndSizes > 5) {
    const auto RelocDir = Nt->OptHdr.DataDirectories[5];
    if (RelocDir.VirtualAddress && RelocDir.Size && RelocDir.VirtualAddress + RelocDir.Size <= ImgSize) {
      const uint8_t* RelPtr = static_cast<const uint8_t*>(Mapped) + RelocDir.VirtualAddress;
      const uint8_t* RelEnd = RelPtr + RelocDir.Size;
      while (RelPtr + 8 <= RelEnd) {
        uint32_t PageRVA = *reinterpret_cast<const uint32_t*>(RelPtr);
        uint32_t BlockSize = *reinterpret_cast<const uint32_t*>(RelPtr + 4);
        if (BlockSize < 8 || RelPtr + BlockSize > RelEnd) break;
        const uint16_t* Entries = reinterpret_cast<const uint16_t*>(RelPtr + 8);
        size_t NumEntries = (BlockSize - 8) / 2;
        for (size_t ri = 0; ri < NumEntries && FileInfo.Relocations.size() < 65536; ++ri) {
          uint16_t Type = Entries[ri] >> 12;
          uint16_t Offset = Entries[ri] & 0x0FFFu;
          if (Type == 10) { // IMAGE_REL_BASED_DIR64
            FileInfo.Relocations[PageRVA + Offset] = FEXCore::GuestRelocationType::Rel64;
          }
        }
        if (FileInfo.Relocations.size() >= 65536) break;
        RelPtr += BlockSize;
      }
    }
  }
  OfflineSyscallHandler SyscallHandler(ImgBase, ImgSize, FileInfo);
  CTX->SetSignalDelegator(&SigDelegator);
  CTX->SetSyscallHandler(&SyscallHandler);
  CTX->GetCodeCache().InitiateCacheGeneration();
  CTX->InitCore();

  OutResult.Manifest.CodeCacheConfigId = FEXCore::AOT::ComputeCodeCacheConfigId(CTX, true);

  auto* Thread = CTX->CreateThread(nullptr);
  FEXCore::Core::CPUState::gdt_segment Gdt[32] {};
  auto Frame = Thread->CurrentFrame;
  Frame->State.segment_arrays[FEXCore::Core::CPUState::SEGMENT_ARRAY_INDEX_GDT] = &Gdt[0];
  Frame->State.segment_arrays[FEXCore::Core::CPUState::SEGMENT_ARRAY_INDEX_LDT] = &Gdt[0];
  Frame->State.cs_idx = FEXCore::Core::CPUState::DEFAULT_USER_CS << 3;
  auto GdtSeg = FEXCore::Core::CPUState::GetSegmentFromIndex(Frame->State, Frame->State.cs_idx);
  FEXCore::Core::CPUState::SetGDTBase(GdtSeg, 0);
  FEXCore::Core::CPUState::SetGDTLimit(GdtSeg, 0xFFFFFU);
  GdtSeg->L = 1;
  GdtSeg->D = 0;

  fextl::set<uint64_t> ExtBranches;
  Thread->FrontendDecoder->SetExternalBranches(&ExtBranches);

  std::vector<uint64_t> Worklist(Seeds.begin(), Seeds.end());
  std::set<uint64_t> Visited(Seeds.begin(), Seeds.end());

  FEXCore::AOT::LLVMArm64ECAOTCompiler::Options LLVMOpts;
  LLVMOpts.OptPipeline = "default<O2>";
  LLVMOpts.TargetTriple = "arm64ec-pc-windows-msvc";
  LLVMOpts.DeduplicateExitStubs = true;
  LLVMOpts.EmitArm64ECThunks = true;
  LLVMOpts.EnableDualABIPartitioning = !ForceAllSRA;
  LLVMOpts.ForceAllFEXSRA = ForceAllSRA;
  LLVMOpts.UseGVisorOffset = (getenv("FEX_AOT_GVISOR_OFFSET") != nullptr);
  FEXCore::AOT::LLVMArm64ECAOTCompiler AOTCompiler(LLVMOpts);

  std::vector<FEXCore::AOT::LLVMArm64ECAOTCompiler::LiftedFunctionIR> LiftedFunctions;

  for (size_t wi = 0; wi < Worklist.size() && LiftedFunctions.size() < g_MaxFunctionsCap; ++wi) {
    uint64_t EntryVA = Worklist[wi];
    if (EntryVA < TextBegin || EntryVA >= TextEnd) continue;

    Thread->FrontendDecoder->SetupDecodeInstructionsAtEntry(Thread, EntryVA, 5000);
    auto IrRes = CTX->GenerateIR(Thread, EntryVA, true, 5000);
    if (!IrRes.IRView) {
      Thread->FrontendDecoder->ValidateDisownedOrFree();
      Thread->OpDispatcher->ValidateDisownedOrFree();
      continue;
    }

    auto Lifted = AOTCompiler.LiftIRToLLVM(
      EntryVA, IrRes.Length, static_cast<uint32_t>(IrRes.TotalInstructions), *IrRes.IRView);

    Thread->OpDispatcher->DelayedDisownBuffer();
    Thread->FrontendDecoder->ValidateDisownedOrFree();
    Thread->OpDispatcher->ValidateDisownedOrFree();

    for (uint64_t Eb : ExtBranches) {
      if (Eb >= TextBegin && Eb < TextEnd && Visited.insert(Eb).second) {
        Worklist.push_back(Eb);
      }
    }
    ExtBranches.clear();
    for (const auto& Site : Lifted.ExitSites) {
      if (Site.IsDirect && Site.DirectNewRIP >= TextBegin && Site.DirectNewRIP < TextEnd &&
          Visited.insert(Site.DirectNewRIP).second) {
        Worklist.push_back(Site.DirectNewRIP);
      }
      if (Site.CallReturnAddress >= TextBegin && Site.CallReturnAddress < TextEnd &&
          Visited.insert(Site.CallReturnAddress).second) {
        Worklist.push_back(Site.CallReturnAddress);
      }
    }
    if (Lifted.HasUnhandledIR) {
      continue;
    }

    // Benchmark FEX-JIT compilation time and code size on the exact same function
    auto T0 = std::chrono::steady_clock::now();
    Thread->FrontendDecoder->SetupDecodeInstructionsAtEntry(Thread, EntryVA, 5000);
    auto FexComp = CTX->CompileCode(Thread, EntryVA, 5000);
    auto T1 = std::chrono::steady_clock::now();
    double FexUs = std::chrono::duration<double, std::micro>(T1 - T0).count();

    uint32_t FexTotalBytes = FexComp.DebugData ? static_cast<uint32_t>(FexComp.DebugData->HostCodeSize) : 0;
    uint32_t FexCodeOnlyBytes = 0;
    if (FexTotalBytes > sizeof(FEXCore::CPU::CPUBackend::JITCodeHeader) && FexComp.CompiledCode.BlockBegin) {
      const auto* Hdr = reinterpret_cast<const FEXCore::CPU::CPUBackend::JITCodeHeader*>(FexComp.CompiledCode.BlockBegin);
      if (Hdr->OffsetToBlockTail > sizeof(FEXCore::CPU::CPUBackend::JITCodeHeader) && Hdr->OffsetToBlockTail <= FexTotalBytes) {
        FexCodeOnlyBytes = Hdr->OffsetToBlockTail - sizeof(FEXCore::CPU::CPUBackend::JITCodeHeader);
      }
    }

    FEXCore::AOT::DiscoveredFunctionInfo FnInfo {};
    FnInfo.EntryVA = EntryVA;
    FnInfo.EntryRVA = static_cast<uint32_t>(EntryVA - ImgBase);
    FnInfo.EndRVA = FunctionEndRVAs.count(EntryVA) ? FunctionEndRVAs[EntryVA] : static_cast<uint32_t>(FnInfo.EntryRVA + IrRes.Length);
    FnInfo.GuestInstCount = static_cast<uint32_t>(IrRes.TotalInstructions);
    FnInfo.GuestByteSize = static_cast<uint32_t>(IrRes.TotalInstructionsLength);
    FnInfo.BasicBlockCount = Lifted.BasicBlockCount;
    FnInfo.TargetABI = Lifted.TargetABI;
    FnInfo.Safety = Lifted.Safety;
    FnInfo.FEXJITCodeOnlyBytes = FexCodeOnlyBytes;
    FnInfo.FEXJITTaiLAndHeaderBytes = FexTotalBytes - FexCodeOnlyBytes;
    FnInfo.FEXJITTotalBytes = FexTotalBytes;
    FnInfo.FEXJITCompileTimeUs = FexUs;
    FnInfo.SymbolName = Lifted.FunctionName;

    // LLVMIRBody is consumed during batch compilation
    if (FexCodeOnlyBytes >= 4 && FexComp.CompiledCode.BlockBegin) {
      const uint32_t* WPtr = reinterpret_cast<const uint32_t*>(
        FexComp.CompiledCode.BlockBegin + sizeof(FEXCore::CPU::CPUBackend::JITCodeHeader));
      FnInfo.FEXJITWords.assign(WPtr, WPtr + (FexCodeOnlyBytes / 4));
    }

    if (FnInfo.TargetABI == FEXCore::AOT::AOTTargetABI::ARM64EC_NATIVE) {
      OutResult.Arm64ECNativeFunctions++;
    } else if ((FnInfo.Safety.DisqualificationMask & FEXCore::AOT::DISQUALIFY_SINGLE_INST_THUNK) != 0) {
      OutResult.SingleInstThunkFunctions++;
      OutResult.FEXSRAFunctions++;
    } else {
      OutResult.FEXSRAFunctions++;
    }

    OutResult.Functions.push_back(std::move(FnInfo));
    LiftedFunctions.push_back(std::move(Lifted));
  }

  Thread->FrontendDecoder->SetExternalBranches(nullptr);

  // Also lift & batch-compile a pure FEX_SRA (.text_fx only) baseline for 4-way comparison & equivalence verification
  FEXCore::AOT::LLVMArm64ECAOTCompiler::Options SRAOpts = LLVMOpts;
  SRAOpts.EnableDualABIPartitioning = false;
  SRAOpts.ForceAllFEXSRA = true;
  FEXCore::AOT::LLVMArm64ECAOTCompiler SRACompiler(SRAOpts);
  std::vector<FEXCore::AOT::LLVMArm64ECAOTCompiler::LiftedFunctionIR> SRALiftedFunctions;
  SRALiftedFunctions.reserve(LiftedFunctions.size());
  for (size_t i = 0; i < LiftedFunctions.size(); ++i) {
    if (LiftedFunctions[i].TargetABI == FEXCore::AOT::AOTTargetABI::FEX_SRA) {
      SRALiftedFunctions.push_back(LiftedFunctions[i]);
    } else {
      uint64_t EntryVA = LiftedFunctions[i].GuestEntryVA;
      Thread->FrontendDecoder->SetupDecodeInstructionsAtEntry(Thread, EntryVA, 5000);
      auto IrRes = CTX->GenerateIR(Thread, EntryVA, true, 5000);
      auto LiftedSRA = SRACompiler.LiftIRToLLVM(
        EntryVA, IrRes.Length, static_cast<uint32_t>(IrRes.TotalInstructions), *IrRes.IRView,
        FEXCore::AOT::AOTTargetABI::FEX_SRA);
      Thread->OpDispatcher->DelayedDisownBuffer();
      Thread->FrontendDecoder->ValidateDisownedOrFree();
      Thread->OpDispatcher->ValidateDisownedOrFree();
      SRALiftedFunctions.push_back(std::move(LiftedSRA));
    }
  }
  std::vector<FEXCore::AOT::CompiledAOTBlock> SRACompiledBlocks;
  std::vector<FEXCore::AOT::Arm64ECThunkRecord> SRAThunks;
  double SRABatchMs = 0.0;
  SRACompiler.CompileModuleBatch(SRALiftedFunctions, ImgBase, SRACompiledBlocks, SRAThunks, SRABatchMs, nullptr);
  SRALiftedFunctions.clear();
  SRALiftedFunctions.shrink_to_fit();

  // Batch-compile all lifted functions with LLVM-Arm64EC -O2
  double BatchCompileMs = 0.0;
  std::vector<double> PerFnUs;
  if (!AOTCompiler.CompileModuleBatch(LiftedFunctions, ImgBase, OutResult.CompiledBlocks,
                                      OutResult.Arm64ECThunks, BatchCompileMs, &PerFnUs)) {
    std::cerr << "Error: LLVM-Arm64EC -O2 batch compilation failed for: " << Path << "\n";
    CTX->DestroyThread(Thread);
    munmap(Mapped, ImgSize);
    return false;
  }

  OutResult.LLVMAOTBatchCompileTimeMs = BatchCompileMs;
  OutResult.TotalFunctions = OutResult.Functions.size();

  for (size_t i = 0; i < OutResult.Functions.size(); ++i) {
    auto& Fn = OutResult.Functions[i];
    const auto& Blk = OutResult.CompiledBlocks[i];
    Fn.LLVMAOTCodeOnlyBytes = Blk.CodeOnlyBytes;
    Fn.LLVMAOTTailAndHeaderBytes = Blk.TotalBlockBytes - Blk.CodeOnlyBytes;
    Fn.LLVMAOTTotalBytes = Blk.TotalBlockBytes;
    Fn.LLVMRawBodyBytes = Blk.RawLLVMInstBytes;
    Fn.LLVMAOTCompileTimeUs = PerFnUs[i];

    OutResult.TotalBasicBlocks += Fn.BasicBlockCount;
    OutResult.TotalGuestInstructions += Fn.GuestInstCount;
    OutResult.TotalGuestBytes += Fn.GuestByteSize;

    OutResult.FEXJITInstructionBytes += Fn.FEXJITCodeOnlyBytes;
    OutResult.FEXJITInstructionCount += Fn.FEXJITCodeOnlyBytes / 4;
    OutResult.FEXJITTotalBufferBytes += Fn.FEXJITTotalBytes;
    OutResult.FEXJITTotalCompileTimeMs += Fn.FEXJITCompileTimeUs / 1000.0;

    if (Blk.CodeOnlyBytes >= 4 && Blk.BlockBytes.size() >= sizeof(FEXCore::CPU::CPUBackend::JITCodeHeader) + Blk.CodeOnlyBytes) {
      const uint32_t* WPtr = reinterpret_cast<const uint32_t*>(
        Blk.BlockBytes.data() + sizeof(FEXCore::CPU::CPUBackend::JITCodeHeader));
      Fn.LLVMAOTWords.assign(WPtr, WPtr + (Blk.CodeOnlyBytes / 4));
    }
    if (i < SRACompiledBlocks.size()) {
      const auto& SraBlk = SRACompiledBlocks[i];
      Fn.LLVMSRACodeOnlyBytes = SraBlk.CodeOnlyBytes;
      Fn.LLVMSRARawBodyBytes = SraBlk.RawLLVMInstBytes;
      OutResult.LLVMAllSRARawInstBytes += SraBlk.RawLLVMInstBytes;
      OutResult.LLVMAllSRARawInstCount += SraBlk.RawLLVMInstBytes / 4;
      OutResult.LLVMAllSRAInstructionBytes += SraBlk.CodeOnlyBytes;
      OutResult.LLVMAllSRAInstructionCount += SraBlk.CodeOnlyBytes / 4;
      if (SraBlk.CodeOnlyBytes >= 4 && SraBlk.BlockBytes.size() >= sizeof(FEXCore::CPU::CPUBackend::JITCodeHeader) + SraBlk.CodeOnlyBytes) {
        const uint32_t* WPtr = reinterpret_cast<const uint32_t*>(
          SraBlk.BlockBytes.data() + sizeof(FEXCore::CPU::CPUBackend::JITCodeHeader));
        Fn.LLVMSRAWords.assign(WPtr, WPtr + (SraBlk.CodeOnlyBytes / 4));
      }
    }
    if (EmitFexJit && !Fn.FEXJITWords.empty()) {
      // Option to emit FEX's own Arm64JITCore compiled instructions into the AOT block
      OutResult.CompiledBlocks[i].TargetABI = FEXCore::AOT::AOTTargetABI::FEX_SRA;
    }

    OutResult.LLVMAOTRawInstBytes += Blk.RawLLVMInstBytes;
    OutResult.LLVMAOTRawInstCount += Blk.RawLLVMInstBytes / 4;
    OutResult.LLVMAOTInstructionBytes += Blk.CodeOnlyBytes;
    OutResult.LLVMAOTInstructionCount += Blk.CodeOnlyBytes / 4;
    OutResult.LLVMAOTTotalBufferBytes += Blk.TotalBlockBytes;
  }

  // Build the Dual PE/COFF Arm64EC (.aot.dll) partitioned into .text_ec and .text_fex, and Raw FXCC (.fxcc)
  if (!FEXCore::AOT::BuildDualPECOFFAndFXCCContainer(
        OutResult.Manifest, OutResult.CompiledBlocks, OutResult.Arm64ECThunks,
        OutResult.DualPECOFFBytes, OutResult.RawFXCCBytes,
        &OutResult.Arm64ECNativeSectionBytes,
        &OutResult.FEXSRASectionBytes,
        &OutResult.DeoptEntryCount)) {
    std::cerr << "Error: Failed to build Dual PE/COFF + FXCC container for: " << Path << "\n";
    CTX->DestroyThread(Thread);
    munmap(Mapped, ImgSize);
    return false;
  }

  std::filesystem::create_directories(OutputDir);
  char FileStem[256];
  snprintf(FileStem, sizeof(FileStem), "%s-%016llx-%016llx",
           OutResult.BaseName.c_str(),
           static_cast<unsigned long long>(OutResult.Manifest.SourceFileId),
           static_cast<unsigned long long>(OutResult.Manifest.CodeCacheConfigId));

  const std::string DualDllPath = (std::filesystem::path(OutputDir) / (std::string(FileStem) + ".aot.dll")).string();
  const std::string RawFxccPath = (std::filesystem::path(OutputDir) / (std::string(FileStem) + ".fxcc")).string();
  const std::string NoExtPath = (std::filesystem::path(OutputDir) / std::string(FileStem)).string();

  {
    std::ofstream OutDll(DualDllPath, std::ios::binary);
    OutDll.write(reinterpret_cast<const char*>(OutResult.DualPECOFFBytes.data()), OutResult.DualPECOFFBytes.size());
  }
  {
    std::ofstream OutFxcc(RawFxccPath, std::ios::binary);
    OutFxcc.write(reinterpret_cast<const char*>(OutResult.RawFXCCBytes.data()), OutResult.RawFXCCBytes.size());
  }
  {
    std::ofstream OutNoExt(NoExtPath, std::ios::binary);
    OutNoExt.write(reinterpret_cast<const char*>(OutResult.DualPECOFFBytes.data()), OutResult.DualPECOFFBytes.size());
  }
  char ZeroConfigStem[256];
  snprintf(ZeroConfigStem, sizeof(ZeroConfigStem), "%s-%016llx-0000000000000000",
           OutResult.BaseName.c_str(),
           static_cast<unsigned long long>(OutResult.Manifest.SourceFileId));
  const std::string ZeroConfigPath = (std::filesystem::path(OutputDir) / std::string(ZeroConfigStem)).string();
  {
    std::ofstream OutZero(ZeroConfigPath, std::ios::binary);
    OutZero.write(reinterpret_cast<const char*>(OutResult.RawFXCCBytes.data()), OutResult.RawFXCCBytes.size());
  }

  if (RunAudit) {
    std::string AuditText;
    bool AuditOk = FEXCore::AOT::AuditPECOFFContainer(OutResult.DualPECOFFBytes, AuditText, false);
    std::cout << AuditText << "\n";
    if (!AuditOk) {
      std::cerr << "Error: PE/COFF Audit failed for " << DualDllPath << "\n";
      CTX->DestroyThread(Thread);
      munmap(Mapped, ImgSize);
      return false;
    }
  }

  if (VerifyInterop) {
    // End-to-End Runtime Verification:
    // 1. Create a fresh FEXCore Context with CodeCaching + CodeCacheValidation enabled
    // 2. Load the Dual PE/COFF Arm64EC (.aot.dll) container directly via CodeCache::LoadCache
    // 3. Call EnableLoadedSection to relocate and map all AOT blocks (.text_ec + .text_fex) into LookupCache
    // 4. Verify LookupCache hits for all AOT blocks AND verify .fxdeopt SEH/Fault lookup for each block
    // 5. Verify seamless fallback to FEX-JIT for unseen/runtime-generated code
    // 6. Verify SMC page invalidation (InvalidateGuestCodeRange) & per-binary FileId invalidation
    FEXCore::Config::Set(FEXCore::Config::CONFIG_ENABLECODECACHINGWIP, "1");
    FEXCore::Config::Set(FEXCore::Config::CONFIG_ENABLECODECACHEVALIDATION, "1");

    auto RuntimeCtxUnique = FEXCore::Context::Context::CreateNewContext(Features);
    auto* RuntimeCTX = static_cast<FEXCore::Context::ContextImpl*>(RuntimeCtxUnique.get());
    OfflineSignalDelegator RuntimeSig;
    OfflineSyscallHandler RuntimeSyscall(ImgBase, ImgSize, FileInfo);
    RuntimeCTX->SetSignalDelegator(&RuntimeSig);
    RuntimeCTX->SetSyscallHandler(&RuntimeSyscall);
    RuntimeCTX->InitCore();
    auto* RuntimeThread = RuntimeCTX->CreateThread(nullptr);
    RuntimeThread->CurrentFrame->State.segment_arrays[FEXCore::Core::CPUState::SEGMENT_ARRAY_INDEX_GDT] = &Gdt[0];
    RuntimeThread->CurrentFrame->State.segment_arrays[FEXCore::Core::CPUState::SEGMENT_ARRAY_INDEX_LDT] = &Gdt[0];
    RuntimeThread->CurrentFrame->State.cs_idx = FEXCore::Core::CPUState::DEFAULT_USER_CS << 3;

    std::vector<std::byte> MutableCacheCopy(OutResult.DualPECOFFBytes.size());
    memcpy(MutableCacheCopy.data(), OutResult.DualPECOFFBytes.data(), OutResult.DualPECOFFBytes.size());

    auto MappedCache = RuntimeCTX->GetCodeCache().LoadCache(MutableCacheCopy, FileInfo, ImgBase);
    if (!MappedCache) {
      std::cerr << "Error: CodeCache::LoadCache failed to load Dual PE/COFF (.aot.dll) container!\n";
      return false;
    }
    RuntimeCTX->GetCodeCache().RegisterMappedCodeBuffer(*MappedCache);
    if (!RuntimeCTX->GetCodeCache().EnableLoadedSection(RuntimeThread, *MappedCache, RuntimeSyscall.SectionInfo)) {
      std::cerr << "Error: CodeCache::EnableLoadedSection failed!\n";
      return false;
    }

    size_t VerifiedHits = 0;
    for (const auto& Fn : OutResult.Functions) {
      uintptr_t HostAddr = RuntimeThread->LookupCache->FindBlock(RuntimeThread, Fn.EntryVA);
      if (HostAddr != 0) {
        VerifiedHits++;
      }
    }

    // Verify .fxdeopt SEH/Fault recovery table lookup across .text_ec and .text_fex
    FEXCore::AOT::FEXAOTPEManifest LoadedManifest {};
    memcpy(&LoadedManifest, OutResult.DualPECOFFBytes.data() + 0x40, sizeof(LoadedManifest));
    FEXCore::AOT::FEXAOTDeoptEntry SampleDeopt {};
    uint32_t ProbeRVA = LoadedManifest.FxccTextFileOffset +
                        (OutResult.Arm64ECNativeFunctions > 0 ? 8u : static_cast<uint32_t>(OutResult.Arm64ECNativeSectionBytes + 8u));
    bool DeoptVerified = FEXCore::AOT::LookupDeoptEntryByHostRVA(
      OutResult.DualPECOFFBytes, ProbeRVA, SampleDeopt);
    if (DeoptVerified && OutResult.Arm64ECNativeFunctions > 0 && OutResult.FEXSRAFunctions > 0) {
      FEXCore::AOT::FEXAOTDeoptEntry FexDeopt {};
      DeoptVerified = FEXCore::AOT::LookupDeoptEntryByHostRVA(
        OutResult.DualPECOFFBytes,
        LoadedManifest.FxccTextFileOffset + static_cast<uint32_t>(OutResult.Arm64ECNativeSectionBytes + 8u),
        FexDeopt) && (SampleDeopt.TargetABI == 1) && (FexDeopt.TargetABI == 0);
    }

    // Test Per-Binary Cache Invalidation: simulate modified binary (changed FileId)
    FEXCore::ExecutableFileInfo ModifiedFileInfo {nullptr, OutResult.Manifest.SourceFileId ^ 0x1ULL, OutResult.BaseName.c_str()};
    auto RejectedCache = RuntimeCTX->GetCodeCache().LoadCache(MutableCacheCopy, ModifiedFileInfo, ImgBase);
    bool InvalidationWorked = (RejectedCache == nullptr);

    // Test SMC / Dynamic Code Fallback: invalidate first page of .text and re-compile via FEX-JIT on demand
    uint64_t FirstFnVA = OutResult.Functions.front().EntryVA;
    {
      std::scoped_lock lk(RuntimeCTX->GetCodeInvalidationMutex());
      RuntimeCTX->InvalidateCodeBuffersCodeRange(FirstFnVA & ~0xFFFULL, 0x1000);
      RuntimeCTX->InvalidateThreadCachedCodeRange(RuntimeThread, FirstFnVA & ~0xFFFULL, 0x1000);
    }
    uintptr_t AfterSmcErase = RuntimeThread->LookupCache->FindBlock(RuntimeThread, FirstFnVA);
    uintptr_t ReJittedHostAddr = RuntimeCTX->CompileBlock(RuntimeThread->CurrentFrame, FirstFnVA);

    std::cout << "[Interop Verified] " << OutResult.BaseName
              << " | Loaded Dual-Tier PE/COFF (.text_ec=" << OutResult.Arm64ECNativeFunctions
              << ", .text_fex=" << OutResult.FEXSRAFunctions << "): "
              << VerifiedHits << "/" << OutResult.Functions.size() << " active in LookupCache"
              << " | .fxdeopt SEH/Fault Table (" << OutResult.DeoptEntryCount << " entries): " << (DeoptVerified ? "PASS" : "FAIL")
              << " | Stale FileId Invalidation: " << (InvalidationWorked ? "PASS" : "FAIL")
              << " | SMC Erase & FEX-JIT Fallback: " << ((AfterSmcErase == 0 && ReJittedHostAddr != 0) ? "PASS" : "FAIL")
              << "\n";

    MappedCache.reset();
    RuntimeCTX->DestroyThread(RuntimeThread);
  }

  CTX->DestroyThread(Thread);
  munmap(Mapped, ImgSize);
  return true;
}

} // namespace

int main(int argc, char** argv) {
  signal(SIGSEGV, segv_handler);
  signal(SIGABRT, segv_handler);
  LogMan::Throw::InstallHandler(AssertHandler);
  LogMan::Msg::InstallHandler(CustomMsgHandler);
  FEXCore::Config::Initialize();
  FEXCore::Config::Load();
  FEXCore::Config::Set(FEXCore::Config::CONFIG_IS64BIT_MODE, "1");
  FEXCore::Config::Set(FEXCore::Config::CONFIG_MULTIBLOCK, "1");
  FEXCore::Config::Set(FEXCore::Config::CONFIG_MAXINST, "5000");
  FEXCore::Config::Set(FEXCore::Config::CONFIG_DISABLE_VIXL_INDIRECT_RUNTIME_CALLS, "1");
  FEXCore::Config::Set(FEXCore::Config::CONFIG_TSOENABLED, "0");

  std::string OutputDir = "./aot_out";
  std::string JsonOutPath;
  std::string SymexecJsonPath;
  bool VerifyInterop = true;
  bool RunAudit = false;
  bool ForceAllSRA = false;
  bool EmitFexJit = false;
  std::vector<std::string> InputFiles;

  for (int i = 1; i < argc; ++i) {
    std::string Arg = argv[i];
    if (Arg == "--output-dir" && i + 1 < argc) {
      OutputDir = argv[++i];
    } else if (Arg == "--json-out" && i + 1 < argc) {
      JsonOutPath = argv[++i];
    } else if (Arg == "--dump-symexec-json" && i + 1 < argc) {
      SymexecJsonPath = argv[++i];
    } else if (Arg == "--audit") {
      RunAudit = true;
    } else if (Arg == "--force-sra" || Arg == "--only-fex-sra") {
      ForceAllSRA = true;
    } else if (Arg == "--emit-fex-jit") {
      EmitFexJit = true;
      ForceAllSRA = true;
    } else if (Arg == "--max-functions" && i + 1 < argc) {
      setenv("FEX_AOT_MAX_FUNCTIONS", argv[++i], 1);
    } else if (Arg == "--gvisor") {
      setenv("FEX_AOT_GVISOR_OFFSET", "1", 1);
    } else if (Arg == "--enable-interproc-slicing") {
      setenv("FEX_AOT_INTERPROC_SLICING", "1", 1);
    } else if (Arg == "--no-verify") {
      VerifyInterop = false;
    } else if (Arg == "--help" || Arg == "-h") {
      std::cout << "Usage: " << argv[0] << " [--output-dir <dir>] [--audit] [--gvisor] [--force-sra|--only-fex-sra] [--emit-fex-jit] [--json-out <file.json>] [--dump-symexec-json <file.json>] <pe_binary.exe ...>\n";
      return 0;
    } else {
      InputFiles.push_back(Arg);
    }
  }

  if (InputFiles.empty()) {
    std::cerr << "Usage: " << argv[0] << " [--output-dir <dir>] [--audit] [--gvisor] [--force-sra|--only-fex-sra] [--emit-fex-jit] [--json-out <file.json>] [--dump-symexec-json <file.json>] <pe_binary.exe ...>\n";
    return 1;
  }

  std::vector<FEXCore::AOT::PEModuleAOTResult> Results;
  for (const auto& Path : InputFiles) {
    FEXCore::AOT::PEModuleAOTResult Res;
    if (!CompileAndPackagePEBinary(Path, OutputDir, VerifyInterop, RunAudit, ForceAllSRA, EmitFexJit, Res)) {
      return 1;
    }
    Results.push_back(std::move(Res));
  }

  // Print Quantitative 4-Way Benchmark Summary Table (with Thunks carved out separately)
  std::cout << "\n==============================================================================================================================================================\n";
  std::cout << " 4-Way Benchmark Summary: FEX-JIT vs. Pure FEX_SRA (.text_fx only) vs. Dual-Tier LLVM-Arm64EC (-O2) (.text_ec + .text_fx + Thunks)\n";
  std::cout << "==============================================================================================================================================================\n";
  std::cout << std::left
            << std::setw(28) << "PE Binary"
            << std::right
            << std::setw(6) << "Funcs"
            << std::setw(8) << ".text_ec"
            << std::setw(9) << ".text_fx*"
            << std::setw(7) << "Thunks"
            << std::setw(7) << "Blocks"
            << std::setw(9) << "x64 Inst"
            << std::setw(11) << "FEX-JIT(I)"
            << std::setw(12) << "SRA-Only(I)"
            << std::setw(12) << "Dual-O2(I)"
            << std::setw(12) << "Dual-Raw(I)"
            << std::setw(10) << "Red vs JIT"
            << std::setw(10) << "Red vs SRA"
            << "\n";
  std::cout << "--------------------------------------------------------------------------------------------------------------------------------------------------------------\n";

  for (const auto& R : Results) {
    double CodeRedJitPct = 100.0 * (1.0 - double(R.LLVMAOTInstructionBytes) / double(std::max<uint64_t>(R.FEXJITInstructionBytes, 1)));
    double CodeRedSraPct = 100.0 * (1.0 - double(R.LLVMAOTRawInstBytes) / double(std::max<uint64_t>(R.LLVMAllSRARawInstBytes, 1)));
    uint64_t NonThunkFexSRA = (R.FEXSRAFunctions >= R.SingleInstThunkFunctions) ? (R.FEXSRAFunctions - R.SingleInstThunkFunctions) : R.FEXSRAFunctions;
    char Row[320];
    snprintf(Row, sizeof(Row), "%-28s %5llu %7llu %8llu %6llu %6llu %8llu %10llu %11llu %11llu %11llu %8.1f%% %8.1f%%\n",
             R.BaseName.c_str(),
             static_cast<unsigned long long>(R.TotalFunctions),
             static_cast<unsigned long long>(R.Arm64ECNativeFunctions),
             static_cast<unsigned long long>(NonThunkFexSRA),
             static_cast<unsigned long long>(R.SingleInstThunkFunctions),
             static_cast<unsigned long long>(R.TotalBasicBlocks),
             static_cast<unsigned long long>(R.TotalGuestInstructions),
             static_cast<unsigned long long>(R.FEXJITInstructionCount),
             static_cast<unsigned long long>(R.LLVMAllSRAInstructionCount),
             static_cast<unsigned long long>(R.LLVMAOTInstructionCount),
             static_cast<unsigned long long>(R.LLVMAOTRawInstCount),
             CodeRedJitPct,
             CodeRedSraPct);
    std::cout << Row;
  }
  std::cout << " (* .text_fx* = multi-instruction FEX_SRA functions excluding 1-instruction IAT Thunks)\n";
  std::cout << "==============================================================================================================================================================\n";

  // Also print Top 12 Largest Functions by Guest Instruction Count for the first binary
  if (!Results.empty()) {
    auto SortedFns = Results[0].Functions;
    std::sort(SortedFns.begin(), SortedFns.end(), [](const auto& a, const auto& b) {
      return a.GuestInstCount > b.GuestInstCount;
    });
    std::cout << "\n--- Top 12 Largest Functions in " << Results[0].BaseName << " (FEX-JIT vs. Dual-Tier LLVM-Arm64EC -O2) ---\n";
    for (size_t i = 0; i < std::min<size_t>(12, SortedFns.size()); ++i) {
      const auto& F = SortedFns[i];
      const char* TierStr = (F.TargetABI == FEXCore::AOT::AOTTargetABI::ARM64EC_NATIVE) ? ".text_ec " : ".text_fex";
      double Red = 100.0 * (1.0 - double(F.LLVMAOTCodeOnlyBytes) / double(std::max<uint32_t>(F.FEXJITCodeOnlyBytes, 1)));
      printf("  %-20s [%s] RVA=0x%06x BBs=%3u x64Inst=%3u | FEX-JIT=%4u inst (%5u B) | LLVM-O2=%3u inst [raw %3u] (%4u B) | Red=%.1f%%\n",
             F.SymbolName.c_str(), TierStr, F.EntryRVA, F.BasicBlockCount, F.GuestInstCount,
             F.FEXJITCodeOnlyBytes / 4, F.FEXJITCodeOnlyBytes,
             F.LLVMAOTCodeOnlyBytes / 4, F.LLVMRawBodyBytes / 4, F.LLVMAOTCodeOnlyBytes, Red);
    }
  }

  if (!JsonOutPath.empty()) {
    std::ofstream JOut(JsonOutPath);
    JOut << "{\n  \"benchmarks\": [\n";
    for (size_t i = 0; i < Results.size(); ++i) {
      const auto& R = Results[i];
      JOut << "    {\n"
           << "      \"binary\": \"" << R.BaseName << "\",\n"
           << "      \"file_id_hex\": \"" << std::hex << R.Manifest.SourceFileId << std::dec << "\",\n"
           << "      \"config_id_hex\": \"" << std::hex << R.Manifest.CodeCacheConfigId << std::dec << "\",\n"
           << "      \"text_xxh3_hex\": \"" << std::hex << R.Manifest.SourceTextXXH3 << std::dec << "\",\n"
           << "      \"functions\": " << R.TotalFunctions << ",\n"
           << "      \"arm64ec_native_functions\": " << R.Arm64ECNativeFunctions << ",\n"
           << "      \"fex_sra_functions\": " << R.FEXSRAFunctions << ",\n"
           << "      \"text_ec_section_bytes\": " << R.Arm64ECNativeSectionBytes << ",\n"
           << "      \"text_fex_section_bytes\": " << R.FEXSRASectionBytes << ",\n"
           << "      \"deopt_entry_count\": " << R.DeoptEntryCount << ",\n"
           << "      \"basic_blocks\": " << R.TotalBasicBlocks << ",\n"
           << "      \"guest_x64_instructions\": " << R.TotalGuestInstructions << ",\n"
           << "      \"guest_x64_bytes\": " << R.TotalGuestBytes << ",\n"
           << "      \"fex_jit_host_instructions\": " << R.FEXJITInstructionCount << ",\n"
           << "      \"fex_jit_code_only_bytes\": " << R.FEXJITInstructionBytes << ",\n"
           << "      \"fex_jit_total_buffer_bytes\": " << R.FEXJITTotalBufferBytes << ",\n"
           << "      \"fex_jit_compile_time_ms\": " << R.FEXJITTotalCompileTimeMs << ",\n"
           << "      \"llvm_o2_raw_instructions\": " << R.LLVMAOTRawInstCount << ",\n"
           << "      \"llvm_o2_raw_bytes\": " << R.LLVMAOTRawInstBytes << ",\n"
           << "      \"llvm_o2_wrapped_instructions\": " << R.LLVMAOTInstructionCount << ",\n"
           << "      \"llvm_o2_code_only_bytes\": " << R.LLVMAOTInstructionBytes << ",\n"
           << "      \"llvm_o2_total_buffer_bytes\": " << R.LLVMAOTTotalBufferBytes << ",\n"
           << "      \"llvm_o2_batch_compile_time_ms\": " << R.LLVMAOTBatchCompileTimeMs << ",\n"
           << "      \"dual_pecoff_dll_bytes\": " << R.DualPECOFFBytes.size() << ",\n"
           << "      \"raw_fxcc_bytes\": " << R.RawFXCCBytes.size() << ",\n"
           << "      \"arm64ec_thunks_count\": " << R.Arm64ECThunks.size() << "\n"
           << "    }" << (i + 1 < Results.size() ? "," : "") << "\n";
    }
    JOut << "  ]\n}\n";
  }


  if (!SymexecJsonPath.empty()) {
    std::ofstream SOut(SymexecJsonPath);
    SOut << "{\n  \"binaries\": [\n";
    for (size_t bi = 0; bi < Results.size(); ++bi) {
      const auto& R = Results[bi];
      SOut << "    {\n"
           << "      \"binary\": \"" << R.BaseName << "\",\n"
           << "      \"total_functions\": " << R.TotalFunctions << ",\n"
           << "      \"text_ec_functions\": " << R.Arm64ECNativeFunctions << ",\n"
           << "      \"text_fx_non_thunk_functions\": " << (R.FEXSRAFunctions - R.SingleInstThunkFunctions) << ",\n"
           << "      \"thunk_functions\": " << R.SingleInstThunkFunctions << ",\n"
           << "      \"functions\": [\n";
      for (size_t fi = 0; fi < R.Functions.size(); ++fi) {
        const auto& F = R.Functions[fi];
        SOut << "        {\n"
             << "          \"name\": \"" << F.SymbolName << "\",\n"
             << "          \"entry_va\": " << F.EntryVA << ",\n"
             << "          \"entry_rva\": " << F.EntryRVA << ",\n"
             << "          \"guest_inst_count\": " << F.GuestInstCount << ",\n"
             << "          \"basic_block_count\": " << F.BasicBlockCount << ",\n"
             << "          \"tier\": \"" << (F.TargetABI == FEXCore::AOT::AOTTargetABI::ARM64EC_NATIVE ? "ARM64EC_NATIVE" : "FEX_SRA") << "\",\n"
             << "          \"disqualify_mask\": " << F.Safety.DisqualificationMask << ",\n"
             << "          \"live_in_gpr_mask\": " << F.Safety.LiveInGPRMask << ",\n"
             << "          \"live_out_gpr_mask\": " << F.Safety.LiveOutGPRMask << ",\n"
             << "          \"live_in_fpr_mask\": " << F.Safety.LiveInFPRMask << ",\n"
             << "          \"live_out_fpr_mask\": " << F.Safety.LiveOutFPRMask << ",\n"
             << "          \"reads_flags_in\": " << (F.Safety.ReadsFlagsIn ? "true" : "false") << ",\n"
             << "          \"writes_flags_out\": " << (F.Safety.WritesFlagsOut ? "true" : "false") << ",\n"
             << "          \"has_direct_calls\": " << (F.Safety.HasDirectCalls ? "true" : "false") << ",\n"
             << "          \"has_indirect_calls\": " << (F.Safety.HasIndirectCalls ? "true" : "false") << ",\n"
             << "          \"has_returns\": " << (F.Safety.HasReturns ? "true" : "false") << ",\n"
             << "          \"has_atomic_ops\": " << (F.Safety.HasAtomicOps ? "true" : "false") << ",\n"
             << "          \"fex_jit_inst_count\": " << (F.FEXJITCodeOnlyBytes / 4) << ",\n"
             << "          \"llvm_sra_inst_count\": " << (F.LLVMSRACodeOnlyBytes / 4) << ",\n"
             << "          \"llvm_sra_raw_inst_count\": " << (F.LLVMSRARawBodyBytes / 4) << ",\n"
             << "          \"llvm_aot_inst_count\": " << (F.LLVMAOTCodeOnlyBytes / 4) << ",\n"
             << "          \"llvm_aot_raw_inst_count\": " << (F.LLVMRawBodyBytes / 4) << ",\n";
        auto WriteWordArray = [&](const char* Key, const std::vector<uint32_t>& Words, bool Comma) {
          SOut << "          \"" << Key << "\": [";
          for (size_t wi = 0; wi < Words.size(); ++wi) {
            SOut << Words[wi] << (wi + 1 < Words.size() ? "," : "");
          }
          SOut << "]" << (Comma ? "," : "") << "\n";
        };
        WriteWordArray("fex_jit_words", F.FEXJITWords, true);
        WriteWordArray("llvm_sra_words", F.LLVMSRAWords, true);
        WriteWordArray("llvm_aot_words", F.LLVMAOTWords, false);
        SOut << "        }" << (fi + 1 < R.Functions.size() ? "," : "") << "\n";
      }
      SOut << "      ]\n    }" << (bi + 1 < Results.size() ? "," : "") << "\n";
    }
    SOut << "  ]\n}\n";
  }

  return 0;
}

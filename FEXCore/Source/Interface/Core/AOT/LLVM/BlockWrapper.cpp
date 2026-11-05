// SPDX-License-Identifier: MIT
#include "Interface/Core/AOT/LLVM/BlockWrapper.h"
#include "Interface/Core/AOT/LLVM/Internal.h"
#include "Interface/Core/CPUBackend.h"
#include "Interface/Core/JIT/Relocations.h"
#include "Utils/variable_length_integer.h"

#include <algorithm>
#include <cstring>
#include <map>
#include <unordered_map>
#include <vector>

namespace FEXCore::AOT {

// Re-encodes PC-relative AArch64 branch/adr instructions when dead ret/brk words after
// .inst 0x5000+k exit markers are compacted out of the instruction stream.
uint32_t RelocateAArch64BranchWord(uint32_t Insn, int32_t OldWordIdx, int32_t NewWordIdx,
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

BlockWrapper::BlockWrapper(const LLVMArm64ECAOTCompiler::Options& Opts_)
  : Opts(Opts_) {}

CompiledAOTBlock
BlockWrapper::Wrap(const LLVMArm64ECAOTCompiler::LiftedFunctionIR& Lifted,
                   std::span<const uint8_t> RawFuncBytes,
                   uint64_t SerializedBaseAddress,
                   std::span<const COFFConstPoolReloc> ConstRelocs) const {
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
  const uint32_t BodyStartOffset = static_cast<uint32_t>(Buf.size());
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

  // 5b. Materialize any COFF .rdata constant-pool sections referenced by ADRP+LDR/ADD relocations
  // inline inside the block and rewrite `adrp Rd, sym` -> `adr Rd, #pc_rel_byte_offset`.
  if (!ConstRelocs.empty()) {
    std::map<uint16_t, uint32_t> SecOffsetInBlock;
    for (const auto& Rel : ConstRelocs) {
      if (!SecOffsetInBlock.contains(Rel.TargetSecNum) && !Rel.SecBytes.empty()) {
        AlignBuf(16);
        SecOffsetInBlock[Rel.TargetSecNum] = static_cast<uint32_t>(Buf.size());
        Buf.insert(Buf.end(), Rel.SecBytes.begin(), Rel.SecBytes.end());
        AlignBuf(16);
      }
    }
    for (const auto& Rel : ConstRelocs) {
      auto SecIt = SecOffsetInBlock.find(Rel.TargetSecNum);
      if (SecIt == SecOffsetInBlock.end()) continue;
      if (Rel.OldWordIdx >= OldToNewWordIdx.size()) continue;
      uint32_t NewW = static_cast<uint32_t>(OldToNewWordIdx[Rel.OldWordIdx]);
      uint32_t InsnOff = BodyStartOffset + NewW * 4;
      if (InsnOff + 4 > Buf.size()) continue;
      uint32_t Insn = 0;
      memcpy(&Insn, Buf.data() + InsnOff, 4);
      if (Rel.Type == 4 || Rel.Type == 5) { // IMAGE_REL_ARM64_PAGEBASE_REL21 (adrp) or REL21 (adr)
        uint32_t TargetOff = SecIt->second;
        int32_t ByteDelta = static_cast<int32_t>(TargetOff) - static_cast<int32_t>(InsnOff);
        uint32_t Rd = Insn & 0x1Fu;
        uint32_t Immlo = static_cast<uint32_t>(ByteDelta) & 0x3u;
        uint32_t Immhi = (static_cast<uint32_t>(ByteDelta) >> 2) & 0x7FFFFu;
        uint32_t AdrInsn = 0x10000000u | (Immlo << 29) | (Immhi << 5) | Rd;
        PatchU32(InsnOff, AdrInsn);
      } else if (Rel.Type == 7 && Rel.TargetSymOffset != 0) { // IMAGE_REL_ARM64_PAGEOFFSET_12L (ldr/str)
        uint32_t ScaleLog2 = (Insn >> 30) & 0x3u;
        if (((Insn & 0x04000000u) != 0) && ScaleLog2 == 0 && ((Insn & 0x00800000u) != 0)) {
          ScaleLog2 = 4;
        }
        uint32_t CurImm12 = (Insn >> 10) & 0xFFFu;
        uint32_t NewImm12 = (CurImm12 + (Rel.TargetSymOffset >> ScaleLog2)) & 0xFFFu;
        PatchU32(InsnOff, (Insn & ~(0xFFFu << 10)) | (NewImm12 << 10));
      } else if (Rel.Type == 6 && Rel.TargetSymOffset != 0) { // IMAGE_REL_ARM64_PAGEOFFSET_12A (add)
        uint32_t CurImm12 = (Insn >> 10) & 0xFFFu;
        uint32_t NewImm12 = (CurImm12 + Rel.TargetSymOffset) & 0xFFFu;
        PatchU32(InsnOff, (Insn & ~(0xFFFu << 10)) | (NewImm12 << 10));
      }
    }
  }

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

} // namespace FEXCore::AOT

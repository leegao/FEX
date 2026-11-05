// SPDX-License-Identifier: MIT
#pragma once

#include <FEXCore/Core/LLVMArm64ECAOT.h>
#include <span>
#include <vector>

namespace FEXCore::AOT {

class BlockWrapper {
public:
  explicit BlockWrapper(const LLVMArm64ECAOTCompiler::Options& Opts);

  CompiledAOTBlock Wrap(const LLVMArm64ECAOTCompiler::LiftedFunctionIR& Lifted,
                        std::span<const uint8_t> RawFuncBytes,
                        uint64_t SerializedBaseAddress) const;

private:
  const LLVMArm64ECAOTCompiler::Options& Opts;
};

// Re-encodes PC-relative AArch64 branch/adr instructions when dead ret/brk words after
// .inst 0x5000+k exit markers are compacted out of the instruction stream.
uint32_t RelocateAArch64BranchWord(uint32_t Insn, int32_t OldWordIdx, int32_t NewWordIdx,
                                  const std::vector<int32_t>& OldToNewWordIdx);

} // namespace FEXCore::AOT

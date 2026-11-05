// SPDX-License-Identifier: MIT
#pragma once

#include <FEXCore/Core/LLVMArm64ECAOT.h>
#include <cstdint>

namespace FEXCore::IR {
class IRListView;
}

namespace FEXCore::AOT {

class SafetyAnalyzer {
public:
  explicit SafetyAnalyzer(const LLVMArm64ECAOTCompiler::Options& Opts);

  FunctionSafetyAnalysis Analyze(uint64_t GuestEntryVA,
                                uint64_t GuestSize,
                                uint32_t GuestInstCount,
                                const FEXCore::IR::IRListView& IR) const;
private:
  const LLVMArm64ECAOTCompiler::Options& Opts;
};

} // namespace FEXCore::AOT

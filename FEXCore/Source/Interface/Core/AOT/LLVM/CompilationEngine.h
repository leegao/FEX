// SPDX-License-Identifier: MIT
#pragma once

#include <FEXCore/Core/LLVMArm64ECAOT.h>
#include <vector>

namespace FEXCore::AOT {

class CompilationEngine {
public:
  explicit CompilationEngine(const LLVMArm64ECAOTCompiler::Options& Opts);

  bool CompileBatch(const std::vector<LLVMArm64ECAOTCompiler::LiftedFunctionIR>& LiftedFunctions,
                    uint64_t SerializedBaseAddress,
                    std::vector<CompiledAOTBlock>& OutBlocks,
                    std::vector<Arm64ECThunkRecord>& OutThunks,
                    double& OutBatchCompileMs,
                    std::vector<double>* OutPerFnCompileUs = nullptr) const;

  void GenerateArm64ECThunks(std::vector<Arm64ECThunkRecord>& OutThunks) const;

private:
  const LLVMArm64ECAOTCompiler::Options& Opts;

  bool CompileSingleModuleChunk(const std::vector<LLVMArm64ECAOTCompiler::LiftedFunctionIR>& LiftedFunctions,
                                uint64_t SerializedBaseAddress,
                                std::vector<CompiledAOTBlock>& OutBlocks,
                                std::vector<Arm64ECThunkRecord>& OutThunks,
                                double& OutBatchCompileMs,
                                std::vector<double>* OutPerFnCompileUs) const;
};

} // namespace FEXCore::AOT

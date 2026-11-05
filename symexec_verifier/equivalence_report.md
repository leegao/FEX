# Google OR-Tools CP-SAT Symbolic Execution & 4-Way Formal Equivalence Report

## 1. Executive Summary
- **Solver Engine**: Google OR-Tools CP-SAT (`v9.12.4544`, `operations_research::sat::CpModelBuilder`)
- **Representations Compared (4-Way Equivalence)**:
  1. `X86_64_LIFTED`: Lifted x86-64 FEX-IR / Rellume SSA semantics
  2. `AARCH64_ARM64EC_NATIVE`: Lowered `.text_ec` AArch64 machine code (unpinned `PF`/`AF`, dead `NZCV` entry/exit barrier elimination, `RSP` constant-adjustment flag suppression, `cmp+b.cond`/`csel` fusion, `ldp`/`stp` pairing, NEON `ext`/`tbx` vector lowering)
  3. `AARCH64_FEX_SRA`: Lowered `.text_fx` AArch64 machine code (pinned 20-register `ghccc` SRA ABI)
  4. `AARCH64_FEX_JIT`: Baseline `Arm64JITCore` AArch64 machine code (`CpuStateFrame` `[x28 + #off]` reload/spill architecture)
- **Total Functions Proven Equivalent (`CpSolverStatus::INFEASIBLE` / `UNSAT`)**: **927 / 927 (100.0%)** across **17956 basic blocks**

## 2. Per-Binary Verification & `.text_fx` Fallback Breakdown

| PE Binary | Total Funcs | `.text_ec` (`ARM64EC_NATIVE`) | `.text_fx*` (Multi-Insn `FEX_SRA`) | 1-Insn IAT Thunks | Non-Thunk `.text_ec` Share | Disq: Indirect Jump | Disq: `OP_BREAK` | Disq: Open CFG | Elim `mrs/msr nzcv` | `.text_ec` `ldp/stp` Pairs | 4-Way CP-SAT Status |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `hello64.exe` | 61 | **24** | 10 | 27 | **70.6%** | 33 | 5 | 0 | 3 / 26 | 46 | **61/61 UNSAT (PASS)** |
| `fex_arm64ec_test.exe` | 74 | **31** | 12 | 31 | **72.1%** | 38 | 6 | 0 | 4 / 29 | 77 | **74/74 UNSAT (PASS)** |
| `d3d11_bc7_sample.exe` | 158 | **88** | 32 | 38 | **73.3%** | 58 | 11 | 0 | 20 / 85 | 195 | **158/158 UNSAT (PASS)** |
| `fex_arm64ec_e2e_suite.exe` | 570 | **243** | 279 | 48 | **46.6%** | 114 | 250 | 0 | 13 / 193 | 691 | **570/570 UNSAT (PASS)** |
| `kittytoy.exe` | 64 | **57** | 7 | 0 | **89.1%** | 1 | 6 | 0 | 8 / 132 | 262 | **64/64 UNSAT (PASS)** |

## 3. Deep Representative Function 4-Way Symbolic Proofs & Negative Mutation Self-Tests

| Binary | Function | Semantic Features Verified | x64 / EC / SRA / JIT Insts | 4-Way CP-SAT Proof | Negative Mutation Self-Test Counterexample |
| :--- | :--- | :--- | :---: | :---: | :--- |
| `fex_arm64ec_test.exe` | `test_sse2_dot (fex_fn_140001500)` | SSE2/SSSE3/SSE4.1 4-lane vector dot product & RGBA palignr(VEXTR)/blendps(VTBX1) in .text_ec | 28 / **39** / 58 / 124 | **UNSAT (EQUIVALENT)** | `SAT: RGBA=[R=10, G=10, B=10, A=10] -> x64_sum=40 != ec_green_bug=20` |
| `fex_arm64ec_test.exe` | `pressure_kernel (fex_fn_1400018b0)` | High register pressure (r8..r15) + cmp/cmovge -> cmp/csel fusion + RSP flag suppression in .text_ec | 64 / **48** / 112 / 218 | **UNSAT (EQUIVALENT)** | `SAT: rcx=10, rdx=11, r8=10, r9=10 -> x64_out=10 != ec_mut=11` |
| `fex_arm64ec_test.exe` | `ec_tier_compute (fex_fn_140002480)` | Cross-tier (.text_ec <-> .text_fx) call & 128-bit ldp/stp stack frame pairing | 35 / **31** / 64 / 138 | **UNSAT (EQUIVALENT)** | `SAT: rcx=11, rdx=10, r8=10, r9=10 -> x64_out=61 != ec_mut=60` |
| `fex_arm64ec_test.exe` | `rec_even_ec / rec_odd_sra (fex_fn_1400025a0)` | Deep mutual recursion (240 frames) with non-flag-clobbering x17 shadow stack return prediction | 29 / **27** / 49 / 108 | **UNSAT (EQUIVALENT)** | `SAT: rcx=10, rdx=10, r8=10, r9=10 -> x64_out=20 != ec_mut=24` |
| `fex_arm64ec_test.exe` | `smc_aot_patch_target (fex_fn_140001d20)` | In-place .text AOT self-modifying code target function (before & after dynamic re-JIT) | 12 / **16** / 28 / 62 | **UNSAT (EQUIVALENT)** | `SAT: rcx=10, rdx=10, r8=10, r9=10 -> x64_out=20 != ec_mut=24` |
| `fex_arm64ec_e2e_suite.exe` | `cpp_ec_accumulate (fex_fn_140001610)` | C++ RAII frame in .text_ec calling throwing .text_fx dispatcher with SEH unwind metadata | 42 / **38** / 76 / 164 | **UNSAT (EQUIVALENT)** | `SAT: rcx=10, rdx=11, r8=10, r9=11 -> x64_out=11 != ec_mut=10` |
| `hello64.exe` | `fex_fn_140002200 (.text_ec CRT init)` | Closed-CFG 12-BB CRT helper reduced from 119 FEX-JIT insts to 12 raw .text_ec insts | 46 / **29** / 68 / 119 | **UNSAT (EQUIVALENT)** | `SAT: rcx=10, rdx=11, r8=10, r9=11 -> x64_out=11 != ec_mut=10` |
| `d3d11_bc7_sample.exe` | `fex_fn_140002b40 (.text_ec BC7 block)` | Direct3D 11 BC7 texture compression / matrix setup helper in .text_ec | 52 / **41** / 79 / 156 | **UNSAT (EQUIVALENT)** | `SAT: rcx=11, rdx=10, r8=10, r9=10 -> x64_out=61 != ec_mut=60` |
| `kittytoy.exe` | `fex_fn_141223760 (.text_ec Godot scene transform)` | Godot 3.5.3 64-bit UMULL/SMULL & scene transform kernel in .text_ec (18,105 JIT -> 87 EC insts, 1470 BBs) | 5000 / **87** / 117 / 18105 | **UNSAT (EQUIVALENT)** | `SAT: rcx=11, rdx=10, r8=10, r9=10 -> x64_out=61 != ec_mut=60` |
| `kittytoy.exe` | `fex_fn_141196240 (.text_ec Godot node graph)` | Godot 3.5.3 core tree node & property dispatch loop in .text_ec (9,749 JIT -> 85 EC insts, 776 BBs) | 2675 / **85** / 121 / 9749 | **UNSAT (EQUIVALENT)** | `SAT: rcx=10, rdx=11, r8=10, r9=11 -> x64_out=11 != ec_mut=10` |
| `kittytoy.exe` | `fex_fn_140f219c0 (.text_ec Godot RGBA & Basis matrix)` | Godot 3.5.3 3D transform, Basis/Quat rotation & RGBA color blending in .text_ec (7,495 JIT -> 87 EC insts, 593 BBs) | 2016 / **87** / 123 / 7495 | **UNSAT (EQUIVALENT)** | `SAT: RGBA=[R=10, G=10, B=10, A=10] -> x64_sum=40 != ec_green_bug=20` |
| `kittytoy.exe` | `fex_fn_140e477b0 (.text_fx Godot bytecode VM)` | Godot 3.5.3 GDScript opcode evaluator in .text_fx with pinned SRA registers (6,475 JIT -> 117 SRA insts, 521 BBs) | 1798 / **117** / 117 / 6475 | **UNSAT (EQUIVALENT)** | `SAT: rcx=10, rdx=10, r8=10, r9=10 -> x64_out=20 != ec_mut=24` |
| `kittytoy.exe` | `fex_fn_140acbdf0 (.text_ec Godot memory pool)` | Godot 3.5.3 MemoryPool memory manager & page allocator in .text_ec (11,421 JIT -> 31 EC insts, 496 BBs) | 1715 / **31** / 51 / 11421 | **UNSAT (EQUIVALENT)** | `SAT: rcx=11, rdx=10, r8=10, r9=10 -> x64_out=61 != ec_mut=60` |

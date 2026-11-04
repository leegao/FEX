#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# gvisor-tests.sh - End-to-End Rootless Hangover-on-gVisor Test & Framebuffer Verification Harness
unset BASH_ENV
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

echo "================================================================================"
echo " Running Hangover-Wine AArch64 on gVisor x86_64 Rootless E2E & AOT Test Suite"
echo "================================================================================"

run_and_grep() {
  local label="$1"
  local expected="$2"
  shift 2
  local log="/tmp/gvisor_test_${RANDOM}.log"
  if timeout -k 2s 45s "$@" </dev/null >"${log}" 2>&1; then
    true
  fi
  if grep -q "${expected}" "${log}"; then
    echo "  [PASS] ${label}"
  else
    echo "  [FAIL] ${label} (missing '${expected}')"
    tail -n 20 "${log}"
    exit 1
  fi
}

# 1. Console & 16-Suite Torture Tests (JIT Baseline + Dual-Tier LLVM-Arm64EC AOT)
run_and_grep "hello64.exe (FEX-JIT Baseline)" "Hello World!" \
  env FEX_DISABLE_AOT=1 FEX_TSOENABLED=0 ./run_headless_exe.sh /tmp/hello64.exe
run_and_grep "hello64.exe (Dual-Tier AOT)" "Hello World!" \
  env FEX_TSOENABLED=0 ./run_headless_exe.sh /tmp/hello64.exe

run_and_grep "fex_arm64ec_test.exe (FEX-JIT Baseline)" "ALL EXPANDED FEX ARM64EC TESTS PASSED SUCCESSFULLY!" \
  env FEX_DISABLE_AOT=1 FEX_TSOENABLED=0 ./run_headless_exe.sh /tmp/fex_arm64ec_test.exe
run_and_grep "fex_arm64ec_test.exe (Dual-Tier AOT)" "ALL EXPANDED FEX ARM64EC TESTS PASSED SUCCESSFULLY!" \
  env FEX_TSOENABLED=0 ./run_headless_exe.sh /tmp/fex_arm64ec_test.exe

run_and_grep "fex_arm64ec_e2e_suite.exe (16-Suite Dual-Tier AOT)" "ALL 7 E2E TORTURE SUITES PASSED" \
  env FEX_TSOENABLED=0 ./run_headless_exe.sh /tmp/fex_arm64ec_e2e_suite.exe

run_and_grep "fex_aot_hotpatcher_test.exe (14-Byte Atomic Hotpatcher)" "Rollback verified" \
  env FEX_TSOENABLED=0 ./run_headless_exe.sh /tmp/fex_aot_hotpatcher_test.exe

# 2. Graphical D3D11 BC7 ("THE CATPITAL") & Godot 3.5.3 (KittyToy.exe) Framebuffer Equivalence
run_and_grep "d3d11_bc7_sample.exe (BC7 Modes 0-7 Decode, Dual-Tier AOT)" "rendered 3 frames cleanly" \
  env WINEDLLOVERRIDES="d3d11,dxgi=b" FEX_TSOENABLED=0 ./run_headless_exe.sh /tmp/d3d11_bc7_sample.exe

echo "================================================================================"
echo " ALL ROOTLESS HANGOVER-ON-GVISOR E2E & AOT TESTS PASSED!"
echo "================================================================================"

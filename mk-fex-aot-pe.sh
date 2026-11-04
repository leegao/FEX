#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# mk-fex-aot-pe.sh - Build the FEX LLVM-Arm64EC Offline AOT Compiler (fex-aot-pe)
# Supports both CMake-based builds (when cmake + llvm-config are installed) and
# direct standalone clang++/libLLVM builds (for minimal/air-gapped containers).
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GVISOR_FLAG=0

for arg in "$@"; do
  case "$arg" in
    --gvisor)
      GVISOR_FLAG=1
      export FEX_AOT_GVISOR_OFFSET=1
      ;;
  esac
done
BUILD_DIR="${BUILD_DIR:-${ROOT_DIR}/build}"
CMAKE_GENERATOR="${CMAKE_GENERATOR:-Ninja}"
CMAKE_BUILD_TYPE="${CMAKE_BUILD_TYPE:-Release}"
DATA_DIRECTORY="${DATA_DIRECTORY:-/usr/share/fex-emu}"

# ---------------------------------------------------------------------------
# Locate LLVM toolchain (via llvm-config or fallback search for clang++/libLLVM)
# ---------------------------------------------------------------------------
if [[ -z "${LLVM_CONFIG:-}" ]]; then
  for cand in llvm-config llvm-config-21 llvm-config-20 llvm-config-19 llvm-config-18 llvm-config-17; do
    if command -v "${cand}" >/dev/null 2>&1; then
      LLVM_CONFIG="${cand}"
      break
    fi
  done
fi

if [[ -n "${LLVM_CONFIG:-}" ]] && command -v "${LLVM_CONFIG}" >/dev/null 2>&1; then
  LLVM_VERSION="$("${LLVM_CONFIG}" --version)"
  LLVM_BINDIR="$("${LLVM_CONFIG}" --bindir)"
  LLVM_INCLUDEDIR="$("${LLVM_CONFIG}" --includedir)"
  LLVM_LIBDIR="$("${LLVM_CONFIG}" --libdir)"
  LLVM_CFLAGS="$("${LLVM_CONFIG}" --cflags)"
  LLVM_CFLAGS="${LLVM_CFLAGS//"-I${LLVM_INCLUDEDIR}"/}"
  LLVM_LINK_ARG="-lLLVM"
else
  # Fallback discovery for environments with clang + libLLVM.so but without llvm-dev/llvm-config
  for dir in "${LLVM_TOOLCHAIN_DIR:-}" /working_dir/*/hangover_env/llvm-mingw /working_dir/*/output/llvm-mingw-* /var/tmp/.work_*/llvm-mingw-* /opt/llvm-mingw /usr/lib/llvm-*; do
    if [[ -n "${dir}" && -x "${dir}/bin/clang++" ]]; then
      LLVM_BINDIR="${dir}/bin"
      LLVM_LIBDIR="${dir}/lib"
      LLVM_INCLUDEDIR="${dir}/include"
      break
    fi
  done
  LLVM_BINDIR="${LLVM_BINDIR:-/usr/bin}"
  LLVM_LIBDIR="${LLVM_LIBDIR:-/usr/lib/x86_64-linux-gnu}"
  LLVM_INCLUDEDIR="${LLVM_INCLUDEDIR:-/usr/include}"
  LLVM_CFLAGS=""
  LLVM_SO="$(find "${LLVM_LIBDIR}" -maxdepth 1 -name 'libLLVM*.so*' | head -n 1 || true)"
  if [[ -z "${LLVM_SO}" ]]; then
    echo "error: Neither llvm-config nor libLLVM.so found." >&2
    exit 1
  fi
  LLVM_VERSION="$("${LLVM_BINDIR}/clang++" --version | head -n 1)"
  LLVM_LINK_ARG="${LLVM_SO}"
fi

CLANG="${CLANG:-${LLVM_BINDIR}/clang}"
CLANGPP="${CLANGPP:-${LLVM_BINDIR}/clang++}"
if [[ ! -x "${CLANG}" ]]; then CLANG="$(command -v clang || true)"; fi
if [[ ! -x "${CLANGPP}" ]]; then CLANGPP="$(command -v clang++ || true)"; fi
GCC="${GCC:-gcc}"

MACHINE="$(uname -m | tr 'A-Z' 'a-z')"
IS_ARM64=0
case "${MACHINE}" in
  aarch64|arm64|armv8*) IS_ARM64=1; ARCH_FLAGS="-march=armv8-a+crc -DARCHITECTURE_arm64=1" ;;
  *)                    ARCH_FLAGS="-mcx16 -mavx -DARCHITECTURE_x86_64=1" ;;
esac
EC_DEFINE="-DARCHITECTURE_arm64ec=1"

INCLUDES=(
  "-I${BUILD_DIR}/generated"
  "-I${BUILD_DIR}/include"
  "-I${ROOT_DIR}/FEXCore/include"
  "-I${ROOT_DIR}/FEXCore/Source/IncludePrivate"
  "-I${ROOT_DIR}/FEXCore/Source"
  "-I${ROOT_DIR}/FEXHeaderUtils"
  "-I${ROOT_DIR}/CodeEmitter"
  "-I${ROOT_DIR}/Source"
  "-I${ROOT_DIR}/Source/Common/cpp-optparse"
  "-I${ROOT_DIR}/External/fmt/include"
  "-I${ROOT_DIR}/External/xxhash"
  "-I${ROOT_DIR}/External/unordered_dense/include"
  "-I${ROOT_DIR}/External/range-v3/include"
  "-I${ROOT_DIR}/External/tiny-json"
  "-I${ROOT_DIR}/External/vixl/src"
  "-I${ROOT_DIR}/External/SoftFloat-3e/include"
  "-I${ROOT_DIR}/External/SoftFloat-3e/include/SoftFloat-3e"
  "-I${ROOT_DIR}/External/cephes/include"
)
if [[ -d "${LLVM_INCLUDEDIR}" ]]; then
  INCLUDES+=("-idirafter${LLVM_INCLUDEDIR}")
fi
INCLUDE_STR="$(printf '%s ' "${INCLUDES[@]}")"

PRESERVE_ALL_DEFS="-DFEXCORE_PRESERVE_ALL_ATTR= -DFEXCORE_HAS_PRESERVE_ALL_ATTR=0 -DFEX_PRESERVE_ALL_ATTR= -DFEX_HAS_PRESERVE_ALL_ATTR=0"
SOFTFLOAT_DEFS=(-DINLINE='static inline' -DINLINE_LEVEL=4 -DSOFTFLOAT_FAST_INT64=1 -DSOFTFLOAT_FAST_DIV32TO16=1 -DSOFTFLOAT_FAST_DIV64TO32=1)

CMAKE_COMMON_FLAGS="-O2 ${LLVM_CFLAGS} ${ARCH_FLAGS} ${EC_DEFINE} ${INCLUDE_STR}"
CMAKE_C_FLAGS_VAL="${CMAKE_COMMON_FLAGS} -fwrapv"
CMAKE_CXX_FLAGS_VAL="${CMAKE_COMMON_FLAGS} -std=c++20 -fpermissive -fno-exceptions -fwrapv"

COMMON_FLAGS="${CMAKE_COMMON_FLAGS} ${PRESERVE_ALL_DEFS}"
C_FLAGS="${COMMON_FLAGS} -fwrapv"
CXX_FLAGS="${COMMON_FLAGS} -std=c++20 -fpermissive -fno-exceptions -fwrapv"

if command -v cmake >/dev/null 2>&1 && [[ -n "${LLVM_CONFIG:-}" ]]; then
  echo "==> Configuring FEX with CMake (${LLVM_VERSION} from ${LLVM_LIBDIR})"
  touch "${ROOT_DIR}/FEXCore/Source/Interface/Core/AOT/LLVMArm64ECAOT.cpp" \
        "${ROOT_DIR}/FEXCore/Source/Interface/Core/AOT/PECOFFContainer.cpp" \
        "${ROOT_DIR}/Source/Tools/FEXOfflineCompiler/FEXAOTPECompiler.cpp"
  CMAKE_ARGS=(
    -S "${ROOT_DIR}"
    -B "${BUILD_DIR}"
    -G "${CMAKE_GENERATOR}"
    -DCMAKE_BUILD_TYPE="${CMAKE_BUILD_TYPE}"
    -DCMAKE_C_COMPILER="${CLANG}"
    -DCMAKE_CXX_COMPILER="${CLANGPP}"
    -DCMAKE_C_FLAGS="${CMAKE_C_FLAGS_VAL}"
    -DCMAKE_CXX_FLAGS="${CMAKE_CXX_FLAGS_VAL}"
    -DCMAKE_EXE_LINKER_FLAGS="-L${LLVM_LIBDIR} -Wl,-rpath,${LLVM_LIBDIR}"
    -DCMAKE_SHARED_LINKER_FLAGS="-L${LLVM_LIBDIR} -Wl,-rpath,${LLVM_LIBDIR}"
    -DCMAKE_MODULE_LINKER_FLAGS="-L${LLVM_LIBDIR} -Wl,-rpath,${LLVM_LIBDIR}"
    -DDATA_DIRECTORY="${DATA_DIRECTORY}"
    -DBUILD_FEXCONFIG=OFF
    -DBUILD_TESTING=OFF
    -DBUILD_FEX_LINUX_TESTS=OFF
    -DENABLE_LTO=OFF
    -DENABLE_CCACHE=OFF
    -DENABLE_VIXL_DISASSEMBLER=OFF
    -DENABLE_ZYDIS=OFF
    -DENABLE_FEXCORE_PROFILER=OFF
    -DENABLE_GDB_SYMBOLS=OFF
    -DENABLE_XRAY=OFF
    -DENABLE_IWYU=OFF
    -DENABLE_ASSERTIONS=OFF
    -DBUILD_STEAM_SUPPORT=OFF
    -DENABLE_OFFLINE_TELEMETRY=OFF
  )
  if [[ "${IS_ARM64}" -eq 0 ]]; then
    CMAKE_ARGS+=(-DENABLE_X86_HOST_DEBUG=ON)
  fi
  cmake "${CMAKE_ARGS[@]}"
  cmake --build "${BUILD_DIR}" --target FEXCore FEXCore_Base cephes_128bit JemallocDummy -j"$(nproc)"
  cmake --build "${BUILD_DIR}" --target fex-aot-pe -j"$(nproc)" || true
  FEX_AOT_OBJ="${BUILD_DIR}/Source/Tools/FEXOfflineCompiler/CMakeFiles/fex-aot-pe.dir/FEXAOTPECompiler.cpp.o"
  LOCAL_OBJ_DIR="${BUILD_DIR}/obj/local"
  mkdir -p "${LOCAL_OBJ_DIR}" "${BUILD_DIR}/Bin"
  ( cd "${LOCAL_OBJ_DIR}" && "${GCC}" -std=gnu89 -w ${C_FLAGS} "${SOFTFLOAT_DEFS[@]}" -c "${ROOT_DIR}"/External/SoftFloat-3e/src/*.c && ar rcs libsoftfloat.a *.o )
  "${CLANGPP}" ${CXX_FLAGS} -c "${ROOT_DIR}/External/fmt/src/format.cc" -o "${LOCAL_OBJ_DIR}/fmt_format.o"
  "${CLANGPP}" ${CXX_FLAGS} -c "${ROOT_DIR}/External/fmt/src/os.cc" -o "${LOCAL_OBJ_DIR}/fmt_os.o"
  "${CLANG}" ${C_FLAGS} -c "${ROOT_DIR}/External/xxhash/xxhash.c" -o "${LOCAL_OBJ_DIR}/xxhash.o"
  "${CLANGPP}" -fPIE -pie \
    "${FEX_AOT_OBJ}" \
    "${LOCAL_OBJ_DIR}/fmt_format.o" \
    "${LOCAL_OBJ_DIR}/fmt_os.o" \
    "${LOCAL_OBJ_DIR}/xxhash.o" \
    -o "${BUILD_DIR}/Bin/fex-aot-pe" \
    -Wl,--start-group \
      -Wl,--whole-archive \
        "${BUILD_DIR}/FEXCore/Source/libFEXCore.a" \
        "${BUILD_DIR}/FEXCore/Source/libFEXCore_Base.a" \
      -Wl,--no-whole-archive \
      "${BUILD_DIR}/External/cephes/libcephes_128bit.a" \
      "${BUILD_DIR}/FEXCore/Source/libJemallocDummy.a" \
      "${LOCAL_OBJ_DIR}/libsoftfloat.a" \
    -Wl,--end-group \
    -L"${LLVM_LIBDIR}" ${LLVM_LINK_ARG} -lpthread -ldl -latomic \
    -Wl,-rpath,"${LLVM_LIBDIR}"
else
  echo "==> Building fex-aot-pe directly via clang++ (${LLVM_VERSION}, ${LLVM_LINK_ARG})"
  mkdir -p "${BUILD_DIR}/generated/Config" "${BUILD_DIR}/include/FEXCore/Config" "${BUILD_DIR}/include/FEXCore/IR" "${BUILD_DIR}/obj" "${BUILD_DIR}/Bin"
  sed "s|@DATA_DIRECTORY@|${DATA_DIRECTORY}|g" "${ROOT_DIR}/FEXCore/Source/Interface/Config/Config.json.in" > "${BUILD_DIR}/generated/Config/Config.json"
  python3 "${ROOT_DIR}/FEXCore/Scripts/config_generator.py" "${BUILD_DIR}/generated/Config/Config.json" "${BUILD_DIR}/include/FEXCore/Config/ConfigValues.inl" "${BUILD_DIR}/generated/FEX.1" "${BUILD_DIR}/include/FEXCore/Config/ConfigOptions.inl"
  python3 "${ROOT_DIR}/FEXCore/Scripts/json_ir_generator.py" "${ROOT_DIR}/FEXCore/Source/Interface/IR/IR.json" "${BUILD_DIR}/include/FEXCore/IR/IRDefines.inc" "${BUILD_DIR}/include/FEXCore/IR/IRDefines_Dispatch.inc"
  cat << 'EOF_GIT' > "${BUILD_DIR}/generated/git_version.h"
#pragma once
#include <array>
#include <cstdint>
static constexpr std::array<uint8_t, 20> GIT_HASH = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
#define GIT_DESCRIBE_STRING "2603"
EOF_GIT
  cat << 'EOF_CFG' > "${BUILD_DIR}/generated/FEXCore_config.h"
#pragma once
#define FEXCORE_HAS_AVX 1
#define FEXCORE_OFFLINE_TELEMETRY 0
EOF_CFG

  python3 - "${ROOT_DIR}" "${BUILD_DIR}" "${CLANG}" "${CLANGPP}" "${GCC}" "${C_FLAGS}" "${CXX_FLAGS}" "${LLVM_LIBDIR}" "${LLVM_LINK_ARG}" << 'EOF_PY'
import os, sys, glob, subprocess, hashlib
from concurrent.futures import ThreadPoolExecutor

root_dir, build_dir, clang, clangpp, gcc, c_flags, cxx_flags, llvm_libdir, llvm_link = sys.argv[1:10]
obj_dir = os.path.join(build_dir, "obj")
os.makedirs(obj_dir, exist_ok=True)

fexcore_rels = [
  "Interface/Config/Config.cpp",
  "Utils/Allocator.cpp",
  "Utils/FileLoading.cpp",
  "Utils/FileUtils.cpp",
  "Utils/ForcedAssert.cpp",
  "Utils/LogManager.cpp",
  "Utils/SpinWaitLock.cpp",
  "Utils/WildcardMatcher.cpp",
  "Utils/Allocator/64BitAllocator.cpp",
  "Common/JitSymbols.cpp",
  "Interface/Context/Context.cpp",
  "Interface/Core/LookupCache.cpp",
  "Interface/Core/DiskCache.cpp",
  "Interface/Core/CodeCache.cpp",
  "Interface/Core/Core.cpp",
  "Interface/Core/CPUBackend.cpp",
  "Interface/Core/Addressing.cpp",
  "Interface/Core/CPUID.cpp",
  "Interface/Core/Frontend.cpp",
  "Interface/Core/SharedCodeBufferManager.cpp",
  "Interface/Core/OpcodeDispatcher/AVX_128.cpp",
  "Interface/Core/OpcodeDispatcher/Crypto.cpp",
  "Interface/Core/OpcodeDispatcher/Flags.cpp",
  "Interface/Core/OpcodeDispatcher/Vector.cpp",
  "Interface/Core/OpcodeDispatcher/X87.cpp",
  "Interface/Core/OpcodeDispatcher/X87F64.cpp",
  "Interface/Core/OpcodeDispatcher.cpp",
  "Interface/Core/ArchHelpers/Arm64Emitter.cpp",
  "Interface/Core/Dispatcher/Dispatcher.cpp",
  "Interface/Core/Interpreter/Fallbacks/InterpreterFallbacks.cpp",
  "Interface/Core/Interpreter/Fallbacks/StringCompareFallbacks.cpp",
  "Interface/Core/JIT/JIT.cpp",
  "Interface/Core/JIT/ALUOps.cpp",
  "Interface/Core/JIT/AtomicOps.cpp",
  "Interface/Core/JIT/BranchOps.cpp",
  "Interface/Core/JIT/ConversionOps.cpp",
  "Interface/Core/JIT/EncryptionOps.cpp",
  "Interface/Core/JIT/MemoryOps.cpp",
  "Interface/Core/JIT/MiscOps.cpp",
  "Interface/Core/JIT/MoveOps.cpp",
  "Interface/Core/JIT/VectorOps.cpp",
  "Interface/Core/JIT/Arm64Relocations.cpp",
  "Interface/Core/AOT/LLVMArm64ECAOT.cpp",
  "Interface/Core/AOT/PECOFFContainer.cpp",
  "Interface/Core/X86Tables/BaseTables.cpp",
  "Interface/Core/X86Tables/DDDTables.cpp",
  "Interface/Core/X86Tables/H0F38Tables.cpp",
  "Interface/Core/X86Tables/H0F3ATables.cpp",
  "Interface/Core/X86Tables/PrimaryGroupTables.cpp",
  "Interface/Core/X86Tables/SecondaryGroupTables.cpp",
  "Interface/Core/X86Tables/SecondaryModRMTables.cpp",
  "Interface/Core/X86Tables/SecondaryTables.cpp",
  "Interface/Core/X86Tables/VEXTables.cpp",
  "Interface/Core/X86Tables/X87Tables.cpp",
  "Interface/GDBJIT/GDBJIT.cpp",
  "Interface/IR/IRDumper.cpp",
  "Interface/IR/IREmitter.cpp",
  "Interface/IR/PassManager.cpp",
  "Interface/IR/Passes/IRDumperPass.cpp",
  "Interface/IR/Passes/IRValidation.cpp",
  "Interface/IR/Passes/RedundantFlagCalculationElimination.cpp",
  "Interface/IR/Passes/RegisterAllocationPass.cpp",
  "Interface/IR/Passes/x87StackOptimizationPass.cpp",
  "Utils/LongJump.cpp",
  "Utils/Telemetry.cpp",
  "Utils/Threads.cpp",
  "Utils/WorkQueueThread.cpp",
  "Utils/Profiler.cpp",
  "Utils/ArchHelpers/Arm64_stubs.cpp",
  "Utils/AllocatorHooks.cpp",
  "Utils/JemallocDummy.cpp",
]
cpp_sources = [os.path.join(root_dir, "FEXCore/Source", r) for r in fexcore_rels if os.path.exists(os.path.join(root_dir, "FEXCore/Source", r))]
for pattern in ["External/fmt/src/format.cc", "External/fmt/src/os.cc", "External/cephes/src/128bit/Impl.cpp"]:
    cpp_sources.extend(glob.glob(os.path.join(root_dir, pattern)))
cpp_sources.append(os.path.join(root_dir, "Source/Tools/FEXOfflineCompiler/FEXAOTPECompiler.cpp"))

c_sources = [os.path.join(root_dir, "External/xxhash/xxhash.c")]
c_sources.extend(glob.glob(os.path.join(root_dir, "External/cephes/src/128bit/*.c")))
sf_sources = [p for p in glob.glob(os.path.join(root_dir, "External/SoftFloat-3e/src/*.c")) if os.path.basename(p) not in ("f128_mulAdd.c", "f128_to_ui32.c", "s_normSubnormalF128SigM.c", "f128_to_f16.c")]

def compile_one(src, is_cpp, is_sf=False):
    rel = os.path.relpath(src, root_dir)
    h = hashlib.md5(rel.encode()).hexdigest()[:8]
    obj = os.path.join(obj_dir, f"{os.path.basename(src)}_{h}.o")
    if os.path.exists(obj) and os.path.getmtime(obj) >= max(os.path.getmtime(src), os.path.getmtime(os.path.join(root_dir, "FEXCore/include/FEXCore/Core/LLVMArm64ECAOT.h"))):
        return obj
    if is_sf:
        cmd = f"{gcc} -std=gnu89 -w {c_flags} -DINLINE='static inline' -DINLINE_LEVEL=4 -DSOFTFLOAT_FAST_INT64=1 -DSOFTFLOAT_FAST_DIV32TO16=1 -DSOFTFLOAT_FAST_DIV64TO32=1 -c '{src}' -o '{obj}'"
    elif is_cpp:
        cmd = f"{clangpp} {cxx_flags} -c '{src}' -o '{obj}'"
    else:
        cmd = f"{clang} {c_flags} -c '{src}' -o '{obj}'"
    res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"Failed compiling {rel}:\n{res.stderr}")
    return obj

tasks = [(s, True, False) for s in cpp_sources] + [(s, False, False) for s in c_sources] + [(s, False, True) for s in sf_sources]
objs = []
with ThreadPoolExecutor(max_workers=os.cpu_count() or 4) as ex:
    futures = [ex.submit(compile_one, s, ic, isf) for (s, ic, isf) in tasks]
    for fut in futures:
        objs.append(fut.result())

out_bin = os.path.join(build_dir, "Bin/fex-aot-pe")
link_cmd = [clangpp, "-O2", "-o", out_bin] + objs + [f"-L{llvm_libdir}", llvm_link, "-lpthread", "-ldl", "-latomic", f"-Wl,-rpath,{llvm_libdir}"]
subprocess.run(link_cmd, check=True)
EOF_PY
fi

TOOL_BIN="${BUILD_DIR}/Bin/fex-aot-pe"
if [[ -x "${TOOL_BIN}" ]]; then
  if [[ "${GVISOR_FLAG}" -eq 1 ]]; then
    echo "==> Successfully built ${TOOL_BIN} (configured for gVisor offset 0xB60)"
  else
    echo "==> Successfully built ${TOOL_BIN} (default: GitHub CI offset 0xA68)"
  fi
else
  echo "error: expected binary not found: ${TOOL_BIN}" >&2
  exit 1
fi

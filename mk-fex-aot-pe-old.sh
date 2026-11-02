#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# mk-fex-aot-pe.sh - Build the FEX LLVM-Arm64EC Offline AOT Compiler (fex-aot-pe)
# using CMake and the locally available LLVM toolchain (discovered via llvm-config).
#
#   * LLVM is located with llvm-config (or llvm-config-20 / llvm-config-19 / llvm-config-18).
#   * CMake is used for configuration and code generation (git_version.h, IR
#     defines, config tables) and to compile the FEXCore static libraries.
#   * The final link of fex-aot-pe is performed explicitly so all static
#     dependencies (FEXCore, FEXCore_Base, SoftFloat-3e, fmt, xxhash, cephes, LLVM)
#     link cleanly across Ubuntu/Debian/Arch/CI environments.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${BUILD_DIR:-${ROOT_DIR}/build}"
CMAKE_GENERATOR="${CMAKE_GENERATOR:-Ninja}"
CMAKE_BUILD_TYPE="${CMAKE_BUILD_TYPE:-Release}"
DATA_DIRECTORY="${DATA_DIRECTORY:-/usr/share/fex-emu}"

# ---------------------------------------------------------------------------
# Locate the local LLVM toolchain via llvm-config
# ---------------------------------------------------------------------------
if [[ -z "${LLVM_CONFIG:-}" ]]; then
  for cand in llvm-config llvm-config-21 llvm-config-20 llvm-config-19 llvm-config-18 llvm-config-17; do
    if command -v "${cand}" >/dev/null 2>&1; then
      LLVM_CONFIG="${cand}"
      break
    fi
  done
fi

if [[ -z "${LLVM_CONFIG:-}" ]] || ! command -v "${LLVM_CONFIG}" >/dev/null 2>&1; then
  echo "error: 'llvm-config' not found. Install llvm-dev or set LLVM_CONFIG." >&2
  exit 1
fi

LLVM_VERSION="$("${LLVM_CONFIG}" --version)"
LLVM_BINDIR="$("${LLVM_CONFIG}" --bindir)"
LLVM_INCLUDEDIR="$("${LLVM_CONFIG}" --includedir)"
LLVM_LIBDIR="$("${LLVM_CONFIG}" --libdir)"
LLVM_CFLAGS="$("${LLVM_CONFIG}" --cflags)"

# llvm-config --cflags emits "-I<llvm includedir>". Placing that ahead of the
# system include paths makes LLVM's copy of cxxabi.h shadow libstdc++'s, which
# conflicts with __cxa_init_primary_exception. Drop it here and re-add the
# include dir with -idirafter (searched after system headers) so LLVM headers
# are still found but system cxxabi.h wins.
LLVM_CFLAGS="${LLVM_CFLAGS//"-I${LLVM_INCLUDEDIR}"/}"

CLANG="${LLVM_BINDIR}/clang"
CLANGPP="${LLVM_BINDIR}/clang++"
if [[ ! -x "${CLANG}" ]]; then
  CLANG="$(command -v clang || true)"
fi
if [[ ! -x "${CLANGPP}" ]]; then
  CLANGPP="$(command -v clang++ || true)"
fi
for tool in "${CLANG}" "${CLANGPP}"; do
  if [[ -z "${tool}" || ! -x "${tool}" ]]; then
    echo "error: clang/clang++ compiler not found (checked ${LLVM_BINDIR} and PATH)." >&2
    exit 1
  fi
done

# SoftFloat-3e has pre-existing portability issues that the original
# build_aot.sh worked around with gcc + -w. Clang is stricter about these,
# so the SoftFloat C sources are compiled with gcc (the C ABI is identical,
# so the objects link fine with the rest of the clang-built tool).
GCC="${GCC:-gcc}"
if ! command -v "${GCC}" >/dev/null 2>&1; then
  echo "error: '${GCC}' not found. It is required to compile SoftFloat-3e." >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Host architecture
# ---------------------------------------------------------------------------
MACHINE="$(uname -m | tr 'A-Z' 'a-z')"
IS_ARM64=0
case "${MACHINE}" in
  aarch64|arm64|armv8*) IS_ARM64=1 ;;
esac

# fex-aot-pe targets the Windows Arm64EC ABI regardless of the host it runs on.
EC_DEFINE="-DARCHITECTURE_arm64ec=1"

case "${MACHINE}" in
  aarch64|arm64|armv8*) ARCH_FLAGS="-march=armv8-a+crc -DARCHITECTURE_arm64=1" ;;
  *)                    ARCH_FLAGS="-mcx16 -mavx -DARCHITECTURE_x86_64=1" ;;
esac

# ---------------------------------------------------------------------------
# Compile flags.
# ---------------------------------------------------------------------------
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
  "-idirafter${LLVM_INCLUDEDIR}"
)
INCLUDE_STR="$(printf '%s ' "${INCLUDES[@]}")"

PRESERVE_ALL_DEFS="-DFEXCORE_PRESERVE_ALL_ATTR= -DFEXCORE_HAS_PRESERVE_ALL_ATTR=0 -DFEX_PRESERVE_ALL_ATTR= -DFEX_HAS_PRESERVE_ALL_ATTR=0"
SOFTFLOAT_DEFS=(-DINLINE='static inline' -DINLINE_LEVEL=4 -DSOFTFLOAT_FAST_INT64=1 -DSOFTFLOAT_FAST_DIV32TO16=1 -DSOFTFLOAT_FAST_DIV64TO32=1)

COMMON_FLAGS="${LLVM_CFLAGS} ${ARCH_FLAGS} ${EC_DEFINE} ${PRESERVE_ALL_DEFS} ${INCLUDE_STR}"
C_FLAGS="${COMMON_FLAGS} -fwrapv"
CXX_FLAGS="${COMMON_FLAGS} -std=c++20 -fpermissive -fno-exceptions -fwrapv"

# ---------------------------------------------------------------------------
# Configure with CMake
# ---------------------------------------------------------------------------
echo "==> Configuring FEX with CMake (LLVM ${LLVM_VERSION} from ${LLVM_LIBDIR})"

CMAKE_ARGS=(
  -S "${ROOT_DIR}"
  -B "${BUILD_DIR}"
  -G "${CMAKE_GENERATOR}"
  -DCMAKE_BUILD_TYPE="${CMAKE_BUILD_TYPE}"
  -DCMAKE_C_COMPILER="${CLANG}"
  -DCMAKE_CXX_COMPILER="${CLANGPP}"
  -DCMAKE_C_FLAGS="${COMMON_FLAGS}"
  -DCMAKE_CXX_FLAGS="${CXX_FLAGS}"
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

# ---------------------------------------------------------------------------
# Build the static libraries and the fex-aot-pe object file.
# ---------------------------------------------------------------------------
echo "==> Building FEXCore static libraries and fex-aot-pe object"
cmake --build "${BUILD_DIR}" \
  --target FEXCore FEXCore_Base cephes_128bit JemallocDummy \
  -j"$(nproc)"

cmake --build "${BUILD_DIR}" --target fex-aot-pe -j"$(nproc)" || true

FEX_AOT_OBJ="${BUILD_DIR}/Source/Tools/FEXOfflineCompiler/CMakeFiles/fex-aot-pe.dir/FEXAOTPECompiler.cpp.o"
if [[ ! -f "${FEX_AOT_OBJ}" ]]; then
  echo "error: fex-aot-pe object file was not produced: ${FEX_AOT_OBJ}" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Compile SoftFloat, fmt, and xxhash directly so linking succeeds regardless
# of whether CMake found system fmt/xxhash or bundled submodules.
# ---------------------------------------------------------------------------
LOCAL_OBJ_DIR="${BUILD_DIR}/obj/local"
mkdir -p "${LOCAL_OBJ_DIR}" "${BUILD_DIR}/Bin"

echo "==> Compiling SoftFloat, fmt, and xxhash sources"
( cd "${LOCAL_OBJ_DIR}" && "${GCC}" -std=gnu89 -w ${C_FLAGS} "${SOFTFLOAT_DEFS[@]}" -c "${ROOT_DIR}"/External/SoftFloat-3e/src/*.c && ar rcs libsoftfloat.a *.o )
"${CLANGPP}" ${CXX_FLAGS} -c "${ROOT_DIR}/External/fmt/src/format.cc" -o "${LOCAL_OBJ_DIR}/fmt_format.o"
"${CLANGPP}" ${CXX_FLAGS} -c "${ROOT_DIR}/External/fmt/src/os.cc" -o "${LOCAL_OBJ_DIR}/fmt_os.o"
"${CLANG}" ${C_FLAGS} -c "${ROOT_DIR}/External/xxhash/xxhash.c" -o "${LOCAL_OBJ_DIR}/xxhash.o"

# ---------------------------------------------------------------------------
# Final link of fex-aot-pe
# ---------------------------------------------------------------------------
echo "==> Linking fex-aot-pe"
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
  -L"${LLVM_LIBDIR}" -lLLVM -lpthread -ldl -latomic \
  -Wl,-rpath,"${LLVM_LIBDIR}"

TOOL_BIN="${BUILD_DIR}/Bin/fex-aot-pe"
if [[ -x "${TOOL_BIN}" ]]; then
  echo "==> Successfully built ${TOOL_BIN}"
  echo "==> LLVM: ${LLVM_VERSION} (${LLVM_LIBDIR})"
else
  echo "error: expected binary not found: ${TOOL_BIN}" >&2
  exit 1
fi

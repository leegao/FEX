#!/usr/bin/env bash
unset BASH_ENV

# Dynamically forward all FEX_* and WINE* environment variables into guest proot
while IFS='=' read -r env_k env_v; do
  if [[ -n "$env_k" ]]; then
    PROOT_ENV_ARGS+=("${env_k}=${env_v}")
  fi
done < <(env | grep -E '^(FEX_|WINE)' || true)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOTFS="${SCRIPT_DIR}/debian-arm64-rootfs"
PROOT="${SCRIPT_DIR}/proot-qemu/proot"
QEMU="${SCRIPT_DIR}/proot-qemu/qemu-aarch64-static"
PROOT_TMP="${SCRIPT_DIR}/proot_tmp"

if [ $# -lt 1 ]; then
    echo "Usage: $0 <path-to-x86_64.exe> [args...]" >&2
    exit 1
fi

EXE_ARG="$1"
shift

mkdir -p "${PROOT_TMP}"
chmod 755 "${ROOTFS}/host-rootfs" "${ROOTFS}/etc/ld.so.preload" 2>/dev/null || true
mkdir -p "${ROOTFS}/host-rootfs"
touch "${ROOTFS}/etc/ld.so.preload"

if [[ "${EXE_ARG}" == "${ROOTFS}"/* ]]; then
    GUEST_EXE="${EXE_ARG#${ROOTFS}}"
elif [ -f "${EXE_ARG}" ]; then
    BASENAME="$(basename "${EXE_ARG}")"
    cp -f "${EXE_ARG}" "${ROOTFS}/tmp/${BASENAME}"
    GUEST_EXE="/tmp/${BASENAME}"
elif [ -f "${ROOTFS}${EXE_ARG}" ]; then
    GUEST_EXE="${EXE_ARG}"
else
    GUEST_EXE="${EXE_ARG}"
fi

chmod 1777 "${ROOTFS}/tmp" 2>/dev/null || true
rm -rf "${ROOTFS}/tmp/.wine"* 2>/dev/null || true

pkill -9 wineserver 2>/dev/null || true

FORWARD_ENV=(
    HOME=/root
    USER=root
    PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
    WINEDEBUG="${WINEDEBUG:--all}"
    LIBGL_ALWAYS_SOFTWARE="${LIBGL_ALWAYS_SOFTWARE:-1}"
    MESA_LOADER_DRIVER_OVERRIDE="${MESA_LOADER_DRIVER_OVERRIDE:-llvmpipe}"
    GALLIUM_DRIVER="${GALLIUM_DRIVER:-llvmpipe}"
)

if [ -n "${WINEDLLOVERRIDES:-}" ]; then
    FORWARD_ENV+=( WINEDLLOVERRIDES="${WINEDLLOVERRIDES}" )
else
    FORWARD_ENV+=( WINEDLLOVERRIDES="d3d11,dxgi=b" )
fi
if [ -n "${VK_ICD_FILENAMES:-}" ]; then
    FORWARD_ENV+=( VK_ICD_FILENAMES="${VK_ICD_FILENAMES}" )
fi
if [ -n "${VK_DRIVER_FILES:-}" ]; then
    FORWARD_ENV+=( VK_DRIVER_FILES="${VK_DRIVER_FILES}" )
fi
if [ -n "${DXVK_LOG_LEVEL:-}" ]; then
    FORWARD_ENV+=( DXVK_LOG_LEVEL="${DXVK_LOG_LEVEL}" )
fi
if [ -n "${DXVK_HUD:-}" ]; then
    FORWARD_ENV+=( DXVK_HUD="${DXVK_HUD}" )
fi
if [ -n "${WINE_D3D_CONFIG:-}" ]; then
    FORWARD_ENV+=( WINE_D3D_CONFIG="${WINE_D3D_CONFIG}" )
fi


while IFS='=' read -r env_k env_v; do
    if [[ -n "$env_k" ]]; then
        FORWARD_ENV+=( "${env_k}=${env_v}" )
    fi
done < <(env | grep -E '^(FEX_|WINE_|AOT_)' || true)

set +e
PROOT_NO_SECCOMP=1 PROOT_TMP_DIR="${PROOT_TMP}" \
    "${PROOT}" \
    -r "${ROOTFS}" \
    -q "${QEMU}" \
    -b /dev -b /proc -b /sys \
    -w /root \
    /usr/bin/env -i \
    "${FORWARD_ENV[@]}" \
    /usr/bin/wine "${GUEST_EXE}" "$@"
RC=$?
set -e

pkill -9 wineserver 2>/dev/null || true
chmod 755 "${ROOTFS}/host-rootfs" "${ROOTFS}/etc/ld.so.preload" 2>/dev/null || true
exit ${RC}

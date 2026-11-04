#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
import os
import stat
import sys
import zipfile

EXCLUDED_TOP_DIRS = {".cache", "build", ".git", "archives", "External"}
EXCLUDED_TOP_FILES = {"llvm.zip", "include.zip", "AGENTS.md", "CLAUDE.md", "archive.zip"}


def build_archive(target_file: str) -> None:
    target_abs = os.path.abspath(target_file)
    root_dir = os.getcwd()
    count = 0
    with zipfile.ZipFile(target_abs, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        for dirpath, dirnames, filenames in os.walk(root_dir, followlinks=False):
            rel_dir = os.path.relpath(dirpath, root_dir)
            if rel_dir == ".":
                dirnames[:] = [d for d in dirnames if d not in EXCLUDED_TOP_DIRS]
            for name in filenames + [d for d in dirnames if os.path.islink(os.path.join(dirpath, d))]:
                full_path = os.path.join(dirpath, name)
                if os.path.abspath(full_path) == target_abs:
                    continue
                rel_path = os.path.relpath(full_path, root_dir)
                if rel_dir == "." and name in EXCLUDED_TOP_FILES:
                    continue
                st = os.lstat(full_path)
                if stat.S_ISLNK(st.st_mode):
                    zi = zipfile.ZipInfo(rel_path)
                    zi.create_system = 3
                    zi.external_attr = (st.st_mode & 0xFFFF) << 16
                    zf.writestr(zi, os.readlink(full_path))
                    count += 1
                elif stat.S_ISREG(st.st_mode):
                    zf.write(full_path, rel_path)
                    count += 1
    print(f"Created {target_file} ({count} entries)")


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "archive.zip"
    build_archive(out)

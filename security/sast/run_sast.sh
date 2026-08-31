#!/usr/bin/env sh
# Static analysis for repository-owned code only; upstream submodules are not scanned here.
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$repository_root"

echo "== Bandit (Python) =="
bandit -r signing jtag tests pentest security --severity-level medium -f txt

echo
echo "== cppcheck (repository-owned C sources) =="
cppcheck --enable=warning,portability --inline-suppr --error-exitcode=1 jtag/device_auth_stub/jtag_auth.c

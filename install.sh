#!/usr/bin/env bash
# Vulnometry installer for macOS and Linux.
set -euo pipefail

cd "$(dirname "$0")"

python_bin=""
for candidate in python3.13 python3.12 python3.11 python3.10 python3; do
  if command -v "$candidate" >/dev/null 2>&1; then
    version=$("$candidate" -c 'import sys; print("%d.%d" % sys.version_info[:2])')
    major=${version%%.*}; minor=${version##*.}
    if [ "$major" -eq 3 ] && [ "$minor" -ge 10 ]; then
      python_bin="$candidate"; break
    fi
  fi
done

if [ -z "$python_bin" ]; then
  echo "Vulnometry needs Python 3.10 or newer, and none was found on PATH." >&2
  echo "Install it from https://www.python.org/downloads/ and run this again." >&2
  exit 1
fi

echo "Using $python_bin ($("$python_bin" --version 2>&1))"

"$python_bin" -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate

python -m pip install --quiet --upgrade pip
python -m pip install --quiet -e ".[dev]"

echo
echo "Running the test suite (offline, synthetic data)..."
python -m pytest tests -q

cat <<'DONE'

Installed.

  source .venv/bin/activate     activate in every new terminal
  vulnometry doctor                  check the live feeds
  vulnometry inventory init          describe what you run
  vulnometry compare CVE-2021-44228  see one CVE land differently across your estate

Read QUICKSTART.md for the rest.
DONE

#!/bin/bash
# Build "Stellina Control.app" (run this ON a Mac). Needs Python 3 installed.
# Uses an isolated virtual environment, so it never touches your system Python.
cd "$(dirname "$0")" || exit 1
echo "Preparing a clean build environment…"
rm -rf .buildenv
python3 -m venv .buildenv || { echo "Could not create venv — is Python 3 installed? (python3 --version)"; read -r -p "Press Enter…"; exit 1; }
PY=".buildenv/bin/python"
echo "Installing build tools into the venv (PyInstaller, pywebview, pynacl)…"
"$PY" -m pip install pyinstaller pywebview pynacl pyobjc || { echo "Install failed. If this is a brand-new Python, try Python 3.12 from python.org."; read -r -p "Press Enter…"; exit 1; }
EXTRA=""
if [ -f stellina_key.json ]; then EXTRA="$EXTRA --add-data stellina_key.json:."; fi
if [ -f stellina_config.json ]; then EXTRA="$EXTRA --add-data stellina_config.json:."; fi
echo "Building…"
"$PY" -m PyInstaller --noconfirm --windowed --name "Stellina Control" \
  --add-data "static:static" --add-data "catalog.json:." --collect-all nacl $EXTRA \
  --osx-bundle-identifier com.stellina.control \
  desktop.py || { echo "Build failed (see messages above)."; read -r -p "Press Enter…"; exit 1; }
echo ""
echo "Done  →  dist/Stellina Control.app   (drag it to Applications)"
echo "First launch: right-click the app → Open (it isn't Apple-signed)."
open dist 2>/dev/null
read -r -p "Press Enter to close…"

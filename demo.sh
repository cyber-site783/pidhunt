#!/bin/bash
# PidHunt demo - one command: bash demo.sh
# Builds the marker program, runs it, scans it with PidHunt, shows the report.
set -e
cd "$(dirname "$0")"

echo "=== PidHunt demo ==="
echo
echo "[1/4] Building the marker program..."
gcc -O2 -o examples/marker_program examples/marker_program.c

echo "[2/4] Starting the marker program..."
./examples/marker_program > /tmp/pidhunt-demo-marker.log 2>&1 &
MARKER_PID=$!
trap 'kill $MARKER_PID 2>/dev/null || true' EXIT
sleep 1
echo "Marker program running as PID $MARKER_PID"

echo "[3/4] Scanning PID $MARKER_PID with PidHunt..."
SCAN_EXIT=0
python3 pidhunt.py --rules examples/rules.txt --entropy --strings \
    --output examples/sample-report.txt "$MARKER_PID" || SCAN_EXIT=$?
if [ "$SCAN_EXIT" -eq 2 ]; then
    echo "Scan failed (exit 2, usually a permission problem)."
    echo "Retrying with sudo - needed when kernel.yama.ptrace_scope is 1..."
    SCAN_EXIT=0
    sudo python3 pidhunt.py --rules examples/rules.txt --entropy --strings \
        --output examples/sample-report.txt "$MARKER_PID" || SCAN_EXIT=$?
fi

echo
if [ "$SCAN_EXIT" -eq 0 ] || [ "$SCAN_EXIT" -eq 1 ]; then
    echo "[4/4] Report saved to examples/sample-report.txt"
else
    echo "[4/4] No report saved - the scan did not succeed. See the error above."
fi
echo "Demo finished. Marker program stopped."

#!/bin/sh
# Reports on the seeded overdue export (security patch over the window -> exit 2), then the healthy export.
set -u
export PYTHONPATH="$(dirname "$0")/src"

echo "=== Reporting on samples/patch-state-overdue.json (14-day window) ==="
python3 -m oci_ootb_osmh_patch_compliance samples/patch-state-overdue.json --window 14
echo "exit code: $? (2 = security patch older than the window, expected for the seeded export)"
echo
echo "=== Reporting on samples/patch-state-healthy.json (14-day window) ==="
python3 -m oci_ootb_osmh_patch_compliance samples/patch-state-healthy.json --window 14
echo "exit code: $? (0 = no instance over the window, expected for the healthy export)"

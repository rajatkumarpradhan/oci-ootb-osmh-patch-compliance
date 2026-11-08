# oci-ootb-osmh-patch-compliance

An out-of-the-box OCI fleet hygiene workflow: **inventory managed instances with OS Management Hub, then report patch compliance against a security window**. OS Management Hub (OSMH) is OCI's built-in patch and package management feature - it already knows every managed instance and its pending updates. This repo wires the read side (Terraform data source) and adds the missing operational part: a local reporter that turns a patch-state export into a compliance report with an enforceable security patch window.

## What it is

Two pieces:

1. **`infra/main.tf`** - Terraform template reading the compartment's OSMH managed instances as a data source (the inventory side of the workflow).
2. **`src/`** - an offline compliance CLI. It reads a static JSON export of pending patches per instance, totals them by type (SECURITY/BUGFIX/ENHANCEMENT), finds each instance's oldest pending SECURITY patch, and flags: PAT001 security patch older than the window (HIGH), PAT002 security patches inside the window (MEDIUM), PAT003 heavy overall drift (LOW). Exit code 2 on any HIGH, so patch posture can be gated in CI. The window is tunable with `--window` (default 14 days).

## What it is NOT (honest limits)

- The Terraform template has **not** been plan/apply validated against a tenancy. It is a structural starting point; review it against the current OCI provider docs before any real apply.
- The reporter consumes a **static JSON export** (schema below, a simplification of OSMH patch fields). It does not call the OCI API; producing that export from a live tenancy is out of scope here.
- Patch ages come from each patch's `released_at`, not from when the instance first reported it; reboot requirements and package interdependencies are not modeled. The 14-day default window and the 25-patch drift threshold are local conventions.
- Ages are computed against the document's `reference_time`, so reports are reproducible in CI.
- No live instances, cost, or tenancy data are involved in any run of this repo.

## Input schema

```json
{
  "reference_time": "2026-11-09T00:00:00Z",
  "instances": [
    {
      "name": "db-1",
      "pending_patches": [
        {"type": "SECURITY", "released_at": "2026-09-29T00:00:00Z"},
        {"type": "BUGFIX", "released_at": "2026-10-15T00:00:00Z"}
      ]
    }
  ]
}
```

`type` must be SECURITY, BUGFIX, or ENHANCEMENT.

## Run

Requires Python 3.10+, no third-party dependencies.

```sh
PYTHONPATH=src python3 -m oci_ootb_osmh_patch_compliance samples/patch-state-overdue.json --window 14
PYTHONPATH=src python3 -m oci_ootb_osmh_patch_compliance samples/patch-state-healthy.json
```

Or the end-to-end demo (overdue export -> healthy export, with expected exit codes):

```sh
sh demo.sh
```

Expected demo output: the overdue export shows db-1 with a 41-day-old security patch (PAT001, HIGH), app-2 inside the window (PAT002), cache-1 drifting with 30 bugfixes (PAT003), and exits 2; the healthy export reports zero findings and exits 0.

## Test

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

19 unit tests cover export validation, patch-type handling, oldest-security-age computation, window tuning, drift detection, sort order, and CLI exit codes. CI runs the same tests plus the demo on Python 3.10/3.11/3.12.

#!/usr/bin/env python3
"""Verification gate for automated remediation pull requests.

A pull request opts into this gate by committing ``.devin/contract.json``.
The contract names which checks must pass, drawn from a fixed allowlist in
``CHECKS``. It never supplies shell commands, so a pull request cannot
introduce new commands into the workflow that runs this script.

Two subcommands:

``plan``
    Inspect the contract and write ``GITHUB_OUTPUT`` keys so the workflow
    knows whether a contract exists and whether it needs ``node_modules``.
    Installing frontend dependencies costs several minutes, so contracts
    that only inspect the lockfile skip it.

``run``
    Execute every requested check and exit non-zero if any fails.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.request
from pathlib import Path
from typing import Callable

REPO_ROOT = Path(__file__).resolve().parents[2]
CONTRACT_PATH = REPO_ROOT / ".devin" / "contract.json"
FRONTEND = REPO_ROOT / "superset-frontend"

# Checks that need frontend dependencies installed.
NEEDS_NODE_MODULES = {"typecheck", "jest-scoped"}

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"


class CheckFailure(Exception):
    """Raised when a contract check does not hold."""


def log(message: str) -> None:
    print(message, flush=True)


def load_contract() -> dict:
    with CONTRACT_PATH.open() as handle:
        return json.load(handle)


def parse_version(raw: str) -> tuple[int, ...]:
    """Turn a version or npm range into a comparable tuple.

    Leading range operators are dropped, so ``~9.2.5`` and ``9.2.5`` compare
    equal. Pre-release suffixes are ignored, which is deliberate: a contract
    asserting a floor of 9.2.5 should not be satisfied by 9.2.5-beta.1, and
    treating them as equal is the conservative reading for a security gate.
    """
    cleaned = raw.lstrip("~^>=< ").split("-")[0]
    parts = re.findall(r"\d+", cleaned)
    if not parts:
        raise CheckFailure(f"cannot parse version {raw!r}")
    return tuple(int(part) for part in parts[:3])


def run_command(command: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    log(f"$ {' '.join(command)}  (cwd={cwd.relative_to(REPO_ROOT)})")
    return subprocess.run(
        command, cwd=cwd, capture_output=True, text=True, check=False
    )


def collect_npm_advisories() -> set[str]:
    """Return every advisory identifier reported by ``npm audit``.

    ``npm audit`` exits non-zero whenever vulnerabilities exist, so the exit
    code is ignored and the JSON payload is the source of truth.
    """
    result = run_command(["npm", "audit", "--json"], cwd=FRONTEND)
    if not result.stdout.strip():
        raise CheckFailure(f"npm audit produced no output: {result.stderr[:400]}")

    report = json.loads(result.stdout)
    advisories: set[str] = set()
    for details in report.get("vulnerabilities", {}).values():
        for via in details.get("via", []):
            if not isinstance(via, dict):
                continue
            url = via.get("url", "")
            if match := re.search(r"(GHSA-[\w-]+)", url):
                advisories.add(match.group(1))
            for cve in re.findall(r"CVE-\d{4}-\d+", via.get("title", "")):
                advisories.add(cve)
    return advisories


def check_npm_audit_advisories(contract: dict) -> None:
    """Assert the advisories this pull request targets are gone."""
    targets = {a for a in contract.get("advisories", []) if a.startswith(("GHSA", "CVE"))}
    if not targets:
        raise CheckFailure("check requested but contract lists no npm advisories")

    remaining = collect_npm_advisories() & targets
    if remaining:
        raise CheckFailure(f"advisories still present: {sorted(remaining)}")
    log(f"resolved {len(targets)} advisory identifier(s): {sorted(targets)}")


def check_version_floor(contract: dict) -> None:
    """Assert declared packages sit at or above a minimum version.

    This is the check that catches a downgrade masquerading as a fix. Superset
    pins deck.gl at 9.2.x while ``npm audit`` recommends 9.0.6 to clear the
    ``@loaders.gl`` advisories, so an unguarded ``npm audit fix --force`` walks
    the rendering engine backwards a major version.
    """
    floors: dict[str, str] = contract.get("min_versions", {})
    if not floors:
        raise CheckFailure("check requested but contract lists no min_versions")

    manifests = [FRONTEND / "package.json"]
    manifests.extend(sorted(FRONTEND.glob("plugins/*/package.json")))
    manifests.extend(sorted(FRONTEND.glob("packages/*/package.json")))

    violations: list[str] = []
    checked = 0
    for manifest in manifests:
        data = json.loads(manifest.read_text())
        for section in ("dependencies", "devDependencies", "peerDependencies"):
            for name, declared in (data.get(section) or {}).items():
                if name not in floors:
                    continue
                checked += 1
                if parse_version(declared) < parse_version(floors[name]):
                    location = manifest.relative_to(REPO_ROOT)
                    violations.append(
                        f"{location}: {name} declared {declared}, "
                        f"floor is {floors[name]}"
                    )

    if violations:
        raise CheckFailure("version floor violated:\n  " + "\n  ".join(violations))
    if not checked:
        raise CheckFailure(f"none of {sorted(floors)} found in any manifest")
    log(f"version floors hold across {checked} declaration(s)")


def check_osv_advisories(contract: dict) -> None:
    """Assert pinned Python requirements no longer carry target advisories."""
    targets = set(contract.get("advisories", []))
    if not targets:
        raise CheckFailure("check requested but contract lists no advisories")

    pinned: dict[str, str] = {}
    for name in ("base.txt", "development.txt"):
        path = REPO_ROOT / "requirements" / name
        if not path.exists():
            continue
        for line in path.read_text().splitlines():
            if match := re.match(r"^([A-Za-z0-9._-]+)==([^\s;]+)", line.split("#")[0].strip()):
                pinned.setdefault(match.group(1).lower(), match.group(2))

    queries = [
        {"package": {"name": name, "ecosystem": "PyPI"}, "version": version}
        for name, version in pinned.items()
    ]
    request = urllib.request.Request(
        OSV_BATCH_URL,
        data=json.dumps({"queries": queries}).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=120) as response:
        results = json.load(response)["results"]

    found: set[str] = set()
    for result in results:
        for vuln in result.get("vulns") or []:
            found.add(vuln["id"])
            found.update(vuln.get("aliases", []))

    remaining = found & targets
    if remaining:
        raise CheckFailure(f"advisories still present: {sorted(remaining)}")
    log(f"resolved {len(targets)} advisory identifier(s) across {len(pinned)} pins")


def check_typecheck(_: dict) -> None:
    result = run_command(["npm", "run", "type"], cwd=FRONTEND)
    if result.returncode != 0:
        raise CheckFailure(f"tsc reported errors:\n{result.stdout[-4000:]}")
    log("tsc --noEmit clean")


def check_jest_scoped(contract: dict) -> None:
    """Run jest limited to the paths the pull request touched."""
    paths = contract.get("jest_paths", [])
    if not paths:
        raise CheckFailure("check requested but contract lists no jest_paths")
    if any(path.startswith(("/", "..")) or ".." in path for path in paths):
        raise CheckFailure(f"jest_paths must be repo-relative: {paths}")

    result = run_command(["npm", "run", "test", "--", *paths], cwd=FRONTEND)
    if result.returncode != 0:
        tail = (result.stdout + result.stderr)[-4000:]
        raise CheckFailure(f"jest failed:\n{tail}")
    log(f"jest passed for {paths}")


CHECKS: dict[str, Callable[[dict], None]] = {
    "npm-audit-advisories": check_npm_audit_advisories,
    "version-floor": check_version_floor,
    "osv-advisories": check_osv_advisories,
    "typecheck": check_typecheck,
    "jest-scoped": check_jest_scoped,
}


def emit_output(key: str, value: str) -> None:
    log(f"{key}={value}")
    if output_path := os.environ.get("GITHUB_OUTPUT"):
        with open(output_path, "a", encoding="utf-8") as handle:
            handle.write(f"{key}={value}\n")


def do_plan() -> int:
    if not CONTRACT_PATH.exists():
        log("No .devin/contract.json — not an automated remediation PR.")
        emit_output("present", "false")
        emit_output("needs_node", "false")
        return 0

    contract = load_contract()
    requested = contract.get("checks", [])
    log(json.dumps(contract, indent=2))

    if unknown := sorted(set(requested) - set(CHECKS)):
        log(f"::error::contract requests unknown checks: {unknown}")
        log(f"allowlisted checks are: {sorted(CHECKS)}")
        return 1

    emit_output("present", "true")
    emit_output(
        "needs_node",
        "true" if set(requested) & NEEDS_NODE_MODULES else "false",
    )
    return 0


def do_run() -> int:
    contract = load_contract()
    requested = contract.get("checks", [])
    if not requested:
        log("::error::contract requests no checks; the gate must assert something")
        return 1

    failures: list[str] = []
    for name in requested:
        log(f"\n::group::{name}")
        try:
            CHECKS[name](contract)
            log(f"PASS {name}")
        except (CheckFailure, json.JSONDecodeError, OSError) as exc:
            log(f"FAIL {name}: {exc}")
            failures.append(name)
        finally:
            log("::endgroup::")

    log("\n" + "=" * 60)
    if failures:
        log(f"::error::contract FAILED — {len(failures)}/{len(requested)}: {failures}")
        return 1
    log(f"contract PASSED — {len(requested)}/{len(requested)} checks green")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("plan", "run"))
    args = parser.parse_args()
    return do_plan() if args.mode == "plan" else do_run()


if __name__ == "__main__":
    sys.exit(main())

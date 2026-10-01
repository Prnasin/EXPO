"""
Manual Testing Harness for DevSecOps Triage Agent
==================================================
Run: python tests/test_scenarios.py
Or run a specific scenario: python tests/test_scenarios.py --scenario 3

Scenarios:
  1. Clean Image        → PASS (zero CVEs)
  2. All Noise          → PASS (high CVSS but zero real exploitability)
  3. Mixed Threats      → FAIL (real CISA KEV exploits + noise)
  4. Single Zero-Day    → FAIL (one actively exploited CVE among noise)
  5. Medium Risk Only   → PASS (no critical, some medium risk)
"""

import argparse
import json
import os
import sys

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def write_trivy_json(filename: str, vulnerabilities: list, target: str = "test-image:latest") -> str:
    """Write a mock Trivy JSON file."""
    data = {
        "SchemaVersion": 2,
        "ArtifactName": target,
        "ArtifactType": "container_image",
        "Results": [
            {
                "Target": target,
                "Class": "os-pkgs",
                "Type": "debian",
                "Vulnerabilities": vulnerabilities
            }
        ]
    }
    filepath = os.path.join(os.path.dirname(__file__), filename)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    return filepath


# ─────────────────────────────────────────────────────────────
# SCENARIO 1: Clean image — no vulnerabilities at all
# Expected: PASS, exit code 0, zero CVEs
# ─────────────────────────────────────────────────────────────
SCENARIO_1_VULNS = []


# ─────────────────────────────────────────────────────────────
# SCENARIO 2: "All Noise" — high CVSS scores but ZERO real
# exploitability. These CVEs have extremely low EPSS scores
# and are NOT in CISA KEV. Classic alert fatigue.
# Expected: PASS, exit code 0, all classified as LOW
# ─────────────────────────────────────────────────────────────
SCENARIO_2_VULNS = [
    {
        "VulnerabilityID": "CVE-2020-14155",
        "PkgName": "pcre3",
        "InstalledVersion": "2:8.39-12",
        "FixedVersion": "2:8.39-13",
        "Severity": "HIGH",
        "Title": "libpcre integer overflow in compile_branch()",
        "Description": "libpcre mishandles certain patterns with named subgroups. Rarely exploited in practice.",
        "CVSS": {"nvd": {"V3Score": 7.5}}
    },
    {
        "VulnerabilityID": "CVE-2021-33560",
        "PkgName": "libgcrypt20",
        "InstalledVersion": "1.8.4-5",
        "FixedVersion": "1.8.8-1",
        "Severity": "HIGH",
        "Title": "libgcrypt mishandles ElGamal encryption",
        "Description": "Side-channel timing attack, requires physical proximity. Practically unexploitable remotely.",
        "CVSS": {"nvd": {"V3Score": 7.5}}
    },
    {
        "VulnerabilityID": "CVE-2019-20838",
        "PkgName": "pcre3",
        "InstalledVersion": "2:8.39-12",
        "FixedVersion": "",
        "Severity": "HIGH",
        "Title": "libpcre buffer over-read in JIT",
        "Description": "Requires UTF to be disabled, very niche trigger conditions.",
        "CVSS": {"nvd": {"V3Score": 7.5}}
    },
    {
        # CVSS 9.8 but EPSS is extremely low — truly noise
        "VulnerabilityID": "CVE-2019-17498",
        "PkgName": "libssh2",
        "InstalledVersion": "1.8.0-2.1",
        "FixedVersion": "",
        "Severity": "CRITICAL",
        "Title": "libssh2 integer overflow in SSH_MSG_DISCONNECT",
        "Description": "Theoretical integer overflow in SSH disconnect message parsing. No known exploit.",
        "CVSS": {"nvd": {"V3Score": 8.1}}
    },
    {
        "VulnerabilityID": "CVE-2023-29491",
        "PkgName": "ncurses",
        "InstalledVersion": "6.1+20181013-2",
        "FixedVersion": "6.1+20181013-3",
        "Severity": "HIGH",
        "Title": "ncurses memory corruption via terminfo",
        "Description": "Requires crafted terminfo database. Local attack only.",
        "CVSS": {"nvd": {"V3Score": 7.8}}
    },
]


# ─────────────────────────────────────────────────────────────
# SCENARIO 3: Mixed — real exploits + noise
# Contains Log4Shell (CISA KEV) + HTTP/2 Rapid Reset (CISA KEV)
# plus several noise CVEs. Classic enterprise scan result.
# Expected: FAIL, exit code 1, 2-3 CRITICAL, rest LOW
# ─────────────────────────────────────────────────────────────
SCENARIO_3_VULNS = [
    {
        # Log4Shell — CISA KEV, EPSS ~0.97
        "VulnerabilityID": "CVE-2021-44228",
        "PkgName": "log4j-core",
        "InstalledVersion": "2.14.1",
        "FixedVersion": "2.17.1",
        "Severity": "CRITICAL",
        "Title": "Apache Log4j2 JNDI RCE (Log4Shell)",
        "Description": "Remote code execution via JNDI lookup in log messages. Actively exploited worldwide.",
        "CVSS": {"nvd": {"V3Score": 10.0}}
    },
    {
        # HTTP/2 Rapid Reset — CISA KEV
        "VulnerabilityID": "CVE-2023-44487",
        "PkgName": "nghttp2",
        "InstalledVersion": "1.36.0-2",
        "FixedVersion": "1.36.0-2+deb10u2",
        "Severity": "HIGH",
        "Title": "HTTP/2 Rapid Reset DDoS Attack",
        "Description": "Allows denial of service via rapid stream creation and cancellation.",
        "CVSS": {"nvd": {"V3Score": 7.5}}
    },
    {
        # Noise — high CVSS but no real exploit
        "VulnerabilityID": "CVE-2020-14155",
        "PkgName": "pcre3",
        "InstalledVersion": "2:8.39-12",
        "FixedVersion": "2:8.39-13",
        "Severity": "HIGH",
        "Title": "libpcre integer overflow",
        "Description": "Niche integer overflow, rarely triggered.",
        "CVSS": {"nvd": {"V3Score": 7.5}}
    },
    {
        # Noise
        "VulnerabilityID": "CVE-2021-33560",
        "PkgName": "libgcrypt20",
        "InstalledVersion": "1.8.4-5",
        "FixedVersion": "1.8.8-1",
        "Severity": "HIGH",
        "Title": "libgcrypt ElGamal side-channel",
        "Description": "Requires physical access.",
        "CVSS": {"nvd": {"V3Score": 7.5}}
    },
    {
        # Noise
        "VulnerabilityID": "CVE-2019-20838",
        "PkgName": "pcre3",
        "InstalledVersion": "2:8.39-12",
        "FixedVersion": "",
        "Severity": "HIGH",
        "Title": "pcre buffer over-read in JIT",
        "Description": "Very niche conditions.",
        "CVSS": {"nvd": {"V3Score": 7.5}}
    },
    {
        # Noise — CRITICAL CVSS but basically no exploit code exists
        "VulnerabilityID": "CVE-2022-29155",
        "PkgName": "openldap",
        "InstalledVersion": "2.4.47+dfsg-3",
        "FixedVersion": "2.4.47+dfsg-4",
        "Severity": "CRITICAL",
        "Title": "OpenLDAP experimental back-sql SQLi",
        "Description": "Experimental backend, almost never deployed.",
        "CVSS": {"nvd": {"V3Score": 9.8}}
    },
    {
        # Noise
        "VulnerabilityID": "CVE-2023-29491",
        "PkgName": "ncurses",
        "InstalledVersion": "6.1+20181013-2",
        "FixedVersion": "6.1+20181013-3",
        "Severity": "HIGH",
        "Title": "ncurses terminfo corruption",
        "Description": "Local only.",
        "CVSS": {"nvd": {"V3Score": 7.8}}
    },
]


# ─────────────────────────────────────────────────────────────
# SCENARIO 4: Single Zero-Day needle in a haystack
# One actively exploited CVE (Looney Tunables) buried among
# 6 harmless noise CVEs. Tests if the agent catches it.
# Expected: FAIL, exit code 1, exactly 1 CRITICAL
# ─────────────────────────────────────────────────────────────
SCENARIO_4_VULNS = [
    {
        # Noise
        "VulnerabilityID": "CVE-2020-14155",
        "PkgName": "pcre3",
        "InstalledVersion": "2:8.39-12",
        "FixedVersion": "",
        "Severity": "HIGH",
        "Title": "pcre integer overflow",
        "Description": "Niche.",
        "CVSS": {"nvd": {"V3Score": 7.5}}
    },
    {
        # Noise
        "VulnerabilityID": "CVE-2021-33560",
        "PkgName": "libgcrypt20",
        "InstalledVersion": "1.8.4-5",
        "FixedVersion": "",
        "Severity": "HIGH",
        "Title": "libgcrypt ElGamal",
        "Description": "Physical access needed.",
        "CVSS": {"nvd": {"V3Score": 7.5}}
    },
    {
        # Noise
        "VulnerabilityID": "CVE-2019-20838",
        "PkgName": "pcre3",
        "InstalledVersion": "2:8.39-12",
        "FixedVersion": "",
        "Severity": "HIGH",
        "Title": "pcre JIT over-read",
        "Description": "Niche.",
        "CVSS": {"nvd": {"V3Score": 7.5}}
    },
    {
        # THE NEEDLE: Looney Tunables — CISA KEV, actively exploited
        "VulnerabilityID": "CVE-2023-4911",
        "PkgName": "glibc",
        "InstalledVersion": "2.28-10",
        "FixedVersion": "2.28-10+deb10u3",
        "Severity": "HIGH",
        "Title": "glibc Looney Tunables Local Privilege Escalation",
        "Description": "Buffer overflow in ld.so via GLIBC_TUNABLES. Actively exploited in the wild for privilege escalation.",
        "CVSS": {"nvd": {"V3Score": 7.8}}
    },
    {
        # Noise
        "VulnerabilityID": "CVE-2023-29491",
        "PkgName": "ncurses",
        "InstalledVersion": "6.1+20181013-2",
        "FixedVersion": "",
        "Severity": "HIGH",
        "Title": "ncurses terminfo",
        "Description": "Local.",
        "CVSS": {"nvd": {"V3Score": 7.8}}
    },
    {
        # Noise
        "VulnerabilityID": "CVE-2024-22195",
        "PkgName": "jinja2",
        "InstalledVersion": "3.0.1",
        "FixedVersion": "3.1.3",
        "Severity": "MEDIUM",
        "Title": "Jinja2 xmlattr injection",
        "Description": "Requires specific filter usage.",
        "CVSS": {"nvd": {"V3Score": 6.1}}
    },
]


# ─────────────────────────────────────────────────────────────
# SCENARIO 5: Medium risk only — no CISA KEV, no high EPSS,
# but some packages have moderate exploit probability.
# Expected: PASS, exit code 0
# ─────────────────────────────────────────────────────────────
SCENARIO_5_VULNS = [
    {
        "VulnerabilityID": "CVE-2023-43804",
        "PkgName": "urllib3",
        "InstalledVersion": "1.26.5",
        "FixedVersion": "1.26.17",
        "Severity": "HIGH",
        "Title": "urllib3 Cookie leak on redirect",
        "Description": "Cookie header not stripped on cross-origin redirects.",
        "CVSS": {"nvd": {"V3Score": 8.1}}
    },
    {
        "VulnerabilityID": "CVE-2023-30861",
        "PkgName": "flask",
        "InstalledVersion": "2.0.1",
        "FixedVersion": "2.3.2",
        "Severity": "HIGH",
        "Title": "Flask session cookie disclosure",
        "Description": "Permanent session cookie may be sent insecurely.",
        "CVSS": {"nvd": {"V3Score": 7.5}}
    },
    {
        "VulnerabilityID": "CVE-2024-22195",
        "PkgName": "jinja2",
        "InstalledVersion": "3.0.1",
        "FixedVersion": "3.1.3",
        "Severity": "MEDIUM",
        "Title": "Jinja2 xmlattr HTML injection",
        "Description": "Keys with spaces in xmlattr filter.",
        "CVSS": {"nvd": {"V3Score": 6.1}}
    },
]


SCENARIOS = {
    1: ("Clean Image (zero CVEs)", SCENARIO_1_VULNS, "clean-python:3.12-slim", 0),
    2: ("All Noise (high CVSS, zero exploitability)", SCENARIO_2_VULNS, "noisy-app:latest", 0),
    3: ("Mixed: Real Exploits + Noise", SCENARIO_3_VULNS, "legacy-api:v2.1", 1),
    4: ("Single Zero-Day Hidden in Noise", SCENARIO_4_VULNS, "microservice-auth:latest", 1),
    5: ("Medium Risk Only (no critical)", SCENARIO_5_VULNS, "flask-app:staging", 0),
}


def print_header(scenario_num: int, name: str, expected_exit: int) -> None:
    """Print a clear scenario header."""
    print("\n")
    print("=" * 70)
    print(f"  SCENARIO {scenario_num}: {name}")
    print(f"  Expected gate: {'FAIL (exit 1)' if expected_exit == 1 else 'PASS (exit 0)'}")
    print("=" * 70)


def run_scenario(scenario_num: int) -> bool:
    """Run a single test scenario. Returns True if result matches expectation."""
    name, vulns, image_name, expected_exit = SCENARIOS[scenario_num]
    print_header(scenario_num, name, expected_exit)

    # Write mock Trivy JSON
    filename = f"scenario_{scenario_num}.json"
    filepath = write_trivy_json(filename, vulns, image_name)
    print(f"\n  Mock Trivy JSON written: {filepath}")
    print(f"  CVEs in scan: {len(vulns)}")

    # Import and run the pipeline
    from src.main import run_pipeline
    actual_exit = run_pipeline(trivy_json_path=filepath)

    # Evaluate
    passed = actual_exit == expected_exit
    print("\n" + "-" * 70)
    if passed:
        print(f"  RESULT: CORRECT  |  Expected exit={expected_exit}, Got exit={actual_exit}")
    else:
        print(f"  RESULT: MISMATCH |  Expected exit={expected_exit}, Got exit={actual_exit}")
    print("-" * 70)

    return passed


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Manual test harness for DevSecOps Triage Agent"
    )
    parser.add_argument(
        "--scenario", type=int, choices=[1, 2, 3, 4, 5],
        help="Run a specific scenario (1-5). Omit to run all."
    )
    args = parser.parse_args()

    print("\n" + "#" * 70)
    print("#  DevSecOps Triage Agent — Manual Test Harness")
    print("#  Testing with real CVE IDs against live EPSS + CISA KEV APIs")
    print("#" * 70)

    if args.scenario:
        scenarios_to_run = [args.scenario]
    else:
        scenarios_to_run = [1, 2, 3, 4, 5]

    results = {}
    for num in scenarios_to_run:
        results[num] = run_scenario(num)

    # Final summary
    print("\n\n")
    print("=" * 70)
    print("  FINAL TEST SUMMARY")
    print("=" * 70)
    for num in scenarios_to_run:
        name = SCENARIOS[num][0]
        status = "PASS" if results[num] else "FAIL"
        icon = "[OK]" if results[num] else "[XX]"
        print(f"  {icon} Scenario {num}: {name} -> {status}")

    total = len(results)
    passed = sum(1 for v in results.values() if v)
    print(f"\n  Score: {passed}/{total} scenarios matched expected behavior")
    print("=" * 70)

    if all(results.values()):
        print("\n  All tests passed! The pipeline is working correctly.\n")
    else:
        print("\n  Some tests failed. Review the output above.\n")


if __name__ == "__main__":
    main()

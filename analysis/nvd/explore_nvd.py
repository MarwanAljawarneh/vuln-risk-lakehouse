
"""Explore NVD vulnerability data before designing lakehouse tables."""

import json
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

DATA_DIR = Path("data/landing/nvd")
CVSS_VERSIONS = ("cvssMetricV2", "cvssMetricV30", "cvssMetricV31", "cvssMetricV40")


def load_nvd(data_dir: Path = DATA_DIR) -> list[dict]:
    """Load and deduplicate CVEs from NVD JSON files."""

    files = sorted(data_dir.rglob("*.json"))

    if not files:
        raise FileNotFoundError("No NVD JSON files found")

    cves = {}

    for file in files:
        data = json.loads(file.read_text(encoding="utf-8"))

        for item in data.get("vulnerabilities", []):
            cve = item["cve"]
            cve_id = cve["id"]

            if cve_id not in cves or cve["lastModified"] > cves[cve_id]["lastModified"]:
                cves[cve_id] = cve

    print(f"Files loaded: {len(files)}")
    print(f"Unique CVEs: {len(cves):,}")

    return list(cves.values())


def summarize_nvd(cves: list[dict], days: int = 7) -> None:
    """Summarize CVSS coverage, severity, publication age and weaknesses."""

    total = len(cves)
    if not total:
        print("No CVEs found")
        return

    cvss_versions = Counter()
    severity_counts = Counter()
    weaknesses = Counter()
    missing_metrics = 0
    with_configurations = 0
    multiple_cwes = 0
    newly_published = 0

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    for cve in cves:
        metrics = cve.get("metrics", {})

        if not metrics:
            missing_metrics += 1

        for version in CVSS_VERSIONS:
            if metrics.get(version):
                cvss_versions[version] += 1

        # Prefer the newest available primary CVSS assessment
        for version in reversed(CVSS_VERSIONS):
            entries = metrics.get(version, [])
            if entries:
                entry = next((e for e in entries if e.get("type") == "Primary"), entries[0])
                severity = entry.get("cvssData", {}).get("baseSeverity", entry.get("baseSeverity"))
                severity_counts[severity or "UNKNOWN"] += 1
                break
        else:
            severity_counts["UNSCORED"] += 1

        cwe_ids = set()

        for weakness in cve.get("weaknesses", []):
            for description in weakness.get("description", []):
                if description.get("lang") == "en":
                    cwe_id = description["value"]
                    weaknesses[cwe_id] += 1

                    if cwe_id.startswith("CWE-"):
                        cwe_ids.add(cwe_id)

        if len(cwe_ids) > 1:
            multiple_cwes += 1

        if cve.get("configurations"):
            with_configurations += 1

        published = cve.get("published")

        if published:
            published_date = datetime.fromisoformat(published.replace("Z", "+00:00"))
            if published_date.replace(tzinfo=timezone.utc) >= cutoff:
                newly_published += 1

    previously_published = total - newly_published

    print("\nNVD DATA SUMMARY")
    print("-" * 50)
    print(f"Total unique CVEs: {total:,}")
    print(f"Missing CVSS metrics: {missing_metrics:,} ({missing_metrics / total:.1%})")
    print(f"CVEs with configurations: {with_configurations:,} ({with_configurations / total:.1%})")

    print("\nCVSS VERSION COVERAGE")
    print("-" * 50)
    for version in CVSS_VERSIONS:
        count = cvss_versions[version]
        print(f"{version}: {count:,} ({count / total:.1%})")

    print("\nSEVERITY DISTRIBUTION")
    print("-" * 50)
    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN", "UNSCORED"):
        count = severity_counts[severity]
        print(f"{severity}: {count:,} ({count / total:.1%})")

    print(f"\nPUBLICATION AGE (LAST {days} DAYS)")
    print("-" * 50)
    print(f"Newly published: {newly_published:,} ({newly_published / total:.1%})")
    print(f"Previously published: {previously_published:,} ({previously_published / total:.1%})")

    print("\nCWE CLASSIFICATIONS")
    print("-" * 50)
    print(f"CVEs with multiple CWEs: {multiple_cwes:,} ({multiple_cwes / total:.1%})")

    print("\nTOP 10 WEAKNESSES")
    print("-" * 50)
    for weakness, count in weaknesses.most_common(10):
        print(f"{weakness}: {count:,}")


def inspect_cve(cves: list[dict]) -> None:
    """Display a readable example vulnerability."""

    if not cves:
        return

    cve = cves[0]
    description = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "N/A")

    print("\nEXAMPLE CVE")
    print("-" * 50)
    print(f"CVE ID: {cve['id']}")
    print(f"Published: {cve.get('published')}")
    print(f"Last modified: {cve.get('lastModified')}")
    print(f"Description: {description[:250]}")

    print("\nCVSS METRICS")
    for version, entries in cve.get("metrics", {}).items():
        for entry in entries:
            score = entry.get("cvssData", {}).get("baseScore")
            severity = entry.get("cvssData", {}).get("baseSeverity", entry.get("baseSeverity"))
            print(f"{version}: Score={score} | Severity={severity}")

    print("\nWEAKNESSES")
    for weakness in cve.get("weaknesses", []):
        for item in weakness.get("description", []):
            if item.get("lang") == "en":
                print(item["value"])

    print("\nAFFECTED CONFIGURATIONS")
    for configuration in cve.get("configurations", [])[:2]:
        print(json.dumps(configuration, indent=2))


def main() -> None:
    cves = load_nvd()
    summarize_nvd(cves, days=7)
    inspect_cve(cves)


if __name__ == "__main__":
    main()

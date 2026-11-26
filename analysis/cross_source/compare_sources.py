import csv
import gzip
import json
from pathlib import Path

DATA_DIR = Path("data/landing")


def load_kev() -> set[str]:
    files = sorted((DATA_DIR / "kev").rglob("*.json"))

    if not files:
        raise FileNotFoundError("No KEV files found")

    data = json.loads(files[-1].read_text(encoding="utf-8"))
    return {item["cveID"] for item in data["vulnerabilities"]}


def load_nvd() -> set[str]:
    files = sorted((DATA_DIR / "nvd").rglob("*.json"))

    if not files:
        raise FileNotFoundError("No NVD files found")

    cves = set()

    for file in files:
        data = json.loads(file.read_text(encoding="utf-8"))
        cves.update(item["cve"]["id"] for item in data["vulnerabilities"])

    return cves


def load_epss() -> set[str]:
    files = list((DATA_DIR / "epss").rglob("*.csv.gz"))

    if not files:
        raise FileNotFoundError("No EPSS files found")

    latest = max(files, key=lambda file: file.name)

    with gzip.open(latest, "rt", encoding="utf-8") as file:
        if file.readline().startswith("#"):
            pass
        else:
            file.seek(0)

        return {row["cve"] for row in csv.DictReader(file)}


def compare_sources() -> None:
    kev = load_kev()
    nvd = load_nvd()
    epss = load_epss()

    print("DATA SOURCE COVERAGE")
    print("-" * 50)
    print(f"KEV CVEs: {len(kev):,}")
    print(f"NVD CVEs: {len(nvd):,}")
    print(f"EPSS CVEs: {len(epss):,}")

    print("\nSOURCE OVERLAP")
    print("-" * 50)
    print(f"KEV + NVD: {len(kev & nvd):,}")
    print(f"KEV + EPSS: {len(kev & epss):,}")
    print(f"NVD + EPSS: {len(nvd & epss):,}")
    print(f"All three sources: {len(kev & nvd & epss):,}")

    print("\nMISSING COVERAGE")
    print("-" * 50)
    print(f"KEV CVEs missing from NVD sample: {len(kev - nvd):,}")
    print(f"KEV CVEs missing from EPSS: {len(kev - epss):,}")
    print(f"NVD CVEs missing from EPSS: {len(nvd - epss):,}")

    print("\nCOMBINED COVERAGE")
    print("-" * 50)
    print(f"Total distinct CVEs: {len(kev | nvd | epss):,}")

    print("\nKEV COVERAGE PERCENTAGES")
    print("-" * 50)
    print(f"KEV CVEs found in NVD sample: {len(kev & nvd) / len(kev):.1%}")
    print(f"KEV CVEs found in EPSS: {len(kev & epss) / len(kev):.1%}")


if __name__ == "__main__":
    compare_sources()

import csv
import gzip
import statistics
from collections import Counter
from pathlib import Path

DATA_DIR = Path("data/landing/epss")


def load_epss(data_dir: Path = DATA_DIR) -> tuple[list[dict], str]:
    """Load the latest compressed EPSS snapshot."""

    files = list(data_dir.rglob("*.csv.gz"))

    if not files:
        raise FileNotFoundError("No EPSS files found")

    latest_file = max(files, key=lambda file: file.name)
    records = []

    with gzip.open(latest_file, "rt", encoding="utf-8") as file:
        metadata = file.readline().strip()

        if not metadata.startswith("#"):
            raise ValueError("Missing EPSS metadata header")

        reader = csv.DictReader(file)

        if reader.fieldnames != ["cve", "epss", "percentile"]:
            raise ValueError(f"Unexpected EPSS columns: {reader.fieldnames}")

        for row in reader:
            records.append(row)

    print(f"File loaded: {latest_file.name}")
    print(f"Metadata: {metadata}")
    print(f"Records loaded: {len(records):,}")

    return records, metadata


def summarize_epss(records: list[dict]) -> None:
    """Calculate EPSS distributions, coverage and data quality."""

    total = len(records)

    if not total:
        print("No EPSS records found")
        return

    scores = []
    percentiles = []
    cve_counts = Counter()
    missing_values = 0
    invalid_values = 0

    for row in records:
        cve = row.get("cve", "")
        epss = row.get("epss", "")
        percentile = row.get("percentile", "")

        if not cve or not epss or not percentile:
            missing_values += 1
            continue

        try:
            score = float(epss)
            rank = float(percentile)

            if not (0 <= score <= 1 and 0 <= rank <= 1):
                invalid_values += 1
                continue

        except ValueError:
            invalid_values += 1
            continue

        if not cve.startswith("CVE-"):
            invalid_values += 1
            continue

        scores.append(score)
        percentiles.append(rank)
        cve_counts[cve] += 1

    if not scores:
        raise ValueError("No valid EPSS scores found")

    valid_total = len(scores)
    duplicates = sum(count - 1 for count in cve_counts.values() if count > 1)

    print("\nEPSS DATA SUMMARY")
    print("-" * 50)
    print(f"Total records: {total:,}")
    print(f"Unique CVEs: {len(cve_counts):,}")
    print(f"Duplicate CVE IDs: {duplicates:,}")
    print(f"Missing values: {missing_values:,}")
    print(f"Invalid values: {invalid_values:,}")
    print(f"Valid records: {valid_total:,}")

    print("\nEPSS SCORE STATISTICS")
    print("-" * 50)
    print(f"Minimum: {min(scores):.6f} ({min(scores):.2%})")
    print(f"Maximum: {max(scores):.6f} ({max(scores):.2%})")
    print(f"Average: {statistics.mean(scores):.6f} ({statistics.mean(scores):.2%})")
    print(f"Median: {statistics.median(scores):.6f} ({statistics.median(scores):.2%})")

    print("\nEXPLOITATION PROBABILITY THRESHOLDS")
    print("-" * 50)

    for threshold in (0.01, 0.10, 0.50):
        count = sum(score >= threshold for score in scores)
        print(f"EPSS >= {threshold:.0%}: {count:,} ({count / valid_total:.1%})")

    print("\nEPSS SCORE DISTRIBUTION")
    print("-" * 50)

    ranges = [
        ("0% to <1%", 0, 0.01),
        ("1% to <10%", 0.01, 0.10),
        ("10% to <50%", 0.10, 0.50),
        ("50% to 100%", 0.50, 1.01),
    ]

    for label, lower, upper in ranges:
        count = sum(lower <= score < upper for score in scores)
        print(f"{label}: {count:,} ({count / valid_total:.1%})")

    print("\nTOP 10 HIGHEST EPSS SCORES")
    print("-" * 50)

    valid_records = [
        (cve, float(row["epss"]), float(row["percentile"]))
        for row in records
        if (cve := row.get("cve", "")) in cve_counts
        and row.get("epss")
        and row.get("percentile")
        and 0 <= float(row["epss"]) <= 1
        and 0 <= float(row["percentile"]) <= 1
    ]

    for cve, score, percentile in sorted(valid_records, key=lambda item: item[1], reverse=True)[:10]:
        print(f"{cve} | EPSS: {score:.2%} | Percentile: {percentile:.2%}")


def main() -> None:
    records, _ = load_epss()
    summarize_epss(records)


if __name__ == "__main__":
    main()

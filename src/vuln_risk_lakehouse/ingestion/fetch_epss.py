import csv
import gzip
import hashlib
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import httpx
from loguru import logger

EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
OUTPUT_DIR = Path("data/landing")


def setup_logging(log_dir: Path = Path("logs")) -> None:
    log_dir.mkdir(parents=True, exist_ok=True)
    logger.add(log_dir / "fetch_epss.log", level="INFO", rotation="10 MB", retention="14 days")


def fetch_epss(timeout: float = 60.0) -> bytes:
    """Download the current EPSS compressed CSV."""

    logger.info("Downloading daily EPSS scores")

    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        response = client.get(EPSS_URL)
        response.raise_for_status()

    if not response.content:
        raise ValueError("EPSS returned an empty file")

    logger.success("Downloaded EPSS snapshot: {} bytes", len(response.content))
    return response.content


def validate_epss(payload: bytes) -> tuple[str, int]:
    """Validate the compressed CSV and count records."""

    try:
        csv_text = gzip.decompress(payload).decode("utf-8")
    except (OSError, EOFError, UnicodeDecodeError) as exc:
        raise ValueError("Invalid EPSS gzip file") from exc

    lines = csv_text.splitlines()

    if not lines:
        raise ValueError("EPSS CSV is empty")

    metadata = lines[0] if lines[0].startswith("#") else ""
    csv_lines = lines[1:] if metadata else lines

    reader = csv.DictReader(csv_lines)

    if reader.fieldnames != ["cve", "epss", "percentile"]:
        raise ValueError(f"Unexpected EPSS columns: {reader.fieldnames}")

    count = 0

    for row in reader:
        if not row["cve"].startswith("CVE-"):
            raise ValueError(f"Invalid CVE identifier: {row['cve']}")

        if not 0 <= float(row["epss"]) <= 1:
            raise ValueError(f"Invalid EPSS score for {row['cve']}")

        if not 0 <= float(row["percentile"]) <= 1:
            raise ValueError(f"Invalid percentile for {row['cve']}")

        count += 1

    if count == 0:
        raise ValueError("EPSS CSV contains no records")

    logger.info("EPSS metadata: {}", metadata or "Not provided")
    logger.success("Validated {} EPSS records", count)

    return metadata, count


def save_epss(payload: bytes, out_dir: Path = OUTPUT_DIR) -> Path:
    """Save the original compressed CSV as a raw snapshot."""

    ingested_at = datetime.now(timezone.utc)
    ingest_date = ingested_at.strftime("%Y-%m-%d")
    run_id = ingested_at.strftime("%Y%m%dT%H%M%S%fZ")
    content_hash = hashlib.sha256(payload).hexdigest()

    folder = out_dir / "epss" / f"ingest_date={ingest_date}"
    folder.mkdir(parents=True, exist_ok=True)

    target = folder / f"epss_{run_id}_{content_hash[:12]}.csv.gz"
    temp_path = None

    try:
        with tempfile.NamedTemporaryFile(mode="wb", dir=folder, suffix=".tmp", delete=False) as temp:
            temp.write(payload)
            temp_path = Path(temp.name)

        os.replace(temp_path, target)

    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)

    logger.info("Saved EPSS snapshot to {}", target)
    return target


def main() -> None:
    setup_logging()
    logger.info("Starting EPSS ingestion pipeline")

    try:
        payload = fetch_epss()
        validate_epss(payload)
        file = save_epss(payload)
        logger.success("EPSS ingestion completed successfully: {}", file)

    except Exception:
        logger.exception("EPSS ingestion failed")
        raise


if __name__ == "__main__":
    main()

import hashlib
import json
import os
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from dotenv import load_dotenv

import httpx
from loguru import logger

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OUTPUT_DIR = Path("data/landing")
PAGE_SIZE = 2000


def setup_logging(log_dir: Path = Path("logs")) -> None:
    log_dir.mkdir(parents=True, exist_ok=True)
    logger.add(log_dir / "fetch_nvd.log", level="INFO", rotation="10 MB", retention="14 days")


def fetch_nvd(days: int = 7, timeout: float = 60.0) -> list[dict]:
    """Fetch all pages of NVD records modified within the requested window."""

    if not 1 <= days <= 120:
        raise ValueError("days must be between 1 and 120")

    end_date = datetime.now(timezone.utc)
    start_date = end_date - timedelta(days=days)

    params = {
        "lastModStartDate": start_date.isoformat(timespec="milliseconds"),
        "lastModEndDate": end_date.isoformat(timespec="milliseconds"),
        "resultsPerPage": PAGE_SIZE,
        "startIndex": 0,
    }

    api_key = os.getenv("NVD_API_KEY")

    if api_key:
        logger.info("Using NVD API key from environment variable")
        headers = {"apiKey": api_key} 
    else:
        logger.warning("No NVD API key found in environment variable; using unauthenticated requests")
        headers = {}

    logger.info("Fetching NVD vulnerabilities modified in the last {} days", days)

    pages = []
    total_fetched = 0

    with httpx.Client(timeout=timeout, follow_redirects=True, headers=headers) as client:
        while True:
            response = client.get(NVD_URL, params=params)
            response.raise_for_status()
            data = response.json()

            if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
                raise ValueError("Invalid NVD API response")

            if type(data.get("totalResults")) is not int:
                raise ValueError("NVD totalResults must be an integer")

            records = data["vulnerabilities"]
            pages.append(data)
            total_fetched += len(records)

            logger.info("Fetched page {} | Records={} | Total={}", len(pages), total_fetched, data["totalResults"])

            if total_fetched >= data["totalResults"]:
                break

            if not records:
                raise ValueError("NVD returned an empty page before all records were fetched")

            params["startIndex"] += len(records)
            time.sleep(2 if api_key else 6.5)

    logger.success("NVD fetch completed: {} records across {} pages", total_fetched, len(pages))
    return pages


def save_nvd(pages: list[dict], out_dir: Path = OUTPUT_DIR) -> list[Path]:
    """Save every NVD response page as a raw JSON snapshot."""

    ingested_at = datetime.now(timezone.utc)
    ingest_date = ingested_at.strftime("%Y-%m-%d")
    run_id = ingested_at.strftime("%Y%m%dT%H%M%S%fZ")

    folder = out_dir / "nvd" / f"ingest_date={ingest_date}"
    folder.mkdir(parents=True, exist_ok=True)

    saved_files = []

    for index, data in enumerate(pages, start=1):
        payload = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        content_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()

        target = folder / f"nvd_{run_id}_page_{index:03d}_{content_hash[:12]}.json"
        temp_path = None

        try:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=folder, suffix=".tmp", delete=False) as temp:
                temp.write(payload)
                temp_path = Path(temp.name)

            os.replace(temp_path, target)

        finally:
            if temp_path is not None:
                temp_path.unlink(missing_ok=True)

        saved_files.append(target)
        logger.info("Saved NVD page {} to {}", index, target)

    return saved_files


def main() -> None:
    load_dotenv()
    setup_logging()
    logger.info("Starting NVD ingestion pipeline")

    try:
        pages = fetch_nvd(days=7)
        files = save_nvd(pages)
        logger.success("NVD ingestion completed successfully: {} files saved", len(files))

    except Exception:
        logger.exception("NVD ingestion failed")
        raise


if __name__ == "__main__":
    main()
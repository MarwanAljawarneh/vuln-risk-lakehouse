import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import httpx
from loguru import logger

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OUTPUT_DIR = Path("data/landing")

def setup_logging(log_dir: Path = Path("logs")) -> None:
    """Configure file logging when the pipeline runs."""

    log_dir.mkdir(parents=True, exist_ok=True)
    logger.add(log_dir / "fetch_kev.log", level="INFO", rotation="10 MB", retention="14 days")


def fetch_kev(timeout: float = 30.0) -> dict:
    """Fetch and validate the latest CISA KEV catalog."""

    logger.info("Fetching CISA KEV catalog")

    response = httpx.get(KEV_URL, timeout=timeout, follow_redirects=True)
    response.raise_for_status()
    data = response.json()

    if not isinstance(data, dict):
        raise ValueError("KEV response must be a JSON object")

    required_fields = ("catalogVersion", "dateReleased", "count", "vulnerabilities")

    for field in required_fields:
        if field not in data:
            raise ValueError(f"KEV feed missing required field: {field}")

    if not isinstance(data["catalogVersion"], str) or not data["catalogVersion"]:
        raise ValueError("KEV catalogVersion must be a non-empty string")

    if not isinstance(data["dateReleased"], str) or not data["dateReleased"]:
        raise ValueError("KEV dateReleased must be a non-empty string")

    if not isinstance(data["vulnerabilities"], list):
        raise ValueError("KEV vulnerabilities must be a list")

    if type(data["count"]) is not int:
        raise ValueError("KEV count must be an integer")

    if data["count"] != len(data["vulnerabilities"]):
        raise ValueError("KEV count does not match number of records")

    logger.info("Fetched {} vulnerabilities (version={})", data["count"], data["catalogVersion"])
    return data


def save_kev(data: dict, out_dir: Path = OUTPUT_DIR) -> Path:
    """Save each ingestion as a uniquely named JSON snapshot."""

    version = data["catalogVersion"]
    ingested_at = datetime.now(timezone.utc)
    ingest_date = ingested_at.strftime("%Y-%m-%d")
    run_id = ingested_at.strftime("%Y%m%dT%H%M%S%fZ")

    payload = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    content_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()

    target = out_dir / "kev" / f"ingest_date={ingest_date}" / f"kev_{run_id}_{content_hash[:12]}.json"
    target.parent.mkdir(parents=True, exist_ok=True)

    temp_path = None

    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=target.parent, suffix=".tmp", delete=False) as temp:
            temp.write(payload)
            temp_path = Path(temp.name)

        os.replace(temp_path, target)

    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)

    logger.info("Saved KEV snapshot to {}", target)
    logger.info("Catalog version={} | Records={} | SHA256={}", version, data["count"], content_hash[:12])

    return target


def main() -> None:
    setup_logging()
    logger.info("Starting KEV ingestion pipeline")

    try:
        data = fetch_kev()
        save_kev(data)
        logger.success("KEV ingestion completed successfully")

    except Exception:
        logger.exception("KEV ingestion failed")
        raise


if __name__ == "__main__":
    main()

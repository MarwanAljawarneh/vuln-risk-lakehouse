# Bronze Layer

The Bronze layer ingests source vulnerability datasets into Delta Lake, preserving raw payloads and ingestion metadata for downstream transformations.

## CISA Known Exploited Vulnerabilities (KEV)

| Property | Value |
|---|---|
| Source | CISA KEV Catalog |
| Landing Location | `/Volumes/vuln_lakehouse/bronze/landing/kev/` |
| Target Table | `vuln_lakehouse.bronze.kev_raw` |
| Storage Format | Delta Lake |
| Ingestion Engine | PySpark |

### Implementation

The initial ingestion workflow reads KEV JSON snapshots from a Unity Catalog Volume using Spark's `binaryFile` data source.

Raw JSON payloads are persisted without flattening to preserve the original source structure. Each record includes ingestion metadata for traceability.

### Table Schema

| Column | Type | Description |
|---|---|---|
| `source_file` | STRING | Source file path |
| `raw_json` | STRING | Original JSON payload |
| `ingested_at` | TIMESTAMP | Timestamp of the Databricks ingestion |

### Validation

The initial load was validated using Databricks SQL:

```sql
SELECT
    COUNT(*) AS raw_files,
    CAST(MAX(GET_JSON_OBJECT(raw_json, '$.count')) AS INT) AS total_cves
FROM vuln_lakehouse.bronze.kev_raw;
```

**Result:** 1 raw JSON snapshot containing 1,795 vulnerabilities.

![KEV Bronze Validation](../../docs/screenshots/kev_bronze_validation.png)
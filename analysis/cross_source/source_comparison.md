# Sources Comaprison

```text
DATA SOURCE COVERAGE
--------------------------------------------------
KEV CVEs: 1,795
NVD CVEs: 7,943
EPSS CVEs: 412,861

SOURCE OVERLAP
--------------------------------------------------
KEV + NVD: 18
KEV + EPSS: 1,794
NVD + EPSS: 7,902
All three sources: 18

MISSING COVERAGE
--------------------------------------------------
KEV CVEs missing from NVD sample: 1,777
KEV CVEs missing from EPSS: 1
NVD CVEs missing from EPSS: 41

COMBINED COVERAGE
--------------------------------------------------
Total distinct CVEs: 412,903

KEV COVERAGE PERCENTAGES
--------------------------------------------------
KEV CVEs found in NVD sample: 1.0%
KEV CVEs found in EPSS: 99.9%
```

**Note:** The 1,777 KEV CVEs missing from our NVD dataset are due to the NVD extractor only fetching vulnerabilities modified within the last 7 days. Older CVEs that haven't been recently modified are not included in this sample. These will be retrieved through a historical NVD backfill and processed in Databricks.
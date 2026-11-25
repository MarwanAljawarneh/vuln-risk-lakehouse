# NVD Data Exploration Results

```text
Files loaded: 4
Unique CVEs: 7,943

NVD DATA SUMMARY
--------------------------------------------------
Total unique CVEs: 7,943
Missing CVSS metrics: 606 (7.6%)
CVEs with configurations: 1,615 (20.3%)

CVSS VERSION COVERAGE
--------------------------------------------------
cvssMetricV2: 236 (3.0%)
cvssMetricV30: 99 (1.2%)
cvssMetricV31: 6,257 (78.8%)
cvssMetricV40: 2,692 (33.9%)

SEVERITY DISTRIBUTION
--------------------------------------------------
CRITICAL: 608 (7.7%)
HIGH: 2,973 (37.4%)
MEDIUM: 3,316 (41.7%)
LOW: 440 (5.5%)
UNKNOWN: 0 (0.0%)
UNSCORED: 606 (7.6%)

PUBLICATION AGE (LAST 7 DAYS)
--------------------------------------------------
Newly published: 4,353 (54.8%)
Previously published: 3,590 (45.2%)

CWE CLASSIFICATIONS
--------------------------------------------------
CVEs with multiple CWEs: 682 (8.6%)

TOP 10 WEAKNESSES
--------------------------------------------------
CWE-79: 707
CWE-284: 469
CWE-862: 449
CWE-416: 283
CWE-863: 267
CWE-125: 259
CWE-22: 230
CWE-200: 212
CWE-639: 205
CWE-787: 187

EXAMPLE CVE
--------------------------------------------------
CVE ID: CVE-2004-0468
Published: 2004-12-06T05:00:00.000
Last modified: 2026-11-24T21:57:43.640
Description: Memory leak in Juniper JUNOS Packet Forwarding Engine (PFE) allows remote attackers to cause a denial of service (memory exhaustion and device reboot) via certain IPv6 packets.

CVSS METRICS
cvssMetricV2: Score=5.0 | Severity=MEDIUM

WEAKNESSES
NVD-CWE-Other

AFFECTED CONFIGURATIONS
{
  "nodes": [
    {
      "cpeMatch": [
        {
          "criteria": "cpe:2.3:o:juniper:junos:-:*:*:*:*:*:*:*",
          "matchCriteriaId": "432CAEBA-3386-4FC5-8416-4277114500F1",
          "vulnerable": true
        }
      ],
      "negate": false,
      "operator": "OR"
    }
  ]
}
```
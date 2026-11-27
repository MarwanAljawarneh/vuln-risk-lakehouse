-- Initialize Unity Catalog objects for the vulnerability risk lakehouse.

CREATE CATALOG IF NOT EXISTS vuln_lakehouse;

CREATE SCHEMA IF NOT EXISTS vuln_lakehouse.bronze;
CREATE SCHEMA IF NOT EXISTS vuln_lakehouse.silver;
CREATE SCHEMA IF NOT EXISTS vuln_lakehouse.gold;
CREATE SCHEMA IF NOT EXISTS vuln_lakehouse.monitoring;

-- Storage for raw source files.
CREATE VOLUME IF NOT EXISTS vuln_lakehouse.bronze.landing;

# Vulnerability Risk Lakehouse

A data engineering project that uses **Python, Databricks, and Delta Lake** to build a cybersecurity vulnerability data pipeline.

The goal is to collect vulnerability data from multiple sources, process it in Databricks, and create tables and dashboards to analyze and prioritize security risks.

## Data Sources

- **CISA KEV (Known Exploited Vulnerabilities):** A catalog maintained by the Cybersecurity and Infrastructure Security Agency (CISA) containing vulnerabilities known to have been exploited in the wild.
- **NVD (National Vulnerability Database):** Provides vulnerability details, severity scores (CVSS), and affected software.
- **FIRST EPSS (Exploit Prediction Scoring System):** Estimates the probability of a vulnerability being exploited in the next 30 days.

## Architecture

The project follows the **Bronze, Silver, and Gold Medallion Architecture** in Databricks:

- **Bronze:** Store raw vulnerability data.
- **Silver:** Clean, transform, and combine data from all three sources.
- **Gold:** Create tables for risk analysis, reporting, and dashboards.

## Tech Stack

Python • SQL • Databricks • Delta Lake • GitHub Actions
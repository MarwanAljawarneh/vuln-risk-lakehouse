# Databricks notebook source
"""Load EPSS CSV snapshots into a Bronze Delta table."""

from pyspark.sql import functions as F

SOURCE_PATH = "/Volumes/vuln_lakehouse/bronze/landing/epss/*.csv.gz"
TARGET_TABLE = "vuln_lakehouse.bronze.epss_raw"

# Read gzip-compressed CSV snapshots while preserving source values as strings.
epss_df = (
    spark.read
    .option("header", "true")
    .option("comment", "#")
    .option("inferSchema", "false")
    .csv(SOURCE_PATH)
)

# Attach original file path and ingestion timestamp.
bronze_df = (
    epss_df
    .withColumn("source_file", F.col("_metadata.file_path"))
    .withColumn("ingested_at", F.current_timestamp())
)

# Initial load only; incremental snapshots will be implemented later.
bronze_df.write.format("delta").mode("overwrite").saveAsTable(TARGET_TABLE)

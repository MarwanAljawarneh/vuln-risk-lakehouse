# Databricks notebook source
"""Load raw CISA KEV snapshots into a Bronze Delta table."""

from pyspark.sql import functions as F

SOURCE_PATH = "/Volumes/vuln_lakehouse/bronze/landing/kev/*.json"
TARGET_TABLE = "vuln_lakehouse.bronze.kev_raw"

# Read original JSON documents without flattening vulnerability records.
df = (
    spark.read.format("binaryFile")
    .load(SOURCE_PATH)
    .select(
        F.col("path").alias("source_file"),
        F.col("content").cast("string").alias("raw_json"),
        F.current_timestamp().alias("ingested_at"),
    )
)

# Initial load only; incremental processing will be implemented later.
df.write.format("delta").mode("overwrite").saveAsTable(TARGET_TABLE)
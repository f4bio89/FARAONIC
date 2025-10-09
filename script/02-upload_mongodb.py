#!./projeto/bin/python
# -*- coding: utf-8 -*-

"""
Upload JSON or JSONL traffic data to MongoDB.
If no arguments are passed, it uses default configuration:
  --mongo-uri mongodb://user:user@localhost:27017/
  --db FARAONIC
  --collection normal
  --input json/PCAP.json
  --batch-size 1000
"""

import json
import os
import argparse
from typing import Any, Iterable, List
from pymongo import MongoClient
from bson.decimal128 import Decimal128

# =========================================================
# DEFAULTS
# =========================================================
DEFAULT_MONGO_URI = "mongodb://user:user@localhost:27017/"
DEFAULT_DB = "FARAONIC"
DEFAULT_COLL = "normal"
DEFAULT_INPUT = "json/PCAP.json"
DEFAULT_BATCH = 1000

# MongoDB int64 boundaries
INT64_MIN = -(2**63)
INT64_MAX = (2**63) - 1

# =========================================================
# HELPERS
# =========================================================
def sanitize(obj: Any) -> Any:
    """Recursively convert large integers to Decimal128 or string."""
    if isinstance(obj, int):
        if obj < INT64_MIN or obj > INT64_MAX:
            return Decimal128(str(obj))
        return obj
    if isinstance(obj, list):
        return [sanitize(x) for x in obj]
    if isinstance(obj, dict):
        return {k: sanitize(v) for k, v in obj.items()}
    return obj

def iter_json_records(path: str) -> Iterable[dict]:
    """Accepts JSON array or NDJSON (one JSON per line)."""
    with open(path, "r", encoding="utf-8") as f:
        head = f.read(1)
        f.seek(0)
        if head == "[":
            data = json.load(f)
            if isinstance(data, list):
                for doc in data:
                    yield doc
            else:
                yield data
        else:
            for line in f:
                line = line.strip()
                if line:
                    yield json.loads(line)

def chunked(iterable: Iterable[dict], size: int) -> Iterable[List[dict]]:
    """Yield lists of length `size`."""
    batch = []
    for item in iterable:
        batch.append(item)
        if len(batch) >= size:
            yield batch
            batch = []
    if batch:
        yield batch

# =========================================================
# MAIN
# =========================================================
def main():
    parser = argparse.ArgumentParser(description="Upload JSON/JSONL to MongoDB")
    parser.add_argument("--mongo-uri", default=DEFAULT_MONGO_URI,
                        help=f"MongoDB URI (default: {DEFAULT_MONGO_URI})")
    parser.add_argument("--db", default=DEFAULT_DB, help=f"Database name (default: {DEFAULT_DB})")
    parser.add_argument("--collection", default=DEFAULT_COLL,
                        help=f"Collection name (default: {DEFAULT_COLL})")
    parser.add_argument("--input", default=DEFAULT_INPUT,
                        help=f"Input JSON or JSONL file (default: {DEFAULT_INPUT})")
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH,
                        help=f"Batch insert size (default: {DEFAULT_BATCH})")
    args = parser.parse_args()

    if not os.path.exists(args.input):
        raise FileNotFoundError(f"Input file not found: {args.input}")

    print(f"[INFO] Connecting to MongoDB: {args.mongo_uri}")
    client = MongoClient(args.mongo_uri)
    db = client[args.db]
    coll = db[args.collection]
    print("[INFO] Connection established successfully.")

    print(f"[INFO] Loading records from: {args.input}")
    total, inserted = 0, 0

    for batch in chunked(iter_json_records(args.input), args.batch_size):
        total += len(batch)
        sanitized = [sanitize(doc) for doc in batch]
        try:
            result = coll.insert_many(sanitized, ordered=False)
            inserted += len(result.inserted_ids)
            print(f"[BATCH] Inserted: {len(result.inserted_ids)} (total {inserted})")
        except Exception as e:
            print(f"[WARN] Batch insert failed: {e}")

    print(f"[INFO] Upload completed. Inserted {inserted}/{total} documents.")

if __name__ == "__main__":
    main()

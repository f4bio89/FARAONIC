#!./projeto/bin/python
# -*- coding: utf-8 -*-

"""
03-perguntas.py (Questions / Baseline Inspector)

Description:
  Connect to MongoDB, create helpful indexes (optional), run an aggregation
  that normalizes Modbus/TCP fields and produces several facets:
    - servers list
    - client-server summary
    - function codes (requests & responses)
    - unit IDs per server
    - Modbus request payload signatures

  The script prints human-friendly tables and returns a JSON-like summary.
  Optionally writes the summary to a JSON file (--output).

Defaults:
  --mongo-uri mongodb://user:user@localhost:27017/
  --db MESTRADO_final
  --collection normal

Examples:
  python3 03-perguntas.py
  python3 03-perguntas.py --mongo-uri "mongodb://user:user@192.168.30.15:27017/" \
      --db MESTRADO_final --collection normal --output reports/baseline_summary.json
  python3 03-perguntas.py --limit 10000       # quick test on first 10k docs
  python3 03-perguntas.py --no-index         # do not create indexes
"""

import argparse
import json
import sys
import traceback
from typing import Dict, Any, List

from pymongo import MongoClient, ASCENDING
from pymongo.errors import PyMongoError

# ---------- defaults ----------
DEFAULT_MONGO_URI = "mongodb://user:user@localhost:27017/"
DEFAULT_DB = "FARAONIC"
DEFAULT_COLL = "normal"

# ---------- helpers ----------
def make_indexes(coll, verbose: bool = True) -> None:
    """Create recommended indexes for faster aggregation/queries."""
    try:
        if verbose: print("[+] Creating indexes (if not present)...")
        coll.create_index([("TCP.dport", ASCENDING)])
        coll.create_index([("TCP.sport", ASCENDING)])
        coll.create_index([("IP.src", ASCENDING)])
        coll.create_index([("IP.dst", ASCENDING)])
        coll.create_index([("ModbusTCPRequest.func_code", ASCENDING)])
        coll.create_index([("ModbusTCPResponse.func_code", ASCENDING)])
        coll.create_index([("ModbusTCPRequest.unit_id", ASCENDING)])
        coll.create_index([("ModbusTCPResponse.unit_id", ASCENDING)])
        coll.create_index([("ModbusWriteMultipleCoilsRequest.reference_number", ASCENDING)])
        coll.create_index([("ModbusWriteMultipleCoilsRequest.coil_status", ASCENDING)])
        coll.create_index([("ModbusReadDiscreteInputsRequest.reference_number", ASCENDING)])
        coll.create_index([("ModbusReadDiscreteInputsResponse.input_status", ASCENDING)])
        if verbose: print("[+] Indexes ensured.")
    except PyMongoError as e:
        print("[WARN] Index creation warning:", e)

def build_pipeline(limit: int | None = None) -> List[Dict[str, Any]]:
    """
    Build aggregation pipeline. Optionally add a $limit stage at the beginning
    for quick tests (note: limit is applied BEFORE facets).
    """
    pipeline = []
    if limit and limit > 0:
        pipeline.append({"$limit": limit})

    # match Modbus/TCP involvement (either source or dest port 502)
    pipeline.append(
        {"$match": {"$or": [{"TCP.dport": 502}, {"TCP.sport": 502}]}}
    )

    pipeline.append({
        "$set": {
            "src_ip": "$IP.src",
            "dst_ip": "$IP.dst",
            "sport": "$TCP.sport",
            "dport": "$TCP.dport",
            "direction": {
                "$switch": {
                    "branches": [
                        {
                            "case": {"$and": [
                                {"$eq": ["$TCP.dport", 502]},
                                {"$ne": ["$ModbusTCPRequest", None]}
                            ]},
                            "then": "request"
                        },
                        {
                            "case": {"$and": [
                                {"$eq": ["$TCP.sport", 502]},
                                {"$ne": ["$ModbusTCPResponse", None]}
                            ]},
                            "then": "response"
                        }
                    ],
                    "default": "other"
                }
            },
            "func_code": {"$ifNull": ["$ModbusTCPRequest.func_code", "$ModbusTCPResponse.func_code"]},
            "unit_id": {"$ifNull": ["$ModbusTCPRequest.unit_id", "$ModbusTCPResponse.unit_id"]},
            "write_mult_req": "$ModbusWriteMultipleCoilsRequest",
            "write_mult_resp": "$ModbusWriteMultipleCoilsResponse",
            "read_discrete_req": "$ModbusReadDiscreteInputsRequest",
            "read_discrete_resp": "$ModbusReadDiscreteInputsResponse",
        }
    })

    # The facet stage producing all outputs
    pipeline.append({
        "$facet": {
            "servers": [
                {"$match": {"dport": 502}},
                {"$group": {"_id": "$dst_ip"}},
                {"$project": {"_id": 0, "server_ip": "$_id"}},
                {"$sort": {"server_ip": 1}}
            ],
            "clients_summary": [
                {"$match": {"dport": 502}},
                {"$group": {
                    "_id": {"client_ip": "$src_ip", "server_ip": "$dst_ip"},
                    "count": {"$sum": 1}
                }},
                {"$project": {
                    "_id": 0,
                    "client_ip": "$_id.client_ip",
                    "server_ip": "$_id.server_ip",
                    "count": 1
                }},
                {"$sort": {"server_ip": 1, "client_ip": 1}}
            ],
            "func_codes_req": [
                {"$match": {"dport": 502, "direction": "request", "func_code": {"$ne": None}}},
                {"$group": {
                    "_id": {"server_ip": "$dst_ip", "client_ip": "$src_ip", "func": "$func_code"},
                    "recurrence": {"$sum": 1}
                }},
                {"$project": {
                    "_id": 0,
                    "direction": {"$literal": "request"},
                    "server_ip": "$_id.server_ip",
                    "client_ip": "$_id.client_ip",
                    "func_code": "$_id.func",
                    "recurrence": 1
                }},
                {"$sort": {"server_ip": 1, "client_ip": 1, "recurrence": -1}}
            ],
            "func_codes_resp": [
                {"$match": {"sport": 502, "direction": "response", "func_code": {"$ne": None}}},
                {"$group": {
                    "_id": {"server_ip": "$src_ip", "client_ip": "$dst_ip", "func": "$func_code"},
                    "recurrence": {"$sum": 1}
                }},
                {"$project": {
                    "_id": 0,
                    "direction": {"$literal": "response"},
                    "server_ip": "$_id.server_ip",
                    "client_ip": "$_id.client_ip",
                    "func_code": "$_id.func",
                    "recurrence": 1
                }},
                {"$sort": {"server_ip": 1, "client_ip": 1, "recurrence": -1}}
            ],
            "unit_ids": [
                {"$match": {"dport": 502, "direction": "request", "unit_id": {"$ne": None}}},
                {"$group": {
                    "_id": {"server_ip": "$dst_ip", "unit_id": "$unit_id"},
                    "count": {"$sum": 1}
                }},
                {"$project": {"_id": 0, "server_ip": "$_id.server_ip", "unit_id": "$_id.unit_id", "count": 1}},
                {"$sort": {"server_ip": 1, "count": -1}}
            ],
            "modbus_data_req": [
                {"$match": {"dport": 502, "direction": "request", "func_code": {"$ne": None}}},
                {"$project": {
                    "_id": 0,
                    "server_ip": "$dst_ip",
                    "client_ip": "$src_ip",
                    "func_code": "$func_code",
                    "reference_num": {"$ifNull": ["$write_mult_req.reference_number", "$read_discrete_req.reference_number"]},
                    "bit_cnt": {"$ifNull": ["$write_mult_req.bit_count", "$read_discrete_req.bit_count"]},
                    "byte_cnt": "$write_mult_req.byte_count",
                    "coil_status_hex": "$write_mult_req.coil_status",
                    "input_status_hex": "$read_discrete_resp.input_status"
                }},
                {"$group": {
                    "_id": {
                        "server_ip": "$server_ip",
                        "client_ip": "$client_ip",
                        "func_code": "$func_code",
                        "reference_num": "$reference_num",
                        "bit_cnt": "$bit_cnt",
                        "byte_cnt": "$byte_cnt",
                        "coil_status_hex": "$coil_status_hex",
                        "input_status_hex": "$input_status_hex"
                    },
                    "recurrence": {"$sum": 1}
                }},
                {"$project": {
                    "_id": 0,
                    "server_ip": "$_id.server_ip",
                    "client_ip": "$_id.client_ip",
                    "func_code": "$_id.func_code",
                    "reference_num": "$_id.reference_num",
                    "bit_cnt": "$_id.bit_cnt",
                    "byte_cnt": "$_id.byte_cnt",
                    "coil_status_hex": "$_id.coil_status_hex",
                    "input_status_hex": "$_id.input_status_hex",
                    "recurrence": 1
                }},
                {"$sort": {"server_ip": 1, "client_ip": 1, "recurrence": -1}}
            ]
        }
    })
    return pipeline

def safe_print_long_list(title: str, rows: List[Any], limit: int = 200) -> None:
    print(f"\n=== {title} ===")
    if not rows:
        print(" (none)")
        return
    for r in rows[:limit]:
        print(r)
    if len(rows) > limit:
        print(f"... ({len(rows)-limit} additional rows)")

# ---------- main ----------
def run_inspection(mongo_uri: str, db_name: str, coll_name: str,
                   limit: int | None, create_indexes: bool,
                   allow_disk_use: bool) -> Dict[str, Any]:
    client = None
    try:
        client = MongoClient(mongo_uri)
        client.admin.command("ping")
        print("[OK] Connected to MongoDB.")
    except Exception as e:
        raise RuntimeError(f"Failed to connect to MongoDB at {mongo_uri}: {e}")

    db = client[db_name]
    coll = db[coll_name]

    if create_indexes:
        make_indexes(coll, verbose=True)

    pipeline = build_pipeline(limit=limit)
    print("[+] Running aggregation pipeline (this can take a while for large datasets)...")
    try:
        facets_cursor = coll.aggregate(pipeline, allowDiskUse=allow_disk_use)
        facets_list = list(facets_cursor)
    except Exception as e:
        raise RuntimeError(f"Aggregation failed: {e}\n{traceback.format_exc()}")

    if not facets_list:
        print("[WARN] Aggregation returned no results.")
        return {}

    facets = facets_list[0]

    # Prepare human-readable prints
    servers = [s["server_ip"] for s in facets.get("servers", [])]
    print("\n=== Detected Modbus Servers (dstport=502) ===")
    if servers:
        for ip in servers:
            print(f"- {ip}")
    else:
        print(" (none)")

    print("\n=== Clients -> Servers (summary) ===")
    for row in facets.get("clients_summary", []):
        print(f"{row['client_ip']} -> {row['server_ip']} | reqs: {row['count']}")

    safe_print_long_list("Function Codes — Requests (client -> server)", facets.get("func_codes_req", []))
    safe_print_long_list("Function Codes — Responses (server -> client)", facets.get("func_codes_resp", []))
    safe_print_long_list("Unit IDs in requests (per server)", facets.get("unit_ids", []))
    safe_print_long_list("Modbus request payload signatures", facets.get("modbus_data_req", []), limit=200)

    # build final summary dict
    server_ips_set = set(servers)
    client_ips_set = set(r["client_ip"] for r in facets.get("clients_summary", []))
    unit_ids_set = set(u["unit_id"] for u in facets.get("unit_ids", []))

    func_codes_set = set()
    for r in facets.get("func_codes_req", []) + facets.get("func_codes_resp", []):
        if r.get("func_code") is not None:
            func_codes_set.add(r["func_code"])

    coil_set = set()
    for m in facets.get("modbus_data_req", []):
        if m.get("coil_status_hex") is not None:
            coil_set.add(str(m["coil_status_hex"]).lower())

    result_summary = {
        "server_ips": sorted(server_ips_set),
        "client_ips": sorted(client_ips_set),
        "unit_ids": sorted(unit_ids_set),
        "func_codes": sorted(func_codes_set),
        "coils": sorted(coil_set)
    }

    print("\n" + "-"*80)
    print("Summary:")
    print(" Servers:", result_summary["server_ips"])
    print(" Clients:", result_summary["client_ips"])
    print(" Unit IDs:", result_summary["unit_ids"])
    print(" Function Codes:", result_summary["func_codes"])
    print(" Coils unique:", result_summary["coils"])
    print("-"*80)

    return result_summary

# ---------- CLI ----------
def parse_args():
    p = argparse.ArgumentParser(description="Modbus baseline inspection / questions")
    p.add_argument("--mongo-uri", default=DEFAULT_MONGO_URI, help=f"MongoDB URI (default: {DEFAULT_MONGO_URI})")
    p.add_argument("--db", default=DEFAULT_DB, help=f"Database (default: {DEFAULT_DB})")
    p.add_argument("--collection", default=DEFAULT_COLL, help=f"Collection (default: {DEFAULT_COLL})")
    p.add_argument("--limit", type=int, default=0, help="Optional pre-limit number of documents (0 = no limit)")
    p.add_argument("--no-index", action="store_true", help="Do not create recommended indexes")
    p.add_argument("--allow-disk-use", action="store_true", help="Pass allowDiskUse=True to aggregation")
    p.add_argument("--output", help="Optional output JSON file to save summary (path)")
    return p.parse_args()

def main():
    args = parse_args()
    try:
        summary = run_inspection(
            mongo_uri=args.mongo_uri,
            db_name=args.db,
            coll_name=args.collection,
            limit=(args.limit if args.limit > 0 else None),
            create_indexes=(not args.no_index),
            allow_disk_use=args.allow_disk_use
        )
    except Exception as e:
        print("[ERROR] ", e)
        sys.exit(2)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(summary, f, ensure_ascii=False, indent=2)
            print(f"[OK] Summary written to: {args.output}")
        except Exception as e:
            print("[WARN] Failed to write output file:", e)

    # If invoked as a script, print returned dict as JSON as last line (easy to parse)
    print("\n--- Returned summary (JSON) ---")
    print(json.dumps(summary, ensure_ascii=False))

if __name__ == "__main__":
    main()

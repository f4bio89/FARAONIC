#!./projeto/bin/python
# -*- coding: utf-8 -*-

"""
Capture Modbus/TCP traffic and export JSON + JSONL.

Defaults (if no arguments are provided):
  --iface eth2
  --duration 5 (seconds)
  --outdir json/
  --basename PCAP   -> json/PCAP.json and json/PCAP.jsonl
  --mode summary    -> full layer-by-layer dump
  --filter "tcp"
"""

import time
import json
import os
import argparse
import scapy.all as scapy
from scapy.packet import Packet, bind_layers
from scapy.fields import XShortField, ByteField, ShortField, StrLenField
from scapy.layers.inet import IP, TCP

# =======================
# Custom Modbus Layers
# =======================
class ModbusTCPRequest(Packet):
    name = "ModbusTCPRequest"
    fields_desc = [
        XShortField("trans_id", 0),
        XShortField("prot_id", 0),
        XShortField("length", 0),
        ByteField("unit_id", 0),
        ByteField("func_code", 0),
    ]

class ModbusTCPResponse(Packet):
    name = "ModbusTCPResponse"
    fields_desc = [
        XShortField("trans_id", 0),
        XShortField("prot_id", 0),
        XShortField("length", 0),
        ByteField("unit_id", 0),
        ByteField("func_code", 0),
    ]

class ModbusReadDiscreteInputsRequest(Packet):
    name = "Modbus Read Discrete Inputs Request"
    fields_desc = [
        ShortField("reference_number", 0),
        ShortField("bit_count", 0),
    ]

class ModbusReadDiscreteInputsResponse(Packet):
    name = "Modbus Read Discrete Inputs Response"
    fields_desc = [
        ByteField("byte_count", 0),
        StrLenField("input_status", "", length_from=lambda pkt: pkt.byte_count),
    ]

class ModbusWriteMultipleCoilsRequest(Packet):
    name = "Modbus Write Multiple Coils Request"
    fields_desc = [
        ShortField("reference_number", 0),
        ShortField("bit_count", 0),
        ByteField("byte_count", 0),
        StrLenField("coil_status", "", length_from=lambda pkt: pkt.byte_count),
    ]

class ModbusWriteMultipleCoilsResponse(Packet):
    name = "Modbus Write Multiple Coils Response"
    fields_desc = [
        ShortField("reference_number", 0),
        ShortField("bit_count", 0),
    ]

# Bind layers
bind_layers(scapy.TCP, ModbusTCPRequest, dport=502)
bind_layers(scapy.TCP, ModbusTCPResponse, sport=502)
bind_layers(ModbusTCPRequest, ModbusReadDiscreteInputsRequest, func_code=2)
bind_layers(ModbusTCPResponse, ModbusReadDiscreteInputsResponse, func_code=2)
bind_layers(ModbusTCPRequest, ModbusWriteMultipleCoilsRequest, func_code=15)
bind_layers(ModbusTCPResponse, ModbusWriteMultipleCoilsResponse, func_code=15)

# =======================
# Helpers
# =======================
def make_jsonable(obj):
    """Convert Scapy/bytes/etc. to JSON-serializable primitives."""
    if obj is None or isinstance(obj, (str, int, float, bool)):
        return obj
    if isinstance(obj, (bytes, bytearray)):
        return obj.hex()
    try:
        return int(obj)
    except Exception:
        pass
    try:
        return str(obj)
    except Exception:
        return repr(obj)

# ---------- converters ----------
def packet_to_dict(pkt):
    """Compact summary + Modbus-decoded + TCP payload hex."""
    d = {
        "timestamp": float(getattr(pkt, "time", time.time())),
        "summary": pkt.summary(),
    }
    if IP in pkt:
        d.update({
            "src_ip": pkt[IP].src,
            "dst_ip": pkt[IP].dst,
            "ip_ttl": make_jsonable(pkt[IP].ttl),
            "ip_proto": make_jsonable(pkt[IP].proto),
        })
    if TCP in pkt:
        raw = bytes(pkt[TCP].payload)
        d.update({
            "sport": int(pkt[TCP].sport),
            "dport": int(pkt[TCP].dport),
            "tcp_flags": make_jsonable(pkt[TCP].flags),
            "tcp_seq": make_jsonable(pkt[TCP].seq),
            "tcp_ack": make_jsonable(pkt[TCP].ack),
            "tcp_window": make_jsonable(pkt[TCP].window),
            "tcp_payload_hex": raw.hex() if raw else "",
        })

    # Modbus (Request)
    if pkt.haslayer(ModbusTCPRequest):
        m = pkt.getlayer(ModbusTCPRequest)
        d["modbus"] = {
            "direction": "request",
            "trans_id": int(m.trans_id),
            "prot_id": int(m.prot_id),
            "length": int(m.length),
            "unit_id": int(m.unit_id),
            "func_code": int(m.func_code),
        }
        if pkt.haslayer(ModbusReadDiscreteInputsRequest):
            sub = pkt.getlayer(ModbusReadDiscreteInputsRequest)
            d["modbus"]["read_discrete_req"] = {
                "reference_number": int(sub.reference_number),
                "bit_count": int(sub.bit_count),
            }
        if pkt.haslayer(ModbusWriteMultipleCoilsRequest):
            sub = pkt.getlayer(ModbusWriteMultipleCoilsRequest)
            coil = sub.coil_status
            coil_bytes = (coil if isinstance(coil, (bytes, bytearray))
                          else bytes(coil, "latin1") if isinstance(coil, str) else b"")
            d["modbus"]["write_multiple_coils_req"] = {
                "reference_number": int(sub.reference_number),
                "bit_count": int(sub.bit_count),
                "byte_count": int(sub.byte_count),
                "coil_status_hex": coil_bytes.hex(),
            }

    # Modbus (Response)
    if pkt.haslayer(ModbusTCPResponse):
        m = pkt.getlayer(ModbusTCPResponse)
        d.setdefault("modbus", {})["direction"] = "response"
        d["modbus"].update({
            "trans_id": int(m.trans_id),
            "prot_id": int(m.prot_id),
            "length": int(m.length),
            "unit_id": int(m.unit_id),
            "func_code": int(m.func_code),
        })
        if pkt.haslayer(ModbusReadDiscreteInputsResponse):
            sub = pkt.getlayer(ModbusReadDiscreteInputsResponse)
            istatus = sub.input_status
            istatus_bytes = (istatus if isinstance(istatus, (bytes, bytearray))
                             else bytes(istatus, "latin1") if isinstance(istatus, str) else b"")
            d["modbus"]["read_discrete_resp"] = {
                "byte_count": int(sub.byte_count),
                "input_status_hex": istatus_bytes.hex(),
            }
        if pkt.haslayer(ModbusWriteMultipleCoilsResponse):
            sub = pkt.getlayer(ModbusWriteMultipleCoilsResponse)
            d["modbus"]["write_multiple_coils_resp"] = {
                "reference_number": int(sub.reference_number),
                "bit_count": int(sub.bit_count),
            }
    return d

def pkt_to_dict(pkt, include_iso=True):
    """Full layer-by-layer dump (all fields) + capture timestamp."""
    ts = float(getattr(pkt, "time", time.time()))
    d = {"timestamp": ts}
    if include_iso:
        d["timestamp_iso"] = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(ts))
    for layer in pkt.layers():
        layer_name = layer.__name__
        d[layer_name] = {}
        for field in layer.fields_desc:
            value = pkt[layer].fields.get(field.name)
            d[layer_name][field.name] = make_jsonable(value)
    return d

# =======================
# CLI
# =======================
def parse_args():
    ap = argparse.ArgumentParser(
        description="Capture Modbus/TCP traffic and export JSON/JSONL."
    )
    ap.add_argument("--iface", default="eth2", help="Interface to sniff (default: eth2)")
    ap.add_argument("--duration", type=int, default=5, help="Duration in seconds (default: 5)")
    ap.add_argument("--count", type=int, default=0, help="Stop after N packets (0 = ignore)")
    ap.add_argument("--filter", default="tcp", help="BPF filter (default: tcp)")
    ap.add_argument("--outdir", default="json/", help="Output directory (default: json/)")
    ap.add_argument("--basename", default="PCAP", help="Base filename without extension (default: PCAP)")
    ap.add_argument("--mode", choices=["summary", "full"], default="summary",
                    help="Converter mode: summary (compact+Modbus) or full (all fields) (default: full)")
    ap.add_argument("--no-iso", action="store_true", help="Do not add human-readable ISO timestamp in 'full' mode")
    ap.add_argument("--no-jsonl", action="store_true", help="Do not create .jsonl file (only .json array)")
    ap.add_argument("--pcap", help="Optional: also write raw PCAP to this path")
    return ap.parse_args()

# =======================
# Main
# =======================
def main():
    args = parse_args()

    outdir = args.outdir
    os.makedirs(outdir, exist_ok=True)

    json_path = os.path.join(outdir, f"{args.basename}.json")
    jsonl_path = os.path.join(outdir, f"{args.basename}.jsonl")

    print(f"[INFO] Starting capture on {args.iface} for {args.duration}s (count={args.count})")
    print(f"[INFO] BPF filter: {args.filter}")
    print(f"[INFO] Output: {json_path}" + ("" if args.no_jsonl else f" + {jsonl_path}"))
    if args.pcap:
        print(f"[INFO] Raw PCAP: {args.pcap}")

    try:
        packets = scapy.sniff(
            iface=args.iface,
            timeout=args.duration if args.duration > 0 else None,
            count=args.count if args.count > 0 else 0,
            filter=args.filter,
            store=True,
        )
    except PermissionError:
        print("[ERROR] Permission denied. Try running with sudo or set proper capabilities.")
        return
    except Exception as e:
        print(f"[ERROR] Failed to sniff: {e}")
        return

    print(f"[INFO] Captured: {len(packets)} packets. Converting...")

    # Optionally write raw PCAP
    if args.pcap:
        try:
            scapy.wrpcap(args.pcap, packets)
        except Exception as e:
            print(f"[WARN] Could not write PCAP '{args.pcap}': {e}")

    docs = []
    write_jsonl = not args.no_jsonl
    try:
        fjsonl = open(jsonl_path, "w", encoding="utf-8") if write_jsonl else None
        for pkt in packets:
            if args.mode == "summary":
                doc = packet_to_dict(pkt)
            else:
                doc = pkt_to_dict(pkt, include_iso=(not args.no_iso))
            docs.append(doc)
            if fjsonl:
                fjsonl.write(json.dumps(doc, ensure_ascii=False) + "\n")
    finally:
        if write_jsonl and fjsonl:
            fjsonl.close()

    # Write JSON array
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(docs, f, ensure_ascii=False, indent=2)

    print("[INFO] Done.")
    print(f"[INFO] Lines (packets): {len(docs)}")
    print(f"[INFO] JSON  : {os.path.abspath(json_path)}")
    if not args.no_jsonl:
        print(f"[INFO] JSONL : {os.path.abspath(jsonl_path)}")

if __name__ == "__main__":
    main()

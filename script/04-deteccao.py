#!./projeto/bin/python
# -*- coding: utf-8 -*-
"""
04-deteccao.py — Real-time Modbus/TCP detection runner for FARAONIC

Fixes:
 - corrected nonlocal usage by keeping mutable state inside the detect_attack_factory
 - accepts CLI args for legit IPs, registers, function codes and unit id (defaults preserved)
 - logs to console + rotating file, writes alert files (keeps compatibility)
 - graceful shutdown on SIGINT/SIGTERM
"""

from __future__ import annotations
import argparse
import logging
import logging.handlers
import os
import sys
import signal
import time
from collections import defaultdict, deque
from typing import Dict, Deque, Tuple, Optional, Set
from collections import defaultdict, deque

import scapy.all as scapy
from scapy.packet import Packet, bind_layers
from scapy.fields import XShortField, ByteField, ShortField, StrLenField
from scapy.layers.inet import IP, TCP
from scapy.all import conf, sniff

# -----------------------
# Default config
# -----------------------
DEFAULT_IFACE = "eth2"
DEFAULT_FILTER = "tcp and port 502"
DEFAULT_OUT_DIR = "."
DEFAULT_LOGS_DIR = "logs"
DEFAULT_ALERT_FILES = {
    "unit": "alertsUnit.txt",
    "func": "alertsFunc.txt",
    "reg": "alertsReg.txt",
    "ip_non_legit": "alertsIpNaoLegit.txt",
    "ddos": "alertsDDOS.txt",
}
# defaults coming from your original settings
DEFAULT_LEGIT_IPS = {"192.168.30.20", "192.168.30.25", "192.168.30.40"}
DEFAULT_LEGIT_REGISTERS = {"00", "01", "04", "06", "0c", "10"}
DEFAULT_LEGIT_FUNCS = {2, 15}
DEFAULT_LEGIT_UNIT_ID = 5

DEFAULT_SYN_THRESHOLD = 10
DEFAULT_SYN_WINDOW = 5  # seconds
DEFAULT_DEBOUNCE = 5  # seconds between alerts

# -----------------------
# Modbus layers
# -----------------------
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


# bind layers
bind_layers(scapy.TCP, ModbusTCPRequest, dport=502)
bind_layers(scapy.TCP, ModbusTCPResponse, sport=502)
bind_layers(ModbusTCPRequest, ModbusReadDiscreteInputsRequest, func_code=2)
bind_layers(ModbusTCPResponse, ModbusReadDiscreteInputsResponse, func_code=2)
bind_layers(ModbusTCPRequest, ModbusWriteMultipleCoilsRequest, func_code=15)
bind_layers(ModbusTCPResponse, ModbusWriteMultipleCoilsResponse, func_code=15)

# -----------------------
# Logging & helpers
# -----------------------
def init_logging(log_dir: str):
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, "detection.log")
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    # console
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    logger.addHandler(ch)
    # rotating file
    fh = logging.handlers.RotatingFileHandler(log_path, maxBytes=5_000_000, backupCount=5, encoding="utf-8")
    fh.setLevel(logging.INFO)
    fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    logger.addHandler(fh)
    logging.info("Logging initialized. Console + %s", log_path)


def append_alert_file(path: str, text: str):
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(text + "\n")
    except Exception:
        logging.exception("Failed to write alert file %s", path)


def safe_bytes_hex(val) -> str:
    if val is None:
        return ""
    if isinstance(val, (bytes, bytearray)):
        return val.hex()
    if isinstance(val, str):
        try:
            return val.encode("latin1").hex()
        except Exception:
            return val.encode("utf-8", "ignore").hex()
    return str(val)


def packet_to_dict(pkt) -> dict:
    try:
        d = {
            "timestamp": float(getattr(pkt, "time", time.time())),
            "summary": pkt.summary(),
        }
        if IP in pkt:
            d.update({"src_ip": pkt[IP].src, "dst_ip": pkt[IP].dst})
        if TCP in pkt:
            d.update({
                "sport": int(pkt[TCP].sport),
                "dport": int(pkt[TCP].dport),
                "tcp_flags": str(pkt[TCP].flags),
            })
            raw = bytes(pkt[TCP].payload)
            d["tcp_payload_hex"] = raw.hex() if raw else ""
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
                coil_bytes = sub.coil_status if isinstance(sub.coil_status, (bytes, bytearray)) else (
                    sub.coil_status.encode("latin1") if isinstance(sub.coil_status, str) else b""
                )
                d["modbus"]["write_multiple_coils_req"] = {
                    "reference_number": int(sub.reference_number),
                    "bit_count": int(sub.bit_count),
                    "byte_count": int(sub.byte_count),
                    "coil_status_hex": coil_bytes.hex(),
                }
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
                istatus = sub.input_status if hasattr(sub, "input_status") else b""
                istatus_bytes = istatus if isinstance(istatus, (bytes, bytearray)) else (
                    istatus.encode("latin1") if isinstance(istatus, str) else b""
                )
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
    except Exception:
        logging.exception("Error serializing packet")
        return {"error": "exception_serializing_packet", "summary": getattr(pkt, "summary", lambda: "<no summary>")()}


# -----------------------
# detect factory (stateful, correct nonlocal usage)
# -----------------------
def detect_attack_factory(
    legit_ips: Set[str],
    legit_registers: Set[str],
    legit_funcs: Set[int],
    legit_unit_id: int,
    SYN_threshold: int,
    SYN_window: int,
    DEBOUNCE: int,
    alerts_dir: str,
):
    # mutable state local to closure
    syn_count: Dict[str, Deque[float]] = defaultdict(lambda: deque(maxlen=100000))
    syn_global: Deque[Tuple[str, float]] = deque()
    last_alert_time: Dict[str, float] = {}
    last_alert_ip_non_legit: Dict[str, float] = {}
    masq_last: Dict[Tuple[str, str, int], Dict] = {}
    counters = defaultdict(int)
    last_alert_ddos_ts: float = 0.0  # this is the variable we'll modify using 'nonlocal' below

    def purge_deque_ip_local(dq: Deque[float], now: float, window: int):
        while dq and now - dq[0] > window:
            dq.popleft()

    def detect_attack(packet):
        nonlocal last_alert_ddos_ts  # now valid: it references the factory-scoped variable
        try:
            if not packet.haslayer(IP) or not packet.haslayer(TCP):
                return

            dport = int(packet[TCP].dport)
            sport = int(packet[TCP].sport)
            # focus on any packet involving port 502
            if (dport != 502) and (sport != 502):
                return

            pkt = packet_to_dict(packet)
            if "error" in pkt:
                logging.debug("Packet serialization error: %s", pkt.get("error"))
                return

            src = pkt.get("src_ip")
            now = time.time()
            is_legit = src in legit_ips

            # SYN handling
            if pkt.get("tcp_flags") == "S":
                syn_count[src].append(now)
                purge_deque_ip_local(syn_count[src], now, SYN_window)

                syn_global.append((src, now))
                while syn_global and now - syn_global[0][1] > SYN_window:
                    syn_global.popleft()

                unique_ips = {ip for ip, _ in syn_global}
                if (len(syn_global) > SYN_threshold * 3) and (len(unique_ips) > 5):
                    if now - last_alert_ddos_ts > DEBOUNCE:
                        legit_split = {"legit": 0, "non_legit": 0}
                        for ip, _t in syn_global:
                            if ip in legit_ips:
                                legit_split["legit"] += 1
                            else:
                                legit_split["non_legit"] += 1
                        alert_txt = f"[ALERT - DDoS DISTRIBUTED] {len(syn_global)} SYNs from {len(unique_ips)} IPs in {SYN_window}s | legit={legit_split}"
                        logging.warning(alert_txt)
                        append_alert_file(os.path.join(alerts_dir, DEFAULT_ALERT_FILES["ddos"]), alert_txt)
                        counters["DoS"] += 1
                        last_alert_ddos_ts = now
                    syn_global.clear()
                    return

                total_syns_ip = len(syn_count[src])
                if total_syns_ip > SYN_threshold:
                    prev = last_alert_time.get(src, 0)
                    if now - prev > DEBOUNCE:
                        alert_txt = f"[ALERT - DoS Local] IP: {src} syns_in_window={total_syns_ip}"
                        logging.warning(alert_txt)
                        append_alert_file(os.path.join(alerts_dir, DEFAULT_ALERT_FILES["ddos"]), alert_txt)
                        counters["DoS"] += 1
                        last_alert_time[src] = now
                    return

                if not is_legit:
                    prev = last_alert_ip_non_legit.get(src, 0)
                    if now - prev > DEBOUNCE:
                        alert_txt = f"[ALERT - NON-LEGIT IP] IP: {src} syns_in_window={len(syn_count[src])}"
                        logging.info(alert_txt)
                        append_alert_file(os.path.join(alerts_dir, DEFAULT_ALERT_FILES["ip_non_legit"]), alert_txt)
                        last_alert_ip_non_legit[src] = now
                    return

                return

            # Non-SYN non-legit -> debounced minor alert
            if not is_legit:
                prev = last_alert_ip_non_legit.get(src, 0)
                if now - prev > DEBOUNCE:
                    alert_txt = f"[ALERT - NON-LEGIT IP] IP: {src} activity"
                    logging.info(alert_txt)
                    append_alert_file(os.path.join(alerts_dir, DEFAULT_ALERT_FILES["ip_non_legit"]), alert_txt)
                    last_alert_ip_non_legit[src] = now
                return

            # source legit -> check Modbus payloads
            m = pkt.get("modbus")
            if not m:
                return

            unit_id = m.get("unit_id")
            func_code = m.get("func_code")

            if unit_id != legit_unit_id:
                counters["UnitID"] += 1
                txt = f"[ALERT - UNIT ID] unexpected unit_id={unit_id} from {src}"
                logging.warning(txt)
                append_alert_file(os.path.join(alerts_dir, DEFAULT_ALERT_FILES["unit"]), txt)
                return

            if func_code not in legit_funcs:
                counters["Function"] += 1
                txt = f"[ALERT - FUNCTION CODE] unexpected func_code={func_code} from {src}"
                logging.warning(txt)
                append_alert_file(os.path.join(alerts_dir, DEFAULT_ALERT_FILES["func"]), txt)
                return

            write_req = m.get("write_multiple_coils_req")
            if write_req:
                coil_hex = write_req.get("coil_status_hex") or ""
                if str(coil_hex) not in legit_registers:
                    counters["Register"] += 1
                    txt = f"[ALERT - UNEXPECTED REGISTER WRITE] coil_status_hex={coil_hex} from {src}"
                    logging.warning(txt)
                    append_alert_file(os.path.join(alerts_dir, DEFAULT_ALERT_FILES["reg"]), txt)

                # masquerade detection
                trans_id = m.get("trans_id")
                ref = write_req.get("reference_number")
                if (trans_id is not None) and (ref is not None):
                    key = (pkt.get("src_ip"), pkt.get("dst_ip"), trans_id)
                    prev = masq_last.get(key)
                    if prev:
                        if (ref != prev.get("reference_number")) and (coil_hex != prev.get("coil_status_hex")):
                            counters["Masquerade"] += 1
                            txt = f"[ALERT - MASQUERADE] {key} prev={prev} cur_ref={ref} cur_coil={coil_hex}"
                            logging.warning(txt)
                            append_alert_file(os.path.join(alerts_dir, DEFAULT_ALERT_FILES["reg"]), txt)
                    masq_last[key] = {"reference_number": ref, "coil_status_hex": coil_hex, "t": now}

        except Exception:
            logging.exception("Error processing packet, continuing")

    return detect_attack


# -----------------------
# CLI & main
# -----------------------
def parse_args():
    p = argparse.ArgumentParser(description="FARAONIC Modbus/TCP real-time detector")
    p.add_argument("--iface", default=DEFAULT_IFACE, help=f"Interface to sniff (default: {DEFAULT_IFACE})")
    p.add_argument("--bpf", default=DEFAULT_FILTER, help=f"BPF filter (default: {DEFAULT_FILTER})")
    p.add_argument("--alerts-dir", default=DEFAULT_OUT_DIR, help="Directory where alert files are saved (default: project root)")
    p.add_argument("--logs-dir", default=DEFAULT_LOGS_DIR, help="Directory for rotating logs (default: logs)")
    p.add_argument("--legit-ips", nargs="*", default=list(DEFAULT_LEGIT_IPS), help="Space-separated list of legitimate IPs")
    p.add_argument("--legit-registers", nargs="*", default=list(DEFAULT_LEGIT_REGISTERS), help="Space-separated legitimate coil hex values")
    p.add_argument("--legit-funcs", nargs="*", default=list(DEFAULT_LEGIT_FUNCS), type=int, help="Space-separated legitimate function codes (ints)")
    p.add_argument("--legit-unit", type=int, default=DEFAULT_LEGIT_UNIT_ID, help=f"Legitimate unit id (default: {DEFAULT_LEGIT_UNIT_ID})")
    p.add_argument("--syn-threshold", type=int, default=DEFAULT_SYN_THRESHOLD, help=f"SYN threshold per IP (default: {DEFAULT_SYN_THRESHOLD})")
    p.add_argument("--syn-window", type=int, default=DEFAULT_SYN_WINDOW, help=f"SYN window seconds (default: {DEFAULT_SYN_WINDOW})")
    p.add_argument("--debounce", type=int, default=DEFAULT_DEBOUNCE, help=f"Debounce seconds between alerts (default: {DEFAULT_DEBOUNCE})")
    p.add_argument("--promisc/--no-promisc", dest="promisc", default=True, help="Enable promiscuous mode (default: True)")
    return p.parse_args()


stop_sniff = False


def signal_handler(sig, frame):
    global stop_sniff
    logging.info("Signal received (%s). Stopping sniffing...", sig)
    stop_sniff = True


def main():
    args = parse_args()
    init_logging(args.logs_dir)
    os.makedirs(args.alerts_dir, exist_ok=True)

    legit_ips = set(args.legit_ips)
    legit_registers = set(args.legit_registers)
    legit_funcs = set(args.legit_funcs)
    legit_unit = args.legit_unit

    if os.geteuid() != 0:
        logging.warning("You are not root. Scapy sniff may fail or capture no packets. Consider running with sudo.")

    conf.sniff_promisc = args.promisc

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    detector = detect_attack_factory(
        legit_ips=legit_ips,
        legit_registers=legit_registers,
        legit_funcs=legit_funcs,
        legit_unit_id=legit_unit,
        SYN_threshold=args.syn_threshold,
        SYN_window=args.syn_window,
        DEBOUNCE=args.debounce,
        alerts_dir=args.alerts_dir,
    )

    logging.info("Starting Modbus/TCP monitor on %s (filter='%s')", args.iface, args.bpf)
    logging.info("Legit IPs: %s | legit unit: %s | legit funcs: %s", sorted(legit_ips), legit_unit, sorted(legit_funcs))

    try:
        while not stop_sniff:
            sniff(count=0, iface=args.iface, filter=args.bpf, prn=detector, store=False, timeout=2)
    except Exception:
        logging.exception("Critical error while sniffing")
    finally:
        logging.info("Stopping sniffing. Exiting.")

if __name__ == "__main__":
    main()

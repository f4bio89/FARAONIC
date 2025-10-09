#!./projeto/bin/python
"""
103-Executar-ML.py — Sniff/Replay -> Normalize -> Classify (robusto, com defaults opinativos)

Defaults (podem ser alterados via CLI):
  --iface eth2
  --model mymodels.joblib
  --jsonl normalized.jsonl
  --batch-size 128
  --limit 0
  --threshold 0.5
  --out result1.csv

Exemplos:
  # usar todos os defaults (sniff ao vivo):
  sudo ./103-Executar-ML.py

  # trocar a interface e o arquivo de saída:
  sudo ./103-Executar-ML.py --iface ens19 --out ml_out.csv

  # executar em cima de um PCAP (sem precisar de root):
  ./103-Executar-ML.py --pcap capturas/modbus.pcap --limit 10000

  # mudar o modelo e registrar JSONL em outro caminho:
  sudo ./103-Executar-ML.py --model mymodels.joblib --jsonl logs/run1.jsonl
"""
from __future__ import annotations
import argparse, time, json, os, math
from collections import deque
import joblib
import pandas as pd
import numpy as np
import scapy.all as scapy
from scapy.packet import Packet, bind_layers
from scapy.fields import XShortField, ByteField, ShortField, StrLenField
from scapy.layers.inet import IP, TCP
from scapy.all import Raw, PcapReader, conf

# -----------------------------
# Modbus layers
# -----------------------------
class ModbusTCPRequest(Packet):
    name = "ModbusTCPRequest"
    fields_desc = [
        XShortField("trans_id", 0),
        XShortField("prot_id", 0),
        XShortField("length", 0),
        ByteField("unit_id", 0),
        ByteField("func_code", 0)
    ]

class ModbusTCPResponse(Packet):
    name = "ModbusTCPResponse"
    fields_desc = [
        XShortField("trans_id", 0),
        XShortField("prot_id", 0),
        XShortField("length", 0),
        ByteField("unit_id", 0),
        ByteField("func_code", 0)
    ]

class ModbusReadDiscreteInputsRequest(Packet):
    name = "Modbus Read Discrete Inputs Request"
    fields_desc = [ShortField("reference_number", 0), ShortField("bit_count", 0)]

class ModbusReadDiscreteInputsResponse(Packet):
    name = "Modbus Read Discrete Inputs Response"
    fields_desc = [ByteField("byte_count", 0), StrLenField("input_status", "", length_from=lambda pkt: pkt.byte_count)]

class ModbusWriteMultipleCoilsRequest(Packet):
    name = "Modbus Write Multiple Coils Request"
    fields_desc = [
        ShortField("reference_number", 0),
        ShortField("bit_count", 0),
        ByteField("byte_count", 0),
        StrLenField("coil_status", "", length_from=lambda pkt: pkt.byte_count)
    ]

class ModbusWriteMultipleCoilsResponse(Packet):
    name = "Modbus Write Multiple Coils Response"
    fields_desc = [ShortField("reference_number", 0), ShortField("bit_count", 0)]

bind_layers(scapy.TCP, ModbusTCPRequest, dport=502)
bind_layers(scapy.TCP, ModbusTCPResponse, sport=502)
bind_layers(ModbusTCPRequest, ModbusReadDiscreteInputsRequest, func_code=2)
bind_layers(ModbusTCPResponse, ModbusReadDiscreteInputsResponse, func_code=2)
bind_layers(ModbusTCPRequest, ModbusWriteMultipleCoilsRequest, func_code=15)
bind_layers(ModbusTCPResponse, ModbusWriteMultipleCoilsResponse, func_code=15)

conf.sniff_promisc = True

# -----------------------------
# Helpers
# -----------------------------
def make_jsonable_deep(obj):
    from collections.abc import Mapping
    if obj is None or isinstance(obj, (str, bool, int, float)):
        return obj
    if isinstance(obj, (np.generic, )):
        try: return obj.item()
        except Exception:
            try: return float(obj)
            except Exception: return str(obj)
    if isinstance(obj, (bytes, bytearray)):
        try: return obj.hex()
        except Exception: return str(obj)
    if isinstance(obj, Mapping):
        return {str(k): make_jsonable_deep(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [make_jsonable_deep(v) for v in obj]
    try:
        if hasattr(obj, 'to_int'): return int(obj.to_int())
        if hasattr(obj, 'value'):  return int(obj.value)
    except Exception:
        pass
    try: return int(obj)
    except Exception:
        try: return str(obj)
        except Exception: return repr(obj)

def parse_tcp_options(options):
    if not options:
        return [], (math.nan, math.nan, 0, False)
    lst = []; tsval = math.nan; tsecr = math.nan; nop_count = 0
    for o in options:
        try:
            t = o[0]; v = o[1] if len(o) > 1 else None
            lst.append((t, v))
            if t == 'Timestamp' and isinstance(v, tuple) and len(v) == 2:
                tsval, tsecr = v[0], v[1]
            if t == 'NOP': nop_count += 1
        except Exception:
            continue
    return lst, (tsval, tsecr, nop_count, not math.isnan(tsval))

def tcp_flags_bool(tcp):
    flags_int = 0
    try:
        flags_int = int(tcp.flags)
    except Exception:
        s = str(tcp.flags)
        flags_int |= 0x01 if 'F' in s else 0
        flags_int |= 0x02 if 'S' in s else 0
        flags_int |= 0x04 if 'R' in s else 0
        flags_int |= 0x08 if 'P' in s else 0
        flags_int |= 0x10 if 'A' in s else 0
        flags_int |= 0x20 if 'U' in s else 0
        flags_int |= 0x40 if 'E' in s else 0
        flags_int |= 0x80 if 'C' in s else 0
    return {
        'tcp_fin':  bool(flags_int & 0x01),
        'tcp_syn':  bool(flags_int & 0x02),
        'tcp_rst':  bool(flags_int & 0x04),
        'tcp_psh':  bool(flags_int & 0x08),
        'tcp_ack':  bool(flags_int & 0x10),
        'tcp_urg':  bool(flags_int & 0x20),
        'tcp_ece':  bool(flags_int & 0x40),
        'tcp_cwr':  bool(flags_int & 0x80),
    }

def safe_int(v):
    try: return int(v)
    except Exception: return None

def circular_delta(curr, prev, modulo=(1<<32)):
    if curr is None or prev is None: return None
    try: return (int(curr) - int(prev)) % modulo
    except Exception: return None

def canonical_flow_key(ip_src, ip_dst, sport, dport, proto):
    a = (str(ip_src), int(sport)); b = (str(ip_dst), int(dport))
    if a <= b:
        key = f"{a[0]}:{a[1]}-{b[0]}:{b[1]}/{proto}"; dir_flag = "fw"
    else:
        key = f"{b[0]}:{b[1]}-{a[0]}:{a[1]}/{proto}"; dir_flag = "rev"
    return key, dir_flag

# -----------------------------
# Flow state
# -----------------------------
flow_state = {}
MAX_FLOWS = 10000
flow_queue = deque()

def ensure_flow(key):
    if key in flow_state: return
    flow_state[key] = {'last_ts': None, 'last_seq': None, 'last_ack': None, 'last_tcp_tsval': None, 'last_ip_id': None}
    flow_queue.append(key)
    while len(flow_queue) > MAX_FLOWS:
        old = flow_queue.popleft()
        flow_state.pop(old, None)

# -----------------------------
# Normalization
# -----------------------------
def normalize_packet(pkt):
    try:
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
            return None
        ip = pkt[IP]; tcp = pkt[TCP]
        now = float(getattr(pkt, 'time', time.time()))
        row = {}

        row['timestamp'] = now
        row['event_time'] = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(now))

        row['IP_version'] = getattr(ip, 'version', None)
        row['IP_ihl'] = getattr(ip, 'ihl', None)
        row['IP_tos'] = getattr(ip, 'tos', None)
        row['IP_len'] = getattr(ip, 'len', None)
        row['IP_id'] = getattr(ip, 'id', None)
        row['IP_flags'] = getattr(ip, 'flags', None)
        row['IP_frag'] = getattr(ip, 'frag', None)
        row['IP_ttl'] = getattr(ip, 'ttl', None)
        row['IP_proto'] = getattr(ip, 'proto', None)
        row['IP_chksum'] = getattr(ip, 'chksum', None)
        row['IP_src'] = ip.src; row['IP_dst'] = ip.dst

        try:
            eth = pkt.getlayer(0)
            if eth and eth.name.lower().startswith('ether'):
                row['Ether_src'] = getattr(eth, 'src', None)
                row['Ether_dst'] = getattr(eth, 'dst', None)
                row['Ether_type'] = getattr(eth, 'type', None)
            else:
                row['Ether_src'] = None; row['Ether_dst'] = None; row['Ether_type'] = None
        except Exception:
            row['Ether_src'] = None; row['Ether_dst'] = None; row['Ether_type'] = None

        row['TCP_sport'] = int(getattr(tcp, 'sport', 0))
        row['TCP_dport'] = int(getattr(tcp, 'dport', 0))
        row['TCP_seq'] = safe_int(getattr(tcp, 'seq', None))
        row['TCP_ack'] = safe_int(getattr(tcp, 'ack', None))
        row['TCP_dataofs'] = getattr(tcp, 'dataofs', None)
        row['TCP_reserved'] = getattr(tcp, 'reserved', None)
        row['TCP_flags'] = getattr(tcp, 'flags', None)
        row['TCP_window'] = getattr(tcp, 'window', None)
        row['TCP_chksum'] = getattr(tcp, 'chksum', None)
        row['TCP_urgptr'] = getattr(tcp, 'urgptr', None)

        row.update(tcp_flags_bool(tcp))

        options = getattr(tcp, 'options', []) or []
        opts_list, (tsval, tsecr, nop_count, has_ts) = parse_tcp_options(options)
        row['TCP_options'] = opts_list
        row['tcp_tsval'] = safe_int(tsval)
        row['tcp_tsecr'] = safe_int(tsecr)
        row['tcp_nop_count'] = nop_count
        row['tcp_has_ts'] = bool(has_ts)

        rawb = bytes(tcp.payload) if Raw in tcp else b''
        row['tcp_payload_hex'] = rawb.hex() if rawb else ""

        if pkt.haslayer(ModbusTCPRequest):
            m = pkt.getlayer(ModbusTCPRequest)
            row['ModbusTCPRequest_trans_id'] = int(m.trans_id)
            row['ModbusTCPRequest_prot_id'] = int(m.prot_id)
            row['ModbusTCPRequest_length'] = int(m.length)
            row['ModbusTCPRequest_unit_id'] = int(m.unit_id)
            row['ModbusTCPRequest_func_code'] = int(m.func_code)
            if pkt.haslayer(ModbusReadDiscreteInputsRequest):
                s = pkt.getlayer(ModbusReadDiscreteInputsRequest)
                row['ModbusReadDiscreteInputsRequest_reference_number'] = int(s.reference_number)
                row['ModbusReadDiscreteInputsRequest_bit_count'] = int(s.bit_count)
            else:
                row['ModbusReadDiscreteInputsRequest_reference_number'] = None
                row['ModbusReadDiscreteInputsRequest_bit_count'] = None
            if pkt.haslayer(ModbusWriteMultipleCoilsRequest):
                s = pkt.getlayer(ModbusWriteMultipleCoilsRequest)
                row['ModbusWriteMultipleCoilsRequest_reference_number'] = int(s.reference_number)
                row['ModbusWriteMultipleCoilsRequest_bit_count'] = int(s.bit_count)
                row['ModbusWriteMultipleCoilsRequest_byte_count'] = int(s.byte_count)
            else:
                row['ModbusWriteMultipleCoilsRequest_reference_number'] = None
                row['ModbusWriteMultipleCoilsRequest_bit_count'] = None
                row['ModbusWriteMultipleCoilsRequest_byte_count'] = None
        else:
            for k in ['ModbusReadDiscreteInputsRequest_reference_number','ModbusReadDiscreteInputsRequest_bit_count',
                      'ModbusWriteMultipleCoilsRequest_reference_number','ModbusWriteMultipleCoilsRequest_bit_count',
                      'ModbusWriteMultipleCoilsRequest_byte_count',
                      'ModbusTCPRequest_trans_id','ModbusTCPRequest_prot_id','ModbusTCPRequest_length',
                      'ModbusTCPRequest_unit_id','ModbusTCPRequest_func_code']:
                row[k] = None

        if pkt.haslayer(ModbusTCPResponse):
            m = pkt.getlayer(ModbusTCPResponse)
            row['ModbusTCPResponse_trans_id'] = int(m.trans_id)
            row['ModbusTCPResponse_prot_id'] = int(m.prot_id)
            row['ModbusTCPResponse_length'] = int(m.length)
            row['ModbusTCPResponse_unit_id'] = int(m.unit_id)
            row['ModbusTCPResponse_func_code'] = int(m.func_code)
            if pkt.haslayer(ModbusReadDiscreteInputsResponse):
                s = pkt.getlayer(ModbusReadDiscreteInputsResponse)
                row['ModbusReadDiscreteInputsResponse_byte_count'] = int(s.byte_count)
            else:
                row['ModbusReadDiscreteInputsResponse_byte_count'] = None
            if pkt.haslayer(ModbusWriteMultipleCoilsResponse):
                s = pkt.getlayer(ModbusWriteMultipleCoilsResponse)
                row['ModbusWriteMultipleCoilsResponse_reference_number'] = int(s.reference_number)
                row['ModbusWriteMultipleCoilsResponse_bit_count'] = int(s.bit_count)
            else:
                row['ModbusWriteMultipleCoilsResponse_reference_number'] = None
                row['ModbusWriteMultipleCoilsResponse_bit_count'] = None
        else:
            for k in ['ModbusTCPResponse_trans_id','ModbusTCPResponse_prot_id','ModbusTCPResponse_length',
                      'ModbusTCPResponse_unit_id','ModbusTCPResponse_func_code',
                      'ModbusReadDiscreteInputsResponse_byte_count','ModbusWriteMultipleCoilsResponse_reference_number',
                      'ModbusWriteMultipleCoilsResponse_bit_count']:
                row[k] = None

        row['modbus_func'] = row.get('ModbusTCPRequest_func_code') or row.get('ModbusTCPResponse_func_code') or None
        row['direction'] = 'cli_to_srv' if row['TCP_dport'] == 502 else ('srv_to_cli' if row['TCP_sport'] == 502 else 'other')

        try:
            if row['IP_len'] not in (None, math.nan) and row['IP_ihl'] not in (None, math.nan) and row['TCP_dataofs'] not in (None, math.nan):
                row['approx_payload_len'] = int(row['IP_len']) - (int(row['IP_ihl'])*4) - (int(row['TCP_dataofs'])*4)
            else:
                row['approx_payload_len'] = len(rawb)
        except Exception:
            row['approx_payload_len'] = len(rawb)

        flow_key, dir_flag = canonical_flow_key(row['IP_src'], row['IP_dst'], row['TCP_sport'], row['TCP_dport'], row['IP_proto'])
        row['flow_id'] = flow_key
        row['flow_direction'] = dir_flag
        ensure_flow(flow_key)
        st = flow_state.get(flow_key, {})

        last_ts = st.get('last_ts')
        last_seq = st.get('last_seq')
        last_ack = st.get('last_ack')
        last_tcp_tsval = st.get('last_tcp_tsval')
        last_ipid = st.get('last_ip_id')

        row['iat_flow'] = (now - last_ts) if last_ts is not None else None
        row['delta_seq'] = circular_delta(row.get('TCP_seq'), last_seq, modulo=(1<<32)) if row.get('TCP_seq') is not None else None
        row['delta_ack'] = circular_delta(row.get('TCP_ack'), last_ack, modulo=(1<<32)) if row.get('TCP_ack') is not None else None
        row['delta_tsval'] = circular_delta(row.get('tcp_tsval'), last_tcp_tsval, modulo=(1<<32)) if row.get('tcp_tsval') is not None else None

        try:
            row['ip_id_delta'] = (safe_int(row.get('IP_id')) - safe_int(last_ipid)) if last_ipid is not None and row.get('IP_id') is not None else None
        except Exception:
            row['ip_id_delta'] = None

        st['last_ts'] = now
        st['last_seq'] = row.get('TCP_seq') if row.get('TCP_seq') is not None else st.get('last_seq')
        st['last_ack'] = row.get('TCP_ack') if row.get('TCP_ack') is not None else st.get('last_ack')
        st['last_tcp_tsval'] = row.get('tcp_tsval') if row.get('tcp_tsval') is not None else st.get('last_tcp_tsval')
        st['last_ip_id'] = row.get('IP_id') if row.get('IP_id') is not None else st.get('last_ip_id')

        for k, v in list(row.items()):
            if isinstance(v, float) and math.isnan(v):
                row[k] = None

        return row
    except Exception as e:
        print("[WARN] normalize_packet exception:", e)
        return None

# -----------------------------
# Prediction + CSV writer
# -----------------------------
def load_pipeline(path):
    obj = joblib.load(path)
    if isinstance(obj, dict):
        for key in ('RandomForest','random_forest','rf','rf_model'):
            if key in obj:
                return obj[key]
        return list(obj.values())[0]
    return obj

def infer_expected_columns(pipeline):
    expected = None
    try:
        pre = pipeline.named_steps.get('prep') if hasattr(pipeline, 'named_steps') else None
        if pre is not None:
            t = pre.transformers_
            num_cols = t[0][2] if len(t)>=1 and isinstance(t[0][2], (list,tuple)) else []
            cat_cols = t[1][2] if len(t)>=2 and isinstance(t[1][2], (list,tuple)) else []
            expected = list(num_cols) + list(cat_cols)
    except Exception:
        expected = None
    return expected

def flush_and_predict(pipeline, buffer_rows, output_csv, first_write, expected_cols, clf_classes, threshold, verbose):
    if not buffer_rows:
        return first_write
    df = pd.DataFrame(buffer_rows)
    if expected_cols:
        for c in expected_cols:
            if c not in df.columns:
                df[c] = np.nan
        df = df[expected_cols]
    # coercions típicos
    for c in df.columns:
        if c.startswith('IP_') or c.startswith('TCP_') or c in ('delta_seq','delta_ack','delta_tsval','iat_flow','ip_id_delta','approx_payload_len'):
            df[c] = pd.to_numeric(df[c], errors='coerce')
    try:
        preds = pipeline.predict(df)
    except Exception as e:
        print("[ERROR] pipeline.predict failed:", e)
        preds = ["ERROR"] * len(df)
    probs = None
    try:
        probs = pipeline.predict_proba(df)
    except Exception:
        probs = None

    outdf = df.copy()
    outdf['pred'] = preds
    if probs is not None and clf_classes is not None:
        for i, cls in enumerate(clf_classes):
            outdf[f'prob_{cls}'] = probs[:, i]

    mode = 'w' if first_write else 'a'
    header = first_write
    outdf.to_csv(output_csv, mode=mode, header=header, index=False)
    if verbose:
        print(f"[INFO] Wrote {len(outdf)} rows to {output_csv} (header={header})")

    for idx, row in outdf.iterrows():
        pred = row['pred']
        prob = None
        if probs is not None and clf_classes is not None:
            try:
                prob = row[f'prob_{pred}']
            except Exception:
                prob = row[[c for c in outdf.columns if c.startswith('prob_')]].max()
        if str(pred).upper() != 'NORMAL' and (prob is None or prob >= threshold):
            print(f"[ALERT] pred={pred} prob={prob} flow={buffer_rows[idx].get('flow_id')} modbus_func={buffer_rows[idx].get('modbus_func')}")
    return False

def safe_write_jsonl(path, row):
    try:
        safe_row = make_jsonable_deep(row)
        os.makedirs(os.path.dirname(os.path.abspath(path)) or '.', exist_ok=True)
        with open(path, 'a', encoding='utf-8') as fj:
            fj.write(json.dumps(safe_row, ensure_ascii=False) + "\n")
        return True
    except Exception as e:
        print(f"[WARN] Failed to JSON-serialize packet row: {e}")
        badpath = path + ".badrows.txt"
        try:
            with open(badpath, "a", encoding="utf-8") as fb:
                fb.write(time.strftime("%Y-%m-%d %H:%M:%S") + " " + str(e) + "\n")
                try:
                    fb.write(repr(row)[:10000] + "\n\n")
                except Exception:
                    fb.write("<could not repr row>\n\n")
        except Exception:
            pass
        return False

# -----------------------------
# Runners
# -----------------------------
def run_from_pcap(pcap_path, pipeline, expected_cols, out_csv, jsonl_path, batch_size, replay_speed, threshold, verbose, limit):
    print(f"[INFO] Replaying pcap {pcap_path}")
    reader = PcapReader(pcap_path)
    last_ts = None
    buffer = []
    first_write = not os.path.exists(out_csv)
    try:
        if hasattr(pipeline, 'named_steps') and 'clf' in pipeline.named_steps and hasattr(pipeline.named_steps['clf'], 'classes_'):
            clf_classes = pipeline.named_steps['clf'].classes_
        else:
            clf_classes = getattr(pipeline, 'classes_', None)
    except Exception:
        clf_classes = None

    count = 0
    for pkt in reader:
        count += 1
        try:
            row = normalize_packet(pkt)
            if row:
                if jsonl_path:
                    safe_write_jsonl(jsonl_path, row)
                buffer.append(row)
            if len(buffer) >= batch_size:
                first_write = flush_and_predict(pipeline, buffer, out_csv, first_write, expected_cols, clf_classes, threshold, verbose)
                buffer.clear()
            if replay_speed and replay_speed > 0:
                try:
                    ts = float(getattr(pkt, 'time', time.time()))
                    if last_ts is not None:
                        delta = ts - last_ts
                        if delta > 0:
                            time.sleep(delta / replay_speed)
                    last_ts = ts
                except Exception:
                    pass
            if limit and count >= limit:
                break
        except Exception as ex:
            print("[WARN] exception while processing pcap pkt, skipping:", ex)
            continue
    if buffer:
        first_write = flush_and_predict(pipeline, buffer, out_csv, first_write, expected_cols, clf_classes, threshold, verbose)
    print("[INFO] Replay finished.")

def run_live(iface, pipeline, expected_cols, out_csv, jsonl_path, batch_size, threshold, verbose, limit):
    print(f"[INFO] Listening on iface {iface} (press Ctrl-C to stop)")
    first_write = not os.path.exists(out_csv)
    try:
        if hasattr(pipeline, 'named_steps') and 'clf' in pipeline.named_steps and hasattr(pipeline.named_steps['clf'], 'classes_'):
            clf_classes = pipeline.named_steps['clf'].classes_
        else:
            clf_classes = getattr(pipeline, 'classes_', None)
    except Exception:
        clf_classes = None

    buffer = []
    pkt_count = 0

    def on_pkt(pkt):
        nonlocal buffer, first_write, pkt_count
        pkt_count += 1
        try:
            row = normalize_packet(pkt)
            if row:
                if jsonl_path:
                    safe_write_jsonl(jsonl_path, row)
                buffer.append(row)
            if len(buffer) >= batch_size:
                first_write = flush_and_predict(pipeline, buffer, out_csv, first_write, expected_cols, clf_classes, threshold, verbose)
                buffer.clear()
            if pkt_count <= 5 or pkt_count % 200 == 0:
                print(f"[HEARTBEAT] total pkts processed: {pkt_count} buffered: {len(buffer)}")
            if limit and pkt_count >= limit:
                raise KeyboardInterrupt()
        except Exception as e:
            print("[WARN] on_pkt exception (continuing):", e)
            try:
                badpath = (jsonl_path + ".badrows.txt") if jsonl_path else "badrows.txt"
                with open(badpath, "a", encoding="utf-8") as fb:
                    fb.write(time.strftime("%Y-%m-%d %H:%M:%S") + " on_pkt exception: " + str(e) + "\n")
                    try:
                        fb.write(repr(pkt.summary()) + "\n\n")
                    except Exception:
                        fb.write("<could not repr pkt>\n\n")
            except Exception:
                pass
            return

    try:
        scapy.sniff(iface=iface, prn=on_pkt, store=False, promisc=True)
    except KeyboardInterrupt:
        print("[INFO] Sniff stopped by user/limit.")
    except Exception as e:
        print("[ERROR] Sniffer failed:", e)
    finally:
        if buffer:
            first_write = flush_and_predict(pipeline, buffer, out_csv, first_write, expected_cols, clf_classes, threshold, verbose)
        print("[INFO] Live sniff finished.")

# -----------------------------
# CLI e main (com defaults)
# -----------------------------
def main():
    ap = argparse.ArgumentParser(description="Sniff/Replay -> normalize -> classify (robust, with sensible defaults).")

    # Fonte de dados: por default usamos --iface=eth2; --pcap continua disponível
    grp = ap.add_mutually_exclusive_group(required=False)
    ap.add_argument('--iface', default='eth2', help='interface para sniff ao vivo (default: eth2)')
    grp.add_argument('--pcap', help='arquivo pcap para replay')

    ap.add_argument('--model', default='mymodels.joblib', help='pipeline/modelo .joblib (default: mymodels.joblib)')
    ap.add_argument('--out', default='result1.csv', help='CSV de saída (features + pred + probs) (default: result1.csv)')
    ap.add_argument('--jsonl', default='normalized.jsonl', help='caminho do JSONL normalizado (default: normalized.jsonl)')
    ap.add_argument('--batch-size', type=int, default=128, help='tamanho do lote para predição (default: 128)')
    ap.add_argument('--replay-speed', type=float, default=0.0, help='>0 respeita timestamps do pcap com esse multiplicador')
    ap.add_argument('--limit', type=int, default=0, help='parar após N pacotes (0 = sem limite) (default: 0)')
    ap.add_argument('--threshold', type=float, default=0.5, help='limiar de probabilidade para alertas (default: 0.5)')
    ap.add_argument('--verbose', action='store_true', help='logs adicionais')

    args = ap.parse_args()

    # Se o usuário passou --pcap, ignoramos --iface; caso contrário, exige root para sniff.
    source_mode = 'pcap' if args.pcap else 'iface'
    if source_mode == 'iface' and os.geteuid() != 0:
        print("[ERROR] Live sniffing requires root. Rode com sudo ou use --pcap.")
        return

    print(f"[INFO] Loading pipeline {args.model} ...")
    pipeline = load_pipeline(args.model)
    expected_cols = infer_expected_columns(pipeline)
    if expected_cols:
        print(f"[INFO] Model expects {len(expected_cols)} columns. Example: {expected_cols[:10]}")
    else:
        print("[WARN] Could not infer expected columns from pipeline.prep; will try best-effort alignment.")

    os.makedirs(os.path.dirname(os.path.abspath(args.out)) or '.', exist_ok=True)
    if args.jsonl:
        os.makedirs(os.path.dirname(os.path.abspath(args.jsonl)) or '.', exist_ok=True)

    if source_mode == 'pcap':
        run_from_pcap(args.pcap, pipeline, expected_cols, args.out, args.jsonl, args.batch_size, args.replay_speed, args.threshold, args.verbose, args.limit or None)
    else:
        run_live(args.iface, pipeline, expected_cols, args.out, args.jsonl, args.batch_size, args.threshold, args.verbose, args.limit or None)

    print("[INFO] Done.")

if __name__ == "__main__":
    main()

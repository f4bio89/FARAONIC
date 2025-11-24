#!/home/kali/Desktop/arquivos-defensive/Final/projeto/bin/python
# -*- coding: utf-8 -*-

"""
FARAONIC main launcher (interactive + CLI).

Complete script: banner, capture/upload flows, Option 2 (query -> detector live),
CLI wrappers and menu. Use this file to replace your current faraonic.py.
"""

import os
import sys
import subprocess
import argparse
import shlex
import datetime
import json
from typing import List, Tuple, Optional, Dict, Any

# ==============================
# CONFIGURATION (defaults)
# ==============================
CONFIG = {
    "model_path": "treinamento01.joblib",
    "scripts": {
        "capture_baseline": "./01-captura.py",
        "upload_baseline": "./02-upload_mongodb.py",
        "query_baseline": "./03-perguntas.py",
        "detect_realtime": "./04-deteccao.py",
        "train": "./102-Treinar-ML.py",
        "realtime": "./103-Executar-ML.py",
    },
    # Defaults passed to 01-captura.py
    "capture_defaults": {
        "iface": "eth2",
        "duration": 5,
        "count": 0,
        "filter": "tcp and port 502",
        "outdir": "json/",
        "basename": "PCAP",
        "mode": "full",          # summary|full
        "no_iso": False,         # only for mode=full
        "no_jsonl": False,
        "pcap": None,
    },
    # Defaults for the query (03-perguntas.py)
    "query_defaults": {
        "mongo_uri": "mongodb://user:user@localhost:27017/",
        "db": "FARAONIC",
        "collection": "normal",
        "allow_disk_use": False,
        "limit": 0
    },
    # Defaults passed to 02-upload_mongodb.py
    "upload_defaults": {
        "mongo_uri": "mongodb://user:user@localhost:27017/",
        "db": "FARAONIC",
        "collection": "normal",
        "input": None,           # if None, auto = <outdir>/<basename>.json
        "batch_size": 1000,
    },
    "logs_dir": "logs",
}

# ensure logs dir exists
os.makedirs(CONFIG.get("logs_dir", "logs"), exist_ok=True)

# ==============================
# VISUALS
# ==============================
def _box_text(lines, pad=1):
    w = max(len(l) for l in lines)
    top = "┌" + "─"*(w+pad*2) + "┐"
    bot = "└" + "─"*(w+pad*2) + "┘"
    body = [ "│"+" "*pad + l.ljust(w) + " "*pad + "│" for l in lines ]
    return "\n".join([top, *body, bot])

def banner():
    faraonic_ascii = [
        "FFFFFFFF    AAAA    RRRRRR     AAAA     OOOOOO    N     N    IIIII    CCCCC ",
        "FF         A    A   RR   RR   A    A   O      O   NN    N      I     C     ",
        "FFFFFF     AAAAAA   RRRRRR    AAAAAA   O      O   N N   N      I     C     ",
        "FF         A    A   RR  RR    A    A   O      O   N  N  N      I     C     ",
        "FF         A    A   RR   RR   A    A    OOOOOO    N   N N    IIIII    CCCCC ",
    ]
    print(_box_text(faraonic_ascii))
    print("Framework for Anomaly Recognition and Analysis in Operational Networks for Industrial Cybersecurity")
    print("By Fabio Araujo\n")
    print("usage: faraonic.py [-h] [--capture] [--query] [--train] [--realtime] [--show-config]")
    print("                   [--cap-...] [--up-...]")
    print("\nModules:")
    print("  RULES      → Baseline creation & rule-based real-time engine")
    print("  BEHAVIORAL → ML training & live inference")
    print("-"*80)

# ==============================
# UTILITIES
# ==============================
def _log_filename(script_name: str) -> str:
    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    safe = os.path.basename(script_name).replace("/", "_")
    return os.path.join(CONFIG["logs_dir"], f"{ts}_{safe}.log")

def _save_log(path: str, stdout: str, stderr: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"=== STDOUT ===\n{stdout}\n\n=== STDERR ===\n{stderr}\n")

def _run_python_capture(script: str, args_list: List[str]) -> Tuple[int, str, str, str]:
    """
    Run a script with the same Python interpreter.
    Returns (rc, stdout, stderr, logfile_path)
    """
    if not os.path.exists(script):
        msg = f"[!] Script not found: {script}"
        print(msg)
        return (127, "", msg, "")
    cmd = [ sys.executable, script ] + args_list
    print(f"[+] Running: {shlex.join(cmd)}")
    try:
        completed = subprocess.run(cmd, capture_output=True, text=True)
        stdout = completed.stdout or ""
        stderr = completed.stderr or ""
        rc = completed.returncode
        logpath = _log_filename(script)
        _save_log(logpath, stdout, stderr)
        return (rc, stdout, stderr, logpath)
    except Exception as e:
        err = f"Exception while running {script}: {e}"
        print(err)
        logpath = _log_filename(script)
        _save_log(logpath, "", err)
        return (1, "", err, logpath)

def _run_python_live(script: str, args_list: List[str], use_sudo: bool = False) -> int:
    """
    Run a script live (stdout/stderr forwarded to current terminal).
    Returns the exit code.
    """
    if not os.path.exists(script):
        print(f"[!] Script not found: {script}")
        return 127

    # always use the current venv's interpreter
    venv_py = sys.executable
    if use_sudo:
        cmd = ["sudo", "-E", venv_py, script] + args_list
    else:
        cmd = [venv_py, script] + args_list

    print(f"[+] Launching live: {shlex.join(cmd)}")
    try:
        proc = subprocess.Popen(cmd)
        proc.wait()
        return proc.returncode
    except KeyboardInterrupt:
        print("\n[!] KeyboardInterrupt received — terminating child process...")
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:
            pass
        print("[*] Child stopped.")
        return -1
    except Exception as e:
        print("[ERROR] Live run failed:", e)
        return 1


def parse_trailing_json(stdout: str) -> Optional[Dict[str, Any]]:
    """
    Try to extract the last JSON object from stdout.
    Return parsed dict or None.
    """
    if not stdout:
        return None
    last_rbrace = stdout.rfind("}")
    if last_rbrace == -1:
        return None
    starts = [i for i, ch in enumerate(stdout) if ch == "{" and i < last_rbrace]
    for start in reversed(starts):
        candidate = stdout[start:last_rbrace+1]
        try:
            parsed = json.loads(candidate)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            continue
    return None

def prompt_with_default(prompt: str, default, typ=str, choices=None):
    """
    Prompt the user showing the default. If the user presses Enter, returns default.
    """
    while True:
        if isinstance(default, bool):
            default_str = "y" if default else "n"
            raw = input(f"{prompt} [{default_str}] (y/n, Enter = default): ").strip()
            if raw == "":
                return default
            if raw.lower() in ("y","yes"):
                return True
            if raw.lower() in ("n","no"):
                return False
            print("Please answer y or n.")
            continue

        if choices:
            choices_str = "/".join(choices)
            raw = input(f"{prompt} [{default}] ({choices_str}) : ").strip()
            if raw == "":
                return default
            if raw in choices:
                return typ(raw)
            print(f"Invalid choice, expected one of: {choices_str}")
            continue

        raw = input(f"{prompt} [{default}]: ").strip()
        if raw == "":
            return default
        try:
            if typ == int:
                return int(raw)
            if typ == float:
                return float(raw)
            if typ == str:
                return raw
            return typ(raw)
        except Exception:
            print(f"Invalid value for type {typ.__name__}, try again.")

# ==============================
# CAPTURE + UPLOAD (interactive w/ error handling)
# ==============================
def capture_and_upload_interactive():
    cap_defaults = CONFIG["capture_defaults"].copy()
    up_defaults = CONFIG["upload_defaults"].copy()

    # We'll loop capture step so user can retry or edit on failure
    while True:
        cap = cap_defaults.copy()
        print("\n--- Capture configuration (press Enter to accept default) ---\n")
        cap["iface"] = prompt_with_default("Interface", cap["iface"], typ=str)
        cap["duration"] = prompt_with_default("Duration (seconds, 0 to ignore time and use count)", cap["duration"], typ=int)
        cap["count"] = prompt_with_default("Packet count (0 = ignore)", cap["count"], typ=int)
        cap["filter"] = prompt_with_default("BPF filter", cap["filter"], typ=str)
        cap["outdir"] = prompt_with_default("Output directory", cap["outdir"], typ=str)
        cap["basename"] = prompt_with_default("Base filename (no extension)", cap["basename"], typ=str)
        cap["mode"] = prompt_with_default("Mode", cap["mode"], typ=str, choices=["summary","full"])
        if cap["mode"] == "full":
            cap["no_iso"] = not prompt_with_default("Include ISO timestamp in full dump?", True, typ=bool)
        else:
            cap["no_iso"] = False
        cap["no_jsonl"] = not prompt_with_default("Write JSONL file? (recommended)", True, typ=bool)
        pcap_path = prompt_with_default("Optional: write raw PCAP file (path or Enter to skip)", cap["pcap"] if cap["pcap"] else "", typ=str)
        cap["pcap"] = pcap_path if pcap_path != "" else None

        os.makedirs(cap["outdir"], exist_ok=True)

        print("\nCapture parameters:")
        for k, v in cap.items():
            print(f"  {k}: {v}")
        cont = prompt_with_default("Run capture with above parameters?", True, typ=bool)
        if not cont:
            print("Capture aborted by user.")
            return

        cap_args = [
            "--iface", cap["iface"],
            "--duration", str(cap["duration"]),
            "--count", str(cap["count"]),
            "--filter", cap["filter"],
            "--outdir", cap["outdir"],
            "--basename", cap["basename"],
            "--mode", cap["mode"],
        ]
        if cap["mode"] == "full" and cap["no_iso"]:
            cap_args.append("--no-iso")
        if cap["no_jsonl"]:
            cap_args.append("--no-jsonl")
        if cap["pcap"]:
            cap_args += ["--pcap", cap["pcap"]]

        # run capture and handle result
        rc, out, err, logpath = _run_python_capture(CONFIG["scripts"]["capture_baseline"], cap_args)
        if rc == 0:
            print(f"[OK] Capture completed successfully. Log saved: {logpath}")
            # proceed to upload step
            break

        # non-zero rc: provide options
        print("\n[ERROR] Capture script returned code:", rc)
        print("A short stderr preview:")
        print("-" * 60)
        print(err.strip()[:1200] or "(no stderr)")
        print("-" * 60)
        print(f"Full log saved to: {logpath}")
        while True:
            choice = input("Choose: [R]etry, [S]how log, [E]dit params, [A]bort: ").strip().lower()
            if choice in ("r","retry"):
                print("Retrying capture with same parameters...")
                break
            if choice in ("s","show"):
                print("\n=== FULL LOG ===")
                try:
                    with open(logpath, "r", encoding="utf-8") as lf:
                        print(lf.read())
                except Exception as e:
                    print("Failed to open log:", e)
                continue
            if choice in ("e","edit"):
                print("Restarting parameter entry...")
                break
            if choice in ("a","abort"):
                print("Aborting capture/upload sequence.")
                return
            print("Invalid choice. Please enter R, S, E or A.")
        if choice in ("e","edit"):
            continue

    # Upload step
    while True:
        up = up_defaults.copy()
        default_json = os.path.join(cap["outdir"], f"{cap['basename']}.json")
        up["input"] = prompt_with_default("Input JSON/JSONL file", default_json, typ=str)
        up["mongo_uri"] = prompt_with_default("MongoDB URI", up["mongo_uri"], typ=str)
        up["db"] = prompt_with_default("MongoDB database", up["db"], typ=str)
        up["collection"] = prompt_with_default("MongoDB collection", up["collection"], typ=str)
        up["batch_size"] = prompt_with_default("Batch size (int)", up["batch_size"], typ=int)

        print("\nUpload parameters:")
        for k, v in up.items():
            print(f"  {k}: {v}")
        cont = prompt_with_default("Run upload with above parameters?", True, typ=bool)
        if not cont:
            print("Upload aborted by user.")
            return

        up_args = [
            "--mongo-uri", up["mongo_uri"],
            "--db", up["db"],
            "--collection", up["collection"],
            "--input", up["input"],
            "--batch-size", str(up["batch_size"]),
        ]

        rc, out, err, logpath = _run_python_capture(CONFIG["scripts"]["upload_baseline"], up_args)
        if rc == 0:
            print(f"[OK] Upload completed successfully. Log saved: {logpath}")
            break

        print("\n[ERROR] Upload script returned code:", rc)
        print("A short stderr preview:")
        print("-" * 60)
        print(err.strip()[:1200] or "(no stderr)")
        print("-" * 60)
        print(f"Full log saved to: {logpath}")
        while True:
            choice = input("Choose: [R]etry, [S]how log, [E]dit params, [A]bort: ").strip().lower()
            if choice in ("r","retry"):
                print("Retrying upload with same parameters...")
                break
            if choice in ("s","show"):
                print("\n=== FULL LOG ===")
                try:
                    with open(logpath, "r", encoding="utf-8") as lf:
                        print(lf.read())
                except Exception as e:
                    print("Failed to open log:", e)
                continue
            if choice in ("e","edit"):
                print("Restarting upload parameter entry...")
                break
            if choice in ("a","abort"):
                print("Aborting upload.")
                return
            print("Invalid choice. Please enter R, S, E or A.")

        if choice in ("e","edit"):
            continue

    print("\nCapture + upload sequence finished successfully.")

# ==============================
# NON-INTERACTIVE wrappers (kept for CLI)
# ==============================
def capture_and_upload_args(args):
    cap = CONFIG["capture_defaults"].copy()
    up  = CONFIG["upload_defaults"].copy()

    if args.cap_iface:      cap["iface"] = args.cap_iface
    if args.cap_duration is not None: cap["duration"] = args.cap_duration
    if args.cap_count is not None:    cap["count"] = args.cap_count
    if args.cap_filter:     cap["filter"] = args.cap_filter
    if args.cap_outdir:     cap["outdir"] = args.cap_outdir
    if args.cap_basename:   cap["basename"] = args.cap_basename
    if args.cap_mode:       cap["mode"] = args.cap_mode
    if args.cap_no_iso:     cap["no_iso"] = True
    if args.cap_no_jsonl:   cap["no_jsonl"] = True
    if args.cap_pcap:       cap["pcap"] = args.cap_pcap

    cap_args = [
        "--iface", cap["iface"],
        "--duration", str(cap["duration"]),
        "--count", str(cap["count"]),
        "--filter", cap["filter"],
        "--outdir", cap["outdir"],
        "--basename", cap["basename"],
        "--mode", cap["mode"],
    ]
    if cap["mode"] == "full" and cap["no_iso"]:
        cap_args.append("--no-iso")
    if cap["no_jsonl"]:
        cap_args.append("--no-jsonl")
    if cap["pcap"]:
        cap_args += ["--pcap", cap["pcap"]]

    rc, out, err, logpath = _run_python_capture(CONFIG["scripts"]["capture_baseline"], cap_args)
    if rc != 0:
        print("[!] Capture failed. Log:", logpath)
        print("stderr preview:", err.strip()[:800] or "(no stderr)")
        return

    if args.up_mongo_uri:   up["mongo_uri"] = args.up_mongo_uri
    if args.up_db:          up["db"] = args.up_db
    if args.up_collection:  up["collection"] = args.up_collection
    if args.up_input:       up["input"] = args.up_input
    if args.up_batch_size is not None: up["batch_size"] = args.up_batch_size

    if not up["input"]:
        up["input"] = os.path.join(cap["outdir"], f"{cap['basename']}.json")

    up_args = [
        "--mongo-uri", up["mongo_uri"],
        "--db", up["db"],
        "--collection", up["collection"],
        "--input", up["input"],
        "--batch-size", str(up["batch_size"]),
    ]

    rc, out, err, logpath = _run_python_capture(CONFIG["scripts"]["upload_baseline"], up_args)
    if rc != 0:
        print("[!] Upload failed. Log:", logpath)
        print("stderr preview:", err.strip()[:800] or "(no stderr)")
        return

# ==============================
# QUERY -> DETECTOR (Option 2)
# ==============================
def query_then_detect_interactive():
    """
    Interactive flow:
     - ask/confirm mongo uri/db/collection
     - run 03-perguntas.py to produce a JSON summary
     - parse JSON and start 04-deteccao.py with inferred defaults
    """
    qd = CONFIG["query_defaults"].copy()
    print("\n--- Query configuration (press Enter to accept default) ---\n")
    qd["mongo_uri"] = prompt_with_default("MongoDB URI", qd["mongo_uri"], typ=str)
    qd["db"] = prompt_with_default("Database", qd["db"], typ=str)
    qd["collection"] = prompt_with_default("Collection", qd["collection"], typ=str)
    qd["limit"] = prompt_with_default("Optional pre-limit (0 = no limit)", qd["limit"], typ=int)
    qd["allow_disk_use"] = prompt_with_default("allowDiskUse for aggregation? (y/n)", qd["allow_disk_use"], typ=bool)

    print("\nRunning query script to produce baseline summary...")
    q_args = [
        "--mongo-uri", qd["mongo_uri"],
        "--db", qd["db"],
        "--collection", qd["collection"],
    ]
    if qd["limit"] and qd["limit"] > 0:
        q_args += ["--limit", str(qd["limit"])]
    if qd["allow_disk_use"]:
        q_args += ["--allow-disk-use"]

    rc, stdout, stderr, logpath = _run_python_capture(CONFIG["scripts"]["query_baseline"], q_args)
    if rc != 0:
        print("[!] Query script failed with code", rc)
        print("stderr preview:\n", stderr[:1200] or "(no stderr)")
        print("Full log saved to:", logpath)
        while True:
            choice = input("Choose [S]how log, [R]etry, [A]bort: ").strip().lower()
            if choice in ("s","show"):
                try:
                    with open(logpath, "r", encoding="utf-8") as f:
                        print(f.read())
                except Exception as e:
                    print("Failed to open log:", e)
                continue
            if choice in ("r","retry"):
                return query_then_detect_interactive()
            if choice in ("a","abort"):
                print("Aborting option 2.")
                return
            print("Invalid option.")
    else:
        print(f"[OK] Query completed. Log saved: {logpath}")

    summary = parse_trailing_json(stdout)
    if not summary:
        print("[!] Could not find a JSON summary in the query output.")
        print("stdout tail (last 1200 chars):\n", stdout[-1200:])
        print(f"Full log: {logpath}")
        if prompt_with_default("Do you want to manually input some defaults for the detector? (y = enter manually)", False, typ=bool):
            summary = {}
            s_ips = prompt_with_default("Enter server IPs (comma separated)", "", typ=str)
            c_ips = prompt_with_default("Enter client IPs (comma separated)", "", typ=str)
            summary["server_ips"] = [x.strip() for x in s_ips.split(",") if x.strip()]
            summary["client_ips"] = [x.strip() for x in c_ips.split(",") if x.strip()]
            fc = prompt_with_default("Enter function codes (comma separated)", "", typ=str)
            summary["func_codes"] = [x.strip() for x in fc.split(",") if x.strip()]
            co = prompt_with_default("Enter coil hex values (comma separated)", "", typ=str)
            summary["coils"] = [x.strip() for x in co.split(",") if x.strip()]
            uid = prompt_with_default("Enter legitimate unit id (or Enter to skip)", "", typ=str)
            summary["unit_ids"] = [uid] if uid else []
        else:
            print("Aborting option 2.")
            return

    server_ips = summary.get("server_ips", []) or []
    client_ips = summary.get("client_ips", []) or []
    legit_ips = sorted(set(server_ips + client_ips))
    func_codes_raw = summary.get("func_codes", []) or []
    func_codes_args = []
    for f in func_codes_raw:
        try:
            func_codes_args.append(str(int(f)))
        except Exception:
            # ignore non-numeric for --legit-funcs
            pass
    coils = summary.get("coils", []) or []
    unit_ids = summary.get("unit_ids", []) or []
    unit_arg = None
    if unit_ids:
        try:
            unit_arg = int(unit_ids[0])
        except Exception:
            unit_arg = None

    detect_args = []
    if legit_ips:
        detect_args += ["--legit-ips"] + legit_ips
    if coils:
        detect_args += ["--legit-registers"] + coils
    if func_codes_args:
        detect_args += ["--legit-funcs"] + func_codes_args
    if unit_arg is not None:
        detect_args += ["--legit-unit", str(unit_arg)]

    detect_args += ["--alerts-dir", ".", "--logs-dir", CONFIG.get("logs_dir", "logs")]

    print("\n=== Detector will be launched with the following args ===")
    print("script:", CONFIG["scripts"]["detect_realtime"])
    print("args:", detect_args)
    print("To stop the detector: Ctrl+C in this terminal.\n")
    input("Press Enter to launch the detector (or Ctrl+C to cancel)...")

    rc_live = _run_python_live(CONFIG["scripts"]["detect_realtime"], detect_args)
    if rc_live != 0:
        print("[!] Detector exited with code", rc_live)
    else:
        print("[OK] Detector stopped normally.")

# ==============================
# OTHER ACTIONS
# ==============================
def query_and_realtime(_args=None):
    # backward compatible: run query script and start detector with defaults (non-interactive)
    qd = CONFIG["query_defaults"]
    q_args = ["--mongo-uri", qd["mongo_uri"], "--db", qd["db"], "--collection", qd["collection"]]
    rc, out, err, logpath = _run_python_capture(CONFIG["scripts"]["query_baseline"], q_args)
    if rc != 0:
        print("[!] Query/Realtime script failed:", logpath)
        print(err[:800])
        return
    summary = parse_trailing_json(out)
    if not summary:
        print("[!] Query script did not return a machine-readable summary.")
        return
    # map to detector args (same logic as above)
    server_ips = summary.get("server_ips", []) or []
    client_ips = summary.get("client_ips", []) or []
    legit_ips = sorted(set(server_ips + client_ips))
    coils = summary.get("coils", []) or []
    func_codes = [str(int(f)) for f in summary.get("func_codes", []) if str(f).isdigit()]
    unit_ids = summary.get("unit_ids", []) or []
    unit_arg = int(unit_ids[0]) if unit_ids else None
    detect_args = []
    if legit_ips: detect_args += ["--legit-ips"] + legit_ips
    if coils: detect_args += ["--legit-registers"] + coils
    if func_codes: detect_args += ["--legit-funcs"] + func_codes
    if unit_arg is not None: detect_args += ["--legit-unit", str(unit_arg)]
    detect_args += ["--alerts-dir", ".", "--logs-dir", CONFIG.get("logs_dir", "logs")]
    _run_python_live(CONFIG["scripts"]["detect_realtime"], detect_args)

def train_if_needed(_args=None):
    """
    Executa o script de treinamento 102-Treinar-ML.py com os parâmetros
    padrão definidos para o experimento atual.
    """
    train_args = [
        "--csv", "Modbus_TCP_ Cybersecurity_Dataset_Training.csv",
        "--sep", ";",
        "--target", "Classification",
        "--eval-csv", "Modbus_TCP_ Cybersecurity_Dataset_Validation.csv_",
        "--eval-sep", ";",
        "--eval-target", "Classification",
        # treinar RandomForest e DecisionTree
        "--model", "rf",
        "--model", "dt",
        "--prefix", "experimento",
    ]

    rc, out, err, logpath = _run_python_capture(CONFIG["scripts"]["train"], train_args)
    if rc != 0:
        print("[!] Train script failed:", logpath)
        print(err[:800] or "(no stderr)")
    else:
        print("[OK] Train finished. Log:", logpath)


def realtime_exec(_args=None):
    """
    Executa o script 103-Executar-ML.py em modo live com parâmetros fixos.
    Sempre usa sudo e o Python do venv atual.
    """
    realtime_args = [
        "--iface", "eth2",
        "--out", "live_preds.csv",
        "--threshold", "0.70",
        "--no-jsonl",
        "--verbose",
        "--model", "experimento03/randomforest_model.joblib",
        "--features", "experimento03/randomforest_features.joblib",
        "--class-names", "experimento03/randomforest_class_names.joblib",
    ]

    rc = _run_python_live(
        CONFIG["scripts"]["realtime"],
        realtime_args,
        use_sudo=True
    )

    if rc != 0:
        print("[!] Realtime script failed with code:", rc)
    else:
        print("[OK] Realtime finished.")


def show_config():
    print("\n[ CONFIGURATION ]")
    print("scripts:")
    for k,v in CONFIG["scripts"].items():
        print(f"  {k}: {v}")
    print("capture_defaults:")
    for k,v in CONFIG["capture_defaults"].items():
        print(f"  {k}: {v}")
    print("upload_defaults:")
    for k,v in CONFIG["upload_defaults"].items():
        print(f"  {k}: {v}")
    print("query_defaults:")
    for k,v in CONFIG["query_defaults"].items():
        print(f"  {k}: {v}")
    print("logs_dir:", CONFIG["logs_dir"])
    print()

# ==============================
# ARGUMENTS (CLI)
# ==============================
def parse_args():
    p = argparse.ArgumentParser(description="FARAONIC main script")
    p.add_argument("--capture", action="store_true", help="Run capture & upload baseline (RULES [1])")
    p.add_argument("--query", action="store_true", help="Query baseline & start real-time engine (RULES [2])")
    p.add_argument("--train", action="store_true", help="Train ML model (BEHAVIORAL [3])")
    p.add_argument("--realtime", action="store_true", help="Run real-time ML detection (BEHAVIORAL [4])")
    p.add_argument("--show-config", action="store_true", help="Show current configuration")

    # Capture args
    p.add_argument("--cap-iface", help="Capture iface (default: capture_defaults.iface)")
    p.add_argument("--cap-duration", type=int, help="Duration seconds (default: capture_defaults.duration)")
    p.add_argument("--cap-count", type=int, help="Stop after N packets (default: capture_defaults.count)")
    p.add_argument("--cap-filter", help="BPF filter (default: capture_defaults.filter)")
    p.add_argument("--cap-outdir", help="Output dir (default: capture_defaults.outdir)")
    p.add_argument("--cap-basename", help="Base filename (default: capture_defaults.basename)")
    p.add_argument("--cap-mode", choices=["summary", "full"], help="summary|full (default: capture_defaults.mode)")
    p.add_argument("--cap-no-iso", action="store_true", help="Omit ISO timestamp in full mode")
    p.add_argument("--cap-no-jsonl", action="store_true", help="Do not write .jsonl")
    p.add_argument("--cap-pcap", help="Also write raw PCAP to this path")

    # Upload args
    p.add_argument("--up-mongo-uri", help="Mongo URI (default: upload_defaults.mongo_uri)")
    p.add_argument("--up-db", help="Mongo DB name (default: upload_defaults.db)")
    p.add_argument("--up-collection", help="Mongo collection (default: upload_defaults.collection)")
    p.add_argument("--up-input", help="Input JSON/JSONL (default: <cap_outdir>/<cap_basename>.json)")
    p.add_argument("--up-batch-size", type=int, help="Batch size (default: upload_defaults.batch_size)")
    return p.parse_args()

# ==============================
# MENU
# ==============================
def menu():
    while True:
        #os.system('cls' if os.name == 'nt' else 'clear')
        banner()
        print("MAIN MENU\n")
        print("== RULES ==")
        print("  [1] Capture packets & upload baseline to MongoDB (interactive)")
        print("  [2] Query baseline & start real-time rule engine\n")
        print("== BEHAVIORAL ==")
        print("  [3] Train model (if not exists)")
        print("  [4] Real-time ML detection\n")
        print("== GENERAL ==")
        print("  [5] Show current configuration")
        print("  [q] Quit\n")
        c = input("Select an option: ").strip().lower()
        if   c == "1":
            capture_and_upload_interactive()
        elif c == "2":
            query_then_detect_interactive()
        elif c == "3":
            train_if_needed(None)
        elif c == "4":
            realtime_exec(None)
        elif c == "5":
            show_config()
            input("\nPress Enter to continue...")
        elif c in ("q","quit","exit"):
            print("\nExiting FARAONIC...\n")
            break
        else:
            print("Invalid option.")
            input("\nPress Enter to continue...")

# ==============================
# MAIN
# ==============================
def main():
    args = parse_args()
    #banner()
    # CLI direct actions
    if any([args.capture, args.query, args.train, args.realtime, args.show_config]):
        if args.capture:
            cap_flags = any([args.cap_iface, args.cap_duration, args.cap_count, args.cap_filter,
                             args.cap_outdir, args.cap_basename, args.cap_mode, args.cap_no_iso,
                             args.cap_no_jsonl, args.cap_pcap])
            up_flags  = any([args.up_mongo_uri, args.up_db, args.up_collection, args.up_input, args.up_batch_size])
            if cap_flags or up_flags:
                capture_and_upload_args(args)
            else:
                capture_and_upload_interactive()
        if args.query:
            # non-interactive: use query_defaults, then start detector (as in query_and_realtime)
            query_and_realtime(args)
        if args.train:
            train_if_needed(args)
        if args.realtime:
            realtime_exec(args)
        if args.show_config:
            show_config()
    else:
        menu()

if __name__ == "__main__":
    main()





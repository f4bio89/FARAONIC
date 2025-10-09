#!./projeto/bin/python
"""
102-Treinar-ML.py
Version 2 of the ML pipeline for Modbus/TCP traffic, with opinionated defaults
and full CLI overrides.

Defaults (can be changed via flags):
  -i dataset/dataset_unico.csv
  --safe-exclude (disable with --no-safe-exclude)
  --mk-bitcount-delta (disable with --no-mk-bitcount-delta)
  --save-model mymodels.joblib
  --report-out ml_results/meu_report.md
  --verbose (disable with --quiet)

Examples:
  # use all defaults
  ./11-ML-v2.py

  # change input and disable bitcount-delta
  ./11-ML-v2.py -i other.csv --no-mk-bitcount-delta

  # disable safe-exclude and silence logs
  ./11-ML-v2.py --no-safe-exclude --quiet

  # enable gridsearch and change output model
  ./11-ML-v2.py --gridsearch --save-model results/rf.joblib
"""
from __future__ import annotations
import argparse
import pandas as pd
import numpy as np
from ast import literal_eval
import sys
import os
import datetime
import warnings
import joblib

# sklearn imports
from sklearn.model_selection import train_test_split, GroupKFold, StratifiedKFold, RandomizedSearchCV
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier

# silence specific future warnings we know about
warnings.filterwarnings("ignore", category=FutureWarning)

# -------------------------
# Helpers (parsers / features)
# -------------------------
def parse_list_like(x):
    if pd.isna(x) or x == '' or x == '[]':
        return []
    try:
        return literal_eval(x)
    except Exception:
        return []

def tcp_flag_bits(v):
    if pd.isna(v):
        v = 0
    try:
        v = int(v)
    except Exception:
        v = 0
    return {
        'tcp_fin':  v & 0x01 > 0,
        'tcp_syn':  v & 0x02 > 0,
        'tcp_rst':  v & 0x04 > 0,
        'tcp_psh':  v & 0x08 > 0,
        'tcp_ack':  v & 0x10 > 0,
        'tcp_urg':  v & 0x20 > 0,
        'tcp_ece':  v & 0x40 > 0,
        'tcp_cwr':  v & 0x80 > 0,
    }

def extract_tsvals(opt_list):
    if not isinstance(opt_list, list):
        return np.nan, np.nan, 0, False
    tsval, tsecr = np.nan, np.nan
    nop_count = 0
    for t, v in opt_list:
        if t == 'NOP':
            nop_count += 1
        if t == 'Timestamp' and isinstance(v, tuple) and len(v) == 2:
            tsval, tsecr = v[0], v[1]
    return tsval, tsecr, nop_count, not np.isnan(tsval)

def coalesce(*vals):
    for v in vals:
        if pd.notna(v):
            return v
    return np.nan

def make_ohe_compat():
    """Return a OneHotEncoder compatible with newer/older sklearn versions."""
    try:
        return OneHotEncoder(handle_unknown='ignore', sparse_output=False)
    except TypeError:
        return OneHotEncoder(handle_unknown='ignore', sparse=False)

def ensure_parent_dir(path: str):
    """Create parent directory if needed (for output files)."""
    parent = os.path.dirname(os.path.abspath(path))
    if parent and not os.path.exists(parent):
        os.makedirs(parent, exist_ok=True)

# -------------------------
# CLI (opinionated defaults + overrides)
# -------------------------
parser = argparse.ArgumentParser(
    description="11-ML-v2.py - ML pipeline for Modbus/TCP (safe presets, time-split, group-kfold, report)"
)

# Defaults requested
parser.add_argument('-i', '--input', default='dataset/dataset_unico.csv',
                    help='Input CSV (default: dataset/dataset_unico.csv; use ; as separator if needed)')
parser.add_argument('-t', '--target', default='Classification',
                    help='Target column name (default: Classification)')
parser.add_argument('-e', '--exclude-cols', default='',
                    help='Extra columns to exclude (comma-separated)')

# safe-exclude default ON, with option to turn off
mx_safe = parser.add_mutually_exclusive_group()
mx_safe.add_argument('--safe-exclude', dest='safe_exclude', action='store_true',
                     help='Enable preset excludes (IPs, MACs, timestamps, checksums, trans_id, etc.) [DEFAULT]')
mx_safe.add_argument('--no-safe-exclude', dest='safe_exclude', action='store_false',
                     help='Disable the preset excludes')
parser.set_defaults(safe_exclude=True)

# bitcount-delta default ON, with option to turn off
mx_bit = parser.add_mutually_exclusive_group()
mx_bit.add_argument('--mk-bitcount-delta', dest='mk_bitcount_delta', action='store_true',
                    help='Create bit_count_delta from ModbusWriteMultipleCoilsRequest_bit_count [DEFAULT]')
mx_bit.add_argument('--no-mk-bitcount-delta', dest='mk_bitcount_delta', action='store_false',
                    help='Do not create bit_count_delta')
parser.set_defaults(mk_bitcount_delta=True)

parser.add_argument('--test-size', type=float, default=0.25,
                    help='Test split size (default 0.25)')
parser.add_argument('--random-state', type=int, default=42, help='Random state (default 42)')
parser.add_argument('--models', default='dt,rf', help='Which models to train: dt,rf (e.g., dt,rf)')
parser.add_argument('--no-ml', action='store_true', help='Prepare X/y only, do not train models')

# time split options
parser.add_argument('--time-split-ts', default=None,
                    help='Timestamp ISO threshold (e.g., 2025-10-01T12:00:00): train < TS, test >= TS')
parser.add_argument('--time-split-minutes', type=int, default=None,
                    help='Threshold = min(timestamp) + N minutes (train before, test after)')

# group kfold
parser.add_argument('--group-kfold', type=int, default=None,
                    help='GroupKFold CV with K folds (uses flow_id as group).')

parser.add_argument('--gridsearch', action='store_true',
                    help='Run a light RandomizedSearchCV for RandomForest')

# Outputs: requested defaults
parser.add_argument('--save-model', default='mymodels.joblib',
                    help='Path to save final pipeline/model (default: mymodels.joblib)')
parser.add_argument('--report-out', default='ml_results/meu_report.md',
                    help='Path to output Markdown report (default: ml_results/meu_report.md)')

# Verbose ON by default; can silence with --quiet
mx_verb = parser.add_mutually_exclusive_group()
mx_verb.add_argument('--verbose', dest='verbose', action='store_true', help='Verbose [DEFAULT]')
mx_verb.add_argument('--quiet', dest='verbose', action='store_false', help='Quiet mode')
parser.set_defaults(verbose=True)

args = parser.parse_args()

# -------------------------
# Preset safe exclude
# -------------------------
preset_safe = [
    'IP_src','IP_dst','Ether_src','Ether_dst',
    'tcp_tsval','tcp_tsecr','timestamp',
    'TCP_seq','TCP_ack',
    'ModbusTCPRequest_trans_id','ModbusTCPResponse_trans_id',
    'ModbusWriteMultipleCoilsRequest_reference_number'
    # 'ModbusWriteMultipleCoilsRequest_bit_count'  # optional
]

EXCLUDE_COLS = [c.strip() for c in args.exclude_cols.split(',') if c.strip()]
if args.safe_exclude:
    # add preset without duplicates
    EXCLUDE_COLS = list(dict.fromkeys(EXCLUDE_COLS + preset_safe))

if args.verbose:
    print(f'[INFO] Input: {args.input}')
    print(f'[INFO] Target: {args.target}')
    print(f'[INFO] Exclude columns: {EXCLUDE_COLS}')
    print(f'[INFO] Test size: {args.test_size}  Random state: {args.random_state}')
    print(f'[INFO] Requested models: {args.models}; no-ml={args.no_ml}; gridsearch={args.gridsearch}')
    print(f'[INFO] mk_bitcount_delta={args.mk_bitcount_delta}  safe_exclude={args.safe_exclude}')

# -------------------------
# Load CSV
# -------------------------
try:
    df = pd.read_csv(args.input, sep=';', engine='python')
except Exception as e:
    print(f'[ERROR] Failed to open {args.input}: {e}')
    sys.exit(1)

# basic timestamp conversion
df['timestamp'] = pd.to_numeric(df.get('timestamp'), errors='coerce')
df['event_time'] = pd.to_datetime(df['timestamp'], unit='s', errors='coerce')
df = df.sort_values('timestamp').reset_index(drop=True)

# -------------------------
# Safe pre-processing (type casting)
# -------------------------
num_cols_guess = [
    'Ether_type','IP_version','IP_ihl','IP_tos','IP_len','IP_id','IP_flags','IP_frag','IP_ttl',
    'IP_proto','IP_chksum','TCP_sport','TCP_dport','TCP_seq','TCP_ack','TCP_dataofs',
    'TCP_reserved','TCP_flags','TCP_window','TCP_chksum','TCP_urgptr',
]
modbus_num_guess = [c for c in [
    'ModbusTCPRequest_trans_id','ModbusTCPRequest_prot_id','ModbusTCPRequest_length','ModbusTCPRequest_unit_id','ModbusTCPRequest_func_code',
    'ModbusTCPResponse_trans_id','ModbusTCPResponse_prot_id','ModbusTCPResponse_length','ModbusTCPResponse_unit_id','ModbusTCPResponse_func_code',
    'ModbusReadDiscreteInputsRequest_reference_number','ModbusReadDiscreteInputsRequest_bit_count',
    'ModbusReadDiscreteInputsResponse_byte_count',
    'ModbusWriteMultipleCoilsRequest_reference_number','ModbusWriteMultipleCoilsRequest_bit_count',
    'ModbusWriteMultipleCoilsRequest_byte_count','ModbusWriteMultipleCoilsResponse_bit_count',
    'ModbusWriteMultipleCoilsResponse_reference_number'
] if c in df.columns]

for c in num_cols_guess + modbus_num_guess:
    if c in df.columns:
        df[c] = pd.to_numeric(df[c], errors='coerce')

for c in ['Ether_dst','Ether_src','IP_src','IP_dst']:
    if c in df.columns:
        try:
            df[c] = df[c].astype('category')
        except Exception:
            pass

# parse lists
for c in ['IP_options','TCP_options','ModbusReadDiscreteInputsResponse_input_status','ModbusWriteMultipleCoilsRequest_coil_status']:
    if c in df.columns:
        df[c] = df[c].apply(parse_list_like)

# -------------------------
# Feature engineering
# -------------------------
# direction
direction_arr = np.where(
    df.get('TCP_dport', pd.Series(index=df.index)) == 502, 'cli_to_srv',
    np.where(df.get('TCP_sport', pd.Series(index=df.index)) == 502, 'srv_to_cli', 'other')
)
df['direction'] = pd.Series(direction_arr, index=df.index).astype('category')

# flags
if 'TCP_flags' in df.columns:
    flag_expanded = df['TCP_flags'].apply(tcp_flag_bits).apply(pd.Series)
    df = pd.concat([df, flag_expanded], axis=1)

# approx payload
if set(['IP_len','IP_ihl','TCP_dataofs']).issubset(df.columns):
    df['approx_payload_len'] = df['IP_len'] - (df['IP_ihl'] * 4) - (df['TCP_dataofs'] * 4)
else:
    df['approx_payload_len'] = np.nan

# modbus func
if 'ModbusTCPRequest_func_code' in df.columns or 'ModbusTCPResponse_func_code' in df.columns:
    df['modbus_func'] = df.apply(lambda r: coalesce(r.get('ModbusTCPRequest_func_code'), r.get('ModbusTCPResponse_func_code')), axis=1)
    try:
        df['modbus_func'] = df['modbus_func'].astype('Int64')
    except Exception:
        pass

# tsvals
if 'TCP_options' in df.columns:
    ts_vals = df['TCP_options'].apply(extract_tsvals).apply(pd.Series)
    ts_vals.columns = ['tcp_tsval','tcp_tsecr','tcp_nop_count','tcp_has_ts']
    df = pd.concat([df, ts_vals], axis=1)

# flow_id
for c in ['IP_src','IP_dst','TCP_sport','TCP_dport','IP_proto']:
    if c not in df.columns:
        df[c] = df.get(c, pd.Series(index=df.index))
df['flow_id'] = (
    df['IP_src'].astype(str) + '>' + df['IP_dst'].astype(str) + ':' +
    df['TCP_sport'].astype(str) + '>' + df['TCP_dport'].astype(str) + '/' +
    df['IP_proto'].astype(str)
)

# iat_flow
df['iat_flow'] = df.groupby('flow_id')['timestamp'].diff()

# deltas
for col, newcol in [('TCP_seq','delta_seq'), ('TCP_ack','delta_ack'), ('TCP_window','delta_win')]:
    if col in df.columns:
        df[newcol] = df.groupby('flow_id')[col].diff()

if 'tcp_tsval' in df.columns:
    df['delta_tsval'] = df.groupby('flow_id')['tcp_tsval'].diff()

if 'IP_id' in df.columns:
    df['ip_id_delta'] = df.groupby(['IP_src','IP_dst'], observed=False)['IP_id'].diff()

# optional bit_count_delta
if args.mk_bitcount_delta:
    src = 'ModbusWriteMultipleCoilsRequest_bit_count'
    if src in df.columns:
        df['bit_count_delta'] = df.groupby('flow_id')[src].diff()
        if args.verbose:
            print('[INFO] Created bit_count_delta feature.')
    else:
        print('[WARN] bit_count_delta requested but source column not found:', src)

# -------------------------
# Prepare target and drop columns
# -------------------------
target_col = args.target
if target_col in (set([c.strip() for c in preset_safe]) if args.safe_exclude else set()):
    print(f'[ERROR] Target "{target_col}" cannot be in the preset excludes. Use --no-safe-exclude or change the target.')
    sys.exit(1)

y = None
if target_col in df.columns:
    df[target_col] = df[target_col].astype('string')
    y = df[target_col].astype('category')

drop_cols = set([
    target_col,
    'TCP_options','IP_options',
    'ModbusReadDiscreteInputsResponse_input_status',
    'ModbusWriteMultipleCoilsRequest_coil_status',
    'event_time','flow_id'
])
drop_cols.update(EXCLUDE_COLS)

missing_excludes = [c for c in EXCLUDE_COLS if c not in df.columns and c not in preset_safe]
if missing_excludes and args.verbose:
    print('[WARN] Exclude columns not found in CSV (may be fine):', missing_excludes)

existing_drop = [c for c in drop_cols if c in df.columns]
X = df.drop(columns=existing_drop)

if args.verbose:
    print('[INFO] X columns preview:', X.columns.tolist()[:40])
    print('[INFO] X shape:', X.shape)
    print('[INFO] y distribution:\n', (y.value_counts() if y is not None else 'No target'))

# Save a quick X/y snapshot (helpful to inspect)
preview_dir = os.path.join(os.getcwd(), 'ml_previews')
os.makedirs(preview_dir, exist_ok=True)
try:
    X.head(5).to_csv(os.path.join(preview_dir, 'X_head_preview.csv'), index=False)
    if y is not None:
        y.value_counts().to_csv(os.path.join(preview_dir, 'y_counts_preview.csv'))
except Exception:
    pass

# -------------------------
# If --no-ml just exit after preprocessing
# -------------------------
if args.no_ml:
    print('[INFO] --no-ml set: preprocessing done. Exiting.')
    sys.exit(0)

if y is None:
    print('[INFO] No target column found; cannot run ML. Exiting.')
    sys.exit(0)

# -------------------------
# Prepare columns lists for preprocessing
# -------------------------
cat_cols = [c for c in X.columns if str(X[c].dtype) in ('category','object','string')]
num_cols = [c for c in X.columns if c not in cat_cols]

if args.verbose:
    print(f'[INFO] num_cols: {len(num_cols)}  cat_cols: {len(cat_cols)}')

numeric_tf = Pipeline([('imputer', SimpleImputer(strategy='median'))])
categorical_tf = Pipeline([('imputer', SimpleImputer(strategy='most_frequent')), ('onehot', make_ohe_compat())])

preproc = ColumnTransformer(
    transformers=[('num', numeric_tf, num_cols), ('cat', categorical_tf, cat_cols)],
    remainder='drop'
)

# -------------------------
# Train/test split: time-split or random split
# -------------------------
X_train = X_test = y_train = y_test = None
groups = df['flow_id'] if 'flow_id' in df.columns else None

if args.time_split_ts:
    try:
        ts = pd.to_datetime(args.time_split_ts)
        train_mask = df['event_time'] < ts
        test_mask = df['event_time'] >= ts
        if train_mask.sum() == 0 or test_mask.sum() == 0:
            print('[ERROR] time-split-ts produced empty train or test. Check the provided timestamp.')
            sys.exit(1)
        X_train = X[train_mask]; X_test = X[test_mask]
        y_train = y[train_mask]; y_test = y[test_mask]
        groups_train = groups[train_mask] if groups is not None else None
        groups_test = groups[test_mask] if groups is not None else None
        if args.verbose:
            print(f'[INFO] Time split at {ts}: train={X_train.shape[0]} test={X_test.shape[0]}')
    except Exception as e:
        print('[ERROR] --time-split-ts parse error:', e); sys.exit(1)
elif args.time_split_minutes is not None:
    min_ts = df['timestamp'].min()
    if pd.isna(min_ts):
        print('[ERROR] timestamp column missing or invalid; cannot use time-split-minutes.'); sys.exit(1)
    threshold = min_ts + (args.time_split_minutes * 60)
    train_mask = df['timestamp'] < threshold
    test_mask = df['timestamp'] >= threshold
    if train_mask.sum() == 0 or test_mask.sum() == 0:
        print('[ERROR] time-split-minutes produced empty train/test. Pick a different minutes value.'); sys.exit(1)
    X_train = X[train_mask]; X_test = X[test_mask]
    y_train = y[train_mask]; y_test = y[test_mask]
    groups_train = groups[train_mask] if groups is not None else None
    groups_test = groups[test_mask] if groups is not None else None
    if args.verbose:
        print(f'[INFO] Time split (min): threshold={datetime.datetime.utcfromtimestamp(threshold)} train={X_train.shape[0]} test={X_test.shape[0]}')
else:
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=args.test_size, random_state=args.random_state, stratify=y
    )
    groups_train = groups.loc[X_train.index] if groups is not None else None
    groups_test = groups.loc[X_test.index] if groups is not None else None
    if args.verbose:
        print(f'[INFO] Random stratified split: train={X_train.shape[0]} test={X_test.shape[0]}')

# -------------------------
# Model pipelines
# -------------------------
models_to_run = [m.strip().lower() for m in args.models.split(',') if m.strip()]
pipelines = {}

if 'dt' in models_to_run:
    pipelines['DecisionTree'] = Pipeline([
        ('prep', preproc),
        ('clf', DecisionTreeClassifier(random_state=args.random_state, class_weight='balanced'))
    ])

if 'rf' in models_to_run:
    rf_clf = RandomForestClassifier(
        n_estimators=200, random_state=args.random_state, n_jobs=-1,
        class_weight='balanced_subsample'
    )
    if args.gridsearch:
        pipelines['RandomForest'] = Pipeline([('prep', preproc), ('clf', rf_clf)])
        if args.verbose:
            print('[INFO] Gridsearch enabled for RandomForest (RandomizedSearchCV).')
    else:
        pipelines['RandomForest'] = Pipeline([('prep', preproc), ('clf', rf_clf)])

# -------------------------
# If gridsearch requested, run RandomizedSearchCV (only for RF) using train set
# -------------------------
if args.gridsearch and 'rf' in models_to_run:
    base_pipeline = pipelines['RandomForest']
    param_dist = {
        'clf__n_estimators': [100, 200, 300],
        'clf__max_depth': [None, 10, 20],
        'clf__min_samples_leaf': [1, 2, 5],
        'clf__max_features': ['sqrt', 'log2', 0.3]
    }
    rnd = RandomizedSearchCV(
        base_pipeline, param_distributions=param_dist, n_iter=8, cv=3,
        verbose=1 if args.verbose else 0, n_jobs=-1, random_state=args.random_state
    )
    if args.verbose:
        print('[INFO] Running RandomizedSearchCV on RandomForest pipeline...')
    rnd.fit(X_train, y_train)
    if args.verbose:
        print('[INFO] RandomizedSearchCV done. Best params:', rnd.best_params_)
    pipelines['RandomForest'] = rnd.best_estimator_

# -------------------------
# Training & Evaluation
# -------------------------
report_lines = []
results_folder = os.path.join(os.getcwd(), 'ml_results')
os.makedirs(results_folder, exist_ok=True)

for name, model in pipelines.items():
    print(f'\n[INFO] Training {name}...')
    model.fit(X_train, y_train)
    print(f'[INFO] Evaluating {name}...')
    y_pred = model.predict(X_test)
    creport = classification_report(y_test, y_pred, zero_division=0)
    cm = confusion_matrix(y_test, y_pred)
    print(f'===== {name} =====')
    print(creport)
    print('Confusion matrix:\n', cm)

    # feature importances if available
    imp_text = ''
    try:
        clf = model.named_steps['clf']
        if hasattr(clf, 'feature_importances_'):
            # recover feature names
            num_names = num_cols
            cat_names = []
            if len(cat_cols) > 0:
                ohe = model.named_steps['prep'].named_transformers_['cat'].named_steps['onehot']
                try:
                    cat_names = ohe.get_feature_names_out(cat_cols).tolist()
                except Exception:
                    cat_names = [f'cat_{i}' for i in range(len(cat_cols))]
            all_names = num_names + cat_names
            importances = clf.feature_importances_
            if len(importances) == len(all_names):
                imp_df = pd.DataFrame({'feature': all_names, 'importance': importances}).sort_values('importance', ascending=False)
                imp_text = imp_df.head(50).to_markdown(index=False)
                print(f'\nTop 25 importances ({name}):')
                print(imp_df.head(25).to_string(index=False))
            else:
                imp_text = '[WARN] importances length mismatch'
    except Exception as e:
        imp_text = f'[WARN] Could not extract importances: {e}'

    # Save results to report buffer
    report_lines.append(f'## Model: {name}\n')
    report_lines.append('### Classification Report\n')
    report_lines.append('```\n' + creport + '\n```\n')
    report_lines.append('### Confusion Matrix\n')
    report_lines.append('```\n' + str(cm.tolist()) + '\n```\n')
    if imp_text:
        report_lines.append('### Top feature importances (preview)\n')
        report_lines.append(imp_text + '\n')

# -------------------------
# Optionally: GroupKFold evaluation (cross-val) if requested
# -------------------------
if args.group_kfold is not None and args.group_kfold > 1:
    k = args.group_kfold
    print(f'[INFO] Running GroupKFold (k={k}) cross-validation on the first available model (for speed).')
    eval_model_name = 'RandomForest' if 'RandomForest' in pipelines else next(iter(pipelines.keys()))
    estimator = pipelines[eval_model_name]
    gkf = GroupKFold(n_splits=k)
    fold = 0
    cv_reports = []
    for train_idx, test_idx in gkf.split(X, y, groups=df['flow_id']):
        fold += 1
        X_tr, X_te = X.iloc[train_idx], X.iloc[test_idx]
        y_tr, y_te = y.iloc[train_idx], y.iloc[test_idx]
        estimator.fit(X_tr, y_tr)
        y_p = estimator.predict(X_te)
        crep = classification_report(y_te, y_p, zero_division=0)
        print(f'[CV] Fold {fold} report:\n{crep}')
        cv_reports.append((fold, crep))
    report_lines.append('## GroupKFold Cross-Validation\n')
    for fnum, crep in cv_reports:
        report_lines.append(f'### Fold {fnum}\n```\n{crep}\n```\n')

# -------------------------
# Save pipeline/model + report
# -------------------------
final_model_path = args.save_model
try:
    ensure_parent_dir(final_model_path)
    if len(pipelines) == 1:
        single = list(pipelines.values())[0]
        joblib.dump(single, final_model_path)
    else:
        joblib.dump(pipelines, final_model_path)
    print(f'[INFO] Saved model/pipeline to {final_model_path}')
except Exception as e:
    print('[WARN] Could not save model pipeline:', e)

report_path = args.report_out or os.path.join(
    results_folder, f'ml_report_{datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")}.md'
)
ensure_parent_dir(report_path)
with open(report_path, 'w') as fh:
    fh.write('# ML Report\n\n')
    fh.write(f'- Input: {args.input}\n')
    fh.write(f'- Target: {args.target}\n')
    fh.write(f'- Excluded columns: {EXCLUDE_COLS}\n')
    fh.write(f'- Models: {args.models}\n')
    fh.write(f'- Time split: {args.time_split_ts or args.time_split_minutes}\n')
    fh.write('\n')
    fh.write('\n'.join(report_lines))

print(f'[INFO] Report saved to {report_path}')
print('[INFO] Script finished.')

#!../projeto/bin/python
# -*- coding: utf-8 -*-

"""
Treinador RandomForest / DecisionTree
Saídas (todas dentro de <pasta>/):
- Report de classificação (.txt)
- Matriz de confusão (.png)
- SHAP summary_plot (bar) com nomes corretos das classes (.png)
- (se DT) PNG da árvore de decisão
- Arquivos .joblib (modelo, features, class_names)

Argumentos úteis:
  --csv, --sep, --target, --prefix
  --model {rf,dt} (pode repetir; default: rf dt -> treina ambos)
  --test-size, --random-state
  --shap-test-size (amostra do teste p/ SHAP, default 3000)
  --shap-bg-size   (background SHAP, default 200)

NOVO:
  --eval-csv        (CSV de avaliação externo; se fornecido, NÃO faz split)
  --eval-sep        (separador do CSV de avaliação; default = --sep)
  --eval-target     (nome da coluna-alvo no CSV de avaliação; default = --target ou autodetect)
"""

import os
import re
import warnings
warnings.filterwarnings("ignore")

import argparse
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns

import joblib

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import f1_score, confusion_matrix, classification_report
from sklearn.tree import DecisionTreeClassifier, plot_tree
from sklearn.ensemble import RandomForestClassifier

# =================== ARGUMENTOS ===================
parser = argparse.ArgumentParser(description="Treinamento (RF/DT) + Confusion + Report + SHAP bar")
parser.add_argument("--csv", default="/home/kali/Desktop/arquivos-defensive/Final/dataset/dataset_unico_filtrado.csv",
                    help="Caminho do dataset CSV (treino)")
parser.add_argument("--sep", default=";", help="Separador do CSV de treino (padrão: ';')")
parser.add_argument("--target", default=None, help="Nome da coluna-alvo do treino (senão detecta)")
parser.add_argument("--prefix", default="", help="Nome da PASTA de saída (se vazio, usa nome do CSV)")
parser.add_argument("--model", nargs="+", choices=["rf", "dt"], default=["rf", "dt"],
                    help="Quais modelos treinar (default: rf dt)")
parser.add_argument("--test-size", type=float, default=0.30, help="Proporção do teste (padrão: 0.30)")
parser.add_argument("--random-state", type=int, default=42, help="Seed")
parser.add_argument("--shap-test-size", type=int, default=3000, help="Amostras do teste p/ SHAP (padrão: 3000)")
parser.add_argument("--shap-bg-size", type=int, default=200, help="Amostras de background p/ SHAP (padrão: 200)")
parser.add_argument("--max-display", type=int, default=20, help="Máx. features no SHAP bar (padrão: 20)")

# NOVOS ARGUMENTOS
parser.add_argument("--eval-csv", default=None, help="Caminho do CSV de avaliação (sem split)")
parser.add_argument("--eval-sep", default=None, help="Separador do CSV de avaliação (default = --sep)")
parser.add_argument("--eval-target", default=None, help="Nome da coluna-alvo no CSV de avaliação (senão usa --target ou autodetect)")

args = parser.parse_args()

# ------------------- Paths e pasta de saída -------------------
def sanitize_name(name: str) -> str:
    name = name.strip()
    name = re.sub(r"[\\/]+", "_", name)
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", name)
    name = re.sub(r"_+", "_", name).strip("_.")
    return name or "run"

CSV_PATH = os.path.abspath(os.path.expanduser(args.csv.strip()))
SEP = args.sep
TARGET = args.target
EVAL_CSV_PATH = os.path.abspath(os.path.expanduser(args.eval_csv.strip())) if args.eval_csv else None
EVAL_SEP = args.eval_sep if args.eval_sep is not None else SEP
EVAL_TARGET = args.eval_target

PREFIX_RAW = args.prefix

if not os.path.exists(CSV_PATH):
    raise FileNotFoundError(f"CSV não encontrado: {CSV_PATH}")
if EVAL_CSV_PATH and not os.path.exists(EVAL_CSV_PATH):
    raise FileNotFoundError(f"CSV de avaliação não encontrado: {EVAL_CSV_PATH}")

# Se prefix não for fornecido, usar o nome do CSV (sem extensão)
if PREFIX_RAW.strip():
    RUN_NAME = sanitize_name(PREFIX_RAW)
else:
    RUN_NAME = sanitize_name(os.path.splitext(os.path.basename(CSV_PATH))[0])

RUN_DIR = os.path.join(".", RUN_NAME)
os.makedirs(RUN_DIR, exist_ok=True)

TEST_SIZE = args.test_size
RANDOM_STATE = args.random_state
MODELS = args.model
SHAP_TEST_SIZE = max(1, args.shap_test_size)
SHAP_BG_SIZE = max(1, args.shap_bg_size)
MAX_DISPLAY = args.max_display

print(f"[INFO] Pasta de saída: {os.path.abspath(RUN_DIR)}")

# =======================
# Colunas a excluir
# =======================
EXCLUDE_COLUMNS_BASE: list[str] = [
    "Ether_src", "Ether_dst", "Ether_type",
    "IP_src", "IP_dst", "IP_version", "IP_proto", "IP_chksum",
    "TCP_sport", "TCP_dport", "TCP_seq", "TCP_ack", "TCP_dataofs",
    "TCP_reserved", "TCP_chksum", "TCP_urgptr", "TCP_options",
    "ModbusReadDiscreteInputsRequest_reference_number",
    "ModbusWriteMultipleCoilsRequest_reference_number",
    "ModbusWriteMultipleCoilsResponse_reference_number"
]
EXCLUDE_COLUMNS_BASE: list[str] = []
# ajuste rápido via variáveis (mantido do seu script)
teste2="TCP_flags"
teste3="IP_flags"
teste4="IP_tos" # piorou um pouco se tirar
teste5="IP_len"
teste6="ModbusTCPRequest_length"
teste7="ModbusTCPRequest_trans_id"
teste8="ModbusTCPRequest_func_code"
teste9="TCP_window"
teste10="ModbusReadDiscreteInputsRequest_bit_count"
teste11="timestamp"
EXCLUDE_COLUMNS_EXTRA: list[str] = [
    teste7, teste11,teste3, teste2, teste4, 
    teste6
]
EXCLUDE_COLUMNS_EXTRA: list[str] = []
EXCLUDE_COLUMNS = list(set(EXCLUDE_COLUMNS_BASE + EXCLUDE_COLUMNS_EXTRA))

# =================== HELPERS ===================
def outpath(name: str) -> str:
    return os.path.join(RUN_DIR, name)

def salvar_matriz_confusao(cm, class_names, titulo, filename):
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
                xticklabels=class_names, yticklabels=class_names)
    plt.title(titulo)
    plt.xlabel('Classe Predita')
    plt.ylabel('Classe Real')
    plt.tight_layout()
    path = outpath(filename)
    plt.savefig(path, dpi=150)
    plt.close()
    print(f"[SALVO] {path}")

def salvar_arvore_decisao_png(modelo_dt, feature_names, class_names,
                              filename_png, max_depth_plot=4):
    plt.figure(figsize=(24, 18))
    plot_tree(
        modelo_dt,
        feature_names=feature_names,
        class_names=class_names,
        filled=True,
        rounded=True,
        max_depth=max_depth_plot,
        fontsize=8
    )
    plt.tight_layout()
    path_png = outpath(filename_png)
    plt.savefig(path_png, dpi=180, bbox_inches="tight")
    plt.close()
    print(f"[SALVO] {path_png}")

def avaliar_modelo(modelo, nome_modelo, X_eval, y_eval, class_names, sufixo=""):
    y_pred = modelo.predict(X_eval)
    f1 = f1_score(y_eval, y_pred, average='weighted')
    print(f"\n{nome_modelo}{sufixo} - F1 weighted: {f1:.4f}\n")
    report = classification_report(y_eval, y_pred, target_names=class_names, digits=4)
    print(f"Relatório por classe ({nome_modelo}{sufixo}):\n{report}")

    rep_path = outpath(f"{nome_modelo.lower()}{sufixo}_report.txt")
    with open(rep_path, "w", encoding="utf-8") as f:
        f.write(f"{nome_modelo}{sufixo} - F1 weighted: {f1:.4f}\n\n")
        f.write(report)
    print(f"[SALVO] {rep_path}")

    cm = confusion_matrix(y_eval, y_pred)
    salvar_matriz_confusao(cm, class_names,
                           f"Matriz de Confusão — {nome_modelo}{sufixo}",
                           f"{nome_modelo.lower()}{sufixo}_confusion_matrix.png")
    return f1

def shap_bar_with_true_labels(model, X_train, X_for_shap, class_names, model_name,
                              max_display=20, bg_size=200, test_size=3000, seed=42):
    try:
        import shap
        X_bg = X_train.sample(min(bg_size, len(X_train)), random_state=seed)
        X_ts = X_for_shap.sample(min(test_size, len(X_for_shap)), random_state=seed)

        explainer = shap.TreeExplainer(
            model,
            data=X_bg,
            feature_perturbation="interventional"
        )
        sv = explainer.shap_values(X_ts, check_additivity=False)

        plt.figure()
        shap.summary_plot(sv, X_ts, plot_type="bar", show=False, max_display=max_display)

        ax = plt.gca()
        handles, labels = ax.get_legend_handles_labels()
        if labels:
            new_labels = []
            for lbl in labels:
                try:
                    idx = int(lbl.split()[-1])
                    new_labels.append(str(class_names[idx]))
                except Exception:
                    new_labels.append(lbl)
            ax.legend(handles, new_labels, loc='best', ncol=2, fontsize=8, title=None)

        plt.title(f"Importância SHAP — {model_name}")
        plt.tight_layout()
        path_bar = outpath(f"{model_name.lower()}_shap_bar.png")
        plt.savefig(path_bar, dpi=150, bbox_inches="tight")
        plt.close()
        print(f"[SALVO] {path_bar}")
    except Exception as e:
        print(f"[AVISO] SHAP {model_name} falhou: {e}")

def autodetect_target(df, prefer=None):
    if prefer:
        return prefer
    for cand in ['classe', 'Classification', 'class', 'label', 'target']:
        match = [c for c in df.columns if c.lower() == cand.lower()]
        if match:
            return match[0]
    return None

def preparar_X(df_in, exclude_cols, feature_order=None):
    Xr = df_in.drop(columns=[c for c in exclude_cols if c in df_in.columns], errors="ignore")
    if feature_order is not None:
        # Mantém somente colunas esperadas; cria as ausentes com NaN
        for col in feature_order:
            if col not in Xr.columns:
                Xr[col] = np.nan
        Xr = Xr[feature_order]
    Xr = Xr.apply(pd.to_numeric, errors='coerce').astype(np.float32)
    return Xr


# =================== PIPELINE ===================
# 1) Carregar treino
df_train = pd.read_csv(CSV_PATH, delimiter=SEP, low_memory=False)

# 2) Duplicatas
before = len(df_train)
df_train = df_train.drop_duplicates()
after = len(df_train)
print(f"[INFO] Removidas {before - after} duplicatas (restaram {after}).")

# 3) Target treino
if TARGET is None:
    TARGET = autodetect_target(df_train)
    if TARGET is None:
        raise ValueError("Não encontrei coluna-alvo no treino. Use --target NOME_DA_COLUNA.")
print(f"[INFO] Coluna-alvo (treino): {TARGET}")

# 4) X/y treino e exclusões
y_train_raw = df_train[TARGET]
X_train_raw = df_train.drop(columns=[TARGET])
cols_to_drop_train = [c for c in EXCLUDE_COLUMNS if c in X_train_raw.columns]
if cols_to_drop_train:
    print(f"[INFO] Excluindo {len(cols_to_drop_train)} colunas (treino/leakage): {cols_to_drop_train}")
    X_train_raw = X_train_raw.drop(columns=cols_to_drop_train)

# 5) Numérico + float32 (treino)
X_train = X_train_raw.apply(pd.to_numeric, errors='coerce').astype(np.float32)


# 6) Encode alvo (ajusta em cima do treino)
le = LabelEncoder()
y_train = le.fit_transform(y_train_raw)
class_names = list(le.classes_)
print("Mapeamento das classes (treino):")
for i, c in enumerate(class_names):
    print(f"  {i} -> {c}")

# Preparação de conjuntos de avaliação:
use_external_eval = EVAL_CSV_PATH is not None

if use_external_eval:
    # 7A) Carregar avaliação externa
    df_eval = pd.read_csv(EVAL_CSV_PATH, delimiter=EVAL_SEP, low_memory=False)
    if EVAL_TARGET is None:
        EVAL_TARGET = autodetect_target(df_eval, prefer=args.target)
        if EVAL_TARGET is None:
            raise ValueError("Não encontrei coluna-alvo no CSV de avaliação. Use --eval-target NOME.")
    print(f"[INFO] Coluna-alvo (avaliação): {EVAL_TARGET}")

    y_eval_raw = df_eval[EVAL_TARGET]
    X_eval_raw = df_eval.drop(columns=[EVAL_TARGET])

    # remover mesmas colunas de leakage
    cols_to_drop_eval = [c for c in EXCLUDE_COLUMNS if c in X_eval_raw.columns]
    if cols_to_drop_eval:
        print(f"[INFO] Excluindo {len(cols_to_drop_eval)} colunas (avaliação/leakage): {cols_to_drop_eval}")
        X_eval_raw = X_eval_raw.drop(columns=cols_to_drop_eval)

    # alinhar colunas com treino
    train_features = X_train.columns.tolist()
    X_eval = preparar_X(X_eval_raw, exclude_cols=[], feature_order=train_features)

    # transformar y_eval com o mesmo encoder; filtrar classes desconhecidas
    known_classes = set(le.classes_)
    mask_known = y_eval_raw.astype(str).isin(known_classes)
    if not mask_known.all():
        desconhecidas = sorted(set(y_eval_raw.astype(str)[~mask_known]))
        print(f"[AVISO] Removendo {(~mask_known).sum()} amostras com classes NÃO vistas no treino: {desconhecidas}")
        X_eval = X_eval[mask_known.values]
        y_eval_raw = y_eval_raw[mask_known.values]

    y_eval = le.transform(y_eval_raw.astype(str))
    # Para SHAP, usaremos o próprio X_eval (amostrado)
    X_for_shap = X_eval.copy()
else:
    # 7B) Sem avaliação externa: faz split interno
    from sklearn.model_selection import train_test_split
    X_train, X_test, y_train, y_test = train_test_split(
        X_train, y_train, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y_train
    )
    X_eval, y_eval = X_test, y_test
    X_for_shap = X_test.copy()
    print(f"[INFO] Sem --eval-csv: usando split interno com test_size={TEST_SIZE}")

# =================== TREINOS ===================
for m in MODELS:
    if m == "rf":
        model = RandomForestClassifier(n_estimators=400, max_depth=None, n_jobs=-1, random_state=RANDOM_STATE)
        model_name = "RandomForest"
    elif m == "dt":
        model = DecisionTreeClassifier(random_state=RANDOM_STATE)
        model_name = "DecisionTree"
    else:
        continue

    print(f"\n[INFO] Treinando {model_name} ...")
    model.fit(X_train, y_train)

    if m == "dt":
        salvar_arvore_decisao_png(
            modelo_dt=model,
            feature_names=X_train.columns,
            class_names=class_names,
            filename_png="decisiontree_tree.png",
            max_depth_plot=4
        )

    # Sufixo para arquivos quando há avaliação externa
    suf = "_eval" if use_external_eval else ""
    _ = avaliar_modelo(model, model_name, X_eval, y_eval, class_names, sufixo=suf)

    shap_bar_with_true_labels(
        model, X_train, X_for_shap, class_names, model_name,
        max_display=MAX_DISPLAY, bg_size=SHAP_BG_SIZE, test_size=SHAP_TEST_SIZE, seed=RANDOM_STATE
    )

    # Salvar modelo + features + classes (um por modelo)
    joblib.dump(model, outpath(f"{model_name.lower()}_model.joblib"))
    joblib.dump(X_train.columns.tolist(), outpath(f"{model_name.lower()}_features.joblib"))
    joblib.dump(class_names, outpath(f"{model_name.lower()}_class_names.joblib"))
    print(f"[SALVO] Artefatos do {model_name} em: {os.path.abspath(RUN_DIR)}")

print("\n[OK] Concluído.")

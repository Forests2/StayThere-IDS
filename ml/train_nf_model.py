r"""NF-ToN-IoT-V2 로 네트워크 공격 분류 모델 학습 (AIPFL-IDS 전처리 방식 참고)

AIPFL-IDS 에서 가져온 것 (backend/config.py, train.py, src/preprocessing.py):
  - 라벨 컬럼 'Attack', 10종 (Benign, DDoS, DoS, Injection, Ransomware, Scanning, XSS, Backdoor, Password, MITM)
  - 클래스당 최대 50,000행 균형 샘플링 (2단계: 라벨 집계 → 비율 샘플링), seed 42
  - inf → NaN → 0, 극단값 1e15 클리핑, 상수 컬럼 제거, 식별자 컬럼 제외
  - 테스트 20% 층화 분할
바꾼 것:
  - TensorFlow DNN 대신 scikit-learn HistGradientBoosting (pip 만으로 설치, GPU 불필요)
  - 연합학습(FedAvg) 시뮬레이션 없음 — PC 한 대 학습용

준비:
  1) Kaggle 'dhoogla/nftoniotv2' 에서 NF-ToN-IoT-V2.parquet 를 받아 data\ 에 둔다
  2) python -m pip install pandas pyarrow scikit-learn joblib
실행:
  python ml\train_nf_model.py                       # 기본 경로 data\NF-ToN-IoT-V2.parquet
  python ml\train_nf_model.py --data 경로 --per-class 20000
결과: ml\models\nf_model.joblib, ml\models\nf_report.json
"""
import argparse
import json
import os
import time

import numpy as np
import pandas as pd
import pyarrow.parquet as pq

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LABEL_COL = "Attack"
DROP_ALWAYS = ["Label", LABEL_COL]
# 식별자는 학습에 쓰면 안 됨 (AIPFL train.py: "Identifiers must never become model features")
ID_COLS = ["IPV4_SRC_ADDR", "IPV4_DST_ADDR", "L4_SRC_PORT", "L4_DST_PORT",
           "FLOW_START_MILLISECONDS", "FLOW_END_MILLISECONDS"]
SEED = 42
CLIP = 1e15


def balanced_sample(path, per_class, batch_rows=500_000):
    pf = pq.ParquetFile(path)
    # 1단계: 라벨만 읽어 클래스별 개수 집계
    totals = {}
    for b in pf.iter_batches(batch_size=batch_rows, columns=[LABEL_COL]):
        vc = b.column(0).to_pandas().astype(str).str.strip().value_counts()
        for k, v in vc.items():
            totals[k] = totals.get(k, 0) + int(v)
    frac = {k: min(1.0, per_class / max(1, v)) for k, v in totals.items()}
    print("원본 클래스 분포:", json.dumps(totals, ensure_ascii=False))

    # 2단계: 배치마다 클래스별 비율로 샘플링
    parts, rng = [], np.random.default_rng(SEED)
    for i, b in enumerate(pf.iter_batches(batch_size=batch_rows)):
        df = b.to_pandas()
        df[LABEL_COL] = df[LABEL_COL].astype(str).str.strip()
        keep = df[LABEL_COL].map(frac).fillna(1.0).to_numpy() > rng.random(len(df))
        parts.append(df[keep])
        if i % 5 == 0:
            print(f"  배치 {i + 1}: 누적 {sum(len(p) for p in parts):,}행")
    df = pd.concat(parts, ignore_index=True)
    capped = [g.sample(n=min(len(g), per_class), random_state=SEED) for _, g in df.groupby(LABEL_COL)]
    return pd.concat(capped, ignore_index=True).sample(frac=1, random_state=SEED).reset_index(drop=True), totals


def preprocess(df):
    X = df.drop(columns=[c for c in DROP_ALWAYS + ID_COLS if c in df.columns])
    X = X.select_dtypes(include=[np.number]).replace([np.inf, -np.inf], np.nan).fillna(0)
    X = X.clip(lower=-CLIP, upper=CLIP)
    const = [c for c in X.columns if X[c].nunique() <= 1]
    X = X.drop(columns=const)
    return X.astype(np.float32), const


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=os.path.join(BASE, "data", "NF-ToN-IoT-V2.parquet"))
    ap.add_argument("--per-class", type=int, default=50_000)
    ap.add_argument("--out", default=os.path.join(BASE, "ml", "models"))
    args = ap.parse_args()

    from joblib import dump
    from sklearn.ensemble import HistGradientBoostingClassifier
    from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score
    from sklearn.model_selection import train_test_split
    from sklearn.preprocessing import LabelEncoder

    if not os.path.exists(args.data):
        raise SystemExit(f"데이터 파일이 없어요: {args.data}\n"
                         "Kaggle 'dhoogla/nftoniotv2' 에서 NF-ToN-IoT-V2.parquet 를 받아 data 폴더에 넣어 주세요.")
    t0 = time.time()
    df, raw_totals = balanced_sample(args.data, args.per_class)
    X, const = preprocess(df)
    enc = LabelEncoder()
    y = enc.fit_transform(df[LABEL_COL])
    print(f"학습 데이터 {X.shape}, 클래스 {list(enc.classes_)}")

    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, stratify=y, random_state=SEED)
    clf = HistGradientBoostingClassifier(max_iter=300, learning_rate=0.1, early_stopping=True,
                                         validation_fraction=0.15, random_state=SEED)
    clf.fit(Xtr, ytr)
    pred = clf.predict(Xte)

    report = {
        "dataset": os.path.basename(args.data),
        "reference": "github.com/PrathamWankhade/AIPFL-IDS (preprocessing & labels)",
        "model": "HistGradientBoostingClassifier",
        "rows_train": int(len(Xtr)), "rows_test": int(len(Xte)),
        "features": list(X.columns), "dropped_constant": const,
        "classes": list(enc.classes_), "raw_class_totals": raw_totals,
        "accuracy": round(float(accuracy_score(yte, pred)), 4),
        "macro_f1": round(float(f1_score(yte, pred, average="macro")), 4),
        "per_class": classification_report(yte, pred, target_names=list(enc.classes_), output_dict=True),
        "confusion_matrix": confusion_matrix(yte, pred).tolist(),
        "seconds": round(time.time() - t0, 1),
    }
    os.makedirs(args.out, exist_ok=True)
    dump({"model": clf, "encoder": enc, "features": list(X.columns), "clip": CLIP},
         os.path.join(args.out, "nf_model.joblib"))
    with open(os.path.join(args.out, "nf_report.json"), "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print(classification_report(yte, pred, target_names=list(enc.classes_), digits=3))
    print(f"정확도 {report['accuracy']}, macro F1 {report['macro_f1']}, {report['seconds']}초")
    print(f"저장: {args.out}")


if __name__ == "__main__":
    main()

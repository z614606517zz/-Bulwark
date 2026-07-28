"""
单文件打分探针：加载训练好的 LightGBM 模型，对一个 PE 文件（或加密样本 zip）打恶意概率分。

用法:
  python infer_probe.py path/to/file.exe
  python infer_probe.py path/to/sample.zip --zip           # 加密样本 zip（密码 infected）
  python infer_probe.py file.exe --model model.txt --meta model_meta.json

输出恶意概率 [0,1] 与按阈值的判定；这一路分数将来作为“评分信号”喂给 RuleEngine，
而不是单独拦截（符合“soft signal 需互证”的产品原则）。
"""

import argparse
import json
import os
import sys
import zipfile

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pe_features import PEFeatureExtractor  # noqa: E402


def read_zip_sample(zip_path, pw=b"infected"):
    try:
        with zipfile.ZipFile(zip_path) as z:
            return z.read(z.namelist()[0], pwd=pw)
    except Exception:
        import pyzipper
        with pyzipper.AESZipFile(zip_path) as z:
            z.setpassword(pw)
            return z.read(z.namelist()[0])


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser()
    ap.add_argument("path", help="待打分的 PE 文件；--zip 时为加密样本 zip")
    ap.add_argument("--zip", action="store_true", help="输入是加密样本 zip（密码 infected）")
    ap.add_argument("--model", default=os.path.join(here, "model.txt"))
    ap.add_argument("--meta", default=os.path.join(here, "model_meta.json"))
    args = ap.parse_args()

    import lightgbm as lgb

    if not os.path.isfile(args.model):
        print(f"找不到模型: {args.model}（先跑 train.py）")
        return
    # 用 Python 文件 I/O 读模型（避免 LightGBM 原生读在含中文路径上失败）
    with open(args.model, "r", encoding="utf-8") as mf:
        booster = lgb.Booster(model_str=mf.read())

    thr = 0.5
    meta = {}
    if os.path.isfile(args.meta):
        with open(args.meta, "r", encoding="utf-8") as f:
            meta = json.load(f)
        thr = float(meta.get("chosen_threshold", 0.5))

    data = read_zip_sample(args.path) if args.zip else open(args.path, "rb").read()
    ex = PEFeatureExtractor()
    vec = ex.feature_vector(data).reshape(1, -1)

    if meta.get("feature_dim") and vec.shape[1] != meta["feature_dim"]:
        print(f"[警告] 特征维度不符: 当前 {vec.shape[1]} vs 模型 {meta['feature_dim']}")

    prob = float(booster.predict(vec)[0])
    verdict = "MALICIOUS" if prob >= thr else "benign"
    print(f"文件      : {args.path}")
    print(f"恶意概率  : {prob:.4f}")
    print(f"判定阈值  : {thr:.4f}  (target_fpr={meta.get('target_fpr')})")
    print(f"结论      : {verdict}")


if __name__ == "__main__":
    main()

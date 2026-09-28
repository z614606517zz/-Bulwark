"""
用 LightGBM 训练静态 PE 恶意/良性二分类器。

- 读 extract_features.py 产出的 features.npz
- 分层 K 折交叉验证，报 ROC-AUC / PR-AUC
- 在全量上训练最终模型，按【目标误报率 FPR】挑阈值（杀软最看重低误报）
- 导出模型(.txt LightGBM 原生格式，便于 C++ 侧加载) + 元数据(阈值/维度/指标)

用法:
  python train.py                       # 用 features.npz
  python train.py --features features.npz --target-fpr 0.001
"""

import argparse
import hashlib
import json
import os
import sys
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, OSError):
    pass


def load(features_path):
    d = np.load(features_path, allow_pickle=True)
    X = d["X"].astype(np.float32)
    y = d["y"].astype(np.int32)
    fam = d["family"] if "family" in d else np.array([""] * len(y))
    pe_type = d["pe_type"] if "pe_type" in d else np.array([""] * len(y))
    first_seen = (d["first_seen"].astype(np.int64) if "first_seen" in d
                  else np.zeros(len(y), dtype=np.int64))
    if "feature_names" in d:
        names = [str(x) for x in list(d["feature_names"])]
    else:
        try:
            from pe_features import feature_names
            names = feature_names()
            if len(names) != X.shape[1]:
                names = ["f%d" % i for i in range(X.shape[1])]
        except Exception:
            names = ["f%d" % i for i in range(X.shape[1])]
    return X, y, fam, names, pe_type, first_seen


def make_splits(X, y, fam, first_seen, folds, mode, seed=42):
    """产出 (train_idx, valid_idx) 列表。

    切分方式是这份脚本最要命的地方，比任何超参都重要：

    random  —— 曾经的默认，【不要用】。恶意样本同族近似重复极多（一个家族几十个
        变种只差几个字节），随机切会把同族变种分到训练集和验证集两边，模型只要
        记住这个家族就能全对，测出来 AUC 0.99 全是泄漏，上线原地爆炸。
    group   —— 默认。按 family 分组，同一家族只可能整体落在一侧。良性侧的 family
        字段装的是厂商/来源包，所以同一个 wheel 里的几十个 .pyd 也会被绑在一起，
        同样防住"同包近似重复"。
    time    —— 更接近线上真实处境：拿旧样本训、新样本测，衡量的是对【没见过的新
        家族】的泛化。恶意侧按 first_seen 排序取最新一段做验证；良性侧没有可信
        时间轴，按哈希稳定分配，比例与恶意侧一致。
    """
    from sklearn.model_selection import (StratifiedKFold, StratifiedGroupKFold)

    if mode == "random":
        print("[!] 用随机切分。同族近似重复会跨集泄漏，指标会虚高，只适合冒烟。")
        skf = StratifiedKFold(n_splits=folds, shuffle=True, random_state=seed)
        return list(skf.split(X, y))

    if mode == "time":
        pos = np.where(y == 1)[0]
        neg = np.where(y == 0)[0]
        # 恶意侧按时间排序；没有 first_seen 的排在最前(当作最旧)
        order = pos[np.argsort(first_seen[pos], kind="stable")]
        splits = []
        for k in range(folds):
            lo = int(len(order) * k / folds)
            hi = int(len(order) * (k + 1) / folds)
            va_pos = order[lo:hi]
            tr_pos = np.concatenate([order[:lo], order[hi:]])
            # 良性侧没有时间轴：用 sha 的稳定哈希分桶，避免每折随机重排
            h = np.array([int(hashlib.sha1(str(i).encode()).hexdigest()[:8], 16)
                          % folds for i in neg])
            va_neg = neg[h == k]
            tr_neg = neg[h != k]
            splits.append((np.concatenate([tr_pos, tr_neg]),
                           np.concatenate([va_pos, va_neg])))
        return splits

    # group
    groups = np.array([f if f else "(unknown)" for f in fam])
    n_g = len(set(groups))
    if n_g < folds * 2:
        print(f"[!] 分组数只有 {n_g}，不够做 {folds} 折分组切分，退回分层切分。")
        skf = StratifiedKFold(n_splits=folds, shuffle=True, random_state=seed)
        return list(skf.split(X, y))
    sgk = StratifiedGroupKFold(n_splits=folds, shuffle=True, random_state=seed)
    return list(sgk.split(X, y, groups=groups))


def pick_threshold(y_true, scores, target_fpr):
    """在给定目标 FPR 下，选满足 FPR<=target 的最低分数阈值（尽量高召回）。"""
    order = np.argsort(-scores)
    y_sorted = y_true[order]
    s_sorted = scores[order]
    n_neg = max(int((y_true == 0).sum()), 1)
    fp = 0
    best_thr = 1.0
    for i in range(len(s_sorted)):
        if y_sorted[i] == 0:
            fp += 1
        if fp / n_neg > target_fpr:
            best_thr = s_sorted[i] + 1e-9
            break
    else:
        best_thr = float(s_sorted[-1])
    return float(best_thr)


def metrics_at(y_true, scores, thr):
    pred = (scores >= thr).astype(int)
    tp = int(((pred == 1) & (y_true == 1)).sum())
    fp = int(((pred == 1) & (y_true == 0)).sum())
    tn = int(((pred == 0) & (y_true == 0)).sum())
    fn = int(((pred == 0) & (y_true == 1)).sum())
    tpr = tp / max(tp + fn, 1)   # 召回/检出率
    fpr = fp / max(fp + tn, 1)   # 误报率
    prec = tp / max(tp + fp, 1)
    return dict(threshold=thr, detection_tpr=tpr, false_positive_rate=fpr,
                precision=prec, tp=tp, fp=fp, tn=tn, fn=fn)


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser()
    ap.add_argument("--features", default=os.path.join(here, "features.npz"))
    ap.add_argument("--out-model", default=os.path.join(here, "model.txt"))
    ap.add_argument("--out-meta", default=os.path.join(here, "model_meta.json"))
    ap.add_argument("--folds", type=int, default=5)
    ap.add_argument("--target-fpr", type=float, default=0.001, help="挑阈值的目标误报率")
    ap.add_argument("--rounds", type=int, default=800)
    # 可调正则(小数据集用更小的树防过拟合;默认沿用静态模型的值,向后兼容)
    ap.add_argument("--num-leaves", type=int, default=128)
    ap.add_argument("--min-data-in-leaf", type=int, default=32)
    ap.add_argument("--feature-fraction", type=float, default=0.7)
    ap.add_argument("--learning-rate", type=float, default=0.05)
    ap.add_argument("--split", default="group", choices=["group", "time", "random"],
                    help="切分方式。group=按家族/厂商分组(默认)，"
                         "time=按首见时间，random=随机(会泄漏,仅冒烟)")
    args = ap.parse_args()

    import lightgbm as lgb
    from sklearn.metrics import roc_auc_score, average_precision_score

    d_probe = np.load(args.features, allow_pickle=True)
    SCHEMA_VER = int(d_probe["schema_ver"][0]) if "schema_ver" in d_probe else 0
    del d_probe

    X, y, fam, feat_names, pe_type, first_seen = load(args.features)
    n_pos = int((y == 1).sum()); n_neg = int((y == 0).sum())
    print(f"数据: X{X.shape}  良性 {n_neg} / 恶意 {n_pos}")
    print(f"切分: {args.split}")

    # 负样本太少就没法测低误报率：要在 FPR=0.1% 上看到 1 个误报，验证集里
    # 至少得有 1000 个负样本。样本不够时把这一点说清楚，而不是报一个测不准的数。
    n_neg_va = n_neg // max(args.folds, 1)
    min_fpr = 1.0 / max(n_neg_va, 1)
    if args.target_fpr < min_fpr:
        print(f"[!] 每折验证集只有约 {n_neg_va} 个良性样本，能分辨的最小 FPR 约为"
              f" {min_fpr:.4f}（{min_fpr*100:.2f}%）。")
        print(f"    你要求的 target-fpr={args.target_fpr} 低于这个下限，"
              f"报出来的误报率不可信。要么补良性样本，要么放宽目标。")
    if n_pos < 10 or n_neg < 10:
        print("样本太少，无法可靠训练（每类至少几十个）。先多抽点样本。")
        # 仍继续尝试，便于冒烟

    # 类不均衡 -> scale_pos_weight
    spw = max(n_neg / max(n_pos, 1), 1.0)
    params = dict(
        objective="binary", metric=["auc"], learning_rate=args.learning_rate,
        num_leaves=args.num_leaves, min_data_in_leaf=args.min_data_in_leaf,
        feature_fraction=args.feature_fraction,
        bagging_fraction=0.8, bagging_freq=1, max_depth=-1,
        scale_pos_weight=spw, verbose=-1, n_jobs=-1,
    )

    # ---- 交叉验证 ----
    folds = min(args.folds, n_pos, n_neg)
    oof = np.zeros(len(y), dtype=np.float64)
    covered = np.zeros(len(y), dtype=bool)
    if folds >= 2:
        splits = make_splits(X, y, fam, first_seen, folds, args.split)
        for k, (tr, va) in enumerate(splits, 1):
            if len(va) == 0 or len(set(y[tr])) < 2:
                print(f"  fold {k}/{folds}  跳过(某一侧为空)")
                continue
            dtr = lgb.Dataset(X[tr], label=y[tr])
            dva = lgb.Dataset(X[va], label=y[va], reference=dtr)
            booster = lgb.train(params, dtr, num_boost_round=args.rounds,
                                valid_sets=[dva],
                                callbacks=[lgb.early_stopping(50, verbose=False),
                                           lgb.log_evaluation(0)])
            oof[va] = booster.predict(X[va], num_iteration=booster.best_iteration)
            covered[va] = True
            print(f"  fold {k}/{folds}  train={len(tr)} valid={len(va)}"
                  f"  valid恶意={int((y[va]==1).sum())}"
                  f"  best_iter={booster.best_iteration}")
        # 分组切分下并非每个样本都恰好被覆盖一次，只在覆盖到的样本上算指标
        yv, ov = y[covered], oof[covered]
        if len(set(yv)) < 2:
            auc = ap_ = float("nan"); thr = 0.5; m = {}
            print("覆盖到的样本只剩一个类别，无法评估。")
        else:
            auc = roc_auc_score(yv, ov)
            ap_ = average_precision_score(yv, ov)
            print(f"\nCV ROC-AUC={auc:.5f}  PR-AUC={ap_:.5f}"
                  f"  (覆盖 {int(covered.sum())}/{len(y)})")
            thr = pick_threshold(yv, ov, args.target_fpr)
            m = metrics_at(yv, ov, thr)
            print(f"阈值@FPR<= {args.target_fpr}: thr={thr:.4f}  "
                  f"检出率={m['detection_tpr']:.4f}  "
                  f"实际FPR={m['false_positive_rate']:.5f}  "
                  f"(FP={m['fp']}/{m['fp']+m['tn']})")
    else:
        auc = ap_ = float("nan"); thr = 0.5; m = {}
        print("折数不足，跳过交叉验证。")

    # ---- 全量训练最终模型 ----
    dall = lgb.Dataset(X, label=y)
    final = lgb.train(params, dall, num_boost_round=args.rounds,
                      callbacks=[lgb.log_evaluation(0)])
    # 用 Python 文件 I/O 写模型（LightGBM 原生 save_model 在含中文的路径上会失败）
    model_str = final.model_to_string(num_iteration=(final.best_iteration or args.rounds))
    with open(args.out_model, "w", encoding="utf-8") as mf:
        mf.write(model_str)

    # ---- 特征重要度(gain)：用于核验模型是否靠真实行为、而非某个捷径特征 ----
    try:
        imp = final.feature_importance(importance_type="gain")
        order = np.argsort(-imp)
        top_features = [[feat_names[i], round(float(imp[i]), 2)] for i in order[:30] if imp[i] > 0]
        print("Top 特征(gain):")
        for nm, g in top_features[:20]:
            print(f"  {nm:30s} {g}")
    except Exception as e:
        top_features = []
        print("特征重要度计算失败:", e)

    # pe_type 分布必须记进元数据：它是这套数据最容易被走捷径的一维，
    # 后来的人看到指标时得能立刻判断这个模型是不是只学会了区分 EXE/DLL。
    pt_mix = {}
    for t in sorted(set(pe_type.tolist())):
        pt_mix[str(t)] = {
            "malicious": int(((pe_type == t) & (y == 1)).sum()),
            "benign": int(((pe_type == t) & (y == 0)).sum()),
        }

    meta = dict(
        schema_ver=int(SCHEMA_VER) if SCHEMA_VER else None,
        feature_dim=int(X.shape[1]),
        n_benign=n_neg, n_malicious=n_pos,
        split=args.split,
        n_groups=int(len(set(fam.tolist()))),
        pe_type_mix=pt_mix,
        min_measurable_fpr=float(min_fpr),
        scale_pos_weight=spw, target_fpr=args.target_fpr,
        chosen_threshold=float(thr),
        cv_roc_auc=None if np.isnan(auc) else float(auc),
        cv_pr_auc=None if np.isnan(ap_) else float(ap_),
        cv_metrics_at_threshold=m,
        lightgbm_params=params,
        top_features=top_features,
    )
    with open(args.out_meta, "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)
    print(f"模型 -> {args.out_model}")
    print(f"元数据 -> {args.out_meta}")


if __name__ == "__main__":
    main()

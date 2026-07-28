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
import json
import os
import numpy as np


def load(features_path):
    d = np.load(features_path, allow_pickle=True)
    X = d["X"].astype(np.float32)
    y = d["y"].astype(np.int32)
    fam = d["family"] if "family" in d else np.array([""] * len(y))
    if "feature_names" in d:
        names = [str(x) for x in list(d["feature_names"])]
    else:
        names = ["f%d" % i for i in range(X.shape[1])]
    return X, y, fam, names


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
    args = ap.parse_args()

    import lightgbm as lgb
    from sklearn.model_selection import StratifiedKFold
    from sklearn.metrics import roc_auc_score, average_precision_score

    X, y, fam, feat_names = load(args.features)
    n_pos = int((y == 1).sum()); n_neg = int((y == 0).sum())
    print(f"数据: X{X.shape}  良性 {n_neg} / 恶意 {n_pos}")
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
    if folds >= 2:
        skf = StratifiedKFold(n_splits=folds, shuffle=True, random_state=42)
        for k, (tr, va) in enumerate(skf.split(X, y), 1):
            dtr = lgb.Dataset(X[tr], label=y[tr])
            dva = lgb.Dataset(X[va], label=y[va], reference=dtr)
            booster = lgb.train(params, dtr, num_boost_round=args.rounds,
                                valid_sets=[dva],
                                callbacks=[lgb.early_stopping(50, verbose=False),
                                           lgb.log_evaluation(0)])
            oof[va] = booster.predict(X[va], num_iteration=booster.best_iteration)
            print(f"  fold {k}/{folds}  best_iter={booster.best_iteration}")
        auc = roc_auc_score(y, oof) if n_pos and n_neg else float("nan")
        ap_ = average_precision_score(y, oof) if n_pos and n_neg else float("nan")
        print(f"CV ROC-AUC={auc:.5f}  PR-AUC={ap_:.5f}")
        thr = pick_threshold(y, oof, args.target_fpr)
        m = metrics_at(y, oof, thr)
        print(f"阈值@FPR<= {args.target_fpr}: thr={thr:.4f}  "
              f"检出率={m['detection_tpr']:.4f}  实际FPR={m['false_positive_rate']:.5f}")
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

    meta = dict(
        feature_dim=int(X.shape[1]),
        n_benign=n_neg, n_malicious=n_pos,
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

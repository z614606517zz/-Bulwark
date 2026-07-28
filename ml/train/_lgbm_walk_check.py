# -*- coding: utf-8 -*-
"""验证 C++ 侧的 LightGBM 文本推理算法:用纯 Python 复刻同一套树遍历(数值<=、叶子= -child-1、
Σleaf_value 后 sigmoid),与 lightgbm 官方 predict 对比。匹配则证明 C++ BehaviorModel 逻辑正确。"""
import math, re, os
import numpy as np
import lightgbm as lgb

HERE = os.path.dirname(os.path.abspath(__file__))
MODEL = os.path.join(HERE, 'behavior_model_v1.txt')
NPZ = os.path.join(HERE, 'behavior_gran_features.npz')


def parse_trees(path):
    trees = []
    cur = None
    sigmoid = 1.0
    with open(path, encoding='utf-8') as f:
        for raw in f:
            line = raw.strip()
            if not line:
                continue
            if line.startswith('Tree='):
                if cur:
                    trees.append(cur)
                cur = {}
                continue
            if cur is None:
                if line.startswith('objective='):
                    m = re.search(r'sigmoid:([0-9.]+)', line)
                    if m:
                        sigmoid = float(m.group(1))
                continue
            if line.startswith('split_feature='):
                cur['sf'] = [int(x) for x in line[14:].split()]
            elif line.startswith('threshold='):
                cur['th'] = [float(x) for x in line[10:].split()]
            elif line.startswith('left_child='):
                cur['lc'] = [int(x) for x in line[11:].split()]
            elif line.startswith('right_child='):
                cur['rc'] = [int(x) for x in line[12:].split()]
            elif line.startswith('leaf_value='):
                cur['lv'] = [float(x) for x in line[11:].split()]
            elif line.startswith(('feature_importances', 'parameters:', 'end of trees')):
                if cur:
                    trees.append(cur); cur = None
                break
    if cur and 'lv' in cur:
        trees.append(cur)
    # keep only complete trees
    trees = [t for t in trees if all(k in t for k in ('sf', 'th', 'lc', 'rc', 'lv'))]
    return trees, sigmoid


def walk_raw(trees, x):
    raw = 0.0
    for t in trees:
        node = 0
        while node >= 0:
            fi = t['sf'][node]
            v = float(x[fi]) if fi < len(x) else 0.0
            nxt = t['lc'][node] if v <= t['th'][node] else t['rc'][node]
            if nxt < 0:
                raw += t['lv'][-nxt - 1]
                break
            node = nxt
    return raw


trees, sigmoid = parse_trees(MODEL)
print('parsed trees:', len(trees), ' sigmoid factor:', sigmoid)

d = np.load(NPZ, allow_pickle=True)
X = d['X'].astype(np.float32)
y = d['y'].astype(np.int32)

booster = lgb.Booster(model_str=open(MODEL, encoding='utf-8').read())  # 避开 LightGBM C 库的中文路径 bug
lgb_prob = booster.predict(X)
lgb_raw = booster.predict(X, raw_score=True)

# compare on a spread of rows
idxs = [0, 1, 2, 100, 300, 500, 700, 857, len(X) // 2]
max_raw_err = 0.0
max_prob_err = 0.0
print('%5s %6s | %12s %12s | %10s %10s' % ('row', 'label', 'my_raw', 'lgb_raw', 'my_prob', 'lgb_prob'))
for i in idxs:
    mr = walk_raw(trees, X[i])
    mp = 1.0 / (1.0 + math.exp(-sigmoid * mr))
    re_ = abs(mr - lgb_raw[i])
    pe_ = abs(mp - lgb_prob[i])
    max_raw_err = max(max_raw_err, re_)
    max_prob_err = max(max_prob_err, pe_)
    print('%5d %6d | %12.6f %12.6f | %10.6f %10.6f' % (i, y[i], mr, lgb_raw[i], mp, lgb_prob[i]))

# full-set check
all_my = np.array([1.0 / (1.0 + math.exp(-sigmoid * walk_raw(trees, X[i]))) for i in range(len(X))])
full_max = float(np.max(np.abs(all_my - lgb_prob)))
print('---')
print('sampled max raw err : %.3e' % max_raw_err)
print('sampled max prob err: %.3e' % max_prob_err)
print('FULL-SET max prob err (all %d rows): %.3e' % (len(X), full_max))
print('PARITY OK' if full_max < 1e-6 else 'MISMATCH!!')

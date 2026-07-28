#!/usr/bin/env python3
# Characterize what the behavior model learned: top features by gain, grouped.
import json, os, collections
import lightgbm as lgb

here = os.path.dirname(os.path.abspath(__file__))
spec = json.load(open(os.path.join(here, 'behavior_feature_spec.json'), encoding='utf-8'))
names = spec['feature_names']
with open(os.path.join(here, 'model_behavior.txt'), encoding='utf-8') as mf:
    model_str = mf.read()
bst = lgb.Booster(model_str=model_str)
gain = bst.feature_importance(importance_type='gain')
split = bst.feature_importance(importance_type='split')

pairs = sorted(zip(names, gain, split), key=lambda x: -x[1])
tot = sum(gain) or 1.0

def group(n):
    if n.startswith('sbx_cls_'): return 'sandbox_class'
    if n.startswith('sbx_'): return 'sandbox_verdict'
    if n.startswith('sigma_'): return 'sigma_rules'
    if n.startswith('ids_'): return 'network_ids'
    if n.startswith('tag_'): return 'behavior_tag'
    if n in ('yara_count',): return 'yara'
    return 'community/meta'

grp = collections.Counter()
for n, g, s in pairs:
    grp[group(n)] += g

print('=== gain share by feature GROUP ===')
for k, v in sorted(grp.items(), key=lambda x: -x[1]):
    print(f'  {v/tot*100:5.1f}%   {k}')

print('\n=== top 25 features by gain ===')
for n, g, s in pairs[:25]:
    print(f'  {g/tot*100:5.1f}%  splits={int(s):4d}  {n}')

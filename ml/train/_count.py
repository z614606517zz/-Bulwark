import os, json, time
base = r"d:\新建文件夹 (3)\ml\data\vt"

def stat(fn):
    p = os.path.join(base, fn)
    if not os.path.exists(p):
        return None
    for attempt in range(4):
        total = hit = 0
        try:
            with open(p, encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    total += 1
                    try:
                        o = json.loads(line)
                    except Exception:
                        continue
                    if fn.startswith('mb'):
                        if o.get('query_status') == 'ok':
                            hit += 1
                    else:
                        if int(o.get('http', 0) or 0) == 200:
                            hit += 1
            return total, hit
        except Exception:
            time.sleep(0.4)
    return total, hit  # best-effort partial

print(time.strftime('%H:%M:%S'))
for fn in ('vt_results.jsonl', 'mb_results.jsonl'):
    s = stat(fn)
    print(f'  {fn}: (missing)' if s is None else f'  {fn}: total={s[0]} hit={s[1]}')

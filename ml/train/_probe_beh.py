import os, sys, traceback
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import vt_enrich as ve

outp = os.path.join(os.path.dirname(os.path.abspath(__file__)), '_beh_probe_result.txt')
lines = []
try:
    keys = ve.load_keys()
    lines.append('keys loaded: %d' % len(keys))
    h = '81c589fae253795f2a6625709d192409df2349b929b3ea692b8ea3af08767ffd'
    tested_beh = False
    for i, k in enumerate(keys):
        c1, b1 = ve.curl_get('https://www.virustotal.com/api/v3/files/' + h, k, 15)
        lines.append('key#%d /files HTTP %s' % (i, c1))
        if c1 == 200 and not tested_beh:
            # same healthy key -> test behaviour_summary definitively
            c2, b2 = ve.curl_get('https://www.virustotal.com/api/v3/files/%s/behaviour_summary' % h, k, 15)
            lines.append('  >>> key#%d /behaviour_summary HTTP %s' % (i, c2))
            lines.append('  >>> body: ' + (b2 or '')[:900].replace('\n', ' '))
            tested_beh = True
            break
    if not tested_beh:
        lines.append('NO healthy key found (all quota/rate limited) - cannot conclude premium-gating')
except Exception:
    lines.append('EXC: ' + traceback.format_exc())

with open(outp, 'w', encoding='utf-8') as f:
    f.write('\n'.join(lines))
print('wrote', outp)

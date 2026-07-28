import numpy as np, os
here = r"d:\新建文件夹 (3)\ml\train"
for fn in ["features_v2.npz", "features_v2_clean.npz", "script_features.npz"]:
    p = os.path.join(here, fn)
    if not os.path.isfile(p):
        print(fn, "MISSING"); continue
    d = np.load(p, allow_pickle=True)
    y = d["y"]; fd = d["feature_dim"][0] if "feature_dim" in d else "?"
    print(f"{fn}: N={len(y)} benign={(y==0).sum()} malicious={(y==1).sum()} dim={fd}")
bd = r"d:\新建文件夹 (3)\ml\data\benign"
print("benign corpus dir exists:", os.path.isdir(bd))

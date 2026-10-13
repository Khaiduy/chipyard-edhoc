#!/usr/bin/env python3
"""perf_table.py <logdir>: one Markdown table (ms) of the per-message handshake
steps from TIMING=1 board logs, <run>.ini.log / <run>.res.log per pair
(s<suite>_m<method>, akTBD1..3), as the sweep scripts name them.
I = initiator, R = responder."""
import re, sys, os
D = sys.argv[1]
def perf(path):
    out = {}
    for l in open(path, errors="ignore"):
        m = re.match(r"PERF (\S+)\s+(\d+) cyc ([\d.]+) s(?: (\d+) bytes (\d+) B/s)?", l.strip())
        if m:
            out.setdefault(m.group(1), (int(m.group(2)), float(m.group(3)), m.group(5)))
    return out
rows = [f"s{s}_m{m}" for s in (0, 1, 2, 3, 4, 5, 6, 24, 25) for m in (0, 1, 2, 3)] + ["akTBD1", "akTBD2", "akTBD3"]
ms = lambda d, k: f"{d[k][1]*1000:.1f}" if k in d else "-"
print("| run | I keygen | I m1 build | R m1 proc+m2 build | I m2 proc | I m3 build | R m3 proc | I m4 proc | R m4 build | I m5 build | R m5 proc | I hs total | I compute |")
print("|" + "---|" * 13)
for r in rows:
    fi, fr = f"{D}/{r}.ini.log", f"{D}/{r}.res.log"
    if not (os.path.exists(fi) and os.path.exists(fr)):
        continue
    i, s = perf(fi), perf(fr)
    m2 = s.get("msg2_build")
    if r.startswith("ak"):   # AuthKEM: responder has separate msg1_process
        r_m2 = f"{(s['msg1_process'][1]+s['msg2_build'][1])*1000:.1f}" if "msg1_process" in s and m2 else "-"
    else:
        r_m2 = ms(s, "msg2_build")
    print(f"| {r} | {ms(i,'keygen')} | {ms(i,'msg1_build')} | {r_m2} | {ms(i,'msg2_process')} | {ms(i,'msg3_build')} | "
          f"{ms(s,'msg3_process')} | {ms(i,'msg4_process')} | {ms(s,'msg4_build')} | {ms(i,'msg5_build')} | {ms(s,'msg5_process')} | "
          f"{ms(i,'handshake_total')} | {ms(i,'handshake_compute')} |")

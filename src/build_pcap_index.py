from pathlib import Path
from collections import Counter, defaultdict
import pandas as pd
from scapy.all import RawPcapReader, RadioTap, Dot11

ROOT = Path(__file__).resolve().parent.parent
BASE = (Path.home() / "Downloads" / "WPA3 Attacks Dataset" / "WPA3 Attacks Dataset"
        / "WPA3 Denial of Service attacks" / "Deauthentication attack")
CSV, PCAP = BASE / "Deauth.csv", BASE / "Deauth.pcap"
OUT = ROOT / "outputs" / "deauth_pairs.csv"

# The CSV tells us the second of every packet AND which packets are deauth frames,
# in the same order as the PCAP, so we only decode the deauth ones.
df = pd.read_csv(CSV, usecols=["frame.time_epoch", "wlan.fc.type_subtype"])
secs = df["frame.time_epoch"].to_numpy()
is_deauth = (pd.to_numeric(df["wlan.fc.type_subtype"], errors="coerce") == 12).to_numpy()
print("Deauth frames expected:", int(is_deauth.sum()))

counts = Counter()
rssi_sum = defaultdict(float)
rssi_n = Counter()
done = 0

with RawPcapReader(str(PCAP)) as reader:          # reads raw bytes, no decoding
    for i, (raw, meta) in enumerate(reader):
        if i % 100000 == 0:
            print(f"  read {i} packets...")
        if not is_deauth[i]:
            continue
        pkt = RadioTap(raw)                        # decode only the deauth frames
        if not pkt.haslayer(Dot11):
            continue
        d = pkt[Dot11]
        key = (int(secs[i]), d.addr2, d.addr1)     # (second, sender, receiver)
        counts[key] += 1
        sig = getattr(pkt, "dBm_AntSignal", None)
        if sig is not None:
            rssi_sum[key] += sig
            rssi_n[key] += 1
        done += 1

rows = []
for key, n in counts.items():
    sec, src, dst = key
    mean_rssi = rssi_sum[key] / rssi_n[key] if rssi_n[key] else None
    rows.append({"second": sec, "src": src, "dst": dst, "frames": n, "mean_rssi": mean_rssi})

pairs = pd.DataFrame(rows).sort_values(["second", "frames"], ascending=[True, False])
pairs.to_csv(OUT, index=False)
print("Deauth frames indexed:", done)
print("Saved", OUT, "with", len(pairs), "rows")
print(pairs.head(10))
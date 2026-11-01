import argparse
import time
from datetime import datetime
from pathlib import Path
import joblib
import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
PROTECTED_AP = "02:00:00:00:00:cb"     # the lab AP: it is the BSSID in every deauth frame

parser = argparse.ArgumentParser()
parser.add_argument("--all", action="store_true",
                    help="replay the whole capture instead of only the unseen test part")
parser.add_argument("--delay", type=float, default=0.05,
                    help="seconds to wait between replayed seconds (slower looks better in a demo)")
args = parser.parse_args()

# --- load the trained model, the per-second features and the PCAP index ---
bundle = joblib.load(ROOT / "outputs" / "model_A_all_features.joblib")
model, cols = bundle["model"], bundle["features"]
feat = pd.read_csv(ROOT / "outputs" / "features.csv", index_col="second")
pairs = pd.read_csv(ROOT / "outputs" / "deauth_pairs.csv")

if not args.all:                                   # same unseen 30% the model was tested on
    feat = feat.iloc[int(len(feat) * 0.7):]

alert_log = ROOT / "outputs" / "alerts.log"
blocklist = ROOT / "outputs" / "wips_blocklist.csv"
alert_log.write_text("")
blocklist.write_text("time,mac,role,frames,action\n")

logged_macs = set()
in_attack = False
tp = fp = fn = tn = 0

print(f"Replaying {len(feat)} seconds of traffic...\n")
for sec, row in feat.iterrows():
    t = datetime.fromtimestamp(sec).strftime("%H:%M:%S")
    pred = int(model.predict(feat.loc[[sec], cols])[0])     # 1 = attack, 0 = normal
    actual = int(row["label"])

    tp += pred == 1 and actual == 1
    fp += pred == 1 and actual == 0
    fn += pred == 0 and actual == 1
    tn += pred == 0 and actual == 0

    if pred == 1:
        # Which addresses sent the deauth frames in this second? (from the PCAP index)
        now = pairs[pairs["second"] == sec].groupby("src")["frames"].sum().sort_values(ascending=False)
        top_src = now.index[0] if len(now) else "unknown"
        top_n = int(now.iloc[0]) if len(now) else 0

        if not in_attack:
            msg = (f"[{t}] ALERT: deauthentication flood detected "
                   f"({int(row['deauth_count'])} deauth frames/s, signal {row['mean_rssi']:.0f} dBm)")
            print(msg)
            alert_log.write_text(alert_log.read_text() + msg + "\n")
            in_attack = True
        flows = pairs[pairs["second"] == sec].sort_values("frames", ascending=False)
        flow_text = ",  ".join(f"{r.src[-2:]} -> {r.dst[-2:]}: {int(r.frames)}"
                               for r in flows.itertuples())
        print(f"[{t}]   deauth flows (last MAC byte): {flow_text}")

        # WIPS action: log the offending MAC the first time it is seen
        if top_src not in logged_macs and top_src != "unknown":
            role = "protected AP (address is probably spoofed)" if top_src == PROTECTED_AP else "client/unknown"
            with open(blocklist, "a") as f:
                f.write(f"{t},{top_src},{role},{top_n},LOGGED\n")
            print(f"[{t}]   WIPS: logged {top_src} ({role})")
            logged_macs.add(top_src)
    else:
        if in_attack:
            print(f"[{t}] Attack no longer detected - traffic back to normal")
            in_attack = False
        else:
            print(f"[{t}] normal  ({int(row['frames_per_sec'])} frames/s)")
    time.sleep(args.delay)

print("\n--- Replay summary ---")
print(f"Seconds replayed: {len(feat)}")
print(f"Attack seconds caught: {tp}   missed: {fn}   false alarms: {fp}   correct normal: {tn}")
print("Alert log:", alert_log)
print("WIPS log: ", blocklist)
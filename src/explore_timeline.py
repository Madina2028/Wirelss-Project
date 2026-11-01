from pathlib import Path
import pandas as pd

CSV = (Path.home() / "Downloads" / "WPA3 Attacks Dataset" / "WPA3 Attacks Dataset"
       / "WPA3 Denial of Service attacks" / "Deauthentication attack" / "Deauth.csv")

cols = ["frame.time_epoch", "frame.len", "radiotap.dbm_antsignal",
        "wlan.fc.type_subtype", "wlan.fixed.reason_code", "Label"]
df = pd.read_csv(CSV, usecols=cols, low_memory=False)

# Make sure signal strength is numeric (bad values become NaN)
df["radiotap.dbm_antsignal"] = pd.to_numeric(df["radiotap.dbm_antsignal"], errors="coerce")
df["is_deauth"] = (df["wlan.fc.type_subtype"] == 12).astype(int)

# ---- One row per second ----
per_sec = df.groupby("frame.time_epoch").agg(
    frames=("is_deauth", "size"),
    deauth=("is_deauth", "sum"),
    mean_rssi=("radiotap.dbm_antsignal", "mean"),
    mean_len=("frame.len", "mean"),
)
print("Seconds in capture:", len(per_sec))
print("Seconds with at least 1 deauth frame:", (per_sec["deauth"] > 0).sum())
print("\nFrames per second, normal-only seconds vs attack seconds:")
print(per_sec.groupby(per_sec["deauth"] > 0)[["frames", "mean_rssi", "mean_len"]].describe().T)

print("\nDeauth frames per second (only seconds that have any):")
print(per_sec.loc[per_sec["deauth"] > 0, "deauth"].describe())

# ---- Timeline in 30-second blocks, to see WHERE the attack happens ----
start = per_sec.index.min()
block = ((per_sec.index - start) // 30) * 30
print("\nDeauth frames per 30-second block (seconds since start):")
print(per_sec.groupby(block)["deauth"].sum())

# ---- What do deauth frames look like vs the rest? ----
print("\nReason codes on deauth frames:")
print(df.loc[df["is_deauth"] == 1, "wlan.fixed.reason_code"].value_counts().head(5))
print("\nMean frame length: deauth vs others")
print(df.groupby("is_deauth")["frame.len"].mean())
print("\nMean signal (dBm): deauth vs others")
print(df.groupby("is_deauth")["radiotap.dbm_antsignal"].mean())
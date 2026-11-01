from pathlib import Path
import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
CSV = (Path.home() / "Downloads" / "WPA3 Attacks Dataset" / "WPA3 Attacks Dataset"
       / "WPA3 Denial of Service attacks" / "Deauthentication attack" / "Deauth.csv")
OUT = ROOT / "outputs" / "features.csv"

cols = ["frame.time_epoch", "frame.len", "radiotap.dbm_antsignal",
        "wlan.fc.type_subtype", "wlan.fc.retry", "Label"]
df = pd.read_csv(CSV, usecols=cols, low_memory=False)

# --- clean and label each frame ---
df["rssi"] = pd.to_numeric(df["radiotap.dbm_antsignal"], errors="coerce")
df["retry"] = pd.to_numeric(df["wlan.fc.retry"], errors="coerce").fillna(0)
sub = pd.to_numeric(df["wlan.fc.type_subtype"], errors="coerce")

df["is_deauth"] = (sub == 12).astype(int)            # deauthentication frame
df["is_mgmt"] = (sub < 16).astype(int)               # management frames
df["is_ctrl"] = ((sub >= 16) & (sub < 32)).astype(int)  # control frames
df["is_data"] = ((sub >= 32) & (sub < 48)).astype(int)  # data frames
df["is_attack"] = (df["Label"] != "Normal").astype(int)

# --- collapse 722,606 frames into one row per second ---
g = df.groupby("frame.time_epoch")
feat = pd.DataFrame({
    "frames_per_sec": g.size(),
    "mean_len": g["frame.len"].mean(),
    "std_len": g["frame.len"].std(),
    "mean_rssi": g["rssi"].mean(),
    "std_rssi": g["rssi"].std(),
    "frac_mgmt": g["is_mgmt"].mean(),
    "frac_ctrl": g["is_ctrl"].mean(),
    "frac_data": g["is_data"].mean(),
    "retry_rate": g["retry"].mean(),
    "deauth_count": g["is_deauth"].sum(),
    "label": g["is_attack"].max(),   # 1 if any frame in that second is labelled attack
})
feat = feat.fillna(feat.median())    # fill any gaps (e.g. std of a single frame)
feat.index.name = "second"

OUT.parent.mkdir(exist_ok=True)
feat.to_csv(OUT)

print("Rows (seconds):", len(feat))
print(feat["label"].value_counts())
print(feat.describe().T[["mean", "min", "max"]])
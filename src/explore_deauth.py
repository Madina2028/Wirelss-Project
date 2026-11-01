from pathlib import Path
import pandas as pd

CSV = (Path.home() / "Downloads" / "WPA3 Attacks Dataset" / "WPA3 Attacks Dataset"
       / "WPA3 Denial of Service attacks" / "Deauthentication attack" / "Deauth.csv")

# Load ONLY the columns we care about (much faster and lighter than all 154)
cols = ["frame.number", "frame.time_epoch", "frame.len",
        "radiotap.dbm_antsignal", "wlan.fc.type", "wlan.fc.subtype",
        "wlan.fc.type_subtype", "wlan.fixed.reason_code", "wlan.seq",
        "wlan.fc.retry", "Label"]
df = pd.read_csv(CSV, usecols=cols, low_memory=False)

print("Rows:", len(df))
print("\nFirst rows of the key columns:")
print(df.head(10))

print("\nLabel counts (how many frames are Normal vs attack):")
print(df["Label"].value_counts())

print("\nFrame type/subtype values seen (raw):")
print(df["wlan.fc.type_subtype"].value_counts().head(15))

print("\nTime range:")
print("start:", df["frame.time_epoch"].min(), " end:", df["frame.time_epoch"].max(),
      " duration (s):", df["frame.time_epoch"].max() - df["frame.time_epoch"].min())

print("\nLabel vs frame subtype (top combinations):")
print(df.groupby(["Label", "wlan.fc.type_subtype"]).size().sort_values(ascending=False).head(15))
from pathlib import Path
import pandas as pd

# Where the Denial-of-Service folder lives on your laptop
DATA_DIR = (Path.home() / "Downloads" / "WPA3 Attacks Dataset"
            / "WPA3 Attacks Dataset" / "WPA3 Denial of Service attacks")

# 1) List every file with its size
print("FILES")
for p in sorted(DATA_DIR.rglob("*")):
    if p.is_file():
        print(f"  {p.relative_to(DATA_DIR)}  ({p.stat().st_size / 1e6:.1f} MB)")

# 2) Peek at the top of every CSV
for csv_file in sorted(DATA_DIR.rglob("*.csv")):
    print("=" * 70)
    print(csv_file.name)
    df = pd.read_csv(csv_file, nrows=5, low_memory=False)
    print("number of columns:", len(df.columns))
    print(list(df.columns))
    print(df.head())
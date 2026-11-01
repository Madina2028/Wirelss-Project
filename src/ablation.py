from pathlib import Path
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                             confusion_matrix, ConfusionMatrixDisplay)

ROOT = Path(__file__).resolve().parent.parent
feat = pd.read_csv(ROOT / "outputs" / "features.csv", index_col="second")

split = int(len(feat) * 0.7)
train, test = feat.iloc[:split], feat.iloc[split:]

ALL = [c for c in feat.columns if c != "label"]
MIX = ["frac_mgmt", "frac_ctrl", "frac_data"]   # frame-type mix (leaks deauth share)
RSSI = ["mean_rssi", "std_rssi"]                 # signal strength (lab-layout artifact)

experiments = {
    "A_all_features": ALL,
    "B_no_deauth_count": [c for c in ALL if c != "deauth_count"],
    "C_no_deauth_no_frame_mix": [c for c in ALL if c not in ["deauth_count"] + MIX],
    "D_also_no_rssi": [c for c in ALL if c not in ["deauth_count"] + MIX + RSSI],
}

results = []

def record(name, y_true, y_pred):
    cm = confusion_matrix(y_true, y_pred)
    results.append({
        "experiment": name,
        "accuracy": accuracy_score(y_true, y_pred),
        "precision": precision_score(y_true, y_pred, zero_division=0),
        "recall": recall_score(y_true, y_pred, zero_division=0),
        "false_alarms": int(cm[0, 1]),
        "missed_attacks": int(cm[1, 0]),
    })
    ConfusionMatrixDisplay(cm, display_labels=["Normal", "Deauth attack"]).plot(cmap="Blues")
    plt.title(name)
    plt.savefig(ROOT / "outputs" / f"cm_{name}.png", dpi=200, bbox_inches="tight")
    plt.close()

# Baseline: a fixed rule with no machine learning
rule_pred = (test["deauth_count"] >= 100).astype(int)
record("Baseline_rule_deauth_ge_100", test["label"], rule_pred)

# Random Forest on each feature set
for name, cols in experiments.items():
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(train[cols], train["label"])
    record(name, test["label"], model.predict(test[cols]))
    print(f"\n{name} - features used: {cols}")
    print(pd.Series(model.feature_importances_, index=cols)
            .sort_values(ascending=False).round(3).to_string())

table = pd.DataFrame(results)
for col in ["accuracy", "precision", "recall"]:
    table[col] = (table[col] * 100).round(2)          # fraction -> percent
table = table.rename(columns={"accuracy": "accuracy_%",
                              "precision": "precision_%",
                              "recall": "recall_%"})
print("\n" + "=" * 70)
print(table.to_string(index=False))
table.to_csv(ROOT / "outputs" / "results_table.csv", index=False)
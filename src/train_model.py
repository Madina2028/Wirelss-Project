from pathlib import Path
import pandas as pd
import joblib
import matplotlib
matplotlib.use("Agg")                 # save images to files, don't pop up windows
import matplotlib.pyplot as plt
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, classification_report,
                             confusion_matrix, ConfusionMatrixDisplay)

ROOT = Path(__file__).resolve().parent.parent
feat = pd.read_csv(ROOT / "outputs" / "features.csv", index_col="second")

# --- chronological split: first 70% of time to train, last 30% to test ---
split = int(len(feat) * 0.7)
train, test = feat.iloc[:split], feat.iloc[split:]
print("Train seconds:", len(train), dict(train["label"].value_counts()))
print("Test seconds: ", len(test),  dict(test["label"].value_counts()))

ALL_FEATURES = [c for c in feat.columns if c != "label"]
NO_DEAUTH_COUNT = [c for c in ALL_FEATURES if c != "deauth_count"]

experiments = {
    "A_all_features": ALL_FEATURES,
    "B_without_deauth_count": NO_DEAUTH_COUNT,
}

for name, cols in experiments.items():
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(train[cols], train["label"])          # learn from the training seconds
    pred = model.predict(test[cols])                # predict the unseen test seconds

    acc = accuracy_score(test["label"], pred)
    print("\n" + "=" * 60)
    print(f"Experiment {name}")
    print(f"Accuracy: {acc * 100:.2f}%")
    report = classification_report(test["label"], pred,
        target_names=["Normal", "Deauth attack"],
        output_dict=True)
    for label in ["Normal", "Deauth attack"]:
        r = report[label]
    print(f"{label:14s} precision {r['precision']*100:6.2f}%   "
    f"recall {r['recall']*100:6.2f}%   f1 {r['f1-score']*100:6.2f}%   "
    f"(n={int(r['support'])})")

    cm = confusion_matrix(test["label"], pred)
    print("Confusion matrix (rows = actual, columns = predicted):")
    print(cm)

    ConfusionMatrixDisplay(cm, display_labels=["Normal", "Deauth attack"]).plot(cmap="Blues")
    plt.title(f"Confusion matrix - {name} (accuracy {acc:.3f})")
    plt.savefig(ROOT / "outputs" / f"confusion_{name}.png", dpi=200, bbox_inches="tight")
    plt.close()

    importances = pd.Series(model.feature_importances_, index=cols).sort_values(ascending=False)
    print("Feature importance:")
    print(importances.round(3))

    joblib.dump({"model": model, "features": cols},
                ROOT / "outputs" / f"model_{name}.joblib")
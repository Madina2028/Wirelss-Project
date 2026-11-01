# ML-Based Wireless Intrusion Detection System (WIDS) for Deauthentication Floods

A small prototype that reads 802.11 (Wi-Fi) traffic, turns it into simple per-second features, and uses a scikit-learn Random Forest to label each second as **normal** or **deauthentication flood**. When it detects a flood it raises an alert and logs the source MAC address seen in the attack frames (a simple WIPS-style action).

> Course assignment: *Building a Basic ML-Based Wireless Intrusion Detection/Prevention System*.
> All traffic used is from a public dataset captured in someone else's lab. No capture or attack generation was done by me.

---

## 1. Dataset

**WPA3 Attacks Dataset** (Mendeley Data), by Asmaa Halbouni, Lee-Yeng Ong and Meng-Chew Leow. DOI: `10.17632/cxx5t5nw7z.1`.

- Lab capture with one WPA3-Personal access point and four stations, on channel 11 (2.4 GHz).
- Each attack is provided as a CSV (154 Wireshark-derived columns, with a `Label` column) and a PCAP.
- This project uses only the **Deauthentication attack** folder: `Deauth.csv` (722,606 frames, 207,222 labelled `Deauth`) and `Deauth.pcap`.

The dataset is **not included** in this repository. Download it from the Mendeley page and unzip it so that the files are at:

```
~/Downloads/WPA3 Attacks Dataset/WPA3 Attacks Dataset/WPA3 Denial of Service attacks/Deauthentication attack/
    Deauth.csv
    Deauth.pcap
```

If yours is somewhere else, change the `CSV` / `PCAP` / `DATA_DIR` path near the top of each script.

---

## 2. How it works

```
Deauth.csv  --> build_features.py --> outputs/features.csv --> train_model.py / ablation.py
(722,606 frames)   (1 row per second)                          (Random Forest, results)
                                                                      |
Deauth.pcap --> build_pcap_index.py --> outputs/deauth_pairs.csv      v
(sender / receiver MACs)                        +--------------> wids_alert.py
                                                                 (replay, ALERT, MAC log)
```

1. **Feature building.** Frames are grouped into 1-second windows. For each second we compute:
   `frames_per_sec`, `mean_len`, `std_len`, `mean_rssi`, `std_rssi`, `frac_mgmt`, `frac_ctrl`, `frac_data`, `retry_rate`, `deauth_count`.
   A second is labelled *attack* if any frame in it carries an attack label.
2. **Model.** `RandomForestClassifier(n_estimators=100, random_state=42)`.
3. **Split.** Chronological: the first 70% of seconds train the model (641 s), the last 30% test it (276 s: 179 normal, 97 attack). A random split is not used because neighbouring seconds are almost identical and would leak between train and test.
4. **Detection and alerting.** `wids_alert.py` replays the capture second by second, asks the model for a prediction, prints `ALERT` when a flood starts, and prints a message when it ends.
5. **WIPS action (logging).** The CSV has no MAC addresses, so the PCAP is used to find the deauth senders in the alert second. The first time a sender is seen it is written to `outputs/wips_blocklist.csv`.

---

## 3. Project layout

```
src/
  inspect_data.py       list dataset files and CSV columns
  explore_deauth.py     label counts and frame-subtype check
  explore_timeline.py   per-second statistics and attack timeline
  build_features.py     frames -> one row of features per second
  train_model.py        trains Random Forest, prints accuracy + confusion matrix
  ablation.py           feature-removal experiments + simple-rule baseline
  explore_pcap.py       checks that the PCAP matches the CSV, lists MACs
  build_pcap_index.py   deauth sender/receiver counts per second from the PCAP
  wids_alert.py         replay, alert, and MAC logging
outputs/                features, models, confusion matrices, logs (generated)
```

---

## 4. Setup (Windows, VS Code)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install pandas scikit-learn scapy matplotlib joblib
```

Tested with Python 3.13.

## 5. Run order

```powershell
python src\build_features.py        # creates outputs\features.csv
python src\train_model.py           # trains and saves outputs\model_*.joblib, confusion matrices
python src\ablation.py              # results table (outputs\results_table.csv) and confusion matrices
python src\build_pcap_index.py      # creates outputs\deauth_pairs.csv (takes a few minutes)
python src\wids_alert.py            # replay the unseen test part with alerts
python src\wids_alert.py --all --delay 0.05    # replay the whole capture (good for a demo)
```

`wids_alert.py` options: `--all` replays the whole capture instead of only the unseen test part; `--delay N` sets the pause in seconds between replayed seconds.

---

## 6. Results

All numbers are on the **276 unseen test seconds** (chronological last 30%).

| Experiment | Accuracy | Precision | Recall | False alarms | Missed attacks |
|---|---|---|---|---|---|
| Baseline rule (alert if deauth frames >= 100 per second) | 100.00% | 100.00% | 100.00% | 0 | 0 |
| A: all features | 100.00% | 100.00% | 100.00% | 0 | 0 |
| B: without `deauth_count` | 100.00% | 100.00% | 100.00% | 0 | 0 |
| C: also without frame-type mix (`frac_*`) | 97.83% | 95.05% | 98.97% | 5 | 1 |
| D: also without signal strength | 91.30% | 83.49% | 93.81% | 18 | 6 |

Confusion matrices are saved as `outputs/cm_*.png` and `outputs/confusion_*.png`.

**Full replay** (`--all`, 917 seconds): 371 attack seconds flagged, 0 missed, 0 false alarms, 546 normal seconds correct. Most of this is training data, so it is a demonstration, not a test result. The first alert fires in the first attack second.

**WIPS log.** The addresses logged are `02:00:00:00:00:cb` (the access point, which is the BSSID in every deauth frame) and `02:00:00:00:00:72` (the station most frames were aimed at). Neither is the real attacker.

---

## 7. Limitations (read before trusting the numbers)

- **The dataset is easy.** Labels are assigned frame by frame, and in this capture every deauth frame is labelled as the attack. A fixed threshold rule matches the Random Forest, so ML adds no advantage on this data. It only helps when features such as `deauth_count` are removed (experiments C and D).
- **One lab, one session.** Everything comes from a single capture. The attacker was much closer to the capture adapter than the other devices, so signal strength separates the classes strongly. That will not carry over to other rooms.
- **The test attack is not new to the model.** The unseen test seconds are all from the broadcast phase of the attack, which also appears at the end of the training window.
- **No legitimate deauthentication in normal traffic.** Real networks contain it (devices leaving, roaming), so false alarms on real traffic are untested.
- **Spoofed addresses.** The flood is sent in both directions as the access point and as a client. The logged MACs are the forged ones, so automatically blocking them would block the real AP and a real client. The system therefore logs instead of blocking. The MAC addresses in the dataset also look anonymised (`02:00:00:00:00:xx`).
- **Replay, not live capture.** The prototype replays a recorded capture. It does not sniff live traffic.

## 8. Ideas to improve

- Test on a different attack style or a different dataset (for example AWID3) to check generalisation.
- Add legitimate deauthentication to the normal traffic and measure false alarms.
- Use the model's probability output to tune the alert threshold, accepting a few more false alarms to miss fewer attacks.
- Use sequence numbers or per-device signal fingerprints to separate forged frames from real ones.
- Enable Management Frame Protection (802.11w), which is the standard defence against deauthentication floods.
- Read live traffic from a monitor-mode interface.


## 9. Statement on AI use

I used an AI assistant (Claude, by Anthropic) throughout this project, in a chat conversation. This is how the work was shared:

**What the AI did**
- Helped me break the assignment into stages and plan the approach.
- Searched for public datasets and compared the options (AWID3, a Kaggle copy of AWID3, and the WPA3 Attacks Dataset on Mendeley).
- Wrote the Python scripts in `src/` and explained what each part does.
- Helped me interpret the outputs, including pointing out that the 100% accuracy is partly because this dataset is easy to separate, and suggesting the feature-removal experiments and the simple-rule baseline to test that.

**What I did**
- Chose the dataset and downloaded it, and set up VS Code and the Python environment.
- Ran every script myself on my own laptop and checked the outputs against what the AI told me, including the file counts and labels.
- Pointed out the MAC spoofing limitation when the PCAP showed the same addresses sending in both directions.
- Fixed errors as they came up (for example a cancelled package install and a slow PCAP script that had to be replaced with a faster version).
- Decided what to change (for example showing results as percentages, and keeping the main results on one dataset).
- Reviewed the results and the limitations, and I am ready to explain how the code works in the demonstration: the feature building, the Random Forest and chronological split, the ablation and baseline, and the alert and logging logic.


## 10. Ethics

The project only uses an existing public dataset. No traffic was captured and no attacks were generated. Any future live capture or attack generation must be done only on a network I own or am authorised to test.

## 11. Reference

Halbouni, A., Ong, L.-Y., Leow, M.-C. *WPA3 Attacks Dataset*. Mendeley Data, V1, 2026. doi:10.17632/cxx5t5nw7z.1
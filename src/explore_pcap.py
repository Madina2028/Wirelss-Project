from pathlib import Path
from collections import Counter
from scapy.all import PcapReader, Dot11

PCAP = (Path.home() / "Downloads" / "WPA3 Attacks Dataset" / "WPA3 Attacks Dataset"
        / "WPA3 Denial of Service attacks" / "Deauthentication attack" / "Deauth.pcap")

total = 0
deauth = 0
senders = Counter()      # addr2 = transmitter (who sent the frame)
receivers = Counter()    # addr1 = receiver (who it was aimed at)
bssids = Counter()       # addr3 = BSSID (the access point it claims to be from)
first_time = None
first_deauth_time = None

with PcapReader(str(PCAP)) as reader:      # streams packets, so memory stays low
    for pkt in reader:
        total += 1
        if first_time is None:
            first_time = float(pkt.time)
        if pkt.haslayer(Dot11):
            d = pkt[Dot11]
            if d.type == 0 and d.subtype == 12:      # management frame, subtype 12 = deauth
                deauth += 1
                senders[d.addr2] += 1
                receivers[d.addr1] += 1
                bssids[d.addr3] += 1
                if first_deauth_time is None:
                    first_deauth_time = float(pkt.time)

print("Total packets:", total, "(CSV had 722606)")
print("Deauth frames:", deauth, "(CSV had 207222)")
print("First packet time:", int(first_time), "(CSV started at 1770985685)")
print("First deauth time:", int(first_deauth_time) if first_deauth_time else None)
print("\nTop senders (addr2):", senders.most_common(5))
print("Top receivers (addr1):", receivers.most_common(5))
print("Top BSSIDs (addr3):", bssids.most_common(5)) 
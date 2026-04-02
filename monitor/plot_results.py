import json
import os
import sys
from collections import defaultdict
import matplotlib.pyplot as plt

INPUT_FILE = os.path.expanduser("~/iot-monitoring-lab/data/logs/devices/collector.jsonl")
OUTPUT_DIR = os.path.expanduser("~/iot-monitoring-lab/monitor/output_by_attack")

MAX_RECORDS = 3000
MAX_TEMP_FOR_GRAPH = 120

ATTACK_FILTERS = {
    "baseline": {"device-1", "device-2"},
    "flood": {"device-1", "device-2", "bot-device"},
    "payload": {"attacker-big", "device-1", "device-2"},
    "impersonation": {"device-1", "device-2"},
    "rogue": {"rogue-device-99", "device-1", "device-2"},
    "all": None,
}


def ensure_output_dir():
    os.makedirs(OUTPUT_DIR, exist_ok=True)


def get_allowed_devices(mode):
    if mode not in ATTACK_FILTERS:
        print(f"[ERROR] Unknown mode: {mode}")
        print(f"Allowed modes: {', '.join(ATTACK_FILTERS.keys())}")
        sys.exit(1)
    return ATTACK_FILTERS[mode]


def load_records(allowed_devices):
    records = []

    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            try:
                outer = json.loads(line)
                payload_raw = outer.get("payload", "")
                payload = json.loads(payload_raw)

                device_id = payload.get("device_id", "unknown")

                if allowed_devices is not None and device_id not in allowed_devices:
                    continue

                ts = float(outer.get("ts", 0))
                temp = payload.get("temp")
                humidity = payload.get("humidity")
                payload_size = len(payload_raw.encode("utf-8"))

                records.append({
                    "ts": ts,
                    "device_id": device_id,
                    "temp": temp,
                    "humidity": humidity,
                    "payload_size": payload_size,
                })
            except Exception:
                continue

    records.sort(key=lambda x: x["ts"])
    if len(records) > MAX_RECORDS:
        records = records[-MAX_RECORDS:]

    return records


def normalize_time(records):
    for i, r in enumerate(records):
        r["t"] = i


def plot_message_rate(records, mode):
    rates = defaultdict(lambda: defaultdict(int))

    for r in records:
        bucket = r["t"] // 10
        rates[r["device_id"]][bucket] += 1

    plt.figure(figsize=(12, 6))

    for device_id, per_bucket_counts in rates.items():
        xs = sorted(per_bucket_counts.keys())
        ys = [per_bucket_counts[x] for x in xs]
        plt.plot(xs, ys, label=device_id)

    plt.xlabel("Relative time window")
    plt.ylabel("Messages per window")
    plt.title(f"Message Rate Over Time ({mode})")
    plt.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, f"{mode}_message_rate.png"))
    plt.close()


def plot_payload_size(records, mode):
    per_device_x = defaultdict(list)
    per_device_y = defaultdict(list)

    for r in records:
        per_device_x[r["device_id"]].append(r["t"])
        per_device_y[r["device_id"]].append(r["payload_size"])

    plt.figure(figsize=(12, 6))

    for device_id in per_device_x:
        if device_id == "attacker-big":
            plt.scatter(
                per_device_x[device_id],
                per_device_y[device_id],
                label=device_id,
                s=40,
                marker="x"
            )
        else:
            plt.plot(
                per_device_x[device_id],
                per_device_y[device_id],
                label=device_id
            )

    plt.axhline(y=10000, linestyle="--", label="threshold")
    plt.xlabel("Relative time")
    plt.ylabel("Payload size (bytes)")
    plt.title(f"Payload Size Over Time ({mode})")
    plt.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, f"{mode}_payload_size.png"))
    plt.close()


def plot_temperature(records, mode):
    per_device_x = defaultdict(list)
    per_device_y = defaultdict(list)

    for r in records:
        temp = r["temp"]
        if temp is None:
            continue
        if temp > MAX_TEMP_FOR_GRAPH or temp < -50:
            continue

        per_device_x[r["device_id"]].append(r["t"])
        per_device_y[r["device_id"]].append(temp)

    plt.figure(figsize=(12, 6))

    for device_id in per_device_x:
        plt.plot(per_device_x[device_id], per_device_y[device_id], label=device_id)

    plt.xlabel("Relative time")
    plt.ylabel("Temperature")
    plt.title(f"Temperature Over Time ({mode})")
    plt.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, f"{mode}_temperature.png"))
    plt.close()


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 plot_by_attack.py <baseline|flood|payload|impersonation|rogue|all>")
        sys.exit(1)

    mode = sys.argv[1].strip().lower()
    allowed_devices = get_allowed_devices(mode)

    ensure_output_dir()

    if not os.path.exists(INPUT_FILE):
        print(f"[ERROR] File not found: {INPUT_FILE}")
        sys.exit(1)

    records = load_records(allowed_devices)
    if not records:
        print(f"[ERROR] No valid records found for mode: {mode}")
        sys.exit(1)

    normalize_time(records)

    plot_message_rate(records, mode)
    plot_payload_size(records, mode)
    plot_temperature(records, mode)

    print(f"[OK] Graphs created for mode: {mode}")
    print(os.path.join(OUTPUT_DIR, f"{mode}_message_rate.png"))
    print(os.path.join(OUTPUT_DIR, f"{mode}_payload_size.png"))
    print(os.path.join(OUTPUT_DIR, f"{mode}_temperature.png"))


if __name__ == "__main__":
    main()
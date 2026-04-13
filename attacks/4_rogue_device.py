import json
import random
import time
import threading
import paho.mqtt.client as mqtt

BROKER = "localhost"
PORT = 1883

ROGUE_DEVICES = [
    "rogue-device-99",
    "rogue-device-100",
    "rogue-device-101",
    "rogue-sensor-x",
    "device-1",
    "rogue-device-102",
    "rogue-device-103",
    "rogue-device-104",
    "rogue-sensor-y",
    "rogue-device-z",
    "rogue-device-105",   
]

def run_rogue(device_id, interval=1.0):
    topic = f"iot/{device_id}/telemetry"

    client = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2)
    client.connect(BROKER, PORT, 60)
    client.loop_start()

    print(f"[INFO] Rogue device started: {device_id}")

    while True:
        payload = {
            "device_id": device_id,
            "ts": time.time(),
            "temp": round(random.uniform(120, 150), 2),
            "humidity": round(random.uniform(120, 150), 2),
            "status": "rogue"
        }
        client.publish(topic, json.dumps(payload))
        time.sleep(interval)


threads = []
for dev in ROGUE_DEVICES:
    t = threading.Thread(target=run_rogue, args=(dev, 1.0), daemon=True)
    t.start()
    threads.append(t)

print("[INFO] Multiple rogue devices are publishing. Press Ctrl+C to stop.")

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("\n[INFO] Stopped rogue-device attack.")

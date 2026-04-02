import json
import time
import paho.mqtt.client as mqtt

BROKER = "localhost"
PORT = 1883
DEVICE_ID = "rogue-device-99"
TOPIC = f"iot/{DEVICE_ID}/telemetry"

client = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2)
client.connect(BROKER, PORT, 60)
client.loop_start()

print(f"[INFO] Starting rogue device attack: {DEVICE_ID}")

while True:
    payload = {
        "device_id": DEVICE_ID,
        "ts": time.time(),
        "temp": 999,
        "humidity": 999,
        "status": "rogue"
    }
    client.publish(TOPIC, json.dumps(payload))
    time.sleep(1)
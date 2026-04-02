import json
import time
import paho.mqtt.client as mqtt

BROKER = "localhost"
PORT = 1883

client = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2)
client.connect(BROKER, PORT, 60)
client.loop_start()

payload_blob = "A" * 50000

while True:
    payload = {
        "device_id": "attacker-big",
        "blob": payload_blob
    }

    client.publish("iot/attacker-big/telemetry", json.dumps(payload))
    time.sleep(1)
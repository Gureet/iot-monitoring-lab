import os, json, time, random
import paho.mqtt.client as mqtt

BROKER = os.getenv("MQTT_BROKER", "mosquitto")
PORT = int(os.getenv("MQTT_PORT", "1883"))
DEVICE_ID = os.getenv("DEVICE_ID", "device-1")
TOPIC = os.getenv("TOPIC", f"iot/{DEVICE_ID}/telemetry")
BASE_INTERVAL = float(os.getenv("BASE_INTERVAL", "3.0"))
JITTER = float(os.getenv("JITTER", "1.0"))

client = mqtt.Client(client_id=DEVICE_ID, clean_session=True)
client.connect(BROKER, PORT, keepalive=60)
client.loop_start()

while True:
    payload = {
        "device_id": DEVICE_ID,
        "ts": time.time(),
        "temp": round(random.uniform(18, 30), 2),
        "humidity": round(random.uniform(30, 70), 2),
        "status": "ok",
    }
    client.publish(TOPIC, json.dumps(payload), qos=0, retain=False)
    time.sleep(max(0.001, BASE_INTERVAL + random.uniform(-JITTER, JITTER)))
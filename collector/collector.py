import os, json, time
import paho.mqtt.client as mqtt

BROKER = os.getenv("MQTT_BROKER", "mosquitto")
PORT = int(os.getenv("MQTT_PORT", "1883"))
TOPIC =  os.getenv("TOPIC", "iot/+/telemetry")
OUTFILE =  os.getenv("OUTFILE", "/logs/collector.jsonl")

def on_connect(client, userdata, flags, rc): # re-subscribe after reconnect
	print("connect rc=", rc)
	if rc == 0:
		client.subscribe(TOPIC)

def on_message(client, userdata, msg):
	record = {
		"ts": time.time(),
		"topic": msg.topic,
		"payload": msg.payload.decode("utf-8", errors="replace"),
	}
	with open(OUTFILE, "a", encoding="utf-8") as f:
		f.write(json.dumps(record) + "\n")

client = mqtt.Client(client_id="collector", clean_session=True)
client.on_connect = on_connect
client.on_message = on_message
client.reconnect_delay_set(min_delay=1, max_delay=30) # for backoff
client.connect(BROKER, PORT, keepalive=60)
client.subscribe(TOPIC)
client.loop_forever()

#!/bin/bash

# IoT Telemetry Flood Attack Simulation
# Sends high-rate telemetry messages to MQTT broker

NETWORK="iot-monitoring-lab_iotnet"
BROKER="mosquitto"
PORT=1883

echo "---------------------------------------"
echo "Starting IoT Telemetry Flood Simulation"
echo "Flooding: bot-device + device-1 + device-2"
echo "Broker: $BROKER:$PORT"
echo "Press Ctrl+C to stop"
echo "---------------------------------------"

# bot-device (external attacker)
docker run --rm \
  --network $NETWORK \
  -e MQTT_BROKER=$BROKER \
  -e MQTT_PORT=$PORT \
  -e DEVICE_ID=bot-device \
  -e BASE_INTERVAL=0.015 \
  -e JITTER=0.005 \
  iot-monitoring-lab-device1 &

# device-1 (compromised trusted)
docker run --rm \
  --network $NETWORK \
  -e MQTT_BROKER=$BROKER \
  -e MQTT_PORT=$PORT \
  -e DEVICE_ID=device-1 \
  -e BASE_INTERVAL=0.015 \
  -e JITTER=0.005 \
  iot-monitoring-lab-device1 &

# device-2 (compromised trusted)
docker run --rm \
  --network $NETWORK \
  -e MQTT_BROKER=$BROKER \
  -e MQTT_PORT=$PORT \
  -e DEVICE_ID=device-2 \
  -e BASE_INTERVAL=0.015 \
  -e JITTER=0.005 \
  iot-monitoring-lab-device1 &

wait
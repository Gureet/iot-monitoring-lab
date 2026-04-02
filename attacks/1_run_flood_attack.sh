#!/bin/bash

# IoT Telemetry Flood Attack Simulation
# Sends very high-rate telemetry messages to MQTT broker

NETWORK="iot-monitoring-lab_iotnet"
BROKER="mosquitto"
PORT=1883
DEVICE="bot-device"

echo "---------------------------------------"
echo "Starting IoT Telemetry Flood Simulation"
echo "Device ID: $DEVICE"
echo "Broker: $BROKER:$PORT"
echo "Telemetry starts flooding..."
echo "Press Ctrl+C to stop"
echo "---------------------------------------"

docker run --rm \
  --network $NETWORK \
  -e MQTT_BROKER=$BROKER \
  -e MQTT_PORT=$PORT \
  -e DEVICE_ID=$DEVICE \
  -e BASE_INTERVAL=0.015 \
  -e JITTER=0.005 \
  iot-monitoring-lab-device1

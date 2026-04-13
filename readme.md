# IoT Monitoring Lab

## Architecture Diagram
########################################

IoT devices
 |
MQTT Broker (Mosquitto)
 |
Collector (JSON logs)
 |
Monitoring App (Python)
 |
Plots + Alerts

* Network Monitoring:
Devices -> Broker -> tcpdump -> Zeek

#######################################

## Start Lab
cd ~/iot-monitoring-lab
docker compose up -d

## MQTT access (Python app)
Broker: localhost
Port: 1883
Topic: iot/+/telemetry

Payload is JSON like:

{"device_id":"device-1","ts":...,"temp":...,"humidity":...,"status":"ok"}

## Logs available for analysis
- Zeek logs: ~/iot-monitoring-lab/data/logs/zeek/
- Collector JSONL: ~/iot-monitoring-lab/data/logs/devices/collector.jsonl
- PCAPs: ~/iot-monitoring-lab/data/pcap/

## Stop Lab
docker compose down

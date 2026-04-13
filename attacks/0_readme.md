# Scenario 1: Telemetry Flood (Compromised IoT Device)
- Infected device sending too many messages.
- The running container send ~50 messages per second.
  + Collector: huge message rate
  + PCAP: packet burst
  + Zeek: many connections/ packets
- Execute: ./1_run_flood_attack.sh
- Monitor App can detect: msg_rate > threshold.
- Example detection rule: device publishes > 10msgs/sec (message per device)

# Scenario 2: Payload Size Anomaly
- Compromised device sending large data blobs.
- This resembles:
  + data exfiltration
  + malware logs
  + sensor malfunction
- What happens:
  + Collector: huge payload
  + PCAP: large MQTT packets
  + Zeek: abnormal bytes transferred
- Execute: python3 2_big_payload.py
- Example detection rule: payload_size > 10KB
  + baseline devices: ~200 bytes
  + attack device: ~50,000 bytes

# Scenario 3: Device Impersonate (duplicate device IDs)
- An attacker pretends to be a real device by using the same MQTT device_id, so:
  + the real device may get kicked off (MQTT brokers often disconnect the old client when a duplicate client_id connects)
  + telemetry becomes mixed or spoofed
  + monitoring app can detect inconsistencies (rate spikes, conflicting values, frequent disconnects)
- In the lab, the normal device has DEVICE_ID=device-1, publishes to iot/device-1/telemetry.
- Execute: python3 3_impersonate_device-1.py
  + same device-1 producing two different distributions
  + sudden jump in temp/ humidity outside normal range
- Detection rules:
  1. disconnect storm:
    + If broker disconnects the original and keeps swapping: high connect/ disconnect rate (from mosquitto logs)
  2. value plausibility:
    + If temp suddenly goes from 20-30 to 90+: out-of-range values -> alert
  3. rate spike:
    + If device-1 normally publishes every ~3s but suddenly publishes every 0.5s: msg/sec threshold exceeded.

# Scenario 4: Rogue Device Injection (Unauthorized Devices)
- An attacker introduces unauthorized devices into the system by publishing to MQTT topics with unknown device IDs, so:
  + the broker accepts messages without authentication (no access control)
  + fake devices can send arbitrary telemetry
  + monitoring app may detect unknown IDs, abnormal values, or unusual device activity
- In the lab, rogue devices use IDs like rogue-device-*, rogue-sensor-*, and publish to iot/<device_id>/telemetry.
- Execute: python3 4_rogue_device.py
  + multiple fake devices publish simultaneously
  + extreme values (e.g., temp=999, humidity=999)
  + sudden appearance of many new device IDs
- Detection rules:
1. unknown device detection:
  + device_id not in trusted_devices.json → alert
2. abnormal values:
  + unrealistic sensor values (e.g., temp=999) → anomaly
3. device explosion:
  + sudden increase in number of active devices → suspicious

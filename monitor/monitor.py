import json
import time
from collections import defaultdict, deque
import paho.mqtt.client as mqtt

BROKER = "localhost"
PORT = 1883
TOPIC = "iot/+/telemetry"

# Attack 1: Flood
RATE_THRESHOLD = 30

# Attack 2: Big payload
PAYLOAD_THRESHOLD = 10 * 1024  # 10 KB

# Attack 3: Impersonation / trusted-device anomaly
TEMP_MIN = -20
TEMP_MAX = 60
HUMIDITY_MIN = 0
HUMIDITY_MAX = 100
TRUSTED_RATE_THRESHOLD = 1
IMPERSONATION_WINDOW = 5
IMPERSONATION_THRESHOLD = 3
SESSION_RESET_AFTER = 5

# New: adaptive baseline
TEMP_DEVIATION_THRESHOLD = 20
TEMP_HISTORY_SIZE = 20

ALERT_COOLDOWN = 3
ATTACK_ACTIVE_HOLD = 5

message_times = defaultdict(deque)
last_alert_time = defaultdict(float)
last_msg_print = defaultdict(float)
normal_counts = defaultdict(int)

abnormal_times = defaultdict(deque)
impersonation_session_active = defaultdict(bool)
last_abnormal_time = defaultdict(float)
impersonation_session_counts = defaultdict(int)

temp_history = defaultdict(deque)

attack_active_until = 0

RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
RESET = "\033[0m"
BOLD = "\033[1m"


def load_trusted_devices():
    try:
        with open("trusted_devices.json", "r", encoding="utf-8") as f:
            data = json.load(f)
        return set(data.keys())
    except Exception:
        return {"device-1", "device-2"}


TRUSTED_DEVICES = load_trusted_devices()


def info(msg):
    print(f"{GREEN}{msg}{RESET}")


def normal(msg):
    print(f"{CYAN}{msg}{RESET}")


def warn(msg):
    print(f"{YELLOW}{msg}{RESET}")


def alert(msg):
    print(f"{RED}{BOLD}{msg}{RESET}")


def success(msg):
    print(f"{GREEN}{BOLD}{msg}{RESET}")


def mark_attack_active(now, duration=ATTACK_ACTIVE_HOLD):
    global attack_active_until
    attack_active_until = max(attack_active_until, now + duration)


def should_alert(key, now):
    if now - last_alert_time[key] >= ALERT_COOLDOWN:
        last_alert_time[key] = now
        return True
    return False


def prune_rate(device_id, now):
    while message_times[device_id] and now - message_times[device_id][0] > 1:
        message_times[device_id].popleft()


def prune_abnormal(device_id, now):
    while abnormal_times[device_id] and now - abnormal_times[device_id][0] > IMPERSONATION_WINDOW:
        abnormal_times[device_id].popleft()


def print_msg(device_id, msg, now):
    if device_id in TRUSTED_DEVICES:
        normal(msg)
        return

    if now - last_msg_print[device_id] >= 1:
        last_msg_print[device_id] = now
        normal(msg)


def print_normal_summary(device_id):
    success(
        f"[OK] {device_id} is behaving normally. "
        f"Normal messages observed={normal_counts[device_id]}"
    )


def print_impersonation_summary():
    summary_parts = [
        f"{device}: {count}" for device, count in impersonation_session_counts.items()
    ]
    summary_text = ", ".join(summary_parts) if summary_parts else "none"
    warn(f"[SUMMARY] Impersonation sessions detected | Per device -> {summary_text}")


def any_impersonation_session_active():
    return any(impersonation_session_active.values())


def end_finished_sessions(now):
    for device_id in list(impersonation_session_active.keys()):
        if impersonation_session_active[device_id]:
            if now - last_abnormal_time[device_id] > SESSION_RESET_AFTER:
                impersonation_session_active[device_id] = False
                info(f"[INFO] Impersonation session ended for {device_id}")


def update_temp_baseline(device_id, temp):
    if temp is None:
        return
    temp_history[device_id].append(temp)
    if len(temp_history[device_id]) > TEMP_HISTORY_SIZE:
        temp_history[device_id].popleft()


def get_temp_baseline(device_id):
    values = temp_history[device_id]
    if len(values) < 5:
        return None
    return sum(values) / len(values)


def on_connect(client, userdata, flags, rc, properties=None):
    info(f"[INFO] Connected to MQTT broker with rc={rc}")
    client.subscribe(TOPIC)
    info(f"[INFO] Subscribed to {TOPIC}")
    info(f"[INFO] Trusted devices loaded: {sorted(TRUSTED_DEVICES)}")


def on_message(client, userdata, msg):
    now = time.time()
    end_finished_sessions(now)

    raw = msg.payload
    payload_size = len(raw)

    try:
        data = json.loads(raw.decode())
    except Exception as e:
        warn(f"[WARN] Invalid JSON on {msg.topic}: {e}")
        return

    device_id = data.get("device_id", "unknown")
    temp = data.get("temp")
    humidity = data.get("humidity")

    message_times[device_id].append(now)
    prune_rate(device_id, now)
    rate = len(message_times[device_id])

    print_msg(
        device_id,
        f"[MSG] {device_id} rate={rate}/s size={payload_size}B temp={temp} humidity={humidity}",
        now
    )

    suspicious_this_message = False

    # New: Unknown / rogue device detection
    if device_id not in TRUSTED_DEVICES:
        suspicious_this_message = True
        if should_alert(f"unknown:{device_id}", now):
            mark_attack_active(now)
            alert(f"[ALERT] Unknown device detected: {device_id}")

    # Attack 1: Flood
    if rate > RATE_THRESHOLD:
        suspicious_this_message = True
        if should_alert(f"flood:{device_id}", now):
            mark_attack_active(now)
            alert(
                f"[ALERT] Flood detected: {device_id} exceeded threshold "
                f"with {rate} msgs in the last 1s"
            )

    # Attack 2: Big payload
    if payload_size > PAYLOAD_THRESHOLD:
        suspicious_this_message = True
        if should_alert(f"payload:{device_id}", now):
            mark_attack_active(now)
            alert(f"[ALERT] Big payload detected: {device_id} payload size {payload_size} bytes")

    # Attack 3: Trusted-device impersonation + adaptive behavior anomaly
    if device_id in TRUSTED_DEVICES:
        abnormal_indicators = []

        temp_avg = get_temp_baseline(device_id)

        if temp is not None and (temp < TEMP_MIN or temp > TEMP_MAX):
            abnormal_indicators.append(f"implausible temperature={temp}")

        if humidity is not None and (humidity < HUMIDITY_MIN or humidity > HUMIDITY_MAX):
            abnormal_indicators.append(f"implausible humidity={humidity}")

        if rate > TRUSTED_RATE_THRESHOLD:
            abnormal_indicators.append(f"abnormal trusted-device rate={rate}/s")

        if temp is not None and temp_avg is not None:
            if abs(temp - temp_avg) > TEMP_DEVIATION_THRESHOLD:
                abnormal_indicators.append(
                    f"temperature deviation from baseline avg={temp_avg:.2f}"
                )

        if abnormal_indicators:
            suspicious_this_message = True
            last_abnormal_time[device_id] = now
            abnormal_times[device_id].append(now)
            prune_abnormal(device_id, now)

            warn(f"[WARN] Suspicious {device_id}: " + ", ".join(abnormal_indicators))

            if (
                len(abnormal_times[device_id]) >= IMPERSONATION_THRESHOLD
                and not impersonation_session_active[device_id]
            ):
                impersonation_session_active[device_id] = True
                impersonation_session_counts[device_id] += 1
                mark_attack_active(now)

                alert(
                    f"[ALERT] Impersonation suspected for {device_id}: "
                    f"{len(abnormal_times[device_id])} abnormal readings within {IMPERSONATION_WINDOW}s"
                )
                print_impersonation_summary()
        else:
            prune_abnormal(device_id, now)
            update_temp_baseline(device_id, temp)

    if device_id in TRUSTED_DEVICES and not suspicious_this_message:
        if now > attack_active_until and not any_impersonation_session_active():
            normal_counts[device_id] += 1
            if normal_counts[device_id] % 10 == 0:
                print_normal_summary(device_id)


def main():
    client = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2)
    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(BROKER, PORT, 60)
    client.loop_forever()


if __name__ == "__main__":
    main()
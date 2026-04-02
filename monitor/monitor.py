import json
import time
from collections import defaultdict, deque
import paho.mqtt.client as mqtt

BROKER = "localhost"
PORT = 1883
TOPIC = "iot/+/telemetry"

# Thresholds
RATE_THRESHOLD = 30
PAYLOAD_THRESHOLD = 10 * 1024

TEMP_MIN = -20
TEMP_MAX = 60
HUMIDITY_MIN = 0
HUMIDITY_MAX = 100

TRUSTED_RATE_THRESHOLD = 1
IMPERSONATION_WINDOW = 5
IMPERSONATION_THRESHOLD = 3
SESSION_RESET_AFTER = 5

TEMP_DEVIATION_THRESHOLD = 20
TEMP_HISTORY_SIZE = 20

ALERT_COOLDOWN = 5
ATTACK_ACTIVE_HOLD = 5

# State
message_times = defaultdict(deque)
last_alert_time = defaultdict(float)
last_msg_print = defaultdict(float)
last_warn_print = defaultdict(float)
normal_counts = defaultdict(int)

abnormal_times = defaultdict(deque)
impersonation_session_active = defaultdict(bool)
last_abnormal_time = defaultdict(float)
impersonation_session_counts = defaultdict(int)

temp_history = defaultdict(deque)

attack_active_until = 0

# Colors
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
RESET = "\033[0m"
BOLD = "\033[1m"


def load_trusted_devices():
    try:
        with open("trusted_devices.json", "r") as f:
            data = json.load(f)
        return set(data.keys())
    except:
        return {"device-1", "device-2"}


TRUSTED_DEVICES = load_trusted_devices()


def info(msg): print(f"{GREEN}{msg}{RESET}")
def normal(msg): print(f"{CYAN}{msg}{RESET}")
def warn(msg): print(f"{YELLOW}{msg}{RESET}")
def alert(msg): print(f"{RED}{BOLD}{msg}{RESET}")
def success(msg): print(f"{GREEN}{BOLD}{msg}{RESET}")


def mark_attack_active(now):
    global attack_active_until
    attack_active_until = now + ATTACK_ACTIVE_HOLD


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
    if now - last_msg_print[device_id] >= 1:
        last_msg_print[device_id] = now
        normal(msg)


def print_normal_summary(device_id):
    success(f"[OK] {device_id} behaving normally ({normal_counts[device_id]} msgs)")


def print_impersonation_summary():
    summary = ", ".join(f"{d}:{c}" for d, c in impersonation_session_counts.items())
    warn(f"[SUMMARY] Impersonation sessions -> {summary}")


def any_impersonation_active():
    return any(impersonation_session_active.values())


def end_sessions(now):
    for d in impersonation_session_active:
        if impersonation_session_active[d] and now - last_abnormal_time[d] > SESSION_RESET_AFTER:
            impersonation_session_active[d] = False
            info(f"[INFO] Session ended for {d}")


def update_baseline(device_id, temp):
    if temp is None:
        return
    temp_history[device_id].append(temp)
    if len(temp_history[device_id]) > TEMP_HISTORY_SIZE:
        temp_history[device_id].popleft()


def get_avg(device_id):
    vals = temp_history[device_id]
    if len(vals) < 5:
        return None
    return sum(vals) / len(vals)


def on_connect(client, userdata, flags, rc, properties=None):
    info(f"[INFO] Connected rc={rc}")
    client.subscribe(TOPIC)
    info(f"[INFO] Subscribed {TOPIC}")
    info(f"[INFO] Trusted devices: {TRUSTED_DEVICES}")


def on_message(client, userdata, msg):
    now = time.time()
    end_sessions(now)

    payload = msg.payload
    size = len(payload)

    try:
        data = json.loads(payload.decode())
    except:
        return

    device_id = data.get("device_id", "unknown")
    temp = data.get("temp")
    humidity = data.get("humidity")

    message_times[device_id].append(now)
    prune_rate(device_id, now)
    rate = len(message_times[device_id])

    print_msg(
        device_id,
        f"[MSG] {device_id} rate={rate}/s size={size}B temp={temp} humidity={humidity}",
        now
    )

    suspicious = False

    # Unknown device
    if device_id not in TRUSTED_DEVICES:
        suspicious = True
        if should_alert(f"unknown:{device_id}", now):
            mark_attack_active(now)
            alert(f"[ALERT] Unknown device detected: {device_id}")

    # Flood
    if rate > RATE_THRESHOLD:
        suspicious = True
        if should_alert(f"flood:{device_id}", now):
            mark_attack_active(now)
            if device_id in TRUSTED_DEVICES:
                alert(f"[ALERT] Flood on trusted device: {device_id} ({rate}/s)")
            else:
                alert(f"[ALERT] Flood detected: {device_id} ({rate}/s)")

    # Big payload
    if size > PAYLOAD_THRESHOLD:
        suspicious = True
        if should_alert(f"payload:{device_id}", now):
            mark_attack_active(now)
            alert(f"[ALERT] Big payload detected: {device_id} ({size} bytes)")

    # Impersonation / anomaly detection
    if device_id in TRUSTED_DEVICES:
        issues = []
        avg = get_avg(device_id)

        if temp is not None and (temp < TEMP_MIN or temp > TEMP_MAX):
            issues.append(f"temp out-of-range ({temp})")

        if humidity is not None and (humidity < HUMIDITY_MIN or humidity > HUMIDITY_MAX):
            issues.append(f"humidity out-of-range ({humidity})")

        if rate > TRUSTED_RATE_THRESHOLD:
            issues.append(f"abnormal rate ({rate}/s)")

        if avg is not None and temp is not None and abs(temp - avg) > TEMP_DEVIATION_THRESHOLD:
            issues.append(f"temp deviation from baseline avg={avg:.2f}")

        if issues:
            suspicious = True
            last_abnormal_time[device_id] = now
            abnormal_times[device_id].append(now)
            prune_abnormal(device_id, now)

            # Throttled WARN
            if now - last_warn_print[device_id] >= 1:
                last_warn_print[device_id] = now
                warn(f"[WARN] Suspicious {device_id}: " + ", ".join(issues))

            # Session detection
            if (
                len(abnormal_times[device_id]) >= IMPERSONATION_THRESHOLD
                and not impersonation_session_active[device_id]
            ):
                impersonation_session_active[device_id] = True
                impersonation_session_counts[device_id] += 1
                mark_attack_active(now)

                alert(f"[ALERT] Impersonation suspected for {device_id}")
                print_impersonation_summary()

        else:
            prune_abnormal(device_id, now)
            update_baseline(device_id, temp)

    # Normal summary
    if device_id in TRUSTED_DEVICES and not suspicious:
        if now > attack_active_until and not any_impersonation_active():
            normal_counts[device_id] += 1
            if normal_counts[device_id] % 10 == 0:
                print_normal_summary(device_id)


def main():
    client = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2)
    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(BROKER, PORT)
    client.loop_forever()


if __name__ == "__main__":
    main()
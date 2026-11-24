"""Constants for the Level BLE integration.

Standard library only: tools/ble_probe.py imports this file directly.
"""

DOMAIN = "level_ble"
MANUFACTURER = "Level Home"
MODEL = "Level Bolt / Level Lock (Bluetooth)"

# Level GATT UUIDs seen in co.level.app. Which of the 9161b20x UUIDs are
# services and which are characteristics is still being pinned down against
# real hardware (that is what the dump_gatt action is for).
UUID_SERVICE_MAIN = "9161b202-1b4b-4727-a3ca-47b35cdcf5c1"
UUID_SERVICE_WIFI = "9161b203-1b4b-4727-a3ca-47b35cdcf5c1"
UUID_SERVICE_NOTIFY = "9161b204-1b4b-4727-a3ca-47b35cdcf5c1"

# Level's own service also appears with these vendor UUIDs in the APK; they are
# logged by the probe tool so we can pin them down against real hardware.
UUID_CANDIDATE_SERVICE = "9d8e06fe-9d7f-48a1-b63e-233e50e7d4e2"
UUID_CANDIDATE_CHAR = "256b4960-d04a-4a01-bebd-23f528e92855"
UUID_MCUBOOT_SMP = "8d53dc1d-1db7-4cd3-868b-8a527460aa84"
UUID_BATTERY_LEVEL = "00002a19-0000-1000-8000-00805f9b34fb"

# 16-bit service UUID Level locks advertise, with service data. The app picks
# out its own devices by it (seen on a real lock, and in co.level.app 2.5.0.56).
UUID_LEVEL_ADVERTISEMENT = "0000fdbf-0000-1000-8000-00805f9b34fb"

# Level's GATT transport on that same FDBF service (co.level.app 2.5.0.56,
# confirmed on a real "Apollo" lock): the app writes to 0x0010 and listens on
# 0x0012, splitting every message into fragments that start with a 1-byte type.
UUID_LEVEL_SERVICE = UUID_LEVEL_ADVERTISEMENT
UUID_LEVEL_TX = "00000010-0000-1000-8000-00805f9b34fb"
UUID_LEVEL_RX = "00000012-0000-1000-8000-00805f9b34fb"

# Prefix shared by the 9161b20x family above.
LEVEL_UUID_PREFIX = "9161b20"

# UUIDs that mark a Level lock in an advertisement or a GATT table.
LEVEL_UUIDS = frozenset(
    {
        UUID_SERVICE_MAIN,
        UUID_SERVICE_WIFI,
        UUID_SERVICE_NOTIFY,
        UUID_CANDIDATE_SERVICE,
        UUID_CANDIDATE_CHAR,
        UUID_LEVEL_ADVERTISEMENT,
    }
)

# Lower-case substrings of an advertised name that suggest a Level lock. Only
# used to find capture targets, never to pick the lock an entity controls.
LEVEL_NAME_HINTS = ("level", "bolt")

# Config entry keys.
CONF_ACCOUNT_UUID = "account_uuid"
CONF_DEVICE = "device"
CONF_PRIVATE_KEY = "private_key"
CONF_TOKEN = "token"

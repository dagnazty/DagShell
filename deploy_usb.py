#!/usr/bin/env python3
"""
DagShell USB Deployer
=====================
Deploys DagShell firmware to the Orbic RCL400 via USB cable.
Mirrors Rayhunter's 'orbic-usb' installation method.

How it works (matching Rayhunter installer/src/orbic.rs):
  1. Detects Orbic device on USB in RNDIS mode (PID 0xf626)
  2. Sends a USB vendor control request to switch it into ADB/debug mode (PID 0xf601)
  3. Device reboots and re-enumerates with ADB interface exposed
  4. Pushes firmware files to /tmp/ via 'adb push' (ADB user can write /tmp)
  5. Installs a SUID rootshell binary via AT+SYSCMD (3 commands: cp, chown, chmod)
  6. Uses 'adb shell /bin/rootshell -c "cmd"' for all remaining privileged ops
  7. Sets up boot persistence via USB composition hook
  8. Reboots device — boot script applies iptables and starts orbic_app

Root Gain Strategy (mirrors Rayhunter setup_rootshell()):
  Fresh Orbic devices have ADB shell as uid=2000 (NOT root).
  AT+SYSCMD runs via atfwd_daemon which IS root — used only for the 3-command
  rootshell install (cp, chown root, chmod 4755). After that, all privileged
  operations go through 'adb shell /bin/rootshell -c "command"'.

  If Rayhunter was previously installed, /bin/rootshell already exists and the
  AT+SYSCMD step is skipped entirely.

  NOTE: iptables via rootshell FAILS (SUID doesn't grant CAP_NET_ADMIN).
  Firewall rules are applied by dagshell_boot.sh which runs from init context
  (has full capabilities) on every boot.

USB IDs (from Rayhunter installer/src/orbic.rs):
  Vendor:  0x05c6  (Qualcomm)
  RNDIS:   0xf626  (normal hotspot mode)
  RNDIS2:  0xf622  (RNDIS + serial exposed)
  ADB:     0xf601  (debug/command mode - target)

AT+SYSCMD Protocol (USB serial, interface 1):
  OUT endpoint: 0x02
  IN  endpoint: 0x82
  Frame:  \\r\\nAT+SYSCMD=<command>\\r\\n
  Read:   echo (discard), then response
  OK if:  response contains \\r\\nOK\\r\\n

Requirements:
  pip install pyusb
  adb (Android Debug Bridge):
    macOS:   brew install android-platform-tools
    Linux:   sudo apt install adb
    Windows: https://developer.android.com/tools/releases/platform-tools
"""

import subprocess
import sys
import time
from pathlib import Path

# Cryptography for fresh PKI cert generation each deploy
try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend
    import datetime
    import ipaddress
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

# Optional pyusb for USB mode switching and AT+SYSCMD
# We also probe for a working libusb backend at import time so that a
# missing native library (e.g. libusb not installed via brew/apt) degrades
# gracefully to the ADB-only path instead of crashing at runtime.
try:
    import usb.core
    import usb.util
    # Probe for a working backend — raises NoBackendError if libusb is absent
    usb.core.find()
    HAS_PYUSB = True
except ImportError:
    HAS_PYUSB = False
except usb.core.NoBackendError:
    HAS_PYUSB = False
    print("  [!] pyusb is installed but no libusb backend was found.")
    print("      Install libusb to enable USB mode switching and AT+SYSCMD:")
    print("        macOS:  brew install libusb")
    print("        Linux:  sudo apt install libusb-1.0-0")
    print("      Falling back to ADB-only mode.\n")


# =============================================================================
# Orbic USB constants (from Rayhunter installer/src/orbic.rs)
# =============================================================================

VENDOR_ID          = 0x05c6   # Qualcomm
PRODUCT_ID_RNDIS   = 0xf626   # Normal RNDIS / hotspot mode
PRODUCT_ID_RNDIS2  = 0xf622   # RNDIS + serial exposed
PRODUCT_ID_ADB     = 0xf601   # ADB / debug / command mode (target)

# USB serial (CDC ACM) interface for AT+SYSCMD commands
# Interface 1, bulk endpoints 0x02 (OUT) and 0x82 (IN)
SERIAL_INTERFACE   = 1
SERIAL_OUT_EP      = 0x02
SERIAL_IN_EP       = 0x82

# Settle time (seconds) to let the device fully re-enumerate and bring up
# atfwd_daemon after a USB mode switch / reboot before we hammer it with
# AT+SYSCMD commands.
USB_STABILIZE_SEC  = 8


class ATDeviceLost(Exception):
    """Raised when the USB device disappears mid-AT-command (errno 19 / no
    such device). Signals the caller to stop retrying and fall back to ADB."""
    pass


# =============================================================================
# File paths
# =============================================================================

SCRIPT_DIR       = Path(__file__).parent.absolute()
FIRMWARE_DIR     = SCRIPT_DIR / "orbic_fw_c"
FIRMWARE_FILE    = "orbic_app"
BOOT_SCRIPT_FILE = "dagshell_boot.sh"
ROOTSHELL_FILE   = "rootshell"

FIRMWARE_PATH    = FIRMWARE_DIR / FIRMWARE_FILE
BOOT_SCRIPT_PATH = SCRIPT_DIR / BOOT_SCRIPT_FILE
ROOTSHELL_PATH   = FIRMWARE_DIR / ROOTSHELL_FILE

# Remote locations on device
REMOTE_TMP_APP       = "/tmp/orbic_app"
REMOTE_FILE          = "/data/orbic_app"
REMOTE_TMP_BOOT      = "/tmp/dagshell_boot.sh"
REMOTE_BOOT          = "/data/dagshell_boot.sh"
REMOTE_TMP_ROOTSHELL = "/tmp/rootshell"
REMOTE_ROOTSHELL     = "/bin/rootshell"

# USB persistence hook (same method used by deploy_base64.py)
USB_WRAPPER_PATH = "/data/usb/boot_hsusb_composition"
USB_ORIGINAL     = "/sbin/usb/compositions/PRJ_SLT779_9025"

# Boot hook wrapper content — written as a file push rather than echo chains
# to avoid AT+SYSCMD quoting issues
BOOT_HOOK_CONTENT = f"""#!/bin/sh
# DagShell USB boot wrapper
sh {REMOTE_BOOT} &
{USB_ORIGINAL} "$@"
"""


# =============================================================================
# SSL Certificate Generation (fresh certs every deploy)
# =============================================================================

def generate_fresh_certs(output_dir: Path) -> bool:
    """
    Generate a fresh 2-tier PKI (Root CA → Leaf) for each deployment.
    Produces DER-encoded files compatible with BearSSL on the device:
      - root.der        : Root CA certificate (install on client for trust)
      - server.der      : Leaf/server certificate (SAN: 192.168.1.1, localhost)
      - server.key.der  : Leaf private key (PKCS#1 / TraditionalOpenSSL DER)

    Fresh certs on every deploy ensure:
      - No stale/expired certificates from previous installs
      - Each device gets a unique keypair
      - No accidental key reuse across devices
    """
    if not HAS_CRYPTO:
        print("  [!] 'cryptography' package not installed — cannot generate certs.")
        print("      Install with: pip install cryptography")
        print("      Or run manually: python3 orbic_fw_c/gen_pki.py")
        return False

    print("  Generating fresh SSL certificates…")
    output_dir.mkdir(parents=True, exist_ok=True)

    # --- Root CA ---
    root_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    root_subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "DagShell Root CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "DagShell"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    root_cert = (
        x509.CertificateBuilder()
        .subject_name(root_subject)
        .issuer_name(root_subject)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(root_key, hashes.SHA256(), default_backend())
    )

    # --- Leaf / Server Certificate ---
    server_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    server_subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "192.168.1.1"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "DagShell"),
    ])
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_subject)
        .issuer_name(root_subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True,
        )
        .add_extension(
            x509.SubjectAlternativeName([
                x509.IPAddress(ipaddress.ip_address("192.168.1.1")),
                x509.DNSName("localhost"),
            ]),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(root_key, hashes.SHA256(), default_backend())
    )

    # --- Write DER files ---
    root_path = output_dir / "root.der"
    cert_path = output_dir / "server.der"
    key_path  = output_dir / "server.key.der"

    root_path.write_bytes(root_cert.public_bytes(serialization.Encoding.DER))
    cert_path.write_bytes(server_cert.public_bytes(serialization.Encoding.DER))
    key_path.write_bytes(server_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ))

    print(f"  [✓] root.der        ({root_path.stat().st_size} bytes)")
    print(f"  [✓] server.der      ({cert_path.stat().st_size} bytes)")
    print(f"  [✓] server.key.der  ({key_path.stat().st_size} bytes)")
    return True


# =============================================================================
# Prerequisites
# =============================================================================

def check_adb() -> bool:
    """Check if adb is installed and accessible"""
    try:
        result = subprocess.run(
            ["adb", "version"],
            capture_output=True, text=True, timeout=5
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


# =============================================================================
# ADB helpers
# =============================================================================

def adb(args: list, check: bool = True, timeout: int = 60) -> str:
    """Run an adb command, return stdout. Raises on non-zero if check=True."""
    cmd = ["adb"] + args
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if check and result.returncode != 0:
        raise RuntimeError(
            f"adb {' '.join(str(a) for a in args[:3])} failed:\n{result.stderr.strip()}"
        )
    return result.stdout.strip()


def adb_devices() -> list:
    """Return list of serial numbers for connected, authorised ADB devices."""
    try:
        output = adb(["devices"], check=False, timeout=10)
    except Exception:
        return []
    devices = []
    for line in output.splitlines()[1:]:
        line = line.strip()
        if "\t" in line:
            serial, state = line.split("\t", 1)
            if state.strip() == "device":
                devices.append(serial.strip())
    return devices


def wait_for_adb(timeout_sec: int = 60) -> bool:
    """Poll until at least one authorised ADB device appears."""
    print(f"  Waiting for ADB device (up to {timeout_sec}s)", end="", flush=True)
    start = time.time()
    while time.time() - start < timeout_sec:
        if adb_devices():
            print(" — found!")
            return True
        time.sleep(2)
        print(".", end="", flush=True)
    print(" — timed out!")
    return False


def adb_push(local: str, remote: str) -> None:
    """Push a single file to the device."""
    name = Path(local).name
    size = Path(local).stat().st_size
    print(f"  push  {name}  ({size:,} bytes)  →  {remote}")
    adb(["push", local, remote], timeout=120)


def adb_shell(cmd: str, check: bool = True) -> str:
    """Run a shell command on the device via ADB and return output."""
    return adb(["shell", cmd], check=check, timeout=30)


def rootshell_cmd(command: str, check: bool = False) -> str:
    """
    Run a privileged command via /bin/rootshell -c on the device.
    This is the primary way to execute root operations after rootshell is
    installed — mirrors Rayhunter's AdbConnection which routes all commands
    through rootshell.
    """
    # Shell-escape: wrap command in single quotes for rootshell -c,
    # but the whole thing is passed through adb shell which also interprets.
    # Safest: pass as a single argument to rootshell.
    return adb_shell(f'/bin/rootshell -c "{command}"', check=check)


# =============================================================================
# USB mode switch (mirrors Rayhunter enable_command_mode())
# =============================================================================

def find_orbic() -> tuple:
    """
    Search for the Orbic device in any of its known USB modes.
    Returns (device_object, product_id) or (None, None).
    """
    if not HAS_PYUSB:
        return None, None
    for pid in (PRODUCT_ID_ADB, PRODUCT_ID_RNDIS2, PRODUCT_ID_RNDIS):
        dev = usb.core.find(idVendor=VENDOR_ID, idProduct=pid)
        if dev is not None:
            return dev, pid
    return None, None


def switch_to_adb_mode() -> bool:
    """
    Send the USB vendor control request that reboots the Orbic into ADB mode.

    Mirrors Rayhunter's enable_command_mode() (installer/src/orbic.rs):
      Control {
          control_type: ControlType::Vendor,
          recipient:    Recipient::Device,
          request:      0xa0,
          value:        0,
          index:        0,
      }
    bmRequestType = 0x40  (Host→Device | Vendor | Device)

    After the request the device reboots; a STALL/pipe/timeout error is normal
    because the firmware restarts mid-transfer.
    """
    if not HAS_PYUSB:
        print("  [!] pyusb not installed — cannot auto-switch USB mode.")
        print("      Install with: pip install pyusb")
        print("      You will need to manually enable ADB on the device.")
        return False

    dev, pid = find_orbic()
    if dev is None:
        print("  [!] No Orbic device found via USB. Is it plugged in?")
        return False

    mode_label = {
        PRODUCT_ID_RNDIS:  "RNDIS (normal hotspot)",
        PRODUCT_ID_RNDIS2: "RNDIS + serial",
        PRODUCT_ID_ADB:    "ADB/debug (already ready)",
    }.get(pid, f"unknown 0x{pid:04x}")

    print(f"  Orbic found: PID=0x{pid:04x}  ({mode_label})")

    if pid == PRODUCT_ID_ADB:
        print("  Device is already in ADB mode — no switch needed.")
        return True

    print("  Sending mode-switch vendor control request…")
    try:
        try:
            dev.set_configuration()
        except Exception:
            pass

        dev.ctrl_transfer(
            bmRequestType=0x40,
            bRequest=0xa0,
            wValue=0,
            wIndex=0,
            data_or_wLength=None,
            timeout=2000,
        )
        print("  Mode-switch sent. Device is rebooting…")
        return True

    except usb.core.USBError as exc:
        err_lower = str(exc).lower()
        if any(kw in err_lower for kw in ("pipe", "stall", "timeout", "no data")):
            print("  Mode-switch sent (device is rebooting)…")
            return True
        print(f"  [!] Unexpected USB error: {exc}")
        return False
    except Exception as exc:
        print(f"  [!] Error during mode switch: {exc}")
        return False


# =============================================================================
# AT+SYSCMD via USB serial  (mirrors Rayhunter adb_serial_cmd / send_serial_cmd)
# =============================================================================

def open_at_interface():
    """
    Claim the CDC ACM serial interface (interface 1) on the Orbic ADB device
    so we can send AT+SYSCMD commands as root.

    The Orbic's atfwd_daemon runs as root and handles AT+SYSCMD — this is how
    Rayhunter performs privileged operations (chmod, mv, etc.) without needing
    a rooted shell.

    IMPORTANT: The system ADB daemon holds the USB device open, which blocks
    pyusb from claiming interface 1.  We kill it first, claim the serial
    interface, and let the caller restart adb when done.
    """
    if not HAS_PYUSB:
        return None

    print("  Stopping ADB daemon to release USB device…")
    try:
        subprocess.run(["adb", "kill-server"], capture_output=True, timeout=8)
        time.sleep(2)
    except Exception:
        pass

    dev = usb.core.find(idVendor=VENDOR_ID, idProduct=PRODUCT_ID_ADB)
    if dev is None:
        print("  [!] Orbic ADB device not found after killing adb server.")
        return None

    try:
        dev.set_configuration()
    except Exception:
        pass

    try:
        if dev.is_kernel_driver_active(SERIAL_INTERFACE):
            dev.detach_kernel_driver(SERIAL_INTERFACE)
    except Exception:
        pass

    try:
        usb.util.claim_interface(dev, SERIAL_INTERFACE)
        return dev
    except usb.core.USBError as exc:
        err = str(exc).lower()
        print(f"  [!] Could not claim AT serial interface: {exc}")
        if "access" in err or "permission" in err or "not permitted" in err:
            print("  On macOS/Linux try:  sudo python3 deploy_usb.py")
        elif "busy" in err or "resource" in err:
            print("  Serial interface is busy. Try unplugging and replugging the device.")
        try:
            subprocess.run(["adb", "start-server"], capture_output=True, timeout=10)
        except Exception:
            pass
        return None


def at_syscmd_raw(dev, command: str, timeout_ms: int = 3000) -> bool:
    """
    Low-level AT+SYSCMD send over USB bulk endpoints.
    Protocol (from Rayhunter installer/src/orbic.rs send_serial_cmd):
      1. CLASS control: SET_CONTROL_LINE_STATE (0x22), value=3, index=interface
      2. Bulk write to 0x02:  "\\r\\nAT+SYSCMD=<cmd>\\r\\n"
      3. Bulk read  from 0x82: echoed command  (discard)
      4. Bulk read  from 0x82: actual response
      5. Success if response contains "\\r\\nOK\\r\\n"
    """
    if dev is None:
        return False

    payload = f"\r\nAT+SYSCMD={command}\r\n".encode()

    try:
        dev.ctrl_transfer(
            bmRequestType=0x21,
            bRequest=0x22,
            wValue=3,
            wIndex=SERIAL_INTERFACE,
            data_or_wLength=None,
            timeout=timeout_ms,
        )

        dev.write(SERIAL_OUT_EP, payload, timeout=timeout_ms)

        try:
            dev.read(SERIAL_IN_EP, 256, timeout=timeout_ms)
        except usb.core.USBTimeoutError:
            pass

        try:
            raw = bytes(dev.read(SERIAL_IN_EP, 256, timeout=timeout_ms))
            resp = raw.decode("utf-8", errors="replace")
            return "\r\nOK\r\n" in resp
        except usb.core.USBTimeoutError:
            return True

    except usb.core.USBError as exc:
        err_lower = str(exc).lower()
        if getattr(exc, "errno", None) == 19 or "no such device" in err_lower:
            raise ATDeviceLost(str(exc))
        print(f"  [!] USB error in AT+SYSCMD ({command[:40]}…): {exc}")
        return False


def at_cmd(dev, command: str, retries: int = 3) -> bool:
    """Print and execute a single AT+SYSCMD command with automatic retry.

    Propagates ATDeviceLost (does not swallow it) so the caller can abort the
    AT path immediately instead of retrying every command against a dead handle.
    """
    print(f"  AT+SYSCMD: {command}")
    for attempt in range(retries):
        if at_syscmd_raw(dev, command):
            return True
        if attempt < retries - 1:
            time.sleep(1)
    print(f"  [!] Command may have failed after {retries} attempts: {command}")
    return False


def at_health_check(dev, attempts: int = 6, delay: float = 2.0) -> bool:
    """
    Confirm the AT+SYSCMD interface is actually responsive before running the
    bulk of privileged commands.
    """
    print(f"  Health check: probing AT interface ({attempts} attempts)…")
    for i in range(1, attempts + 1):
        try:
            if at_syscmd_raw(dev, "true", timeout_ms=2000):
                print(f"  [✓] AT interface responsive (attempt {i}).")
                return True
        except ATDeviceLost:
            print("  [!] AT interface dropped off the bus during health check.")
            return False
        print(f"  [.] AT interface not ready yet (attempt {i}/{attempts}) — waiting {delay:.0f}s…")
        time.sleep(delay)
    print("  [!] AT interface never became responsive.")
    return False


def release_at_interface(dev) -> None:
    """Release the claimed serial interface and restart ADB server."""
    if dev is None:
        return
    try:
        usb.util.release_interface(dev, SERIAL_INTERFACE)
    except Exception:
        pass
    # Always restart ADB server after releasing the AT interface
    try:
        subprocess.run(["adb", "start-server"], capture_output=True, timeout=10)
    except Exception:
        pass


# =============================================================================
# Rootshell install (mirrors Rayhunter setup_rootshell() in orbic.rs)
# =============================================================================

def check_rootshell_exists() -> bool:
    """
    Check if /bin/rootshell is already installed and functional on the device.
    Returns True if rootshell exists and grants uid=0.

    If Rayhunter was previously installed, rootshell will already be at
    /bin/rootshell with correct SUID permissions — no reinstall needed.
    """
    try:
        out = adb_shell('/bin/rootshell -c "id"', check=False).strip()
        if "uid=0" in out:
            return True
    except Exception:
        pass
    return False


def install_rootshell_via_at(at_dev) -> bool:
    """
    Install the rootshell SUID binary using AT+SYSCMD (3 commands).

    Mirrors Rayhunter setup_rootshell() (installer/src/orbic.rs):
      1. Push rootshell to /tmp/rootshell via ADB
      2. AT+SYSCMD: cp /tmp/rootshell /bin/rootshell
      3. AT+SYSCMD: chown root:root /bin/rootshell
      4. AT+SYSCMD: chmod 4755 /bin/rootshell
      5. Verify: adb shell /bin/rootshell -c id → uid=0

    AT+SYSCMD runs via atfwd_daemon (PID 1 child, uid=0) which has the
    authority to chown/chmod files owned by any user.

    Returns True if rootshell is installed and verified, False otherwise.
    May raise ATDeviceLost if the device drops mid-install.
    """
    print("  Installing rootshell via AT+SYSCMD (3 commands)…")

    # The rootshell binary was already pushed to /tmp/rootshell via ADB
    # in the file push step. Now use AT+SYSCMD to install it with root perms.
    if not at_cmd(at_dev, f"cp {REMOTE_TMP_ROOTSHELL} {REMOTE_ROOTSHELL}"):
        print("  [!] Failed to copy rootshell to /bin/")
        return False

    if not at_cmd(at_dev, f"chown root:root {REMOTE_ROOTSHELL}"):
        print("  [!] Failed to chown rootshell")
        return False

    if not at_cmd(at_dev, f"chmod 4755 {REMOTE_ROOTSHELL}"):
        print("  [!] Failed to chmod rootshell")
        return False

    print("  rootshell installed. Releasing AT interface for verification…")

    # Release AT interface and restart ADB to verify rootshell
    release_at_interface(at_dev)
    time.sleep(2)

    if not wait_for_adb(timeout_sec=30):
        print("  [!] ADB did not reconnect after rootshell install.")
        return False

    # Verify rootshell grants uid=0
    out = adb_shell('/bin/rootshell -c "id"', check=False).strip()
    if "uid=0" in out:
        print(f"  [✓] rootshell verified: {out}")
        return True
    else:
        print(f"  [✗] rootshell verification failed: {out}")
        return False


# =============================================================================
# Install via rootshell (primary path for all privileged operations)
# =============================================================================

def install_via_rootshell(has_ssl: bool, ssl_root: Path) -> None:
    """
    Install DagShell using /bin/rootshell for all privileged operations.
    This is the primary install path — works on both fresh devices (after
    AT+SYSCMD rootshell install) and Rayhunter-first devices (rootshell
    already exists).

    Mirrors Rayhunter's setup_rayhunter() which routes all commands through
    its AdbConnection (which uses rootshell -c internally).

    NOTE: iptables via rootshell FAILS with "Permission denied, you must be
    root" because SUID doesn't grant CAP_NET_ADMIN capability. Firewall rules
    are applied by dagshell_boot.sh which runs from init context on boot.
    """
    print()
    print("  Installing files via rootshell…")

    # Move files from /tmp to /data
    for src, dst, label in [
        (REMOTE_TMP_APP,  REMOTE_FILE,  "firmware"),
        (REMOTE_TMP_BOOT, REMOTE_BOOT,  "boot script"),
    ]:
        print(f"  rootshell: cp {src} → {dst}  ({label})")
        rootshell_cmd(f"cp {src} {dst}")

    # Set permissions
    print("  rootshell: setting permissions…")
    rootshell_cmd(f"chmod 755 {REMOTE_FILE}")
    rootshell_cmd(f"chmod 755 {REMOTE_BOOT}")

    # Install SSL certificates
    if has_ssl:
        print("  rootshell: installing SSL certificates…")
        rootshell_cmd("cp /tmp/server.der /data/server.der")
        rootshell_cmd("cp /tmp/server.key.der /data/server.key.der")
        rootshell_cmd("cp /tmp/root.der /data/root.der")
        rootshell_cmd("chmod 644 /data/server.der /data/server.key.der /data/root.der")

    # Verify firmware landed
    check_out = rootshell_cmd(f"ls -la {REMOTE_FILE}", check=False)
    if "No such file" in check_out or not check_out.strip():
        print(f"  [✗] {REMOTE_FILE} not found after copy!")
        sys.exit(1)
    print(f"  [✓] Verified: {check_out.strip()}")

    # Install boot hook — push wrapper script to /tmp, then rootshell cp
    print()
    print("  Setting up boot persistence (USB composition hook)…")

    # Write boot hook content to a temp file locally, push via ADB, then cp
    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', suffix='.sh', delete=False) as f:
        f.write(BOOT_HOOK_CONTENT)
        tmp_hook = f.name

    try:
        adb_push(tmp_hook, "/tmp/boot_hook.sh")
    finally:
        Path(tmp_hook).unlink(missing_ok=True)

    # Clean stale dnsmasq references
    rootshell_cmd("sed -i '/dagshell_boot.sh/d' /data/dnsmasq.conf")

    # Install the hook
    rootshell_cmd(f"mkdir -p /data/usb")
    rootshell_cmd(f"cp /tmp/boot_hook.sh {USB_WRAPPER_PATH}")
    rootshell_cmd(f"chmod 755 {USB_WRAPPER_PATH}")

    # Verify hook
    hook_check = rootshell_cmd(f"cat {USB_WRAPPER_PATH}", check=False)
    if "dagshell_boot.sh" in hook_check:
        print("  [✓] Boot hook installed and verified.")
    else:
        print("  [!] Boot hook may not have installed correctly.")
        print(f"      Content: {hook_check[:200]}")

    # NOTE: We do NOT apply iptables here — rootshell lacks CAP_NET_ADMIN.
    # dagshell_boot.sh applies firewall rules from init context on boot.
    print()
    print("  [i] Firewall rules will be applied on next boot by dagshell_boot.sh")
    print("      (rootshell lacks CAP_NET_ADMIN for iptables)")


# =============================================================================
# Fallback: install via root ADB shell (Rayhunter-first devices)
# =============================================================================

def install_via_adb_root(has_ssl: bool, ssl_root: Path) -> None:
    """
    Fallback install path when ADB shell is already root (uid=0).
    This happens on Rayhunter-first devices or when the stock device
    was already rooted. Uses direct adb shell commands.
    """
    print("  [✓] ADB shell has root — using direct adb shell install.")
    print()
    print("  Moving files to /data/ via adb shell…")
    for src, dst in [
        (REMOTE_TMP_APP,  REMOTE_FILE),
        (REMOTE_TMP_BOOT, REMOTE_BOOT),
    ]:
        print(f"  cp {src} → {dst}")
        adb_shell(f"cp {src} {dst}", check=False)

    print("  Setting permissions…")
    adb_shell(f"chmod 755 {REMOTE_FILE}",  check=False)
    adb_shell(f"chmod 755 {REMOTE_BOOT}",  check=False)

    if has_ssl:
        print("  Installing SSL certificates…")
        adb_shell("cp /tmp/server.der     /data/server.der",     check=False)
        adb_shell("cp /tmp/server.key.der /data/server.key.der", check=False)
        adb_shell("cp /tmp/root.der       /data/root.der",       check=False)
        adb_shell("chmod 644 /data/server.der /data/server.key.der /data/root.der", check=False)

    # Verify firmware landed
    check_out = adb_shell(f"ls -la {REMOTE_FILE} 2>&1", check=False)
    if "No such file" in check_out or not check_out.strip():
        print(f"  [✗] {REMOTE_FILE} not found after copy!")
        sys.exit(1)
    print(f"  [✓] Verified: {check_out.strip()}")

    # Configure network (ADB root shell has full capabilities)
    print()
    print("  Configuring network (iptables / NAT)…")
    adb_shell("iptables -I INPUT -p tcp --dport 8443 -j ACCEPT",             check=False)
    adb_shell("iptables -I INPUT -p tcp --dport 8080 -j ACCEPT",             check=False)
    adb_shell("iptables -t nat -F PREROUTING",                               check=False)
    adb_shell("echo 1 > /proc/sys/net/ipv4/ip_forward",                     check=False)
    adb_shell("iptables -t nat -A POSTROUTING -o rmnet_data0 -j MASQUERADE", check=False)
    adb_shell("iptables -A FORWARD -i bridge0 -o rmnet_data0 -j ACCEPT",     check=False)
    adb_shell("iptables -A FORWARD -i rmnet_data0 -o bridge0 -m state "
              "--state RELATED,ESTABLISHED -j ACCEPT",                        check=False)

    # Boot persistence
    print()
    print("  Setting up boot persistence (USB composition hook)…")
    adb_shell(f"sed -i '/dagshell_boot.sh/d' /data/dnsmasq.conf",          check=False)
    adb_shell(f"mkdir -p /data/usb",                                         check=False)
    adb_shell(f"rm -f {USB_WRAPPER_PATH}",                                  check=False)
    adb_shell(f"echo '#!/bin/sh' > {USB_WRAPPER_PATH}",                    check=False)
    adb_shell(f"echo '# DagShell USB boot wrapper' >> {USB_WRAPPER_PATH}", check=False)
    adb_shell(f"echo 'sh {REMOTE_BOOT} &' >> {USB_WRAPPER_PATH}",          check=False)
    adb_shell(f"echo '{USB_ORIGINAL} \"$@\"' >> {USB_WRAPPER_PATH}",       check=False)
    adb_shell(f"chmod +x {USB_WRAPPER_PATH}",                              check=False)
    print("  [✓] Boot hook installed.")


# =============================================================================
# Post-deploy verification  (mirrors Rayhunter test_rayhunter() in orbic.rs)
# =============================================================================

def verify_deployment() -> bool:
    """
    Prove DagShell is running via ADB port forwarding + host-side curl.

    The device's busybox wget has NO TLS support, so we can't test HTTPS
    from on-device. Instead we:
      1. Check process is alive (adb shell pgrep)
      2. Check port 8443 is listening (adb shell /proc/net/tcp)
      3. Set up ADB port forwarding (adb forward tcp:18443 tcp:8443)
      4. Use host-side curl -k to make a REAL TLS connection
      5. Verify we get actual HTML back from the DagShell web UI
      6. Remove ADB port forwarding when done
    """
    print("\n" + "=" * 58)
    print("  Verifying deployment (ADB port-forward + host TLS)")
    print("=" * 58)

    all_ok = True

    # ── Check 1: process alive ────────────────────────────────────────────────
    pid = adb_shell("pgrep -f orbic_app 2>/dev/null", check=False).strip()
    if pid:
        print(f"  [✓] Process   : orbic_app is running  (PID {pid})")
    else:
        print("  [✗] Process   : orbic_app NOT found in process list")
        all_ok = False

    # ── Check 2: port 8443 listening (poll up to 30s) ─────────────────────────
    port_open = False
    PORT_TIMEOUT = 30
    print(f"  Waiting for port 8443 (up to {PORT_TIMEOUT}s)", end="", flush=True)

    start = time.time()
    while time.time() - start < PORT_TIMEOUT:
        # grep for hex port 20FB in /proc/net/tcp (works on busybox)
        for tcp_file in ("/proc/net/tcp", "/proc/net/tcp6"):
            entry = adb_shell(
                f"grep -i ':20FB ' {tcp_file} 2>/dev/null | head -1",
                check=False,
            ).strip()
            if entry and "20FB" in entry.upper():
                elapsed = int(time.time() - start)
                print(f" — UP after {elapsed}s!")
                print(f"  [✓] Port 8443 : LISTENING  ({tcp_file})")
                port_open = True
                break
        if port_open:
            break
        # Also try nc probe
        nc_out = adb_shell("nc -z 127.0.0.1 8443 2>&1; echo rc=$?", check=False).strip()
        if "rc=0" in nc_out:
            elapsed = int(time.time() - start)
            print(f" — UP after {elapsed}s!")
            print("  [✓] Port 8443 : REACHABLE  (nc probe)")
            port_open = True
            break
        print(".", end="", flush=True)
        time.sleep(3)

    if not port_open:
        print(f" — NOT listening after {PORT_TIMEOUT}s!")
        print("  [✗] Port 8443 : NOT listening")
        # Grab orbic_app stderr — kill the running instance, restart
        # briefly to capture startup errors, then leave it running.
        # NOTE: Cannot restart orbic_app from rootshell/ADB context — Android
        # SELinux blocks socket creation. The app must run from init context
        # (boot script). Check if boot script ran properly.
        boot_hook = adb_shell(f"cat {USB_WRAPPER_PATH} 2>/dev/null", check=False)
        if "dagshell_boot.sh" not in boot_hook:
            print("  [!] Boot hook missing — dagshell_boot.sh may not have run")
        boot_log = adb_shell("cat /data/boot_diag.log 2>/dev/null", check=False).strip()
        if boot_log:
            print("  Boot log (last 5 lines):")
            for line in boot_log.splitlines()[-5:]:
                print(f"    {line}")
        else:
            print("  No boot log found — device may need more time or another reboot")
            print("  Try: adb shell reboot; sleep 60; python3 deploy_usb.py --verify-only")
        all_ok = False

    # ── Check 3: cert files on device ─────────────────────────────────────────
    cert_check = adb_shell(
        "ls -la /data/server.der /data/server.key.der /data/root.der 2>&1",
        check=False,
    ).strip()
    cert_files_ok = (
        "server.der" in cert_check
        and "server.key.der" in cert_check
        and "No such file" not in cert_check
    )
    if cert_files_ok:
        print("  [✓] SSL certs : present on device (/data/*.der)")
    else:
        print("  [✗] SSL certs : MISSING from /data/")
        print(f"      {cert_check}")
        all_ok = False

    # ── Check 4: real TLS probe via ADB port forwarding ───────────────────────
    web_ok = False

    if port_open:
        # Set up ADB port forwarding: host:18443 → device:8443
        LOCAL_PORT = 18443
        print(f"  Setting up ADB port forward (localhost:{LOCAL_PORT} → device:8443)…")
        try:
            adb(["forward", f"tcp:{LOCAL_PORT}", "tcp:8443"], check=True, timeout=10)
        except Exception as exc:
            print(f"  [!] ADB forward failed: {exc}")
            LOCAL_PORT = 0

        if LOCAL_PORT:
            MAX_ATTEMPTS = 5
            print(f"  Probing https://localhost:{LOCAL_PORT}/ with host curl ({MAX_ATTEMPTS} attempts)…")

            for attempt in range(1, MAX_ATTEMPTS + 1):
                try:
                    result = subprocess.run(
                        ["curl", "-sk", "--connect-timeout", "5", "--max-time", "10",
                         f"https://localhost:{LOCAL_PORT}/"],
                        capture_output=True, text=True, timeout=15,
                    )
                    body = result.stdout.strip()
                    body_lower = body.lower()

                    if body and any(kw in body_lower for kw in (
                        "<html", "<!doctype", "dagshell", "orbic"
                    )):
                        # Show a snippet of the HTML
                        snippet = body[:200].replace('\n', ' ')
                        print(f"  [✓] Web server : HTML received!  (attempt {attempt})")
                        print(f"      Preview: {snippet[:120]}…")
                        web_ok = True
                        break
                    elif body:
                        print(f"  [?] Attempt {attempt}/{MAX_ATTEMPTS}: got response but no HTML marker")
                        print(f"      Body: {body[:120]}")
                    else:
                        stderr = result.stderr.strip().lower()
                        if "connection refused" in stderr:
                            print(f"  [!] Attempt {attempt}/{MAX_ATTEMPTS}: connection refused")
                        elif "reset" in stderr:
                            print(f"  [!] Attempt {attempt}/{MAX_ATTEMPTS}: connection reset — TLS handshake failed")
                        elif stderr:
                            print(f"  [!] Attempt {attempt}/{MAX_ATTEMPTS}: {result.stderr.strip()[:120]}")
                        else:
                            print(f"  [!] Attempt {attempt}/{MAX_ATTEMPTS}: empty response")

                except subprocess.TimeoutExpired:
                    print(f"  [!] Attempt {attempt}/{MAX_ATTEMPTS}: timeout")
                except FileNotFoundError:
                    print("  [!] curl not found — install curl to enable TLS verification")
                    break

                if attempt < MAX_ATTEMPTS:
                    time.sleep(3)

            # Clean up port forwarding
            try:
                adb(["forward", "--remove", f"tcp:{LOCAL_PORT}"], check=False, timeout=5)
            except Exception:
                pass

    if not web_ok and port_open and cert_files_ok:
        print("  [✗] Web server : TLS handshake FAILED — BearSSL could not serve content")
        print("      The app is running and port is open but HTTPS is broken.")
        print("      Check /data/server.der + server.key.der are valid DER certs.")
        all_ok = False
    elif not web_ok:
        print("  [✗] Web server : could not verify (port not open or certs missing)")
        all_ok = False

    # ── Check 5: boot log ─────────────────────────────────────────────────────
    boot_log = adb_shell("tail -15 /data/boot_diag.log 2>/dev/null", check=False).strip()
    if boot_log:
        print()
        print("  Boot log  (/data/boot_diag.log):")
        for line in boot_log.splitlines():
            print(f"    {line}")

    # ── Summary ───────────────────────────────────────────────────────────────
    print()
    if all_ok:
        print("  ╔══════════════════════════════════════════════════════╗")
        print("  ║  [✓] ALL CHECKS PASSED — DagShell is LIVE!         ║")
        print("  ║  Connect to device WiFi → https://192.168.1.1:8443 ║")
        print("  ╚══════════════════════════════════════════════════════╝")
    else:
        print("  [✗] One or more checks FAILED.")
        print("  Troubleshooting:")
        print("    • Wait 15s and re-run:  python3 deploy_usb.py --verify-only")
        print("    • Check orbic_app stderr:  adb shell '/data/orbic_app </dev/null 2>&1'")
        print("    • Check boot log above for errors")
    print("=" * 58)
    return all_ok


# =============================================================================
# Main deployment flow
# =============================================================================

def deploy() -> None:

    banner = "=" * 58
    print(banner)
    print("  DagShell USB Deployer  v2.0")
    print("  (Rayhunter orbic-usb method — USB cable, no WiFi needed)")
    print("  Root gain: AT+SYSCMD → rootshell SUID → privileged ops")
    print(banner)

    # ── Step 1: prerequisites ─────────────────────────────────────────────────
    print("\n[1/8] Checking prerequisites…")

    if not check_adb():
        print("  [✗] 'adb' not found in PATH. Install Android Debug Bridge:")
        print("        macOS:   brew install android-platform-tools")
        print("        Linux:   sudo apt install adb")
        print("        Windows: https://developer.android.com/tools/releases/platform-tools")
        sys.exit(1)
    print("  [✓] adb found")

    if HAS_PYUSB:
        print("  [✓] pyusb found — automatic USB mode switching enabled")
    else:
        print("  [!] pyusb not installed — manual ADB mode required")
        print("      Install with: pip install pyusb")

    if not FIRMWARE_PATH.exists():
        print(f"  [✗] Firmware binary not found: {FIRMWARE_PATH}")
        print("      Build it first:  ./build.sh  (macOS/Linux)  or  .\\build.ps1  (Windows)")
        sys.exit(1)
    size_kb = FIRMWARE_PATH.stat().st_size // 1024
    print(f"  [✓] Firmware: {FIRMWARE_PATH.name}  ({size_kb} KB)")

    if not BOOT_SCRIPT_PATH.exists():
        print(f"  [✗] Boot script not found: {BOOT_SCRIPT_PATH}")
        sys.exit(1)
    print(f"  [✓] Boot script: {BOOT_SCRIPT_PATH.name}")

    if not ROOTSHELL_PATH.exists():
        print(f"  [✗] rootshell binary not found: {ROOTSHELL_PATH}")
        print("      Build it:  cd orbic_fw_c && "
              "arm-cortex_a8-linux-gnueabi-as -meabi=5 -o rootshell.o rootshell.S && "
              "arm-cortex_a8-linux-gnueabi-ld -o rootshell rootshell.o && "
              "arm-cortex_a8-linux-gnueabi-strip rootshell")
        sys.exit(1)
    rs_size = ROOTSHELL_PATH.stat().st_size
    print(f"  [✓] rootshell: {ROOTSHELL_PATH.name}  ({rs_size} bytes)")

    # ── Step 2: detect device ─────────────────────────────────────────────────
    print("\n[2/8] Detecting Orbic device…")

    if HAS_PYUSB:
        dev_obj, cur_pid = find_orbic()
        if dev_obj is None:
            print("  [✗] No Orbic device found on USB.")
            print("      Make sure the USB cable is connected and the device is on.")
            sys.exit(1)
        pid_names = {
            PRODUCT_ID_RNDIS:  "RNDIS hotspot",
            PRODUCT_ID_RNDIS2: "RNDIS+serial",
            PRODUCT_ID_ADB:    "ADB/debug",
        }
        print(f"  [✓] Found Orbic: PID=0x{cur_pid:04x}  ({pid_names.get(cur_pid, 'unknown')})")
    else:
        cur_pid = None
        print("  (pyusb unavailable — skipping USB detection)")

    # ── Step 3: mode switch ───────────────────────────────────────────────────
    print("\n[3/8] Switching to ADB mode…")

    need_reboot = False
    if HAS_PYUSB and cur_pid != PRODUCT_ID_ADB:
        if not switch_to_adb_mode():
            print("  [✗] Failed to send mode-switch command.")
            print("  Try unplugging, replugging, and re-running this script.")
            sys.exit(1)
        need_reboot = True
    elif not HAS_PYUSB:
        print("  Skipped (pyusb unavailable). Assuming ADB is already enabled.")
    else:
        print("  Device is already in ADB mode — no reboot needed.")

    if need_reboot:
        wait_secs = 20
        print(f"  Waiting {wait_secs}s for device to reboot and re-enumerate…")
        time.sleep(wait_secs)

    # ── Step 4: wait for ADB ──────────────────────────────────────────────────
    print("\n[4/8] Waiting for ADB device…")
    if not wait_for_adb(timeout_sec=90):
        print("  [✗] ADB device not detected after 90 seconds.")
        print("  Troubleshooting:\n"
              "    • Run 'adb devices' and check for 'unauthorized' status\n"
              "    • Try: adb kill-server && adb start-server\n"
              "    • Replug the USB cable")
        sys.exit(1)

    # ── Step 5: prepare device ────────────────────────────────────────────────
    print("\n[5/8] Preparing device…")
    print("  Stopping any running orbic_app…")
    adb_shell("pkill -f orbic_app 2>/dev/null; true", check=False)
    print("  Ensuring /tmp is writable…")
    adb_shell("mkdir -p /tmp", check=False)
    time.sleep(1)

    # ── Step 6: push files via ADB ────────────────────────────────────────────
    print("\n[6/8] Pushing files to device via ADB…")

    adb_push(str(FIRMWARE_PATH), REMOTE_TMP_APP)
    adb_push(str(BOOT_SCRIPT_PATH), REMOTE_TMP_BOOT)
    adb_push(str(ROOTSHELL_PATH), REMOTE_TMP_ROOTSHELL)

    # Generate fresh SSL certificates for this deployment
    ssl_cert = FIRMWARE_DIR / "server.der"
    ssl_key  = FIRMWARE_DIR / "server.key.der"
    ssl_root = FIRMWARE_DIR / "root.der"

    has_ssl = generate_fresh_certs(FIRMWARE_DIR)

    if has_ssl:
        print("  Pushing SSL certificates…")
        adb_push(str(ssl_cert), "/tmp/server.der")
        adb_push(str(ssl_key),  "/tmp/server.key.der")
        if ssl_root.exists():
            adb_push(str(ssl_root), "/tmp/root.der")
    else:
        print("  [!] SSL cert generation failed — HTTPS will not be available.")
        print("      Install cryptography: pip install cryptography")

    print("  All files pushed to /tmp/")

    # ── Step 7: install rootshell ─────────────────────────────────────────────
    print("\n[7/8] Installing rootshell (SUID root escalation)…")

    # Check if rootshell is already installed (Rayhunter-first device)
    rootshell_ready = check_rootshell_exists()

    if rootshell_ready:
        print("  [✓] rootshell already installed and functional (Rayhunter compatible)")
        print("      Skipping AT+SYSCMD rootshell install.")
    else:
        print("  rootshell not found — installing via AT+SYSCMD…")

        # Also check if ADB shell is already root (no rootshell needed)
        uid_line = adb_shell("id", check=False).split("\n")[0].strip()
        is_adb_root = "uid=0" in uid_line
        print(f"  ADB shell identity: {uid_line or '(unknown)'}")

        if is_adb_root:
            print("  [✓] ADB shell is root — installing rootshell directly.")
            adb_shell(f"cp {REMOTE_TMP_ROOTSHELL} {REMOTE_ROOTSHELL}", check=False)
            adb_shell(f"chown root:root {REMOTE_ROOTSHELL}", check=False)
            adb_shell(f"chmod 4755 {REMOTE_ROOTSHELL}", check=False)
            rootshell_ready = check_rootshell_exists()
            if rootshell_ready:
                print("  [✓] rootshell installed via root ADB shell.")
            else:
                print("  [!] rootshell install via ADB failed — will use direct root ADB path.")
        else:
            # Fresh device, non-root ADB: must use AT+SYSCMD
            print("  ADB shell is NOT root — using AT+SYSCMD for rootshell install.")
            print("  Opening USB AT command interface (interface 1)…")
            at_dev = open_at_interface()

            if at_dev is not None:
                if need_reboot:
                    print(f"  Letting device settle for {USB_STABILIZE_SEC}s after reboot…")
                    time.sleep(USB_STABILIZE_SEC)

                if at_health_check(at_dev):
                    try:
                        rootshell_ready = install_rootshell_via_at(at_dev)
                        at_dev = None  # released inside install_rootshell_via_at
                    except ATDeviceLost as exc:
                        print(f"  [!] AT interface dropped during rootshell install ({exc}).")
                        release_at_interface(at_dev)
                        at_dev = None
                else:
                    print("  [!] AT interface not responsive.")
                    release_at_interface(at_dev)
                    at_dev = None
            else:
                print("  [!] Could not open AT interface.")

            if not rootshell_ready:
                print()
                print("  [✗] FATAL: Cannot gain root on this device.")
                print("      rootshell install via AT+SYSCMD failed and ADB shell is not root.")
                print()
                print("      Troubleshooting:")
                print("        • Ensure the USB cable supports data (not charge-only)")
                print("        • Try:  sudo python3 deploy_usb.py  (for USB permissions)")
                print("        • Install Rayhunter first (provides rootshell)")
                sys.exit(1)

    # ── Step 8: install DagShell ──────────────────────────────────────────────
    print("\n[8/8] Installing DagShell…")

    # Ensure ADB is ready
    if not wait_for_adb(timeout_sec=30):
        print("  [✗] ADB did not reconnect.")
        sys.exit(1)

    # Check which install path to use
    uid_line = adb_shell("id", check=False).split("\n")[0].strip()
    is_adb_root = "uid=0" in uid_line

    if rootshell_ready:
        # Primary path: rootshell for all privileged ops
        install_via_rootshell(has_ssl, ssl_root)
    elif is_adb_root:
        # Fallback: ADB shell is root (Rayhunter-first device without rootshell)
        install_via_adb_root(has_ssl, ssl_root)
    else:
        # Should never reach here — caught in step 7
        print("  [✗] No root access available.")
        sys.exit(1)

    # ── Reboot device to activate boot hook ───────────────────────────────────
    # NOTE: orbic_app CANNOT be started via rootshell pre-reboot because
    # Android SELinux blocks socket creation from the ADB shell security
    # context (even as uid=0). The app must be started by dagshell_boot.sh
    # which runs from init context with full capabilities.
    print()
    print("  Rebooting device to activate boot persistence…")
    print("  (dagshell_boot.sh will apply iptables + start orbic_app on boot)")
    rootshell_cmd("reboot")

    # Wait for reboot cycle
    print("  Waiting 30s for reboot…", end="", flush=True)
    time.sleep(30)
    print(" done.")

    # Reconnect ADB after reboot and run full verification.
    # The boot-started orbic_app runs from init context (has full SELinux
    # permissions for socket creation, unlike rootshell/ADB context).
    if not wait_for_adb(timeout_sec=90):
        print("  [!] ADB did not reconnect after reboot.")
        print("      The device may need more time. Try:")
        print("        python3 deploy_usb.py --verify-only")
    else:
        # Give boot script time to start orbic_app.
        # Boot hook fires early in init, dagshell_boot.sh does sleep 5 before
        # starting orbic_app, plus additional time for BearSSL init + bind.
        print("  Waiting 25s for dagshell_boot.sh to start orbic_app…")
        time.sleep(25)
        # Full post-reboot verification (process + port + TLS)
        verify_deployment()

    # ── Done ──────────────────────────────────────────────────────────────────
    print()
    print(banner)
    print("  Deployment complete!")
    print(banner)
    print(f"  Firmware   : {REMOTE_FILE}")
    print(f"  Boot hook  : {REMOTE_BOOT}  →  {USB_WRAPPER_PATH}")
    print(f"  rootshell  : {REMOTE_ROOTSHELL}  (SUID root)")
    if has_ssl:
        print("  Web UI     : https://192.168.1.1:8443/")
        print("  (Connect to device WiFi, then open the URL in your browser.)")
        print("  (Accept the self-signed certificate warning.)")
    else:
        print("  Note: rebuild with SSL certs for HTTPS access.")
    print(banner)

    # ── Cleanup: kill ADB server on exit ──────────────────────────────────────
    print()
    print("  Stopping ADB server…")
    try:
        subprocess.run(["adb", "kill-server"], capture_output=True, timeout=8)
        print("  [✓] ADB server stopped.")
    except Exception:
        pass


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(
        description="Deploy DagShell to Orbic RCL400 via USB (Rayhunter method)"
    )
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="Skip deployment — just verify an existing DagShell install via ADB",
    )
    args = parser.parse_args()

    if args.verify_only:
        print("=" * 58)
        print("  DagShell USB Verifier  (--verify-only)")
        print("=" * 58)
        if not check_adb():
            print("  [✗] adb not found. Install Android Debug Bridge first.")
            sys.exit(1)
        if not adb_devices():
            print("  [✗] No ADB device connected.")
            sys.exit(1)
        ok = verify_deployment()
        # Kill ADB server on exit
        print()
        print("  Stopping ADB server…")
        try:
            subprocess.run(["adb", "kill-server"], capture_output=True, timeout=8)
            print("  [✓] ADB server stopped.")
        except Exception:
            pass
        sys.exit(0 if ok else 1)
    else:
        deploy()

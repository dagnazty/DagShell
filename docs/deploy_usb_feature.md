# USB Cable Deployment (`deploy_usb.py`)

## Overview

`deploy_usb.py` is a one-command installer that deploys DagShell firmware to the Orbic RCL400 entirely over a USB cable — no existing WiFi connection or network access to the device required. It mirrors the approach used by the [Rayhunter](https://github.com/EFForg/rayhunter) project's `orbic-usb` installer and extends it with DagShell-specific setup, TLS certificate management, and post-deploy verification.

---

## Why This Matters

Previous DagShell installers (`deploy_base64.py`, `deploy_net.py`) required the user to already be connected to the Orbic's WiFi hotspot or have the device in a known network state. This created a chicken-and-egg problem for fresh devices, brick-recovery scenarios, or cases where the WiFi interface was misconfigured.

`deploy_usb.py` eliminates that dependency: if you can plug in a USB cable and run `python3 deploy_usb.py`, you can get DagShell running — even on a **completely fresh device** that has never been rooted.

---

## Root Gain Strategy (`rootshell`)

### The Problem
Fresh Orbic RCL400 devices have an ADB shell that runs as `uid=2000` (shell user), **NOT root**. This means operations like writing to `/data/`, `chmod`, `chown`, and `iptables` all fail silently or with permission errors.

### The Solution: SUID rootshell (mirrors Rayhunter `setup_rootshell()`)
DagShell includes a tiny (408-byte) SUID root binary called `rootshell` — pure ARM assembly with zero libc dependencies. When owned by root with the SUID bit set (`chmod 4755`), it escalates `uid=2000` → `uid=0` and executes `/bin/sh`.

**How rootshell is installed (3 AT+SYSCMD commands):**
1. `adb push orbic_fw_c/rootshell /tmp/rootshell` — ADB user can always write to `/tmp`
2. `AT+SYSCMD=cp /tmp/rootshell /bin/rootshell` — atfwd_daemon runs as root
3. `AT+SYSCMD=chown root:root /bin/rootshell` — set ownership
4. `AT+SYSCMD=chmod 4755 /bin/rootshell` — set SUID bit

After installation, **all remaining privileged operations** use:
```sh
adb shell /bin/rootshell -c "command"
```

This is the same approach Rayhunter uses — their `AdbConnection` routes all privileged commands through rootshell internally.

### Rayhunter Compatibility
If Rayhunter was previously installed on the device, `/bin/rootshell` already exists with the correct SUID permissions. **DagShell detects this and skips the AT+SYSCMD install entirely** — no reinstall or conflict.

### CAP_NET_ADMIN Limitation
SUID binaries do not inherit `CAP_NET_ADMIN`, so `iptables` commands via rootshell fail with "Permission denied, you must be root". Firewall rules are instead applied by `dagshell_boot.sh` which runs from the init context on boot (has full capabilities).

### rootshell Source (`orbic_fw_c/rootshell.S`)
```asm
_start:
    setgroups(2, [3003, 3004])   @ AID_INET, AID_NET_RAW
    setgid(0)
    setuid(0)
    execve("/bin/sh", argv, envp)  @ preserves -c "cmd" args
```

Build locally:
```sh
cd orbic_fw_c
arm-cortex_a8-linux-gnueabi-as -meabi=5 -o rootshell.o rootshell.S
arm-cortex_a8-linux-gnueabi-ld -o rootshell rootshell.o
arm-cortex_a8-linux-gnueabi-strip rootshell
```

A prebuilt binary is included in the repo. GitHub Actions automatically cross-compiles rootshell on every release (see `.github/workflows/build-rootshell.yml`).

---

## What It Does

### 1. USB Mode Switch (mirrors Rayhunter `enable_command_mode()`)
Detects the Orbic on USB via PyUSB. If the device is in normal RNDIS hotspot mode (`PID 0xf626`) it sends the vendor control request (`bmRequestType=0x40`, `bRequest=0xa0`) that reboots the device into ADB/debug mode (`PID 0xf601`). This is the identical mechanism Rayhunter uses.

### 2. File Deployment via ADB
Once in ADB mode, all firmware files are pushed to `/tmp/` (always writable by the ADB shell user):

| Local | Device (tmp) | Device (final) |
|---|---|---|
| `orbic_fw_c/orbic_app` | `/tmp/orbic_app` | `/data/orbic_app` |
| `dagshell_boot.sh` | `/tmp/dagshell_boot.sh` | `/data/dagshell_boot.sh` |
| `orbic_fw_c/rootshell` | `/tmp/rootshell` | `/bin/rootshell` |
| `orbic_fw_c/server.der` | `/tmp/server.der` | `/data/server.der` |
| `orbic_fw_c/server.key.der` | `/tmp/server.key.der` | `/data/server.key.der` |
| `orbic_fw_c/root.der` | `/tmp/root.der` | `/data/root.der` |

### 3. rootshell Install (Step 7)
Uses AT+SYSCMD (only 3 commands) to install rootshell with SUID root permissions. After verification, all subsequent privileged operations go through `rootshell -c`.

### 4. DagShell Install (Step 8)
Uses `rootshell -c` to:
- Copy files from `/tmp/` to `/data/`
- Set file permissions
- Install the boot hook wrapper at `/data/usb/boot_hsusb_composition`

### 5. Boot Persistence (USB Composition Hook)
Installs a wrapper at `/data/usb/boot_hsusb_composition` that runs `dagshell_boot.sh` on every USB init cycle, then chains to the original composition script. Written as a file push + rootshell cp (avoids AT+SYSCMD quoting issues).

### 6. Device Reboot
After installation, the device is rebooted to activate the boot hook. On boot, `dagshell_boot.sh`:
- Opens firewall ports 8443 and 8080 (from init context, has CAP_NET_ADMIN)
- Configures NAT/masquerade for internet passthrough
- Starts `orbic_app` with `</dev/null` (prevents fd 0 bug)
- Starts nc shell listener on port 24

### 7. Post-Deploy Verification (mirrors Rayhunter `test_rayhunter()`)
After reboot, verifies DagShell is live entirely through ADB — no WiFi needed:
- Process check via `pgrep -f orbic_app`
- Port 8443 check via `netstat`, `nc -z`, and `/proc/net/tcp`
- TLS probe via `busybox wget --no-check-certificate https://127.0.0.1:8443/`
- "Connection reset by peer" is treated as success (BearSSL rejects BusyBox cipher suites but TCP+TLS exchange confirms server is live)
- Boot log tail from `/data/boot_diag.log`

---

## Deploy Flow (8 Steps)

```
[1/8] Check prerequisites (adb, pyusb, firmware, rootshell binary)
[2/8] Detect Orbic device on USB
[3/8] Switch to ADB mode (vendor control request)
[4/8] Wait for ADB device
[5/8] Prepare device (kill existing orbic_app)
[6/8] Push all files to /tmp/ via ADB
[7/8] Install rootshell (AT+SYSCMD: cp, chown, chmod 4755)
[8/8] Install DagShell (rootshell -c for all privileged ops)
      → Reboot → Boot hook activates → Verify
```

---

## SSL Certificate Management (`gen_pki.py`)

### Problem Solved
The original `gen_pki.py` generated leaf server certificates with only **365-day validity**. An expired certificate causes BearSSL's `br_ssl_server_init_full_rsa` to silently abort TLS handshakes, making the web UI unreachable even with the firewall open.

### Fix
`gen_pki.py` now generates both the Root CA and the leaf server certificate with **3650-day validity (10 years)**. The `datetime.utcnow()` deprecation warnings are also resolved.

To regenerate certificates:
```sh
cd orbic_fw_c
python3 gen_pki.py
# Then redeploy: python3 ../deploy_usb.py
```

---

## Quick Start

```sh
# Install dependencies
pip install pyusb

# (macOS) Install ADB and libusb
brew install android-platform-tools libusb

# Generate fresh TLS certificates (first time only)
cd orbic_fw_c && python3 gen_pki.py && cd ..

# Deploy — plug in USB cable first
python3 deploy_usb.py

# Or verify an existing install without redeploying
python3 deploy_usb.py --verify-only
```

Once deployed, connect to the Orbic's WiFi hotspot and open:
```
https://192.168.1.1:8443/
```
Accept the self-signed certificate warning (or install `root.der` as a trusted CA).

---

## Requirements

| Requirement | Notes |
|---|---|
| Python 3.8+ | Standard library only for ADB fallback |
| `pyusb` | `pip install pyusb` — needed for USB mode switch & AT+SYSCMD |
| `libusb` | `brew install libusb` (macOS) / `apt install libusb-1.0-0` (Linux) |
| `adb` | Android Debug Bridge in PATH |
| macOS/Linux | `sudo` may be needed to claim USB serial interface on macOS |
| Windows | WSL recommended; native support via `libusb` + Zadig driver |

---

## Compatibility

| Scenario | Works? | Notes |
|---|---|---|
| Fresh device (never rooted) | ✅ | AT+SYSCMD installs rootshell, then rootshell -c for all ops |
| Rayhunter already installed | ✅ | Detects existing rootshell, skips AT+SYSCMD step |
| ADB shell already root | ✅ | Installs rootshell via ADB, or uses direct root ADB |
| No pyusb/libusb | ✅ | Falls back to ADB-only (device must already be in ADB mode) |

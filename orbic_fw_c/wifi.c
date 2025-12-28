#include "wifi.h"
#include "gps.h"
#include "log.h"
#include <arpa/inet.h>
#include <errno.h> // Added for errno
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

typedef struct {
  char bssid[20];
  char ssid[64];
  int rssi;
  int freq;
  char enc[32];
  int wps;
} APInfo;

// --- Duplicate tracking for wardriving ---
#define MAX_SEEN_BSSIDS 500
static char seen_bssids[MAX_SEEN_BSSIDS][20];
static int seen_count = 0;
static char current_wardrive_file[128] = "/data/wardrive.csv";
static char current_bt_file[128] = "/data/wardrive_bt.csv";

static int is_bssid_seen(const char *bssid) {
  for (int i = 0; i < seen_count; i++) {
    if (strcmp(seen_bssids[i], bssid) == 0)
      return 1;
  }
  return 0;
}

static void mark_bssid_seen(const char *bssid) {
  if (seen_count < MAX_SEEN_BSSIDS) {
    strncpy(seen_bssids[seen_count], bssid, 19);
    seen_bssids[seen_count][19] = '\0';
    seen_count++;
  }
}

void wifi_clear_seen_bssids() { seen_count = 0; }

// Start a new wardrive session (creates timestamped file)
void wifi_new_session() {
  time_t now = time(NULL);
  struct tm *t = localtime(&now);
  snprintf(current_wardrive_file, sizeof(current_wardrive_file),
           "/data/wardrive_%04d%02d%02d_%02d%02d%02d.csv", t->tm_year + 1900,
           t->tm_mon + 1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec);
  snprintf(current_bt_file, sizeof(current_bt_file),
           "/data/wardrive_bt_%04d%02d%02d_%02d%02d%02d.csv", t->tm_year + 1900,
           t->tm_mon + 1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec);

  // Clear duplicate tracking for new session
  wifi_clear_seen_bssids();

  // Create file with headers
  FILE *fp = fopen(current_wardrive_file, "w");
  if (fp) {
    fprintf(fp, "WigleWifi-1.4,appRelease=DagShell,model=Orbic,release=1.0,"
                "device=RCL400,display=,board=,brand=Orbic\n");
    fprintf(fp, "MAC,SSID,AuthMode,FirstSeen,Channel,RSSI,CurrentLatitude,"
                "CurrentLongitude,AltitudeMeters,AccuracyMeters,Type\n");
    fclose(fp);
  }
}

static void wifi_run_cmd(const char *cmd, char *out, int max_len) {
  FILE *fp = popen(cmd, "r");
  if (!fp) {
    out[0] = '\0';
    return;
  }
  size_t total = 0;
  char buf[256];
  while (fgets(buf, sizeof(buf), fp)) {
    int len = strlen(buf);
    if (total + len < max_len - 1) {
      strcpy(out + total, buf);
      total += len;
    }
  }
  out[total] = '\0';
  pclose(fp);
}

// Helper: skip leading whitespace
static const char *skip_whitespace(const char *p) {
  while (*p == ' ' || *p == '\t')
    p++;
  return p;
}

static int parse_scan(const char *scan_out, APInfo *aps, int max_aps) {
  int count = 0;
  const char *p = scan_out;
  APInfo current;
  memset(&current, 0, sizeof(current));

  while (*p && count < max_aps) {
    // Skip leading whitespace on each line
    const char *line_start = skip_whitespace(p);

    if (strncmp(p, "BSS ", 4) == 0) {
      if (current.bssid[0]) {
        aps[count++] = current;
        memset(&current, 0, sizeof(current));
      }
      p += 4;
      int i = 0;
      while (*p && *p != '(' && *p != '\n' && i < 17) {
        current.bssid[i++] = *p++;
      }
      current.bssid[i] = '\0';
      strcpy(current.enc, "OPEN");
    } else if (strncmp(line_start, "SSID: ", 6) == 0) {
      // Parse SSID (handles leading whitespace)
      const char *ssid_start = line_start + 6;
      int i = 0;
      while (*ssid_start && *ssid_start != '\n' && i < 63) {
        current.ssid[i++] = *ssid_start++;
      }
      current.ssid[i] = '\0';
    } else if (strncmp(line_start, "signal: ", 8) == 0) {
      current.rssi = atoi(line_start + 8);
    } else if (strncmp(line_start, "freq: ", 6) == 0) {
      current.freq = atoi(line_start + 6);
    } else if (strncmp(line_start, "WPA:", 4) == 0 ||
               strncmp(line_start, "RSN:", 4) == 0) {
      if (strstr(line_start, "SAE") || strstr(line_start, "OWE"))
        strcpy(current.enc, "WPA3");
      else if (strstr(line_start, "PSK"))
        strcpy(current.enc, "WPA2");
      else
        strcpy(current.enc, "WPA");
    } else if (strncmp(line_start, "WEP:", 4) == 0) {
      strcpy(current.enc, "WEP");
    } else if (strstr(line_start, "WPS:")) {
      current.wps = 1;
    }
    while (*p && *p != '\n')
      p++;
    if (*p == '\n')
      p++;
  }
  if (current.bssid[0] && count < max_aps) {
    aps[count++] = current;
  }
  return count;
}

int wifi_scan_json(char *buffer, int max_len) {

  char scan_out[16384];

  // Ensure wlan1 is up for scanning
  system("ifconfig wlan1 up");

  // Scan on wlan1
  wifi_run_cmd("iw dev wlan1 scan", scan_out, sizeof(scan_out));

  APInfo aps[50];
  int count = parse_scan(scan_out, aps, 50);

  int offset = snprintf(buffer, max_len, "[");
  for (int i = 0; i < count; i++) {
    int chan = 0;
    if (aps[i].freq == 2484)
      chan = 14;
    else if (aps[i].freq < 2484)
      chan = (aps[i].freq - 2407) / 5;
    else if (aps[i].freq < 5935)
      chan = (aps[i].freq - 5000) / 5;

    offset +=
        snprintf(buffer + offset, max_len - offset,
                 "{\"bssid\":\"%s\",\"ssid\":\"%s\",\"rssi\":%d,\"enc\":\"%s\","
                 "\"freq\":%d,\"chan\":%d,\"wps\":%d}%s",
                 aps[i].bssid, aps[i].ssid, aps[i].rssi, aps[i].enc,
                 aps[i].freq, chan, aps[i].wps, (i < count - 1) ? "," : "");
    if (offset >= max_len - 10)
      break;
  }
  snprintf(buffer + offset, max_len - offset, "]");
  return count;
}

int wifi_log_kml(const char *lat, const char *lon) {

  char scan_out[8192];
  system("ifconfig wlan1 up");
  wifi_run_cmd("iw dev wlan1 scan", scan_out, sizeof(scan_out));
  APInfo aps[50];
  int count = parse_scan(scan_out, aps, 50);

  // Append to current session file
  FILE *fp = fopen(current_wardrive_file, "a");
  if (!fp)
    return 0;

  // Get current timestamp
  time_t now = time(NULL);
  struct tm *t = localtime(&now);
  char timestamp[32];
  strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", t);

  int new_count = 0;
  for (int i = 0; i < count; i++) {
    // Skip already seen BSSIDs (no duplicates)
    if (is_bssid_seen(aps[i].bssid))
      continue;

    mark_bssid_seen(aps[i].bssid);

    int chan = 0;
    if (aps[i].freq == 2484)
      chan = 14;
    else if (aps[i].freq < 2484)
      chan = (aps[i].freq - 2407) / 5;
    else if (aps[i].freq < 5935)
      chan = (aps[i].freq - 5000) / 5;

    fprintf(fp, "%s,%s,%s,%s,%d,%d,%s,%s,0,10,WIFI\n", aps[i].bssid,
            aps[i].ssid, aps[i].enc, timestamp, chan, aps[i].rssi, lat, lon);
    new_count++;
  }
  fclose(fp);
  return new_count;
}

// Ingest batch data from Pi Companion
// Format: BSSID,SSID,Auth,Chan,RSSI,Lat,Lon
void wifi_ingest_batch(const char *csv_data) {
  FILE *fp = fopen(current_wardrive_file, "a");
  if (!fp)
    return;

  // Get timestamp
  time_t now = time(NULL);
  struct tm *t = localtime(&now);
  char timestamp[32];
  strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", t);

  char *line_dup = strdup(csv_data);
  char *line = strtok(line_dup, "\n");
  while (line) {
    // Parse fields
    char bssid[20] = {0}, ssid[64] = {0}, auth[32] = {0}, lat[16] = {0},
         lon[16] = {0};
    int chan = 0, rssi = 0;

    // Expected: BSSID,SSID,Auth,Chan,RSSI,Lat,Lon
    // Simple sscanf might be risky with spaces, so we tokenize by comma
    // But CSVs can have commas in SSIDs... assuming Pi handles escaping or
    // simple flow For now, simple parsing (Pi should send strict format)

    // Using sscanf with width limits
    if (sscanf(line, "%19[^,],%63[^,],%31[^,],%d,%d,%15[^,],%15s", bssid, ssid,
               auth, &chan, &rssi, lat, lon) == 7) {
      if (!is_bssid_seen(bssid)) {
        mark_bssid_seen(bssid);
        fprintf(fp, "%s,%s,%s,%s,%d,%d,%s,%s,0,10,WIFI\n", bssid, ssid, auth,
                timestamp, chan, rssi, lat, lon);
      }
    }

    line = strtok(NULL, "\n");
  }
  free(line_dup);
  fclose(fp);
}

// --- WARDRIVING LOOP ---

void wifi_wardrive_process() {
  system("echo 'Starting Wardrive Loop...' >> /tmp/wardrive.log");
  system("ifconfig wlan1 up");

  daglog("Wardrive: Waiting for GPS fix...");

  // Wait for GPS fix before starting
  char lat[32], lon[32];
  int wait_count = 0;
  while (1) {
    gps_update();
    if (gps_get_coords(lat, lon, sizeof(lat)) == 0) {
      // Got GPS fix!
      char logbuf[128];
      snprintf(logbuf, sizeof(logbuf), "Wardrive: GPS fix acquired (%s, %s)",
               lat, lon);
      daglog(logbuf);
      break;
    }
    wait_count++;
    if (wait_count % 6 == 0) { // Log every 30 seconds
      daglog("Wardrive: Still waiting for GPS...");
    }
    sleep(5);
  }

  // Start new session (creates timestamped file, clears duplicates)
  wifi_new_session();
  daglog("Wardrive started");

  while (1) {
    // Get current GPS coordinates
    gps_update();
    if (gps_get_coords(lat, lon, sizeof(lat)) < 0) {
      // Lost GPS fix - use last known or wait
      daglog("Wardrive: GPS fix lost, skipping scan");
      sleep(5);
      continue;
    }
    int scanned = wifi_log_kml(lat, lon);

    // Log scan results so user can see progress
    char logbuf[128];
    snprintf(logbuf, sizeof(logbuf), "Wardrive scan: %d new APs at (%s, %s)",
             scanned, lat, lon);
    daglog(logbuf);

    // Log Bluetooth devices found by Pi (stored in memory)
    bt_log_to_file(current_bt_file);

    sleep(5);
  }
}

void wifi_start_wardrive() {
  daglog("Starting wardrive process...");
  system("/data/orbic_app --wardrive > /dev/null 2>&1 &");
  // Give it a moment to start, then record PID
  usleep(500000);
  system("pgrep -f 'orbic_app --wardrive' | head -1 > /tmp/wardrive.pid "
         "2>/dev/null");
}

void wifi_stop_wardrive() {
  daglog("Stopping wardrive process");
  system("pkill -f 'orbic_app --wardrive'");
  // Remove PID file
  unlink("/tmp/wardrive.pid");
}

int wifi_is_wardriving() {
  // Check if PID file exists and process is still running
  FILE *fp = fopen("/tmp/wardrive.pid", "r");
  if (!fp)
    return 0;

  char pid_str[16] = {0};
  if (fgets(pid_str, sizeof(pid_str), fp) == NULL) {
    fclose(fp);
    return 0;
  }
  fclose(fp);

  // Trim newline
  pid_str[strcspn(pid_str, "\n")] = 0;
  if (strlen(pid_str) == 0)
    return 0;

  // Check if process with this PID exists
  char proc_path[32];
  snprintf(proc_path, sizeof(proc_path), "/proc/%s", pid_str);

  if (access(proc_path, F_OK) == 0) {
    return 1; // Process exists
  }

  // PID file exists but process is dead - clean up
  unlink("/tmp/wardrive.pid");
  return 0;
}

// --- WIFI CLIENT CONNECTION ---
// Connect to an AP as a client using wpa_cli
int wifi_connect(const char *ssid, const char *password) {
  char cmd[512];

  // Create wpa_supplicant config
  FILE *fp = fopen("/tmp/wpa_client.conf", "w");
  if (!fp)
    return -1;

  fprintf(fp, "ctrl_interface=/var/run/wpa_supplicant\n");
  fprintf(fp, "update_config=1\n\n");
  fprintf(fp, "network={\n");
  fprintf(fp, "    ssid=\"%s\"\n", ssid);
  if (password && strlen(password) > 0) {
    fprintf(fp, "    psk=\"%s\"\n", password);
  } else {
    fprintf(fp, "    key_mgmt=NONE\n");
  }
  fprintf(fp, "}\n");
  fclose(fp);

  // Kill any existing wpa_supplicant on wlan0
  system("killall wpa_supplicant 2>/dev/null");
  usleep(500000);

  // Start wpa_supplicant
  system("wpa_supplicant -B -iwlan0 -c/tmp/wpa_client.conf -Dnl80211");
  usleep(2000000); // 2s wait for connection

  // Request DHCP
  system("udhcpc -i wlan0 -n -q 2>/dev/null || dhclient wlan0 2>/dev/null");

  daglog("WiFi connect initiated");
  return 0;
}

void wifi_disconnect() {
  system("killall wpa_supplicant 2>/dev/null");
  system("ifconfig wlan0 0.0.0.0");
}

// Returns 1 if connected (has IP), 0 otherwise
int wifi_is_connected() {
  FILE *fp = popen("ip addr show wlan0 | grep 'inet ' | wc -l", "r");
  if (!fp)
    return 0;
  int count = 0;
  fscanf(fp, "%d", &count);
  pclose(fp);
  return (count > 0);
}

// ============================================================================
// BLUETOOTH FLOCK WARDRIVING
// Store and manage BT devices discovered via Web Bluetooth from connected
// phones
// ============================================================================

#define MAX_BT_DEVICES 200
static BluetoothDevice bt_devices[MAX_BT_DEVICES];
static int bt_device_count = 0;

int bt_add_device(const char *mac, const char *name, int rssi) {
  if (!mac || strlen(mac) == 0)
    return -1;

  // Check if device already exists (update if so)
  for (int i = 0; i < bt_device_count; i++) {
    if (strcasecmp(bt_devices[i].mac, mac) == 0) {
      // Update existing device
      bt_devices[i].rssi = rssi;
      bt_devices[i].last_seen = time(NULL);
      if (name && strlen(name) > 0) {
        strncpy(bt_devices[i].name, name, sizeof(bt_devices[i].name) - 1);
      }
      return 0; // Updated
    }
  }

  // Add new device
  if (bt_device_count >= MAX_BT_DEVICES) {
    return -1; // Full
  }

  // Get current GPS location
  char lat[16] = "0.0", lon[16] = "0.0";
  gps_get_coords(lat, lon, sizeof(lat));

  BluetoothDevice *dev = &bt_devices[bt_device_count];
  strncpy(dev->mac, mac, sizeof(dev->mac) - 1);
  strncpy(dev->name, name ? name : "Unknown", sizeof(dev->name) - 1);
  dev->rssi = rssi;
  strncpy(dev->lat, lat, sizeof(dev->lat) - 1);
  strncpy(dev->lon, lon, sizeof(dev->lon) - 1);
  dev->first_seen = time(NULL);
  dev->last_seen = dev->first_seen;

  bt_device_count++;
  daglogf("BT device added: %s (%s)", mac, name ? name : "Unknown");
  return 1; // Added
}

int bt_get_json(char *buffer, int max_len) {
  int offset = 0;
  offset += snprintf(buffer + offset, max_len - offset, "[");

  for (int i = 0; i < bt_device_count && offset < max_len - 100; i++) {
    if (i > 0)
      offset += snprintf(buffer + offset, max_len - offset, ",");

    // Escape name for JSON
    char escaped_name[128] = {0};
    int j = 0, k = 0;
    for (; bt_devices[i].name[j] && k < 120; j++) {
      if (bt_devices[i].name[j] == '"' || bt_devices[i].name[j] == '\\') {
        escaped_name[k++] = '\\';
      }
      escaped_name[k++] = bt_devices[i].name[j];
    }

    offset += snprintf(buffer + offset, max_len - offset,
                       "{\"mac\":\"%s\",\"name\":\"%s\",\"rssi\":%d,\"lat\":\"%"
                       "s\",\"lon\":\"%s\"}",
                       bt_devices[i].mac, escaped_name, bt_devices[i].rssi,
                       bt_devices[i].lat, bt_devices[i].lon);
  }

  offset += snprintf(buffer + offset, max_len - offset, "]");
  return offset;
}

int bt_get_count() { return bt_device_count; }

void bt_clear_devices() {
  bt_device_count = 0;
  daglog("BT devices cleared");
}

void bt_log_to_file(const char *filepath) {
  if (bt_device_count == 0)
    return;

  FILE *fp = fopen(filepath, "a");
  if (!fp)
    return;

  // Write CSV header if file is empty
  fseek(fp, 0, SEEK_END);
  if (ftell(fp) == 0) {
    fprintf(fp, "MAC,Name,RSSI,Latitude,Longitude,FirstSeen,LastSeen\n");
  }

  for (int i = 0; i < bt_device_count; i++) {
    BluetoothDevice *dev = &bt_devices[i];
    fprintf(fp, "%s,\"%s\",%d,%s,%s,%ld,%ld\n", dev->mac, dev->name, dev->rssi,
            dev->lat, dev->lon, (long)dev->first_seen, (long)dev->last_seen);
  }

  fclose(fp);
  daglogf("BT devices logged to %s", filepath);
}

// Global state for BT scanning (0=off, 1=on)
static int bt_scanning_enabled = 0;

void bt_set_scanning(int enabled) {
  bt_scanning_enabled = enabled;
  daglogf("BT scanning set to %d", enabled);
}

int bt_is_scanning() { return bt_scanning_enabled; }

// --- Deauth Attack Targets ---
static DeauthTarget deauth_targets[MAX_DEAUTH_TARGETS];
static int deauth_target_count = 0;

int deauth_add_target(const char *bssid, int channel) {
  if (deauth_target_count >= MAX_DEAUTH_TARGETS) {
    return -1; // Queue full
  }
  // Check for duplicate
  for (int i = 0; i < deauth_target_count; i++) {
    if (strcmp(deauth_targets[i].bssid, bssid) == 0) {
      return 0; // Already exists
    }
  }
  strncpy(deauth_targets[deauth_target_count].bssid, bssid, 17);
  deauth_targets[deauth_target_count].bssid[17] = '\0';
  deauth_targets[deauth_target_count].channel = channel;
  deauth_target_count++;
  daglogf("Queued deauth target: %s (ch %d)", bssid, channel);
  return 1;
}

int deauth_get_json(char *buffer, int max_len) {
  int offset = 0;
  offset += snprintf(buffer + offset, max_len - offset, "[");
  for (int i = 0; i < deauth_target_count && offset < max_len - 30; i++) {
    if (i > 0)
      offset += snprintf(buffer + offset, max_len - offset, ",");
    // Format: "BSSID:CHANNEL"
    offset += snprintf(buffer + offset, max_len - offset, "\"%s:%d\"",
                       deauth_targets[i].bssid, deauth_targets[i].channel);
  }
  offset += snprintf(buffer + offset, max_len - offset, "]");
  return offset;
}

void deauth_clear_targets() { deauth_target_count = 0; }

int deauth_get_count() { return deauth_target_count; }

// Continuous mode flag
static int deauth_continuous_mode = 0;
static int deauth_stop_flag = 0;

void deauth_set_continuous(int enabled) {
  deauth_continuous_mode = enabled;
  daglogf("Deauth continuous mode: %d", enabled);
}

int deauth_is_continuous() { return deauth_continuous_mode; }

void deauth_set_stop(int stop) { deauth_stop_flag = stop; }

int deauth_should_stop() {
  int val = deauth_stop_flag;
  deauth_stop_flag = 0; // Auto-clear after read
  return val;
}

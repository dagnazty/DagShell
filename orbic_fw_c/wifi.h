#ifndef WIFI_H
#define WIFI_H

#include <time.h>

// Perform a WiFi Scan and return JSON array of networks
int wifi_scan_json(char *buffer, int max_len);

// Log scan to CSV (Single Shot)
int wifi_log_kml(const char *lat, const char *lon);

// Ingest batch of WiFi data (CSV format) from external source (Pi)
void wifi_ingest_batch(const char *csv_data);

// Wardriving control
void wifi_start_wardrive();

// Stop Background Loop (Kills process)
void wifi_stop_wardrive();

// Check if running
int wifi_is_wardriving();

// Main loop entry point (called by main --wardrive)
void wifi_wardrive_process();

// Clear seen BSSIDs (call when starting new wardrive session)
void wifi_clear_seen_bssids();

// Start new wardrive session (creates timestamped file)
void wifi_new_session();

// --- Client Connect ---
int wifi_connect(const char *ssid, const char *password);
void wifi_disconnect();
int wifi_is_connected();

// --- Bluetooth Flock Wardriving ---
typedef struct {
  char mac[18];          // BT MAC address
  char name[64];         // Device name
  char manufacturer[32]; // OUI manufacturer name
  int rssi;              // Signal strength
  char lat[16];          // Latitude when discovered
  char lon[16];          // Longitude when discovered
  time_t first_seen;
  time_t last_seen;
} BluetoothDevice;

// Add a discovered BT device
int bt_add_device(const char *mac, const char *name, int rssi,
                  const char *manufacturer);

// Get BT devices as JSON
int bt_get_json(char *buffer, int max_len);

// Get BT device count
int bt_get_count();

// Clear BT devices
void bt_clear_devices();

// Log BT devices to file
void bt_log_to_file(const char *filepath);

// Remote Control for Pi Companion
void bt_set_scanning(int enabled);
int bt_is_scanning();

// --- Deauth Attack Control ---
#define MAX_DEAUTH_TARGETS 10
typedef struct {
  char bssid[18]; // AP MAC
  int channel;    // Channel number
} DeauthTarget;

// Add a target for deauth (called from cmd=deauth)
int deauth_add_target(const char *bssid, int channel);

// Get targets as JSON array string (for poll response)
int deauth_get_json(char *buffer, int max_len);

// Clear all targets after Pi polls
void deauth_clear_targets();

// Get count
int deauth_get_count();

// Continuous mode control
void deauth_set_continuous(int enabled);
int deauth_is_continuous();
void deauth_set_stop(int stop);
int deauth_should_stop();

#endif

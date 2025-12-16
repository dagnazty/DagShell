#ifndef WIFI_H
#define WIFI_H

// Perform a WiFi Scan and return JSON array of networks
int wifi_scan_json(char *buffer, int max_len);

// Log scan to CSV (Single Shot)
int wifi_log_kml(const char *lat, const char *lon);

// Start Background Loop (Spawns process)
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

#endif

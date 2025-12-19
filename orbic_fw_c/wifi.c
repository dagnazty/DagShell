#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <errno.h> // Added for errno
#include "wifi.h"
#include "gps.h"
#include "log.h"

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

static int is_bssid_seen(const char *bssid) {
    for (int i = 0; i < seen_count; i++) {
        if (strcmp(seen_bssids[i], bssid) == 0) return 1;
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

void wifi_clear_seen_bssids() {
    seen_count = 0;
}

// Start a new wardrive session (creates timestamped file)
void wifi_new_session() {
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    snprintf(current_wardrive_file, sizeof(current_wardrive_file),
        "/data/wardrive_%04d%02d%02d_%02d%02d%02d.csv",
        t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
        t->tm_hour, t->tm_min, t->tm_sec);
    
    // Clear duplicate tracking for new session
    wifi_clear_seen_bssids();
    
    // Create file with headers
    FILE *fp = fopen(current_wardrive_file, "w");
    if (fp) {
        fprintf(fp, "WigleWifi-1.4,appRelease=DagShell,model=Orbic,release=1.0,device=RCL400,display=,board=,brand=Orbic\n");
        fprintf(fp, "MAC,SSID,AuthMode,FirstSeen,Channel,RSSI,CurrentLatitude,CurrentLongitude,AltitudeMeters,AccuracyMeters,Type\n");
        fclose(fp);
    }
}

static void wifi_run_cmd(const char *cmd, char *out, int max_len) {
    FILE *fp = popen(cmd, "r");
    if (!fp) { out[0]='\0'; return; }
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
static const char* skip_whitespace(const char *p) {
    while (*p == ' ' || *p == '\t') p++;
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
        }
        else if (strncmp(line_start, "SSID: ", 6) == 0) {
            // Parse SSID (handles leading whitespace)
            const char *ssid_start = line_start + 6;
            int i = 0;
            while (*ssid_start && *ssid_start != '\n' && i < 63) {
                current.ssid[i++] = *ssid_start++;
            }
            current.ssid[i] = '\0';
        }
        else if (strncmp(line_start, "signal: ", 8) == 0) {
            current.rssi = atoi(line_start + 8);
        }
        else if (strncmp(line_start, "freq: ", 6) == 0) {
            current.freq = atoi(line_start + 6);
        }
        else if (strncmp(line_start, "WPA:", 4) == 0 || strncmp(line_start, "RSN:", 4) == 0) {
            if (strstr(line_start, "SAE") || strstr(line_start, "OWE")) strcpy(current.enc, "WPA3");
            else if (strstr(line_start, "PSK")) strcpy(current.enc, "WPA2");
            else strcpy(current.enc, "WPA");
        }
        else if (strncmp(line_start, "WEP:", 4) == 0) {
            strcpy(current.enc, "WEP");
        }
        else if (strstr(line_start, "WPS:")) {
            current.wps = 1;
        }
        while (*p && *p != '\n') p++;
        if (*p == '\n') p++;
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
    for(int i=0; i<count; i++) {
        int chan = 0;
        if (aps[i].freq == 2484) chan = 14;
        else if (aps[i].freq < 2484) chan = (aps[i].freq - 2407) / 5;
        else if (aps[i].freq < 5935) chan = (aps[i].freq - 5000) / 5;
        
        offset += snprintf(buffer + offset, max_len - offset, 
            "{\"bssid\":\"%s\",\"ssid\":\"%s\",\"rssi\":%d,\"enc\":\"%s\",\"freq\":%d,\"chan\":%d,\"wps\":%d}%s",
            aps[i].bssid, aps[i].ssid, aps[i].rssi, aps[i].enc, aps[i].freq, chan, aps[i].wps,
            (i < count - 1) ? "," : "");
        if (offset >= max_len - 10) break; 
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
    if (!fp) return 0;
    
    // Get current timestamp
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", t);
    
    int new_count = 0;
    for(int i=0; i<count; i++) {
        // Skip already seen BSSIDs (no duplicates)
        if (is_bssid_seen(aps[i].bssid)) continue;
        
        mark_bssid_seen(aps[i].bssid);
        
        int chan = 0;
        if (aps[i].freq == 2484) chan = 14;
        else if (aps[i].freq < 2484) chan = (aps[i].freq - 2407) / 5;
        else if (aps[i].freq < 5935) chan = (aps[i].freq - 5000) / 5;

        fprintf(fp, "%s,%s,%s,%s,%d,%d,%s,%s,0,10,WIFI\n",
            aps[i].bssid, aps[i].ssid, aps[i].enc, timestamp, chan, aps[i].rssi, lat, lon);
        new_count++;
    }
    fclose(fp);
    return new_count;
}

// --- WARDRIVING LOOP ---

void wifi_wardrive_process() {
    system("echo 'Starting Wardrive Loop...' >> /tmp/wardrive.log");
    system("ifconfig wlan1 up");
    
    daglog("Wardrive: Waiting for GPS fix...");
    
    // Wait for GPS fix before starting
    char lat[32], lon[32];
    int wait_count = 0;
    while(1) {
        gps_update();
        if (gps_get_coords(lat, lon, sizeof(lat)) == 0) {
            // Got GPS fix!
            char logbuf[128];
            snprintf(logbuf, sizeof(logbuf), "Wardrive: GPS fix acquired (%s, %s)", lat, lon);
            daglog(logbuf);
            break;
        }
        wait_count++;
        if (wait_count % 6 == 0) {  // Log every 30 seconds
            daglog("Wardrive: Still waiting for GPS...");
        }
        sleep(5);
    }
    
    // Start new session (creates timestamped file, clears duplicates)
    wifi_new_session();
    daglog("Wardrive started");
    
    while(1) {
        // Get current GPS coordinates
        gps_update();
        if (gps_get_coords(lat, lon, sizeof(lat)) < 0) {
            // Lost GPS fix - use last known or wait
            daglog("Wardrive: GPS fix lost, skipping scan");
            sleep(5);
            continue;
        }
        wifi_log_kml(lat, lon);
        sleep(5); 
    }
}

void wifi_start_wardrive() {
    daglog("Starting wardrive process...");
    system("/data/orbic_app --wardrive > /dev/null 2>&1 &");
}

void wifi_stop_wardrive() {
    daglog("Stopping wardrive process");
    system("pkill -f 'orbic_app --wardrive'");
}

int wifi_is_wardriving() {
    int ret = system("pgrep -f 'orbic_app --wardrive' > /dev/null");
    return (ret == 0);
}

// --- WIFI CLIENT CONNECTION ---
// Connect to an AP as a client using wpa_cli
int wifi_connect(const char *ssid, const char *password) {
    char cmd[512];
    
    // Create wpa_supplicant config
    FILE *fp = fopen("/tmp/wpa_client.conf", "w");
    if (!fp) return -1;
    
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
    if (!fp) return 0;
    int count = 0;
    fscanf(fp, "%d", &count);
    pclose(fp);
    return (count > 0);
}

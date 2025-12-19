#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include "gps.h"
#include "wigle.h" // For AppConfig
#include "log.h"

#define MODEM_PORT "/dev/smd8"

// Send AT command and read response
static int modem_at_cmd(const char *cmd, char *resp, size_t max, int wait_ms) {
    memset(resp, 0, max);
    int fd = open(MODEM_PORT, O_RDWR | O_NOCTTY | O_NONBLOCK);
    if (fd < 0) return -1;
    
    char buf[512];
    snprintf(buf, sizeof(buf), "%s\r", cmd);
    write(fd, buf, strlen(buf));
    usleep(wait_ms * 1000);
    
    int total = 0, retries = 20;
    while(retries-- > 0 && total < (int)max - 1) {
        int n = read(fd, resp + total, max - total - 1);
        if (n > 0) { total += n; retries = 5; }
        else usleep(100000);
    }
    resp[total] = 0;
    close(fd);
    return total;
}

// HTTP GET using modem AT commands (Quectel-style)
// Returns response body in resp, or negative on error
static int http_get_via_modem(const char *url, char *resp, size_t max) {
    char at_resp[2048];
    char logbuf[256];
    int len;
    
    // Configure HTTP
    modem_at_cmd("AT+QHTTPCFG=\"contextid\",1", at_resp, sizeof(at_resp), 200);
    modem_at_cmd("AT+QHTTPCFG=\"responseheader\",0", at_resp, sizeof(at_resp), 200);
    
    // Set URL (need to send length first, then URL data)
    char url_cmd[64];
    snprintf(url_cmd, sizeof(url_cmd), "AT+QHTTPURL=%d,80", (int)strlen(url));
    len = modem_at_cmd(url_cmd, at_resp, sizeof(at_resp), 500);
    
    snprintf(logbuf, sizeof(logbuf), "Cell GPS: QHTTPURL cmd resp: %.60s", at_resp);
    daglog(logbuf);
    
    // Check for CONNECT prompt
    if (strstr(at_resp, "CONNECT")) {
        // Send URL data
        int fd = open(MODEM_PORT, O_RDWR | O_NOCTTY | O_NONBLOCK);
        if (fd >= 0) {
            write(fd, url, strlen(url));
            usleep(500000);
            char tmp[256];
            read(fd, tmp, sizeof(tmp));
            close(fd);
        }
    }
    
    usleep(500000);
    
    // Execute GET request
    len = modem_at_cmd("AT+QHTTPGET=80", at_resp, sizeof(at_resp), 5000);
    snprintf(logbuf, sizeof(logbuf), "Cell GPS: QHTTPGET resp: %.60s", at_resp);
    daglog(logbuf);
    
    // Check for success
    if (!strstr(at_resp, "OK") && !strstr(at_resp, "+QHTTPGET:")) {
        daglog("Cell GPS: QHTTPGET failed");
        return -2;
    }
    
    usleep(1000000); // Wait for response
    
    // Read response
    len = modem_at_cmd("AT+QHTTPREAD=80", resp, max, 3000);
    snprintf(logbuf, sizeof(logbuf), "Cell GPS: QHTTPREAD resp len=%d", len);
    daglog(logbuf);
    
    // Extract body between CONNECT and OK
    char *start = strstr(resp, "CONNECT");
    if (start) {
        start = strchr(start, '\n');
        if (start) {
            start++;
            char *end = strstr(start, "\r\nOK");
            if (end) {
                *end = 0;
                memmove(resp, start, strlen(start) + 1);
            }
        }
    }
    
    return strlen(resp);
}

// GPS State - can come from browser or cell tower
static char gps_lat[32] = "0";
static char gps_lon[32] = "0";
static int has_fix = 0;
static time_t last_update_time = 0;
static char gps_source[64] = "None";

// Cell tower info
static char cell_mcc[8] = "";
static char cell_mnc[8] = "";
static char cell_lac[16] = "";
static char cell_cid[16] = "";

// GPS state file for sharing between processes
#define GPS_STATE_FILE "/tmp/gps_state"

// Save GPS state to file (for sharing with wardrive process)
static void gps_save_state() {
    FILE *fp = fopen(GPS_STATE_FILE, "w");
    if (fp) {
        fprintf(fp, "%s\n%s\n%ld\n", gps_lat, gps_lon, (long)last_update_time);
        fclose(fp);
    }
}

// Load GPS state from file (for wardrive process to read)
static void gps_load_state() {
    FILE *fp = fopen(GPS_STATE_FILE, "r");
    if (fp) {
        char lat[32], lon[32];
        long update_time = 0;
        if (fscanf(fp, "%31s\n%31s\n%ld", lat, lon, &update_time) == 3) {
            // Only use if newer than current data
            if (update_time > last_update_time) {
                strncpy(gps_lat, lat, sizeof(gps_lat) - 1);
                strncpy(gps_lon, lon, sizeof(gps_lon) - 1);
                last_update_time = (time_t)update_time;
                // Check if still valid (not stale)
                time_t now = time(NULL);
                if (now - last_update_time < 120) {  // 2 minute validity
                    has_fix = 1;
                    strcpy(gps_source, "Shared GPS");
                }
            }
        }
        fclose(fp);
    }
}

static void gps_send_at(const char *cmd, char *resp, size_t max) {
    memset(resp, 0, max);
    int fd = open(MODEM_PORT, O_RDWR | O_NOCTTY | O_NONBLOCK);
    if (fd < 0) return;
    
    char buf[128];
    snprintf(buf, sizeof(buf), "%s\r", cmd);
    write(fd, buf, strlen(buf));
    usleep(200000);
    
    int total = 0, retries = 10;
    while(retries-- > 0 && total < (int)max - 1) {
        int n = read(fd, resp + total, max - total - 1);
        if (n > 0) { total += n; retries = 3; }
        else usleep(50000);
    }
    resp[total] = 0;
    close(fd);
}

void gps_init() {
    strcpy(gps_source, "Waiting...");
    // Query cell tower info on init
    gps_update_cell_info();
}

// Parse cell info from AT+CEREG (LTE) response
// Format: +CEREG: <mode>,<stat>[,<tac>,<ci>,<AcT>]
void gps_update_cell_info() {
    char resp[256];
    char logbuf[256];
    
    // Try LTE first (AT+CEREG), fall back to GSM (AT+CREG)
    gps_send_at("AT+CEREG=2", resp, sizeof(resp)); // Enable location info for LTE
    usleep(100000);
    gps_send_at("AT+CEREG?", resp, sizeof(resp));
    
    // Log raw response
    snprintf(logbuf, sizeof(logbuf), "CEREG response: %.80s", resp);
    daglog(logbuf);
    
    // Parse TAC (LAC equivalent) and CID from CEREG
    // Response format: +CEREG: mode,stat,"TAC","???","CellID",AcT
    // Example: +CEREG: 2,1,"E300","E3","80BCD1C",7
    // We need TAC (3rd field) and the actual CellID (5th field, 3rd quoted value)
    char *p = strstr(resp, "+CEREG:");
    if (p) {
        // Skip to after the status fields
        char *comma1 = strchr(p, ',');
        if (comma1) {
            char *comma2 = strchr(comma1 + 1, ',');
            if (comma2) {
                // TAC (LAC equivalent) - first quoted value after stat
                char *lac_start = comma2 + 1;
                while (*lac_start == ' ' || *lac_start == '"') lac_start++;
                int i = 0;
                while (lac_start[i] && lac_start[i] != ',' && lac_start[i] != '"' && i < 15) {
                    cell_lac[i] = lac_start[i];
                    i++;
                }
                cell_lac[i] = 0;
                
                // Skip to 3rd quoted value (actual Cell ID)
                // Find first quote after TAC, skip to next quoted value, then next
                char *quote1 = strchr(lac_start, '"'); // End of TAC
                if (quote1) {
                    char *quote2 = strchr(quote1 + 1, '"'); // Start of middle field
                    if (quote2) {
                        char *quote3 = strchr(quote2 + 1, '"'); // End of middle field
                        if (quote3) {
                            char *quote4 = strchr(quote3 + 1, '"'); // Start of CellID
                            if (quote4) {
                                char *cid_start = quote4 + 1;
                                i = 0;
                                while (cid_start[i] && cid_start[i] != ',' && cid_start[i] != '"' && cid_start[i] != '\r' && i < 15) {
                                    cell_cid[i] = cid_start[i];
                                    i++;
                                }
                                cell_cid[i] = 0;
                            }
                        }
                    }
                }
            }
        }
    }
    
    // Set COPS to numeric format first
    gps_send_at("AT+COPS=3,2", resp, sizeof(resp));
    usleep(100000);
    
    // Get MCC/MNC from COPS
    gps_send_at("AT+COPS?", resp, sizeof(resp));
    
    // Log raw response
    snprintf(logbuf, sizeof(logbuf), "COPS response: %.80s", resp);
    daglog(logbuf);
    
    p = strstr(resp, "+COPS:");
    if (p) {
        // Format: +COPS: 0,2,"310260",7  (MCC=310, MNC=260)
        char *quote = strchr(p, '"');
        if (quote) {
            quote++;
            // MCC is first 3 digits
            strncpy(cell_mcc, quote, 3);
            cell_mcc[3] = 0;
            // MNC is next 2-3 digits
            strncpy(cell_mnc, quote + 3, 3);
            cell_mnc[3] = 0;
            // Trim trailing quote
            char *end = strchr(cell_mnc, '"');
            if (end) *end = 0;
        }
    }
}

void gps_update() {
    // Load shared GPS state from file (for wardrive process)
    gps_load_state();
    
    // Check if GPS data is stale (>120 seconds old for shared state)
    if (has_fix && last_update_time > 0) {
        time_t now = time(NULL);
        if (now - last_update_time > 120) {
            has_fix = 0;
            strcpy(gps_source, "GPS data stale");
            daglog("GPS data marked stale");
        }
    }
    
    // Update cell info periodically
    static time_t last_cell_update = 0;
    time_t now = time(NULL);
    if (now - last_cell_update > 30) {
        daglog("GPS update: Refreshing cell info...");
        gps_update_cell_info();
        last_cell_update = now;
        
        // Log the conditions
        char logbuf[256];
        snprintf(logbuf, sizeof(logbuf), "GPS update: has_fix=%d mcc=[%s] lac=[%s] cid=[%s]", 
            has_fix, cell_mcc, cell_lac, cell_cid);
        daglog(logbuf);
        
        // Note: Cell tower -> GPS lookup is now done by the browser (JavaScript)
        // since the device has no outgoing internet connectivity.
        // The browser fetches cell info via /?cmd=gps_json and calls OpenCellID API
    }
}

// Query OpenCelliD API for location based on cell tower info
void gps_update_from_cell() {
    // Load config for OpenCelliD token
    AppConfig cfg;
    if (config_load(&cfg) < 0) {
        daglog("Cell GPS: Config load failed");
        return;
    }
    if (strlen(cfg.opencellid_token) == 0) {
        daglog("Cell GPS: No OpenCelliD token configured");
        return;
    }
    
    // Log cell info we have
    char logbuf[256];
    snprintf(logbuf, sizeof(logbuf), "Cell GPS: MCC=%s MNC=%s LAC=%s CID=%s", 
        cell_mcc, cell_mnc, cell_lac, cell_cid);
    daglog(logbuf);
    
    // Convert LAC/CID from hex to decimal
    long lac_dec = strtol(cell_lac, NULL, 16);
    long cid_dec = strtol(cell_cid, NULL, 16);
    
    // Log the decimal values
    snprintf(logbuf, sizeof(logbuf), "Cell GPS: LAC_dec=%ld CID_dec=%ld", lac_dec, cid_dec);
    daglog(logbuf);
    
    // Build full URL for OpenCelliD
    char url[512];
    snprintf(url, sizeof(url),
        "http://opencellid.org/cell/get?key=%s&mcc=%s&mnc=%s&lac=%ld&cellid=%ld&format=json",
        cfg.opencellid_token, cell_mcc, cell_mnc, lac_dec, cid_dec);
    
    // Log URL (without token for privacy)
    snprintf(logbuf, sizeof(logbuf), "Cell GPS: API mcc=%s&mnc=%s&lac=%ld&cid=%ld", 
        cell_mcc, cell_mnc, lac_dec, cid_dec);
    daglog(logbuf);
    
    daglog("Cell GPS: Calling API via modem AT...");
    
    char resp[2048] = {0};
    int result = http_get_via_modem(url, resp, sizeof(resp));
    
    // Log response
    snprintf(logbuf, sizeof(logbuf), "Cell GPS: HTTP result=%d resp_len=%d", result, (int)strlen(resp));
    daglog(logbuf);
    snprintf(logbuf, sizeof(logbuf), "Cell GPS: Response: %.100s", resp);
    daglog(logbuf);
    
    // Parse JSON response for lat/lon
    char *lat_ptr = strstr(resp, "\"lat\":");
    char *lon_ptr = strstr(resp, "\"lon\":");
    
    if (lat_ptr && lon_ptr) {
        lat_ptr += 6;
        lon_ptr += 6;
        
        char lat_str[32] = {0}, lon_str[32] = {0};
        int i = 0;
        while (lat_ptr[i] && lat_ptr[i] != ',' && lat_ptr[i] != '}' && i < 31) {
            lat_str[i] = lat_ptr[i];
            i++;
        }
        i = 0;
        while (lon_ptr[i] && lon_ptr[i] != ',' && lon_ptr[i] != '}' && i < 31) {
            lon_str[i] = lon_ptr[i];
            i++;
        }
        
        if (strlen(lat_str) > 0 && strlen(lon_str) > 0) {
            strncpy(gps_lat, lat_str, sizeof(gps_lat) - 1);
            strncpy(gps_lon, lon_str, sizeof(gps_lon) - 1);
            has_fix = 1;
            last_update_time = time(NULL);
            strcpy(gps_source, "Cell Tower");
            
            snprintf(logbuf, sizeof(logbuf), "Cell GPS: Got fix lat=%s lon=%s", lat_str, lon_str);
            daglog(logbuf);
        }
    } else {
        daglog("Cell GPS: No lat/lon in response");
    }
}

// Receive GPS coordinates from a connected client browser
void gps_set_client_location(const char *lat, const char *lon) {
    if (lat && lon && strlen(lat) > 0 && strlen(lon) > 0) {
        strncpy(gps_lat, lat, sizeof(gps_lat) - 1);
        strncpy(gps_lon, lon, sizeof(gps_lon) - 1);
        has_fix = 1;
        last_update_time = time(NULL);
        strcpy(gps_source, "Browser GPS");
        
        // Save to file so wardrive process can read it
        gps_save_state();
    }
}

// Get current GPS coordinates
int gps_get_coords(char *lat, char *lon, int max_len) {
    if (has_fix) {
        strncpy(lat, gps_lat, max_len - 1);
        strncpy(lon, gps_lon, max_len - 1);
        return 0;
    }
    strncpy(lat, "0", max_len);
    strncpy(lon, "0", max_len);
    return -1;
}

int gps_get_json(char *buffer, int max_len) {
    snprintf(buffer, max_len, 
        "{\"has_fix\":%d,\"lat\":\"%s\",\"lon\":\"%s\",\"source\":\"%s\","
        "\"cell\":{\"mcc\":\"%s\",\"mnc\":\"%s\",\"lac\":\"%s\",\"cid\":\"%s\"}}",
        has_fix, gps_lat, gps_lon, gps_source,
        cell_mcc, cell_mnc, cell_lac, cell_cid);
    return has_fix ? 0 : -1;
}

void gps_get_status_html(char *buffer, int max_len) {
    time_t now = time(NULL);
    int age = last_update_time > 0 ? (int)(now - last_update_time) : -1;
    
    if (has_fix) {
        snprintf(buffer, max_len,
            "<p style='color:#0f0'>\xe2\x9c\x93 <strong>GPS Fix (%s)</strong></p>"
            "<p>Latitude: <strong>%s</strong></p>"
            "<p>Longitude: <strong>%s</strong></p>"
            "<p style='font-size:11px'>Updated %ds ago</p>",
            gps_source, gps_lat, gps_lon, age);
    } else {
        snprintf(buffer, max_len,
            "<p style='color:#ff0'>\xe2\x8f\xb3 <strong>No GPS Fix</strong></p>"
            "<p style='font-size:11px'>Cell: MCC=%s MNC=%s LAC=%s CID=%s</p>",
            cell_mcc[0] ? cell_mcc : "?",
            cell_mnc[0] ? cell_mnc : "?",
            cell_lac[0] ? cell_lac : "?",
            cell_cid[0] ? cell_cid : "?");
    }
}

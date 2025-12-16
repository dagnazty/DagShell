#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include "gps.h"

#define MODEM_PORT "/dev/smd8"

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

// Parse cell info from AT+CREG response
// Format: +CREG: 0,1,"LAC","CID" or +CREG: 0,1,LAC,CID
void gps_update_cell_info() {
    char resp[256];
    
    // Get registration info with LAC/CID
    gps_send_at("AT+CREG=2", resp, sizeof(resp)); // Enable location info
    usleep(100000);
    gps_send_at("AT+CREG?", resp, sizeof(resp));
    
    // Parse LAC and CID
    char *p = strstr(resp, "+CREG:");
    if (p) {
        // Skip to after the status fields
        char *comma1 = strchr(p, ',');
        if (comma1) {
            char *comma2 = strchr(comma1 + 1, ',');
            if (comma2) {
                // LAC
                char *lac_start = comma2 + 1;
                while (*lac_start == ' ' || *lac_start == '"') lac_start++;
                int i = 0;
                while (lac_start[i] && lac_start[i] != ',' && lac_start[i] != '"' && i < 15) {
                    cell_lac[i] = lac_start[i];
                    i++;
                }
                cell_lac[i] = 0;
                
                // CID
                char *comma3 = strchr(lac_start, ',');
                if (comma3) {
                    char *cid_start = comma3 + 1;
                    while (*cid_start == ' ' || *cid_start == '"') cid_start++;
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
    
    // Get MCC/MNC from COPS
    gps_send_at("AT+COPS?", resp, sizeof(resp));
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
    // Check if GPS data is stale (>60 seconds old)
    if (has_fix && last_update_time > 0) {
        time_t now = time(NULL);
        if (now - last_update_time > 60) {
            has_fix = 0;
            strcpy(gps_source, "GPS data stale");
        }
    }
    
    // Update cell info periodically
    static time_t last_cell_update = 0;
    time_t now = time(NULL);
    if (now - last_cell_update > 30) {
        gps_update_cell_info();
        last_cell_update = now;
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

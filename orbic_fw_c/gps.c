#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include "gps.h"

// Reuse main.c's send_at_command via extern or re-implement?
// Better to make send_at_command shared in utils.c but for now we'll duplicate or include
// Actually, let's declare it extern if I move it to a header, but main.c has it static-ish.
// I will implement a local helper to avoid linkage mess for now.
// Or better: I will move send_at_command to utils.h later.
// For speed, local implementation.

#define MODEM_PORT "/dev/smd8"

static void gps_send_at(const char *cmd, char *resp, size_t max) {
    int fd = open(MODEM_PORT, O_RDWR | O_NOCTTY | O_NONBLOCK);
    if (fd < 0) return;
    
    char buf[256];
    snprintf(buf, sizeof(buf), "%s\r", cmd);
    write(fd, buf, strlen(buf));
    usleep(100000); // 100ms
    
    int total = 0;
    while(total < max - 1) {
        int n = read(fd, resp + total, max - total - 1);
        if (n > 0) total += n;
        else { usleep(50000); break; }
    }
    resp[total] = 0;
    close(fd);
}

// Global cached state
static char last_lat[32] = "0";
static char last_lon[32] = "0";
static int has_fix = 0;

void gps_init() {
    char resp[128];
    gps_send_at("AT+GPS=1", resp, sizeof(resp));
}

// Parse: +GPSINFO: 4044.3322,N,07400.1122,W,0.0,34.5,20230501,130005.0
// DDMM.MMMM
void gps_parse_coord(const char *raw, char dir, char *out) {
    // raw format: 4044.3322 (40 deg, 44.3322 min)
    if (strlen(raw) < 5) { strcpy(out, "0"); return; }
    
    double val = atof(raw);
    int deg = (int)(val / 100);
    double min = val - (deg * 100);
    double dec = deg + (min / 60.0);
    
    if (dir == 'S' || dir == 'W') dec = -dec;
    
    sprintf(out, "%.6f", dec);
}

void gps_update() {
    char resp[512];
    gps_send_at("AT+GPSINFO?", resp, sizeof(resp));
    // Check response
    char *hdr = strstr(resp, "+GPSINFO:");
    if (!hdr) return;
    
    hdr += 9; // Skip header
    while(*hdr == ' ') hdr++;
    
    // Format: lat,N,lon,W,...
    // If no fix: +GPSINFO: ,,,,,
    if (hdr[0] == ',') {
        has_fix = 0;
        return;
    }
    
    // Parse
    char lat_raw[32] = {0};
    char lat_dir = 'N';
    char lon_raw[32] = {0};
    char lon_dir = 'E';
    
    // Tokenize manually to avoid strtok modifying buffer weirdly
    int i = 0;
    // Lat
    int j = 0;
    while(hdr[i] != ',' && hdr[i] && j<31) lat_raw[j++] = hdr[i++];
    i++; // skip comma
    lat_dir = hdr[i++];
    i++; // skip comma
    // Lon
    j = 0; 
    while(hdr[i] != ',' && hdr[i] && j<31) lon_raw[j++] = hdr[i++];
    i++;
    lon_dir = hdr[i++];
    
    gps_parse_coord(lat_raw, lat_dir, last_lat);
    gps_parse_coord(lon_raw, lon_dir, last_lon);
    has_fix = 1;
}

int gps_get_json(char *buffer, int max_len) {
    if (!has_fix) return -1;
    snprintf(buffer, max_len, "{\"lat\": %s, \"lon\": %s}", last_lat, last_lon);
    return 0;
}

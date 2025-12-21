#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "clients.h"
#include "log.h"

#define MAX_CLIENTS 64
#define CLIENT_LOG_FILE "/data/client_log.txt"

typedef struct {
    char mac[18];
    char ip[16];
    time_t first_seen;
    time_t last_seen;
    int seen_count;
    int active;
} Client;

static Client clients[MAX_CLIENTS];
static int client_count = 0;

void clients_init() {
    memset(clients, 0, sizeof(clients));
    client_count = 0;
    daglog("Client tracker initialized");
}

// Find client by MAC, return index or -1
static int find_client(const char *mac) {
    for (int i = 0; i < client_count; i++) {
        if (strcmp(clients[i].mac, mac) == 0) {
            return i;
        }
    }
    return -1;
}

// Log new client to file
static void log_client(const Client *c) {
    FILE *fp = fopen(CLIENT_LOG_FILE, "a");
    if (fp) {
        char timebuf[32];
        struct tm *tm = localtime(&c->first_seen);
        strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", tm);
        fprintf(fp, "%s,%s,%s\n", timebuf, c->mac, c->ip);
        fclose(fp);
    }
}

void clients_update() {
    FILE *fp = fopen("/proc/net/arp", "r");
    if (!fp) return;
    
    // Mark all clients as inactive
    for (int i = 0; i < client_count; i++) {
        clients[i].active = 0;
    }
    
    char line[256];
    time_t now = time(NULL);
    
    // Skip header line
    if (fgets(line, sizeof(line), fp) == NULL) {
        fclose(fp);
        return;
    }
    
    // Parse ARP entries
    // Format: IP address       HW type     Flags       HW address            Mask     Device
    while (fgets(line, sizeof(line), fp)) {
        char ip[16], hw_type[8], flags[8], mac[18], mask[8], device[16];
        
        if (sscanf(line, "%15s %7s %7s %17s %7s %15s", 
                   ip, hw_type, flags, mac, mask, device) >= 4) {
            
            // Skip incomplete entries (flags 0x0)
            if (strcmp(flags, "0x0") == 0) continue;
            // Skip localhost
            if (strcmp(ip, "127.0.0.1") == 0) continue;
            
            int idx = find_client(mac);
            if (idx >= 0) {
                // Existing client - update
                clients[idx].last_seen = now;
                clients[idx].seen_count++;
                clients[idx].active = 1;
                strncpy(clients[idx].ip, ip, sizeof(clients[idx].ip) - 1);
            } else if (client_count < MAX_CLIENTS) {
                // New client
                idx = client_count++;
                strncpy(clients[idx].mac, mac, sizeof(clients[idx].mac) - 1);
                strncpy(clients[idx].ip, ip, sizeof(clients[idx].ip) - 1);
                clients[idx].first_seen = now;
                clients[idx].last_seen = now;
                clients[idx].seen_count = 1;
                clients[idx].active = 1;
                
                // Log to file
                log_client(&clients[idx]);
                
                char logbuf[128];
                snprintf(logbuf, sizeof(logbuf), "New client: %s (%s)", mac, ip);
                daglog(logbuf);
            }
        }
    }
    fclose(fp);
}

int clients_get_count() {
    int active = 0;
    for (int i = 0; i < client_count; i++) {
        if (clients[i].active) active++;
    }
    return active;
}

void clients_get_html(char *buf, int max) {
    int o = 0;
    time_t now = time(NULL);
    
    o += snprintf(buf + o, max - o, 
        "<table style='width:100%%;border-collapse:collapse;font-size:12px;'>"
        "<tr style='border-bottom:1px solid #0f0;'>"
        "<th>Status</th><th>MAC Address</th><th>IP</th><th>First Seen</th><th>Last Seen</th><th>Count</th></tr>");
    
    for (int i = 0; i < client_count && o < max - 512; i++) {
        char first_buf[32], last_buf[32];
        struct tm *tm;
        
        tm = localtime(&clients[i].first_seen);
        strftime(first_buf, sizeof(first_buf), "%m/%d %H:%M", tm);
        
        tm = localtime(&clients[i].last_seen);
        strftime(last_buf, sizeof(last_buf), "%m/%d %H:%M", tm);
        
        int age = (int)(now - clients[i].last_seen);
        const char *status = clients[i].active ? "🟢" : (age < 300 ? "🟡" : "🔴");
        
        o += snprintf(buf + o, max - o,
            "<tr style='border-bottom:1px solid #003300;'>"
            "<td style='text-align:center;'>%s</td>"
            "<td><code>%s</code></td>"
            "<td>%s</td>"
            "<td>%s</td>"
            "<td>%s</td>"
            "<td>%d</td></tr>",
            status, clients[i].mac, clients[i].ip, first_buf, last_buf, clients[i].seen_count);
    }
    
    o += snprintf(buf + o, max - o, "</table>");
}

void clients_get_json(char *buf, int max) {
    int o = 0;
    time_t now = time(NULL);
    
    o += snprintf(buf + o, max - o, "{\"count\":%d,\"clients\":[", clients_get_count());
    
    for (int i = 0; i < client_count && o < max - 256; i++) {
        if (i > 0) o += snprintf(buf + o, max - o, ",");
        
        int age = (int)(now - clients[i].last_seen);
        
        o += snprintf(buf + o, max - o,
            "{\"mac\":\"%s\",\"ip\":\"%s\",\"active\":%d,\"age\":%d,\"count\":%d}",
            clients[i].mac, clients[i].ip, clients[i].active, age, clients[i].seen_count);
    }
    
    o += snprintf(buf + o, max - o, "]}");
}

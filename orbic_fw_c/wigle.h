#ifndef WIGLE_H
#define WIGLE_H

// Configuration structure
typedef struct {
    char wigle_api_name[128];
    char wigle_api_token[128];
    char opencellid_token[128];
    int auto_upload;      // 1 = enabled, 0 = disabled
    int auto_wardrive;    // 1 = enabled, 0 = disabled
    // Settings persistence
    int default_ttl;      // 0 = disabled, 65 = typical for hotspot masking
    char spoofed_mac[18]; // XX:XX:XX:XX:XX:XX format
} AppConfig;

// Load full config from file
int config_load(AppConfig *cfg);

// Save full config to file
int config_save(const AppConfig *cfg);

// Upload a wardrive CSV file to Wigle.net
// Returns 0 on success, negative on error
int wigle_upload(const char *filepath);

// Upload all wardrive files in /data/
int wigle_upload_all();

#endif

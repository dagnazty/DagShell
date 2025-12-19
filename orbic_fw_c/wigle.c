#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include "wigle.h"
#include "log.h"

#define CONFIG_FILE "/data/dagshell_config"

// Load full config from file
// Format: key=value per line
int config_load(AppConfig *cfg) {
    memset(cfg, 0, sizeof(AppConfig));
    
    FILE *fp = fopen(CONFIG_FILE, "r");
    if (!fp) return -1;
    
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\n")] = 0;
        
        if (strncmp(line, "wigle_api_name=", 15) == 0) {
            strncpy(cfg->wigle_api_name, line + 15, 127);
        } else if (strncmp(line, "wigle_api_token=", 16) == 0) {
            strncpy(cfg->wigle_api_token, line + 16, 127);
        } else if (strncmp(line, "opencellid_token=", 17) == 0) {
            strncpy(cfg->opencellid_token, line + 17, 127);
        } else if (strncmp(line, "auto_upload=", 12) == 0) {
            cfg->auto_upload = atoi(line + 12);
        } else if (strncmp(line, "auto_wardrive=", 14) == 0) {
            cfg->auto_wardrive = atoi(line + 14);
        }
    }
    fclose(fp);
    return 0;
}

// Save full config to file
int config_save(const AppConfig *cfg) {
    FILE *fp = fopen(CONFIG_FILE, "w");
    if (!fp) return -1;
    
    fprintf(fp, "wigle_api_name=%s\n", cfg->wigle_api_name);
    fprintf(fp, "wigle_api_token=%s\n", cfg->wigle_api_token);
    fprintf(fp, "opencellid_token=%s\n", cfg->opencellid_token);
    fprintf(fp, "auto_upload=%d\n", cfg->auto_upload);
    fprintf(fp, "auto_wardrive=%d\n", cfg->auto_wardrive);
    
    fclose(fp);
    return 0;
}

// Upload a wardrive CSV file to Wigle.net
int wigle_upload(const char *filepath) {
    AppConfig cfg;
    if (config_load(&cfg) < 0 || strlen(cfg.wigle_api_name) == 0) {
        return -1; // No credentials configured
    }
    
    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
        "curl -s -o /tmp/wigle_response.txt -w '%%{http_code}' "
        "-u '%s:%s' "
        "-F 'file=@%s' "
        "https://api.wigle.net/api/v2/file/upload",
        cfg.wigle_api_name, cfg.wigle_api_token, filepath);
    
    FILE *fp = popen(cmd, "r");
    if (!fp) return -2;
    
    char http_code[8] = {0};
    fgets(http_code, sizeof(http_code), fp);
    pclose(fp);
    
    int code = atoi(http_code);
    if (code == 200 || code == 201) {
        daglog("Wigle upload successful");
        return 0; // Success
    } else if (code == 401) {
        daglog("Wigle upload failed: Auth error");
        return -3; // Auth failed
    } else {
        daglog("Wigle upload failed: Unknown error");
        return -4; // Other error
    }
}

// Upload all wardrive files in /data/ and delete on success
int wigle_upload_all() {
    DIR *dir = opendir("/data");
    if (!dir) return -1;
    
    struct dirent *ent;
    int uploaded = 0;
    
    while ((ent = readdir(dir)) != NULL) {
        if (strstr(ent->d_name, "wardrive") && strstr(ent->d_name, ".csv")) {
            char path[256];
            snprintf(path, sizeof(path), "/data/%s", ent->d_name);
            
            if (wigle_upload(path) == 0) {
                unlink(path); // Delete on success
                uploaded++;
            }
        }
    }
    closedir(dir);
    return uploaded;
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <termios.h>
#include <ctype.h>
#include <time.h>

#include "gps.h"
#include "wifi.h"

#define PORT 8081
#define BUFFER_SIZE 8192  // Increased buffer for larger pages
#define MODEM_PORT "/dev/smd8"

// --- HELPERS ---
void url_decode(char *dst, const char *src) {
    char a, b;
    while (*src) {
        if ((*src == '%') &&
            ((a = src[1]) && (b = src[2])) &&
            (isxdigit(a) && isxdigit(b))) {
            if (a >= 'a') a -= 'a'-'A';
            if (a >= 'A') a -= ('A' - 10);
            else a -= '0';
            if (b >= 'a') b -= 'a'-'A';
            if (b >= 'A') b -= ('A' - 10);
            else b -= '0';
            *dst++ = 16*a+b;
            src+=3;
        } else if (*src == '+') {
            *dst++ = ' ';
            src++;
        } else {
            *dst++ = *src++;
        }
    }
    *dst = '\0';
}

void run_command(const char *cmd, char *output, size_t max_len) {
    FILE *fp = popen(cmd, "r");
    if (fp == NULL) {
        snprintf(output, max_len, "Error");
        return;
    }
    size_t total = 0;
    while (fgets(output + total, max_len - total - 1, fp) != NULL) {
        total += strlen(output + total);
        if (total >= max_len - 1) break;
    }
    output[total] = '\0';
    pclose(fp);
}

void send_at_command(const char *cmd, char *response, size_t max_len) {
    int fd = -1;
    int retries = 0;
    while (fd < 0 && retries < 5) {
        fd = open(MODEM_PORT, O_RDWR | O_NOCTTY | O_NONBLOCK);
        if (fd < 0) { usleep(100000); retries++; }
    }
    if (fd < 0) { snprintf(response, max_len, "Modem Busy"); return; }
    char buf[256]; snprintf(buf, sizeof(buf), "%s\r", cmd);
    write(fd, buf, strlen(buf));
    usleep(100000);
    int total = 0;
    int tries = 0;
    while (tries < 10 && total < max_len - 1) {
        ssize_t n = read(fd, response + total, max_len - total - 1);
        if (n > 0) total += n; else { usleep(50000); tries++; }
    }
    response[total] = '\0';
    close(fd);
}

void send_sms(const char *number, const char *msg, char *status, size_t max_len) {
    int fd = open(MODEM_PORT, O_RDWR | O_NOCTTY | O_NONBLOCK);
    if (fd < 0) { snprintf(status, max_len, "Modem Error"); return; }
    char cmd[256];
    write(fd, "AT+CMGF=1\r", 10); usleep(200000);
    snprintf(cmd, sizeof(cmd), "AT+CMGS=\"%s\"\r", number);
    write(fd, cmd, strlen(cmd)); usleep(200000);
    write(fd, msg, strlen(msg));
    write(fd, "\x1A", 1);
    sleep(2);
    snprintf(status, max_len, "Message sent to queue.");
    close(fd);
}


void handle_client(int client_fd) {
    char buffer[BUFFER_SIZE];
    ssize_t bytes_read = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
    if (bytes_read <= 0) { close(client_fd); return; }
    buffer[bytes_read] = '\0';


    // API: File Download - Handle GET /download?file=/data/filename (MUST BE BEFORE BUFFER MODIFICATION)
    if (strncmp(buffer, "GET /download?file=", 19) == 0) {
        char raw_path[256] = {0};
        char filename[256] = {0};
        char *start = buffer + 19;
        char *end = strchr(start, ' ');
        if (!end) end = strchr(start, '\r');
        if (!end) end = strchr(start, '\n');
        
        if (end && (end - start) < 255 && (end - start) > 0) {
            strncpy(raw_path, start, end - start);
            raw_path[end - start] = '\0';
            url_decode(filename, raw_path);
            
            if (strncmp(filename, "/data/", 6) == 0) {
                FILE *fp = fopen(filename, "rb");
                if (fp) {
                    fseek(fp, 0, SEEK_END);
                    long fsize = ftell(fp);
                    fseek(fp, 0, SEEK_SET);
                    
                    char *bname = strrchr(filename, '/');
                    if (bname) bname++; else bname = filename;
                    
                    char header[512];
                    snprintf(header, sizeof(header),
                        "HTTP/1.1 200 OK\r\n"
                        "Content-Type: application/octet-stream\r\n"
                        "Content-Disposition: attachment; filename=\"%s\"\r\n"
                        "Content-Length: %ld\r\n"
                        "Connection: close\r\n\r\n", bname, fsize);
                    send(client_fd, header, strlen(header), 0);
                    
                    char chunk[4096];
                    size_t n;
                    while ((n = fread(chunk, 1, sizeof(chunk), fp)) > 0) {
                        send(client_fd, chunk, n, 0);
                    }
                    fclose(fp);
                    close(client_fd);
                    return;
                }
            }
        }
        char *err = "HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\nFile not found";
        send(client_fd, err, strlen(err), 0);
        close(client_fd);
        return;
    }

    // --- PARSE REQUEST ---
    char page[32] = "home";
    char at_cmd[256] = {0};
    char at_response[1024] = {0};

    char *qm = strchr(buffer, '?');
    if (qm) {
        char *sp = strchr(qm, ' '); if(sp)*sp=0;
        if (strstr(qm, "page=net")) strcpy(page, "net");
        if (strstr(qm, "page=privacy")) strcpy(page, "privacy");
        if (strstr(qm, "page=sms")) strcpy(page, "sms");
        if (strstr(qm, "page=tools")) strcpy(page, "tools");
        if (strstr(qm, "page=gps")) strcpy(page, "gps");
        if (strstr(qm, "page=wardrive")) strcpy(page, "wardrive");

        if (strstr(qm, "page=files")) strcpy(page, "files");
        
        char *cmd_ptr = strstr(qm, "cmd=");
        if (cmd_ptr) url_decode(at_cmd, cmd_ptr + 4);
    }

    // --- EXECUTE ACTIONS (Global) ---
    if (strlen(at_cmd) > 0) send_at_command(at_cmd, at_response, sizeof(at_response));


    // API: GPS JSON
    if (strstr(buffer, "cmd=gps_json")) {
        char json[256];
        if (gps_get_json(json, sizeof(json)) < 0) sprintf(json, "{\"lat\":\"0\",\"lon\":\"0\"}");
        char resp[512];
        snprintf(resp, sizeof(resp), "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\n\r\n%s", json);
        send(client_fd, resp, strlen(resp), 0);
        close(client_fd);
        return;
    }

    // --- RENDER UI ---
    // Using heap for body to avoid stack overflow with large pages
    char *body = malloc(65536);
    if (!body) { close(client_fd); return; }
    
    int o = 0;
    
    // Header & CSS
    o += sprintf(body+o, "<html><head><meta charset='UTF-8'><title>DagShell</title>"
        "<style>"
        "@import url('https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;700&display=swap');"
        "*{box-sizing:border-box;}body{font-family:'Fira Code',monospace;background:#0a0a0a;color:#0f0;margin:0;padding:20px;}"
        ".scan{position:fixed;top:0;left:0;width:100%%;height:100%%;pointer-events:none;background:repeating-linear-gradient(0deg,rgba(0,0,0,0.1),rgba(0,0,0,0.1) 1px,transparent 1px,transparent 2px);z-index:999;}"
        ".logo{color:#0f0;font-size:12px;white-space:pre;text-shadow:0 0 10px #0f0;}"
        ".nav{display:flex;flex-wrap:wrap;gap:10px;margin:20px 0;border-bottom:1px solid #003300;padding-bottom:10px;}"
        ".nav a{color:#0f0;text-decoration:none;padding:5px 10px;border:1px solid #003300;transition:0.3s;}"
        ".nav a:hover,.nav a.active{background:#003300;box-shadow:0 0 10px #0f0;color:#fff;}"
        ".card{background:rgba(0,20,0,0.8);border:1px solid #0f0;padding:20px;margin-bottom:20px;box-shadow:0 0 10px rgba(0,255,0,0.1);}"
        "h1,h2,h3{color:#0ff;text-shadow:0 0 5px #0ff;margin-top:0;}"
        "input,textarea{background:#001100;color:#0f0;border:1px solid #004400;padding:10px;width:100%%;font-family:inherit;}"
        "button{background:#003300;color:#0f0;border:1px solid #0f0;padding:10px 20px;cursor:pointer;}"
        "button:hover{background:#0f0;color:#000;}"
        "pre{background:#000;border-left:3px solid #0f0;padding:10px;overflow-x:auto;}"
        ".warn{color:#ff4444;border-color:#ff4444;}"
        "</style></head><body><div class='scan'></div>"
        "<div style='text-align:center'><pre class='logo'>"
        " ____             ____  _          _ _ \n"
        "|  _ \\  __ _  __ / ___|| |__   ___| | |\n"
        "| | | |/ _` |/ _\\\\___ \\| '_ \\ / _ \\ | |\n"
        "| |_| | (_| | (_| |__) | | | |  __/ | |\n"
        "|____/ \\__,_|\\__, |___/|_| |_|\\___|_|_|\n"
        "             |___/                     \n"
        "[ Orbic RCL400 Custom Firmware v2.0 ]</pre></div>");

    // Navigation
    o += sprintf(body+o, 
        "<div class='nav'>"
        "<a href='/' class='%s'>HOME</a>"
        "<a href='/?page=net' class='%s'>NETWORK</a>"
        "<a href='/?page=privacy' class='%s'>PRIVACY</a>"
        "<a href='/?page=sms' class='%s'>SMS</a>"
        "<a href='/?page=tools' class='%s'>TOOLS</a>"
        "<a href='/?page=gps' class='%s'>GPS</a>"
        "<a href='/?page=wardrive' class='%s'>WARDRIVE</a>"
        "<a href='/?page=files' class='%s'>FILES</a>"
        "</div>",
        strcmp(page,"home")==0?"active":"", strcmp(page,"net")==0?"active":"",
        strcmp(page,"privacy")==0?"active":"", strcmp(page,"sms")==0?"active":"",
        strcmp(page,"tools")==0?"active":"", strcmp(page,"gps")==0?"active":"",
        strcmp(page,"wardrive")==0?"active":"",
        strcmp(page,"files")==0?"active":"");

    // --- PAGE LOGIC ---
    if (strcmp(page, "home") == 0) {
        float up=0; FILE *f=fopen("/proc/uptime","r"); if(f){fscanf(f,"%f",&up);fclose(f);}
        o += sprintf(body+o, 
            "<div class='card'><h2>Status</h2><p>Uptime: %.2fs</p><hr>"
            "<h3>Modem Command (AT)</h3>"
            "<form><input type='text' name='cmd' placeholder='ATI' value='%s'><button>Send</button></form>"
            "<pre>%s</pre></div>",
            up, at_cmd, at_response);
    }
    else if (strcmp(page, "net") == 0) {
        // --- Network Logic Restored ---
        char cmd_out[4096];
        char ttl_msg[64] = "";
        
        // Apply TTL
        if (strstr(buffer, "ttl=")) {
            char *p=strstr(buffer,"ttl=")+4; int v=atoi(p);
            if (v>0) {
                char ic[256];
                sprintf(ic,"iptables -t mangle -I POSTROUTING 1 -j TTL --ttl-set %d",v); system(ic);
                sprintf(ttl_msg,"TTL Set to %d",v);
            }
        }
        
        o += sprintf(body+o, "<div class='card'><h2>Network</h2>"
            "<form><input type='hidden' name='page' value='net'><input type='text' name='ttl' placeholder='TTL Fix (e.g. 65)'><button>Apply</button></form>"
            "<p>%s</p>", ttl_msg);
            
        // Interfaces
        run_command("ip addr show wlan0", cmd_out, sizeof(cmd_out));
        o += sprintf(body+o, "<h3>Management (wlan0)</h3><pre>%s</pre>", cmd_out);
        
        run_command("ip addr show wlan1", cmd_out, sizeof(cmd_out));
        o += sprintf(body+o, "<h3>Attack Interface (wlan1)</h3><pre>%s</pre>", cmd_out);
        
        // ARP (Clients) - Show all
        run_command("cat /proc/net/arp", cmd_out, sizeof(cmd_out));
        o += sprintf(body+o, "<h3>ARP / Clients</h3><pre>%s</pre>", cmd_out);
        
        // Connections
        run_command("netstat -ntu", cmd_out, sizeof(cmd_out));
        o += sprintf(body+o, "<h3>Active Connections</h3><pre>%s</pre></div>", cmd_out);
    }
    else if (strcmp(page, "privacy") == 0) {
        // --- Privacy Logic Restored ---
        char msg[256] = "";
        
        // Adblock
        if (strstr(buffer, "adblock=1")) { system("echo '0.0.0.0 doubleclick.net' > /data/hosts; killall -HUP dnsmasq"); strcpy(msg,"AdBlock ENABLED"); }
        if (strstr(buffer, "adblock=0")) { system("echo '' > /data/hosts; killall -HUP dnsmasq"); strcpy(msg,"AdBlock DISABLED"); }
        
        // MAC Spoofing
        char *mac_ptr = strstr(buffer, "mac=");
        if (mac_ptr) {
            char new_mac[32]={0}, enc_mac[64]={0};
            char *end = strstr(mac_ptr, " "); if(!end) end=buffer+strlen(buffer);
            strncpy(enc_mac, mac_ptr+4, end-(mac_ptr+4));
            url_decode(new_mac, enc_mac);
            if(strlen(new_mac)>8) {
                char c[256];
                system("ifconfig wlan1 down");
                snprintf(c,sizeof(c),"ifconfig wlan1 hw ether %s", new_mac); system(c);
                system("ifconfig wlan1 up");
                sprintf(msg, "MAC Spoofed: %s", new_mac);
            }
        }

        o += sprintf(body+o, "<div class='card'><h2>Privacy</h2><p style='color:#0f0'>%s</p>"
            "<h3>AdBlock</h3><a href='/?page=privacy&adblock=1'><button>Enable</button></a> <a href='/?page=privacy&adblock=0'><button class='warn'>Disable</button></a>"
            "<h3>MAC Spoofing</h3><form><input type='hidden' name='page' value='privacy'><input type='text' name='mac' placeholder='XX:XX:XX...'><button>Spoof</button></form></div>", msg);
    }
    else if (strcmp(page, "sms") == 0) {
        // --- SMS Logic Restored ---
        // Handle Send
        char *num_ptr = strstr(buffer, "num=");
        char *msg_ptr = strstr(buffer, "msg=");
        if (num_ptr && msg_ptr) {
             char number[32]={0}, message[160]={0}, raw_n[64], raw_m[256];
             char *a = strchr(num_ptr,'&'); if(a) strncpy(raw_n,num_ptr+4,a-(num_ptr+4));
             char *e = strchr(msg_ptr,' '); if(!e) e=buffer+strlen(buffer);
             strncpy(raw_m, msg_ptr+4, e-(msg_ptr+4));
             url_decode(number,raw_n); url_decode(message,raw_m);
             send_sms(number, message, at_response, sizeof(at_response));
        }
        
        o += sprintf(body+o, "<div class='card'><h2>SMS Manager</h2>"
            "<p>%s</p>"
            "<form><input type='hidden' name='page' value='sms'>"
            "<input type='text' name='num' placeholder='+1234567890'>"
            "<textarea name='msg' placeholder='Message'></textarea><br><br>"
            "<button>Send</button></form>"
            "<p><a href='http://192.168.1.1/common/shortmessage.html' target='_blank'>[Open Orbic Inbox]</a></p></div>", at_response);
    }
    else if (strcmp(page, "tools") == 0) {
        // --- Tools Logic Restored ---
        
        // IMSI Catcher Info
        char cell[2048], creg[512], csq[256];
        send_at_command("AT+COPS?", cell, sizeof(cell));
        send_at_command("AT+CREG?", creg, sizeof(creg));
        send_at_command("AT+CSQ", csq, sizeof(csq));
        
        // Port Scan
        char scan_res[4096]="";
        char *sip = strstr(buffer, "scan_ip=");
        if (sip) {
            char ip[32]={0}, ports[128]={0};
            char *p2 = strstr(buffer, "scan_ports=");
            if(p2) {
                char *a=strchr(sip,'&'); if(a) strncpy(ip,sip+8,a-(sip+8));
                char *e=strchr(p2,' '); if(!e) e=buffer+strlen(buffer);
                strncpy(ports,p2+11,e-(p2+11));
                
                // Scan Loop
                char *tok = strtok(ports, ",");
                strcat(scan_res, "Scan Results:\n");
                while(tok) {
                    char cmd[256], out[256];
                    snprintf(cmd,sizeof(cmd),"nc -zv -w 1 %s %s 2>&1", ip, tok);
                    run_command(cmd, out, sizeof(out));
                    if(strstr(out,"open")) { strcat(scan_res, "Port "); strcat(scan_res, tok); strcat(scan_res, ": OPEN\n"); }
                    tok = strtok(NULL, ",");
                }
            }
        }
        
        // Firewall
        if (strstr(buffer, "block_ip=")) {
            char *b = strstr(buffer,"block_ip=")+9; char ip[32]; char *e=strchr(b,' '); if(!e)e=b+strlen(b); strncpy(ip,b,e-b); ip[e-b]=0;
            char c[128]; snprintf(c,sizeof(c),"iptables -A INPUT -s %s -j DROP",ip); system(c);
        }
        if (strstr(buffer, "unblock_ip=")) {
            char *b = strstr(buffer,"unblock_ip=")+11; char ip[32]; char *e=strchr(b,' '); if(!e)e=b+strlen(b); strncpy(ip,b,e-b); ip[e-b]=0;
            char c[128]; snprintf(c,sizeof(c),"iptables -D INPUT -s %s -j DROP",ip); system(c);
        }
        
        // Firewall Rules
        char rules[4096];
        run_command("iptables -L INPUT -n --line-numbers | head -20", rules, sizeof(rules));

        o += sprintf(body+o, "<div class='card'><h2>Tools</h2>"
            "<h3>IMSI / Cell Info</h3><pre>COPS: %s\nCREG: %s\nSIG: %s</pre>"
            "<h3>Port Scanner</h3><form><input type='hidden' name='page' value='tools'><input type='text' name='scan_ip' placeholder='IP'><input type='text' name='scan_ports' placeholder='80,443,22'><button>Scan</button></form><pre>%s</pre>"
            "<h3>Firewall</h3><form><input type='hidden' name='page' value='tools'><input type='text' name='block_ip' placeholder='Block IP'><button class='warn'>Block</button></form>"
            "<form><input type='hidden' name='page' value='tools'><input type='text' name='unblock_ip' placeholder='Unblock IP'><button>Unblock</button></form>"
            "<pre>%s</pre></div>", cell, creg, csq, scan_res, rules);
    }
    else if (strcmp(page, "gps") == 0) {
        gps_update(); char json[256]; gps_get_json(json, sizeof(json));
        o += sprintf(body+o, "<div class='card'><h2>GPS Tracker</h2>"
            "<p>Data: %s</p><button onclick='location.reload()'>Refresh</button></div>", json);
    }
    else if (strcmp(page, "wardrive") == 0) {
        char res[8192]="";
        if (strstr(buffer,"action=scan")) {
            // Get scan results as JSON, then format for display
            char json[4096];
            wifi_scan_json(json, sizeof(json));
            
            // Parse JSON and format nicely (one network per line)
            // Format: BSSID | SSID | RSSI | ENC
            strcpy(res, "BSSID              | SSID                           | RSSI | ENC\n");
            strcat(res, "-------------------|--------------------------------|------|-----\n");
            
            char *p = json;
            while ((p = strstr(p, "\"bssid\":\"")) != NULL) {
                char bssid[20]="", ssid[64]="", enc[16]="";
                int rssi = 0;
                
                // Parse bssid
                p += 9;
                char *e = strchr(p, '"');
                if (e && (e-p) < 20) { strncpy(bssid, p, e-p); bssid[e-p]=0; }
                
                // Parse ssid
                char *sp = strstr(p, "\"ssid\":\"");
                if (sp) {
                    sp += 8;
                    e = strchr(sp, '"');
                    if (e && (e-sp) < 64) { strncpy(ssid, sp, e-sp); ssid[e-sp]=0; }
                }
                
                // Parse rssi
                char *rp = strstr(p, "\"rssi\":");
                if (rp) { rssi = atoi(rp + 7); }
                
                // Parse enc
                char *ep = strstr(p, "\"enc\":\"");
                if (ep) {
                    ep += 7;
                    e = strchr(ep, '"');
                    if (e && (e-ep) < 16) { strncpy(enc, ep, e-ep); enc[e-ep]=0; }
                }
                
                // Format line
                char line[256];
                snprintf(line, sizeof(line), "%-18s | %-30s | %4d | %s\n", 
                    bssid, ssid[0] ? ssid : "(hidden)", rssi, enc);
                strcat(res, line);
                
                p++; // Move past to find next entry
            }
        }
        if (strstr(buffer,"action=log")) { wifi_new_session(); wifi_log_kml("0","0"); strcpy(res,"Logged to new file."); }
        if (strstr(buffer,"action=start")) { wifi_start_wardrive(); strcpy(res,"Loop Started."); }
        if (strstr(buffer,"action=stop")) { wifi_stop_wardrive(); strcpy(res,"Loop Stopped."); }
        
        o += sprintf(body+o, "<div class='card'><h2>Wardriver</h2>"
            "<p>Status: <b>%s</b></p>"
            "<a href='/?page=wardrive&action=start'><button>Start Loop</button></a> "
            "<a href='/?page=wardrive&action=stop'><button class='warn'>Stop Loop</button></a><br><br>"
            "<a href='/?page=wardrive&action=scan'><button>Single Scan</button></a> "
            "<a href='/?page=wardrive&action=log'><button>Log Single</button></a>"
            "<pre style='font-size:11px;overflow-x:auto;'>%s</pre></div>", 
            wifi_is_wardriving()?"RUNNING":"STOPPED", res);
    }

    else if (strcmp(page, "files") == 0) {
        char delete_msg[256] = "";
        
        // Handle delete action
        char *del_ptr = strstr(buffer, "delete=");
        if (del_ptr) {
            char raw_file[256] = {0}, filename[256] = {0};
            char *end = strchr(del_ptr + 7, ' ');
            if (!end) end = strchr(del_ptr + 7, '&');
            if (!end) end = del_ptr + 7 + strlen(del_ptr + 7);
            if ((end - (del_ptr + 7)) < 255) {
                strncpy(raw_file, del_ptr + 7, end - (del_ptr + 7));
                url_decode(filename, raw_file);
                // Only allow deleting files in /data/
                if (strncmp(filename, "/data/", 6) == 0 && strlen(filename) > 6) {
                    char cmd[512];
                    snprintf(cmd, sizeof(cmd), "rm -f '%s'", filename);
                    system(cmd);
                    snprintf(delete_msg, sizeof(delete_msg), "Deleted: %s", filename);
                }
            }
        }
        
        o += sprintf(body+o, "<div class='card'><h2>File Explorer</h2>"
            "<p>Download/delete files from <code>/data/</code></p>");
        if (delete_msg[0]) {
            o += sprintf(body+o, "<p style='color:#0f0'>%s</p>", delete_msg);
        }
        
        // List files in /data
        FILE *ls = popen("ls -la /data/", "r");
        if (ls) {
            o += sprintf(body+o, "<table style='width:100%%;border-collapse:collapse;'>"
                "<tr style='border-bottom:1px solid #0f0'><th>Name</th><th>Size</th><th>Actions</th></tr>");
            
            char line[512];
            while (fgets(line, sizeof(line), ls)) {
                // Parse ls -la output: -rw-r--r-- 1 root root 12345 Jan 01 12:00 filename
                char perms[16], links[8], owner[32], group[32], month[8], day[8], time_or_year[16], name[256];
                long size = 0;
                
                if (sscanf(line, "%15s %7s %31s %31s %ld %7s %7s %15s %255[^\n]", 
                    perms, links, owner, group, &size, month, day, time_or_year, name) >= 9) {
                    
                    // Skip directories (start with 'd') and . / ..
                    if (perms[0] == 'd' || strcmp(name, ".") == 0 || strcmp(name, "..") == 0) continue;
                    
                    // Check if it's a wardrive file (safe to delete without warning)
                    int is_wardrive = (strstr(name, "wardrive") != NULL && strstr(name, ".csv") != NULL);
                    
                    if (is_wardrive) {
                        // Wardrive files - direct delete
                        o += sprintf(body+o, 
                            "<tr><td>%s</td><td>%ld</td><td>"
                            "<a href='/download?file=/data/%s'><button>DL</button></a> "
                            "<a href='/?page=files&delete=/data/%s'><button>Del</button></a></td></tr>",
                            name, size, name, name);
                    } else {
                        // Non-wardrive files - delete with JS confirmation
                        o += sprintf(body+o, 
                            "<tr><td>%s</td><td>%ld</td><td>"
                            "<a href='/download?file=/data/%s'><button>DL</button></a> "
                            "<a href='/?page=files&delete=/data/%s' onclick=\"return confirm('WARNING: This is not a wardrive file. Delete %s?');\"><button class='warn'>Del</button></a></td></tr>",
                            name, size, name, name, name);
                    }
                }
            }
            pclose(ls);
            o += sprintf(body+o, "</table>");
        } else {
            o += sprintf(body+o, "<p class='warn'>Error listing directory</p>");
        }
        
        o += sprintf(body+o, "</div>");
    }
    
    strcat(body, "</body></html>");
    char resp[16384]; // Header buffer
    // Send header first
    sprintf(resp, "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n");
    send(client_fd, resp, strlen(resp), 0);
    // Send body
    send(client_fd, body, strlen(body), 0);
    
    free(body);
    close(client_fd);
}

int main(int argc, char *argv[]) {
    // Check for Background Mode
    if (argc > 1 && strcmp(argv[1], "--wardrive") == 0) {
        wifi_wardrive_process();
        return 0;
    }

    gps_init();
    
    int server_fd, client_fd; 
    struct sockaddr_in address; 
    int opt=1; 
    socklen_t addrlen=sizeof(address);
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) exit(1);
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    address.sin_family = AF_INET; address.sin_addr.s_addr = INADDR_ANY; address.sin_port = htons(PORT);
    bind(server_fd, (struct sockaddr *)&address, sizeof(address));
    listen(server_fd, 3);
    while (1) {
        if ((client_fd = accept(server_fd, (struct sockaddr *)&address, &addrlen)) >= 0) {
            handle_client(client_fd);
        }
    }
    return 0;
}

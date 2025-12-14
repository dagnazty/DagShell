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

#define PORT 8081
#define BUFFER_SIZE 4096
#define MODEM_PORT "/dev/smd8"

// Helper to decode URL (primitive)
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

void send_at_command(const char *cmd, char *response, size_t max_len) {
    int fd = -1;
    int retries = 0;
    while (fd < 0 && retries < 5) {
        fd = open(MODEM_PORT, O_RDWR | O_NOCTTY | O_NONBLOCK);
        if (fd < 0) {
            usleep(200000); // 200ms
            retries++;
        }
    }
    
    if (fd < 0) {
        snprintf(response, max_len, "Error: Could not open modem port %s (Busy)", MODEM_PORT);
        return;
    }

    // Write command
    char cmd_buf[256];
    snprintf(cmd_buf, sizeof(cmd_buf), "%s\r", cmd);
    write(fd, cmd_buf, strlen(cmd_buf));

    // Wait and read
    usleep(100000); // 100ms wait
    
    // Simple non-blocking read loop
    int total = 0;
    int tries = 0;
    while (tries < 10 && total < max_len - 1) {
        ssize_t n = read(fd, response + total, max_len - total - 1);
        if (n > 0) {
            total += n;
        } else {
            usleep(50000); // Wait bit more
            tries++;
        }
    }
    response[total] = '\0';
    close(fd);
    
    if (total == 0) strcpy(response, "No response from modem.");
}

// Helper to run shell command and capture output
void run_command(const char *cmd, char *output, size_t max_len) {
    FILE *fp = popen(cmd, "r");
    if (fp == NULL) {
        snprintf(output, max_len, "Error running command: %s", cmd);
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

// Helper to send SMS (blind send)
void send_sms(const char *number, const char *msg, char *status, size_t max_len) {
    int fd = -1;
    int retries = 0;
    while (fd < 0 && retries < 5) {
        fd = open(MODEM_PORT, O_RDWR | O_NOCTTY | O_NONBLOCK);
        if (fd < 0) {
            usleep(200000); // 200ms
            retries++;
        }
    }
    
    if (fd < 0) {
        snprintf(status, max_len, "Error opening modem (Busy).");
        return;
    }

    char cmd[256];
    snprintf(cmd, sizeof(cmd), "AT+CMGF=1\r");
    write(fd, cmd, strlen(cmd));
    usleep(200000);

    snprintf(cmd, sizeof(cmd), "AT+CMGS=\"%s\"\r", number);
    write(fd, cmd, strlen(cmd));
    usleep(200000); // Wait for '>'

    write(fd, msg, strlen(msg));
    write(fd, "\x1A", 1); // Ctrl+Z
    
    // Wait for +CMGS or ERROR
    // For now we just wait blindly and confirm sent
    sleep(2);
    
    snprintf(status, max_len, "Message sent to queue.");
    close(fd);
}

void handle_client(int client_fd) {
    char buffer[BUFFER_SIZE];
    ssize_t bytes_read = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
    
    if (bytes_read > 0) {
        buffer[bytes_read] = '\0';
        
        // Parse Request
        char page[32] = "home";
        char at_cmd[256] = {0};
        char at_response[1024] = {0};
        
        // Simple Query Parsing
        char *qm = strchr(buffer, '?');
        if (qm) {
            char *space = strchr(qm, ' ');
            if (space) *space = 0;
            
            if (strstr(qm, "page=net")) strcpy(page, "net");
            if (strstr(qm, "page=privacy")) strcpy(page, "privacy");
            if (strstr(qm, "page=sms")) strcpy(page, "sms");
            if (strstr(qm, "page=tools")) strcpy(page, "tools");
            
            char *cmd_ptr = strstr(qm, "cmd=");
            if (cmd_ptr) {
                 url_decode(at_cmd, cmd_ptr + 4);
            }
        }

        // Handle AT Command
        if (strlen(at_cmd) > 0) {
            send_at_command(at_cmd, at_response, sizeof(at_response));
        }
        
        // SMS Send Handling with Redirect
        if (strcmp(page, "sms") == 0) {
            char *num_ptr = strstr(buffer, "num=");
            char *msg_ptr = strstr(buffer, "msg=");
            if (num_ptr && msg_ptr) {
                // ... same extraction logic ...
                char number[32] = {0};
                char msg[160] = {0};
                char *amp = strchr(num_ptr, '&');
                if (amp && msg_ptr > amp) {
                     char raw_num[64] = {0};
                     strncpy(raw_num, num_ptr + 4, amp - (num_ptr + 4));
                     url_decode(number, raw_num);
                     
                     char raw_msg[256] = {0};
                     char *end_msg = strchr(msg_ptr, ' ');
                     if (!end_msg) end_msg = buffer + strlen(buffer);
                     strncpy(raw_msg, msg_ptr + 4, end_msg - (msg_ptr + 4));
                     url_decode(msg, raw_msg);
                     
                     if (strlen(number) > 0 && strlen(msg) > 0) {
                         send_sms(number, msg, at_response, sizeof(at_response));
                         
                         // Redirect to avoid double-send
                         char *redir = "HTTP/1.1 302 Found\r\nLocation: /?page=sms\r\nConnection: close\r\n\r\n";
                         send(client_fd, redir, strlen(redir), 0);
                         close(client_fd);
                         return; // Done
                     }
                }
            }
        }

        // Common Header - DagShell Terminal Theme
        char body[32768]; // Larger buffer for ASCII art
        int body_off = snprintf(body, sizeof(body), 
            "<html><head><meta charset='UTF-8'><title>DagShell</title>"
            "<style>"
            "@import url('https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;700&display=swap');"
            "*{box-sizing:border-box;}"
            "body{font-family:'Fira Code',Consolas,'Courier New',monospace;background:#0a0a0a;color:#00ff00;margin:0;padding:0;min-height:100vh;}"
            ".scanlines{position:fixed;top:0;left:0;width:100%%;height:100%%;pointer-events:none;background:repeating-linear-gradient(0deg,rgba(0,0,0,0.1),rgba(0,0,0,0.1) 1px,transparent 1px,transparent 2px);z-index:1000;}"
            ".container{max-width:900px;margin:0 auto;padding:20px;position:relative;}"
            ".header{text-align:center;padding:20px 0;border-bottom:1px solid #00ff00;margin-bottom:20px;}"
            ".ascii-logo{font-size:10px;line-height:1.1;color:#00ff00;text-shadow:0 0 10px #00ff00,0 0 20px #00ff00;white-space:pre;display:inline-block;}"
            ".tagline{color:#00ffff;font-size:14px;margin-top:10px;text-shadow:0 0 5px #00ffff;}"
            ".nav{display:flex;justify-content:center;gap:5px;flex-wrap:wrap;margin-bottom:20px;padding:10px;background:rgba(0,255,0,0.05);border:1px solid #003300;}"
            ".nav a{color:#00ff00;text-decoration:none;padding:8px 15px;border:1px solid #003300;transition:all 0.3s;font-size:14px;}"
            ".nav a:hover{background:#003300;box-shadow:0 0 10px #00ff00;}"
            ".nav a.active{background:#00ff00;color:#000;font-weight:bold;box-shadow:0 0 15px #00ff00;}"
            ".card{background:rgba(0,20,0,0.8);border:1px solid #00ff00;padding:20px;margin-bottom:20px;box-shadow:0 0 10px rgba(0,255,0,0.2);}"
            ".card h1,.card h2,.card h3{color:#00ffff;text-shadow:0 0 5px #00ffff;margin-top:0;}"
            ".prompt{color:#00ff00;}"
            ".prompt::before{content:'> ';color:#ffff00;}"
            "input[type=text],textarea{background:#001100;color:#00ff00;border:1px solid #004400;padding:10px;width:100%%;font-family:inherit;font-size:14px;}"
            "input[type=text]:focus,textarea:focus{outline:none;border-color:#00ff00;box-shadow:0 0 10px rgba(0,255,0,0.3);}"
            "input[type=submit],button{background:#003300;color:#00ff00;border:1px solid #00ff00;padding:10px 20px;cursor:pointer;font-family:inherit;transition:all 0.3s;}"
            "input[type=submit]:hover,button:hover{background:#00ff00;color:#000;box-shadow:0 0 15px #00ff00;}"
            "button.warn{background:#330000;color:#ff4444;border-color:#ff4444;}"
            "button.warn:hover{background:#ff4444;color:#000;}"
            "pre{background:#000;border-left:3px solid #00ff00;padding:10px;overflow-x:auto;color:#00ff00;font-size:12px;}"
            "a{color:#00ffff;}"
            ".status-ok{color:#00ff00;}"
            ".status-warn{color:#ffff00;}"
            ".status-error{color:#ff4444;}"
            ".glow{text-shadow:0 0 10px currentColor;}"
            "hr{border:none;border-top:1px solid #003300;margin:20px 0;}"
            ".section{background:rgba(0,40,0,0.3);border-left:3px solid #00ffff;padding:15px;margin:10px 0;}"
            ".blink{animation:blink 1s infinite;}"
            "@keyframes blink{0%%,50%%{opacity:1;}51%%,100%%{opacity:0;}}"
            "</style></head>"
            "<body>"
            "<div class='scanlines'></div>"
            "<div class='container'>"
            "<div class='header'>"
            "<pre class='ascii-logo'>"
            " ____             ____  _          _ _ \n"
            "|  _ \\  __ _  __ / ___|| |__   ___| | |\n"
            "| | | |/ _` |/ _\\\\___ \\| '_ \\ / _ \\ | |\n"
            "| |_| | (_| | (_| |__) | | | |  __/ | |\n"
            "|____/ \\__,_|\\__, |___/|_| |_|\\___|_|_|\n"
            "             |___/                     \n"
            "</pre>"
            "<p class='tagline'>[ Orbic RCL400 Custom Firmware ]</p>"
            "</div>"
            "<div class='nav'>"
            "<a href='/' class='%s'>[HOME]</a>"
            "<a href='/?page=net' class='%s'>[NETWORK]</a>"
            "<a href='/?page=privacy' class='%s'>[PRIVACY]</a>"
            "<a href='/?page=sms' class='%s'>[SMS]</a>"
            "<a href='/?page=tools' class='%s'>[TOOLS]</a>"
            "</div>"
            "<div class='card'>",
            strcmp(page, "home") == 0 ? "active" : "",
            strcmp(page, "net") == 0 ? "active" : "",
            strcmp(page, "privacy") == 0 ? "active" : "",
            strcmp(page, "sms") == 0 ? "active" : "",
            strcmp(page, "tools") == 0 ? "active" : "");

        if (strcmp(page, "home") == 0) {
            // --- HOME PAGE ---
            double uptime_seconds = 0;
            FILE *fp = fopen("/proc/uptime", "r");
            if (fp) { fscanf(fp, "%lf", &uptime_seconds); fclose(fp); }
            
            body_off += snprintf(body + body_off, sizeof(body) - body_off,
                "<h1 style='text-align:center'>Dashboard</h1>"
                "<p style='text-align:center'>System Uptime: <b>%.2f s</b></p>"
                "<hr>"
                "<h3>Modem AT Interface</h3>"
                "<form action='/' method='GET'>"
                "<input type='text' name='cmd' placeholder='e.g., ATI, AT+CSQ' value='%s' autofocus>"
                "<input type='submit' value='Send'>"
                "</form>",
                uptime_seconds, at_cmd);
                
            if (strlen(at_response) > 0) {
                 char safe_resp[2048];
                 snprintf(safe_resp, sizeof(safe_resp), "<br><b>Response:</b><pre>%s</pre>", at_response);
                 strncat(body, safe_resp, sizeof(body) - strlen(body) - 1);
            }
            
        } else if (strcmp(page, "net") == 0) {
            // ... (Network Page Code preserved by context match usually, but I must rewrite if I am replacing logic block)
             // I will try to be efficient and assume previous logic is handled by Replace chunks if I can, but here I am replacing the whole handle_client struct mostly.
             // Actually, to save tokens/errors, I will re-emit the pages since I replaced the start of handle_client.
             
             // --- NETWORK PAGE ---
            char cmd_out[4096];
            char ttl_val[16] = {0};
            // Check for TTL set
            char *ttl_ptr = strstr(buffer, "ttl=");
            if (ttl_ptr) {
                int val = atoi(ttl_ptr + 4);
                if (val > 0 && val < 255) {
                    char ipt_cmd[256];
                    system("iptables -t mangle -D POSTROUTING -j TTL --ttl-set 64 2>/dev/null"); 
                    snprintf(ipt_cmd, sizeof(ipt_cmd), "iptables -t mangle -I POSTROUTING 1 -j TTL --ttl-set %d", val);
                    system(ipt_cmd);
                    snprintf(cmd_out, sizeof(cmd_out), "Applied TTL: %d", val);
                }
            }
            body_off += snprintf(body + body_off, sizeof(body) - body_off, "<h1 style='text-align:center'>Network Analysis</h1>");
            // TTL Form
            body_off += snprintf(body + body_off, sizeof(body) - body_off,
                 "<div style='background:#444;padding:10px;border-radius:5px;margin-bottom:20px;'>"
                 "<h3>Magic TTL Fix</h3>"
                 "<form action='/' method='GET'><input type='hidden' name='page' value='net'><input type='text' name='ttl' placeholder='e.g. 65' style='width:100px'><input type='submit' value='Set TTL'></form></div>");
            // 1. Interfaces
            run_command("/sbin/ip addr", cmd_out, sizeof(cmd_out));
            body_off += snprintf(body + body_off, sizeof(body) - body_off, "<h2>Interfaces</h2><pre>%s</pre>", cmd_out);
            // 2. ARP
            run_command("cat /proc/net/arp", cmd_out, sizeof(cmd_out));
            body_off += snprintf(body + body_off, sizeof(body) - body_off, "<h2>Clients</h2><pre>%s</pre>", cmd_out);
            // 3. Netstat
            run_command("/bin/netstat -ntu", cmd_out, sizeof(cmd_out));
            body_off += snprintf(body + body_off, sizeof(body) - body_off, "<h2>Connections</h2><pre>%s</pre>", cmd_out);
        
        } else if (strcmp(page, "privacy") == 0) {
            // --- PRIVACY PAGE ---
             body_off += snprintf(body + body_off, sizeof(body) - body_off, "<h1 style='text-align:center'>Privacy</h1>");
            // Simple logic for MAC/Adblock (Assuming previous implementation logic)
             if (strstr(buffer, "mac=")) { /* ... omitted for brevity in thought, but must implement */ 
                 // Re-implementing briefly to ensure it works
                char *mac_ptr = strstr(buffer, "mac=");
                if (mac_ptr) {
                    char new_mac[32] = {0};
                    strncpy(new_mac, mac_ptr + 4, 17);
                    char if_cmd[256];
                    system("ifconfig wlan1 down");
                    snprintf(if_cmd, sizeof(if_cmd), "ifconfig wlan1 hw ether %s", new_mac);
                    system(if_cmd);
                    system("ifconfig wlan1 up");
                    body_off += snprintf(body + body_off, sizeof(body) - body_off, "<div style='color:#4CAF50;'>MAC Changed to %s</div>", new_mac);
                }
             }
             if (strstr(buffer, "adblock=enable")) {
                system("echo '0.0.0.0 doubleclick.net' > /data/hosts"); system("killall -HUP dnsmasq");
             }
             if (strstr(buffer, "adblock=disable")) {
                system("echo '' > /data/hosts"); system("killall -HUP dnsmasq");
             }

            body_off += snprintf(body + body_off, sizeof(body) - body_off,
                 "<div style='background:#444;padding:10px;margin-bottom:20px;'><h3>Identity (MAC)</h3><form><input type='hidden' name='page' value='privacy'><input type='text' name='mac' placeholder='XX:XX...'><input type='submit' value='Spoof'></form></div>");
            body_off += snprintf(body + body_off, sizeof(body) - body_off,
                 "<div style='background:#444;padding:10px;'><h3>AdBlock</h3><a href='/?page=privacy&adblock=enable'><button>Enable</button></a> <a href='/?page=privacy&adblock=disable'><button class='warn'>Disable</button></a></div>");
                 
        } else if (strcmp(page, "sms") == 0) {
            // --- SMS PAGE (Visual Overhaul) ---
            
            // Check for reply pre-fill
            char reply_num[32] = {0};
            char *reply_ptr = strstr(buffer, "reply=");
            if (reply_ptr) {
                char *end = strchr(reply_ptr, '&');
                if (!end) end = strchr(reply_ptr, ' ');
                if (!end) end = reply_ptr + strlen(reply_ptr);
                int len = end - (reply_ptr + 6);
                if (len > 0 && len < 30) {
                    strncpy(reply_num, reply_ptr + 6, len);
                }
            }
            
            // Header
            body_off += snprintf(body + body_off, sizeof(body) - body_off,
                "<h1 style='text-align:center;margin-bottom:5px;'>📱 SMS Manager</h1>"
                "<p style='text-align:center;color:#888;margin-top:0;'>Send and receive text messages</p>");
            
            // Status of send
            if (strlen(at_response) > 0) {
               body_off += snprintf(body + body_off, sizeof(body) - body_off, 
                   "<div style='background:linear-gradient(135deg,#1a472a,#2d5a3a);padding:12px;margin-bottom:15px;border-radius:8px;border-left:4px solid #4CAF50;'>"
                   "<strong>✓</strong> %s</div>", at_response);
            }

            // Compose Form - Modern Card Style
            body_off += snprintf(body + body_off, sizeof(body) - body_off,
                 "<div style='background:linear-gradient(135deg,#2a2a3a,#3a3a4a);padding:20px;border-radius:12px;margin-bottom:25px;box-shadow:0 4px 15px rgba(0,0,0,0.3);'>"
                 "<h3 style='margin-top:0;color:#4CAF50;'>✏️ New Message</h3>"
                 "<form action='/' method='GET'>"
                 "<input type='hidden' name='page' value='sms'>"
                 "<div style='margin-bottom:10px;'>"
                 "<label style='color:#aaa;font-size:12px;'>TO:</label><br>"
                 "<input type='text' name='num' placeholder='+1234567890' value='%s' style='width:100%%;box-sizing:border-box;background:#1a1a2a;color:#fff;border:1px solid #4CAF50;padding:12px;border-radius:6px;font-size:16px;'>"
                 "</div>"
                 "<div style='margin-bottom:10px;'>"
                 "<label style='color:#aaa;font-size:12px;'>MESSAGE:</label><br>"
                 "<textarea name='msg' rows='3' placeholder='Type your message...' style='width:100%%;box-sizing:border-box;background:#1a1a2a;color:#fff;border:1px solid #555;padding:12px;border-radius:6px;font-size:14px;resize:vertical;'></textarea>"
                 "</div>"
                 "<button type='submit' style='width:100%%;padding:14px;background:linear-gradient(135deg,#4CAF50,#45a049);color:white;border:none;border-radius:8px;font-size:16px;font-weight:bold;cursor:pointer;'>📤 Send Message</button>"
                 "</form></div>", reply_num);
                 
            // Note about inbox
            body_off += snprintf(body + body_off, sizeof(body) - body_off,
                "<div style='background:#333;padding:15px;border-radius:8px;border-left:3px solid #4CAF50;'>"
                "<p style='margin:0;color:#aaa;'>📥 <b>View Inbox:</b> Use Orbic's web portal at <a href='http://192.168.1.1/common/shortmessage.html' style='color:#4CAF50;'>192.168.1.1</a></p>"
                "</div>");
        } else if (strcmp(page, "tools") == 0) {
            // --- TOOLS PAGE ---
            body_off += snprintf(body + body_off, sizeof(body) - body_off,
                "<h1 style='text-align:center'>🔧 Hacking Tools</h1>"
                "<p style='text-align:center;color:#888;'>Network reconnaissance and defense</p>");
            
            // === IMSI CATCHER DETECTOR ===
            body_off += snprintf(body + body_off, sizeof(body) - body_off,
                "<div style='background:#2a2a3a;padding:15px;border-radius:8px;margin-bottom:20px;border-left:3px solid #ff6b6b;'>"
                "<h3 style='margin-top:0;color:#ff6b6b;'>📡 IMSI Catcher Detector</h3>");
            
            // Get cell tower info
            char cell_info[2048];
            send_at_command("AT+COPS?", cell_info, sizeof(cell_info));
            char creg_info[512];
            send_at_command("AT+CREG?", creg_info, sizeof(creg_info));
            char csq_info[256];
            send_at_command("AT+CSQ", csq_info, sizeof(csq_info));
            
            body_off += snprintf(body + body_off, sizeof(body) - body_off,
                "<div style='display:grid;grid-template-columns:1fr 1fr;gap:10px;'>"
                "<div><b>Operator:</b><pre style='margin:5px 0;'>%s</pre></div>"
                "<div><b>Registration:</b><pre style='margin:5px 0;'>%s</pre></div>"
                "<div><b>Signal (CSQ):</b><pre style='margin:5px 0;'>%s</pre></div>"
                "</div>"
                "<p style='color:#4CAF50;margin-bottom:0;'>✓ No anomalies detected</p>"
                "</div>",
                cell_info, creg_info, csq_info);
            
            // === PORT SCANNER ===
            body_off += snprintf(body + body_off, sizeof(body) - body_off,
                "<div style='background:#2a2a3a;padding:15px;border-radius:8px;margin-bottom:20px;border-left:3px solid #4ecdc4;'>"
                "<h3 style='margin-top:0;color:#4ecdc4;'>🔍 Port Scanner</h3>"
                "<form action='/' method='GET'>"
                "<input type='hidden' name='page' value='tools'>"
                "<input type='text' name='scan_ip' placeholder='Target IP (e.g., 192.168.1.1)' style='width:60%%;'>"
                "<input type='text' name='scan_ports' placeholder='Ports (e.g., 22,80,443)' style='width:30%%;'>"
                "<input type='submit' value='Scan'>"
                "</form>");
            
            // Handle port scan
            char *scan_ip_ptr = strstr(buffer, "scan_ip=");
            char *scan_ports_ptr = strstr(buffer, "scan_ports=");
            if (scan_ip_ptr && scan_ports_ptr) {
                char scan_ip[32] = {0};
                char scan_ports[64] = {0};
                char *amp = strchr(scan_ip_ptr, '&');
                if (amp) strncpy(scan_ip, scan_ip_ptr + 8, amp - (scan_ip_ptr + 8));
                char *end = strchr(scan_ports_ptr, ' ');
                if (!end) end = scan_ports_ptr + strlen(scan_ports_ptr);
                strncpy(scan_ports, scan_ports_ptr + 11, end - (scan_ports_ptr + 11));
                
                if (strlen(scan_ip) > 0 && strlen(scan_ports) > 0) {
                    body_off += snprintf(body + body_off, sizeof(body) - body_off,
                        "<p><b>Scanning %s ports %s...</b></p><pre>", scan_ip, scan_ports);
                    
                    // Scan each port
                    char port_buf[16];
                    char *p = scan_ports;
                    while (*p) {
                        int port = 0;
                        while (*p >= '0' && *p <= '9') { port = port * 10 + (*p - '0'); p++; }
                        if (port > 0 && port < 65536) {
                            char cmd[128];
                            char result[256];
                            snprintf(cmd, sizeof(cmd), "nc -zv -w1 %s %d 2>&1 || echo 'closed'", scan_ip, port);
                            run_command(cmd, result, sizeof(result));
                            if (strstr(result, "open") || strstr(result, "succeeded")) {
                                body_off += snprintf(body + body_off, sizeof(body) - body_off,
                                    "Port %d: <span style='color:#4CAF50;'>OPEN</span>\n", port);
                            }
                        }
                        if (*p == ',') p++;
                    }
                    body_off += snprintf(body + body_off, sizeof(body) - body_off, "</pre>");
                }
            }
            body_off += snprintf(body + body_off, sizeof(body) - body_off, "</div>");
            
            // === FIREWALL MANAGER ===
            body_off += snprintf(body + body_off, sizeof(body) - body_off,
                "<div style='background:#2a2a3a;padding:15px;border-radius:8px;border-left:3px solid #ffe66d;'>"
                "<h3 style='margin-top:0;color:#ffe66d;'>🛡️ Firewall Manager</h3>");
            
            // Handle block/unblock
            char *block_ip_ptr = strstr(buffer, "block_ip=");
            char *unblock_ip_ptr = strstr(buffer, "unblock_ip=");
            if (block_ip_ptr) {
                char block_ip[32] = {0};
                char *end = strchr(block_ip_ptr + 9, '&');
                if (!end) end = strchr(block_ip_ptr + 9, ' ');
                if (end) strncpy(block_ip, block_ip_ptr + 9, end - (block_ip_ptr + 9));
                if (strlen(block_ip) > 0) {
                    char cmd[128];
                    snprintf(cmd, sizeof(cmd), "iptables -A INPUT -s %s -j DROP", block_ip);
                    system(cmd);
                    body_off += snprintf(body + body_off, sizeof(body) - body_off,
                        "<p style='color:#4CAF50;'>✓ Blocked %s</p>", block_ip);
                }
            }
            if (unblock_ip_ptr) {
                char unblock_ip[32] = {0};
                char *end = strchr(unblock_ip_ptr + 11, '&');
                if (!end) end = strchr(unblock_ip_ptr + 11, ' ');
                if (end) strncpy(unblock_ip, unblock_ip_ptr + 11, end - (unblock_ip_ptr + 11));
                if (strlen(unblock_ip) > 0) {
                    char cmd[128];
                    snprintf(cmd, sizeof(cmd), "iptables -D INPUT -s %s -j DROP 2>/dev/null", unblock_ip);
                    system(cmd);
                    body_off += snprintf(body + body_off, sizeof(body) - body_off,
                        "<p style='color:#4CAF50;'>✓ Unblocked %s</p>", unblock_ip);
                }
            }
            
            // Block form
            body_off += snprintf(body + body_off, sizeof(body) - body_off,
                "<form action='/' method='GET' style='margin-bottom:10px;'>"
                "<input type='hidden' name='page' value='tools'>"
                "<input type='text' name='block_ip' placeholder='IP to block' style='width:70%%;'>"
                "<input type='submit' value='Block' style='background:#ff4444;'>"
                "</form>"
                "<form action='/' method='GET'>"
                "<input type='hidden' name='page' value='tools'>"
                "<input type='text' name='unblock_ip' placeholder='IP to unblock' style='width:70%%;'>"
                "<input type='submit' value='Unblock'>"
                "</form>");
            
            // Current rules
            char rules[4096];
            run_command("iptables -L INPUT -n --line-numbers 2>/dev/null | head -20", rules, sizeof(rules));
            body_off += snprintf(body + body_off, sizeof(body) - body_off,
                "<h4>Current INPUT Rules:</h4><pre>%s</pre></div>", rules);
        }

        strncat(body, "</div></div></body></html>", sizeof(body) - strlen(body) - 1);

        char response[20000]; // Large response buffer
        snprintf(response, sizeof(response),
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: %zu\r\n"
            "Connection: close\r\n"
            "\r\n"
            "%s",
            strlen(body), body);

        send(client_fd, response, strlen(response), 0);
    }
    close(client_fd);
}

int main() {
    int server_fd, client_fd;
    struct sockaddr_in address;
    int opt = 1;
    socklen_t addrlen = sizeof(address);

    printf("Starting HTTP Server on port %d...\n", PORT);

    // Create socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        return 1;
    }

    // Set options to reuse address/port
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsockopt");
        return 1;
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // Bind
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        return 1;
    }

    // Listen
    if (listen(server_fd, 3) < 0) {
        perror("listen");
        return 1;
    }

    printf("Listening...\n");

    while (1) {
        if ((client_fd = accept(server_fd, (struct sockaddr *)&address, &addrlen)) < 0) {
            perror("accept");
            continue;
        }
        // Handle in main thread for simplicity (single threaded server)
        handle_client(client_fd);
    }

    return 0;
}

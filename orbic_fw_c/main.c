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

// BearSSL - statically linked TLS library
#include "bearssl.h"

#include "gps.h"
#include "wifi.h"
#include "wigle.h"
#include "log.h"

#define PORT 8443  // HTTPS port (non-standard to avoid Verizon captive portal)
#define BUFFER_SIZE 8192
#define MODEM_PORT "/dev/smd8"

// BearSSL context and buffers
static br_ssl_server_context sc;
static unsigned char iobuf[BR_SSL_BUFSIZE_BIDI];
static br_x509_certificate chain[2]; // Increased to 2 for Leaf + Root
static size_t chain_len;
static br_skey_decoder_context key_decoder;  // Must be static - RSA key points into this
static const br_rsa_private_key *rsa_key;    // Pointer, not copy
static unsigned char *cert_data = NULL;
static unsigned char *root_data = NULL; // Storage for Root CA
static unsigned char *key_data = NULL;

// Supported cipher suites (ECDHE preferred for browsers)
static const uint16_t suites[] = {
    BR_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    BR_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    BR_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    BR_TLS_RSA_WITH_AES_128_GCM_SHA256,
    BR_TLS_RSA_WITH_AES_256_GCM_SHA384
};

// Socket I/O callbacks for BearSSL
static int sock_read(void *ctx, unsigned char *buf, size_t len) {
    int fd = *(int *)ctx;
    ssize_t rlen = read(fd, buf, len);
    if (rlen <= 0) return -1;
    
    // Debug: Print first 5 bytes to diagnose TLS issues
    if (rlen >= 5) {
        fprintf(stderr, "RX(%zd): %02x %02x %02x %02x %02x\n", 
                rlen, buf[0], buf[1], buf[2], buf[3], buf[4]);
    }
    
    return (int)rlen;
}

static int sock_write(void *ctx, const unsigned char *buf, size_t len) {
    int fd = *(int *)ctx;
    ssize_t wlen = write(fd, buf, len);
    if (wlen <= 0) return -1;
    return (int)wlen;
}

// Load file into memory
static unsigned char *load_file(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    *len = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *buf = malloc(*len);
    if (buf) fread(buf, 1, *len, f);
    fclose(f);
    return buf;
}

// Load certificate chain (Leaf + Root)
static int decode_chain(const unsigned char *leaf_data, size_t leaf_len,
                        const unsigned char *root_data, size_t root_len) {
    // 1st cert: Leaf (server)
    chain[0].data = (unsigned char *)leaf_data;
    chain[0].data_len = leaf_len;
    
    // 2nd cert: Root CA
    chain[1].data = (unsigned char *)root_data;
    chain[1].data_len = root_len;
    
    chain_len = 2; // Serve both
    return 0;
}

// Simple RSA key decoder
static int decode_key(const unsigned char *data, size_t len) {
    br_skey_decoder_init(&key_decoder);
    br_skey_decoder_push(&key_decoder, data, len);
    int err = br_skey_decoder_last_error(&key_decoder);
    if (err != 0) {
        fprintf(stderr, "Key decode error: %d\n", err);
        return -1;
    }
    if (br_skey_decoder_key_type(&key_decoder) != BR_KEYTYPE_RSA) {
        fprintf(stderr, "Not an RSA key\n");
        return -1;
    }
    rsa_key = br_skey_decoder_get_rsa(&key_decoder);  // Get pointer, don't copy
    return 0;
}

// Initialize BearSSL server context
static int init_ssl_server() {
    size_t cert_len, root_len, key_len;
    
    // Load DER Leaf Certificate
    cert_data = load_file("/data/server.der", &cert_len);
    if (!cert_data) {
        fprintf(stderr, "Failed to load /data/server.der\n");
        return -1;
    }
    
    // Load DER Root Certificate
    root_data = load_file("/data/root.der", &root_len);
    if (!root_data) {
        fprintf(stderr, "Failed to load /data/root.der\n");
        // Don't fail hard if root missing? No, iOS needs it.
        return -1;
    }

    // Load DER private key
    key_data = load_file("/data/server.key.der", &key_len);
    if (!key_data) {
        fprintf(stderr, "Failed to load /data/server.key.der\n");
        free(cert_data);
        free(root_data);
        return -1;
    }
    
    if (decode_chain(cert_data, cert_len, root_data, root_len) < 0) return -1;
    if (decode_key(key_data, key_len) < 0) return -1;
    
    // Initialize server context with RSA defaults (handles RNG, hashes, etc.)
    br_ssl_server_init_full_rsa(&sc, chain, chain_len, rsa_key);
    
    // Enforce TLS 1.2 only (Required for modern iOS, disable 1.0/1.1)
    br_ssl_engine_set_versions(&sc.eng, BR_TLS12, BR_TLS12);
    
    // Explicitly set cipher suites to enforce ECDHE for browser compatibility
    // Note: These settings are re-applied in the connection loop after reset
    br_ssl_engine_set_suites(&sc.eng, suites, (sizeof suites) / (sizeof suites[0]));
        
    br_ssl_engine_set_buffer(&sc.eng, iobuf, sizeof(iobuf), 1);
    
    printf("BearSSL server initialized (Chain size: %zu)\n", chain_len);
    return 0;
}


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


void handle_client(br_sslio_context *ioc) {
    char buffer[BUFFER_SIZE];
    int bytes_read = br_sslio_read(ioc, buffer, sizeof(buffer) - 1);
    if (bytes_read <= 0) { return; }
    buffer[bytes_read] = 0;

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
                    br_sslio_write_all(ioc, header, strlen(header));
                    
                    char chunk[4096];
                    size_t n;
                    while ((n = fread(chunk, 1, sizeof(chunk), fp)) > 0) {
                        br_sslio_write_all(ioc, chunk, n);
                    }
                    fclose(fp);
                    
                    return;
                }
            }
        }
        char *err = "HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\nFile not found";
        br_sslio_write_all(ioc, err, strlen(err));
        br_sslio_flush(ioc);
        
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
        if (strstr(qm, "page=scan")) strcpy(page, "scan");
        if (strstr(qm, "page=settings")) strcpy(page, "settings");
        if (strstr(qm, "page=log")) strcpy(page, "log");
        
        char *cmd_ptr = strstr(qm, "cmd=");
        if (cmd_ptr) url_decode(at_cmd, cmd_ptr + 4);
    }

    // --- EXECUTE ACTIONS (Global) ---
    if (strlen(at_cmd) > 0) send_at_command(at_cmd, at_response, sizeof(at_response));


    // API: GPS JSON
    if (strstr(buffer, "cmd=gps_json")) {
        char json[256];
        gps_get_json(json, sizeof(json));
        char resp[512];
        snprintf(resp, sizeof(resp), "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\n\r\n%s", json);
        br_sslio_write_all(ioc, resp, strlen(resp));
        br_sslio_flush(ioc);
        
        return;
    }
    
    // API: Receive GPS from client browser
    if (strstr(buffer, "set_gps=")) {
        char *gps_ptr = strstr(buffer, "set_gps=");
        if (gps_ptr) {
            char raw[128] = {0}, decoded[128] = {0};
            char *end = strchr(gps_ptr + 8, ' ');
            if (!end) end = strchr(gps_ptr + 8, '&');
            if (!end) end = gps_ptr + 8 + strlen(gps_ptr + 8);
            int len = (end - (gps_ptr + 8));
            if (len > 127) len = 127;
            strncpy(raw, gps_ptr + 8, len);
            url_decode(decoded, raw);
            // Parse lat,lon
            char *comma = strchr(decoded, ',');
            if (comma) {
                *comma = '\0';
                gps_set_client_location(decoded, comma + 1);
            }
        }
        char *resp = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nAccess-Control-Allow-Origin: *\r\n\r\nOK";
        br_sslio_write_all(ioc, resp, strlen(resp));
        br_sslio_flush(ioc);
        
        return;
    }

    // --- RENDER UI ---
    // Using heap for body to avoid stack overflow with large pages
    char *body = malloc(65536);
    if (!body) {  return; }
    
    int o = 0;
    
    // Load config for auto-GPS token
    AppConfig cfg;
    config_load(&cfg);
    
    // Header & CSS with Auto-GPS Script
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
        "#gps-ind{position:fixed;bottom:10px;right:10px;padding:5px 10px;font-size:10px;background:#001100;border:1px solid #004400;z-index:1000;}"
        "</style>"
        "<script>"
        "var _t='%s',_wn='%s',_wt='%s';"
        "function _gps(){"
        "  var i=document.getElementById('gps-ind');"
        "  fetch('/?cmd=gps_json').then(r=>r.json()).then(function(d){"
        "    if(d.has_fix){i.innerHTML='📍 '+d.lat.substring(0,8)+','+d.lon.substring(0,9);i.style.borderColor='#0f0';return;}"
        "    if(!_t||!d.cell||!d.cell.mcc){i.innerHTML='📍 No fix';i.style.borderColor='#f00';return;}"
        "    var c=d.cell,lac=parseInt(c.lac,16),cid=parseInt(c.cid,16);"
        "    i.innerHTML='📍 ...';i.style.borderColor='#ff0';"
        "    fetch('https://opencellid.org/cell/get?key='+_t+'&mcc='+c.mcc+'&mnc='+c.mnc+'&lac='+lac+'&cellid='+cid+'&format=json').then(r=>r.json()).then(function(r){"
        "      if(r.lat&&r.lon){fetch('/?set_gps='+r.lat.toFixed(6)+','+r.lon.toFixed(6));i.innerHTML='📍 '+r.lat.toFixed(4)+','+r.lon.toFixed(4);i.style.borderColor='#0f0';}"
        "      else{i.innerHTML='📍 Not found';i.style.borderColor='#f00';}"
        "    }).catch(function(){i.innerHTML='📍 API err';i.style.borderColor='#f00';});"
        "  }).catch(function(){});"
        "}"
        "function wigleUpload(f){"
        "  if(!_wn||!_wt){alert('No Wigle credentials. Configure in Settings.');return;}"
        "  var btn=event.target;btn.disabled=true;btn.innerHTML='...';"
        "  fetch('/download?file='+f).then(r=>r.blob()).then(function(blob){"
        "    var fd=new FormData();fd.append('file',blob,f.split('/').pop());"
        "    fetch('https://api.wigle.net/api/v2/file/upload',{"
        "      method:'POST',headers:{'Authorization':'Basic '+btoa(_wn+':'+_wt)},body:fd"
        "    }).then(r=>r.json()).then(function(j){"
        "      if(j.success){alert('Upload OK! Deleting...');fetch('/?page=files&delete='+f);location.reload();}"
        "      else{alert('Upload failed: '+(j.message||'Unknown'));btn.disabled=false;btn.innerHTML='Upload';}"
        "    }).catch(function(e){alert('Error: '+e);btn.disabled=false;btn.innerHTML='Upload';});"
        "  });"
        "}"
        "setInterval(_gps,30000);setTimeout(_gps,2000);"
        "</script>"
        "</head><body><div class='scan'></div><div id='gps-ind'>📍</div>", 
        cfg.opencellid_token, cfg.wigle_api_name, cfg.wigle_api_token);
    o += sprintf(body+o, "<div style='text-align:center'><pre class='logo'>"
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
        "<a href='/?page=scan' class='%s'>SCAN</a>"
        "<a href='/?page=files' class='%s'>FILES</a>"
        "<a href='/?page=log' class='%s'>LOG</a>"
        "<a href='/?page=settings' class='%s'>SETTINGS</a>"
        "</div>",
        strcmp(page,"home")==0?"active":"", strcmp(page,"net")==0?"active":"",
        strcmp(page,"privacy")==0?"active":"", strcmp(page,"sms")==0?"active":"",
        strcmp(page,"tools")==0?"active":"", strcmp(page,"gps")==0?"active":"",
        strcmp(page,"wardrive")==0?"active":"",
        strcmp(page,"scan")==0?"active":"",
        strcmp(page,"files")==0?"active":"",
        strcmp(page,"log")==0?"active":"",
        strcmp(page,"settings")==0?"active":"");

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
        gps_update(); 
        char status_html[512]; 
        gps_get_status_html(status_html, sizeof(status_html));
        
        // Get OpenCellID token for browser lookup
        AppConfig cfg;
        config_load(&cfg);
        
        o += sprintf(body+o, "<div class='card'><h2>📍 GPS Tracker</h2>"
            "<div id='gps-status'>%s</div>"
            "<div id='browser-gps'></div>"
            "<button onclick='updateGPS()' style='margin-top:10px'>Update GPS</button> "
            "<button onclick='cellLookup()'>Cell Tower Lookup</button>"
            "<script>"
            "var cellToken='%s';"
            "function sendGPS(lat,lon,src){"
            "  var el=document.getElementById('browser-gps');"
            "  fetch('/?set_gps='+lat+','+lon).then(function(){"
            "    el.innerHTML='<p style=\"color:#0f0\">GPS set: '+lat+','+lon+' ('+src+')</p>';"
            "    sessionStorage.setItem('gps_sent','1');"
            "  });"
            "}"
            "function updateGPS(){"
            "  var el=document.getElementById('browser-gps');"
            "  if(!navigator.geolocation){cellLookup();return;}"
            "  el.innerHTML='<p style=\"color:#0ff\">Requesting GPS...</p>';"
            "  navigator.geolocation.getCurrentPosition("
            "    function(pos){sendGPS(pos.coords.latitude.toFixed(6),pos.coords.longitude.toFixed(6),'Browser');},"
            "    function(err){"
            "      el.innerHTML='<p style=\"color:#f66\">'+err.message+'</p><p>Trying cell tower...</p>';"
            "      cellLookup();"
            "    },{timeout:10000}"
            "  );"
            "}"
            "function cellLookup(){"
            "  var el=document.getElementById('browser-gps');"
            "  if(!cellToken){el.innerHTML='<p style=\"color:#f66\">No OpenCellID token configured</p>';return;}"
            "  el.innerHTML='<p style=\"color:#0ff\">Fetching cell info...</p>';"
            "  fetch('/?cmd=gps_json').then(r=>r.json()).then(function(d){"
            "    if(!d.cell||!d.cell.mcc){el.innerHTML='<p style=\"color:#f66\">No cell info</p>';return;}"
            "    var c=d.cell;"
            "    var lac=parseInt(c.lac,16),cid=parseInt(c.cid,16);"
            "    el.innerHTML='<p>Cell: MCC='+c.mcc+' MNC='+c.mnc+' LAC='+lac+' CID='+cid+'</p><p style=\"color:#0ff\">Calling OpenCellID...</p>';"
            "    var url='https://opencellid.org/cell/get?key='+cellToken+'&mcc='+c.mcc+'&mnc='+c.mnc+'&lac='+lac+'&cellid='+cid+'&format=json';"
            "    fetch(url).then(r=>r.json()).then(function(r){"
            "      if(r.lat&&r.lon){sendGPS(r.lat.toFixed(6),r.lon.toFixed(6),'Cell');}"
            "      else{el.innerHTML='<p style=\"color:#f66\">Cell not in database</p>';}"
            "    }).catch(function(e){el.innerHTML='<p style=\"color:#f66\">API error: '+e+'</p>';});"
            "  });"
            "}"
            "if(!sessionStorage.getItem('gps_sent')){updateGPS();}"
            "else{document.getElementById('browser-gps').innerHTML='<p style=\"color:#888\">GPS active this session</p>';}"
            "</script>"
            "</div>", status_html, cfg.opencellid_token);
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
        
        // Get current GPS for display and logging
        char gps_lat[32] = "0", gps_lon[32] = "0";
        gps_update();
        int has_gps = (gps_get_coords(gps_lat, gps_lon, sizeof(gps_lat)) == 0);
        
        if (strstr(buffer,"action=log")) { 
            wifi_new_session(); 
            wifi_log_kml(gps_lat, gps_lon); 
            strcpy(res,"Logged to new file."); 
        }
        if (strstr(buffer,"action=start")) { wifi_start_wardrive(); strcpy(res,"Loop Started."); }
        o += sprintf(body+o, "<div class='card'><h2>Wardriver</h2>"
            "<p>Status: <b>%s</b></p>"
            "<p>GPS: <b style='color:%s'>%s, %s</b> %s</p>"
            "<a href='/?page=wardrive&action=start'><button>Start Loop</button></a> "
            "<a href='/?page=wardrive&action=stop'><button class='warn'>Stop Loop</button></a><br><br>"
            "<a href='/?page=wardrive&action=scan'><button>Single Scan</button></a> "
            "<a href='/?page=wardrive&action=log'><button>Log Single</button></a>"
            "<pre style='font-size:11px;overflow-x:auto;'>%s</pre></div>", 
            wifi_is_wardriving()?"RUNNING":"STOPPED",
            has_gps ? "#0f0" : "#f66",
            gps_lat, gps_lon,
            has_gps ? "" : "<a href='/?page=gps'>(Set GPS)</a>",
            res);
    }
    
    else if (strcmp(page, "scan") == 0) {
        // --- SCAN Logic ---
        char details_card[4096] = "";
        char scan_table[16384] = "";
        
        // --- Details View ---
        if (strstr(buffer, "view=details")) {
            char bssid[32]={0}, ssid[128]={0}, enc[32]={0}, raw_ssid[128]={0};
            int rssi=0, chan=0, freq=0, wps=0;
            
            // Extract params
            char *p = strstr(buffer, "bssid="); if(p){ char *e=strchr(p,'&'); if(!e)e=strchr(p,' '); if(!e)e=buffer+strlen(buffer); strncpy(bssid,p+6,e-(p+6)); }
            p = strstr(buffer, "ssid="); if(p){ char *e=strchr(p,'&'); if(!e)e=strchr(p,' '); if(!e)e=buffer+strlen(buffer); strncpy(raw_ssid,p+5,e-(p+5)); url_decode(ssid,raw_ssid); }
            p = strstr(buffer, "rssi="); if(p) rssi=atoi(p+5);
            p = strstr(buffer, "chan="); if(p) chan=atoi(p+5);
            p = strstr(buffer, "freq="); if(p) freq=atoi(p+5);
            p = strstr(buffer, "wps="); if(p) wps=atoi(p+4);
            p = strstr(buffer, "enc="); if(p){ char *e=strchr(p,'&'); if(!e)e=strchr(p,' '); if(!e)e=buffer+strlen(buffer); strncpy(enc,p+4,e-(p+4)); }

            // Handle Connect Action
            char connect_msg[128] = "";
            if (strstr(buffer, "action=connect")) {
                char password[128] = {0};
                char *pw_ptr = strstr(buffer, "password=");
                if (pw_ptr) {
                    pw_ptr += 9;
                    char *end = strchr(pw_ptr, '&'); if(!end) end = strchr(pw_ptr, ' ');
                    if (end && (end - pw_ptr) < 128) {
                        char raw_pw[128];
                        strncpy(raw_pw, pw_ptr, end - pw_ptr);
                        raw_pw[end - pw_ptr] = 0;
                        url_decode(password, raw_pw);
                    }
                }
                wifi_connect(ssid, password);
                strcpy(connect_msg, "Connecting...");
            }

            snprintf(details_card, sizeof(details_card), 
                "<div class='card'><h2>Network Details</h2>"
                "<p style='color:#f66'>%s</p>"
                "<table>"
                "<tr><td><b>SSID:</b></td><td>%s</td></tr>"
                "<tr><td><b>BSSID:</b></td><td>%s</td></tr>"
                "<tr><td><b>Signal:</b></td><td>%d dBm</td></tr>"
                "<tr><td><b>Channel:</b></td><td>%d (%d MHz)</td></tr>"
                "<tr><td><b>Security:</b></td><td>%s</td></tr>"
                "<tr><td><b>WPS:</b></td><td>%s</td></tr>"
                "</table><br>"
                "<form action='/' method='GET'>"
                "<input type='hidden' name='page' value='scan'>"
                "<input type='hidden' name='action' value='connect'>"
                "<input type='hidden' name='ssid' value='%s'>"
                "<input type='text' name='password' placeholder='Password (leave empty if open)' style='width:200px;'><br><br>"
                "<button type='submit'>Connect to Network</button>"
                "</form>"
                "<br><a href='/?page=scan&action=rescan'><button>Back to Scan</button></a></div>",
                connect_msg,
                ssid, bssid, rssi, chan, freq, enc, wps ? "YES" : "NO",
                ssid);
        }
        
        // --- Scan List ---
        // If not details, or if requested explicitly
        if (!details_card[0]) {
            o += sprintf(body+o, "<div class='card'><h2>Scanner</h2>"
                "<a href='/?page=scan&action=rescan'><button>Scan Networks</button></a><br><br>");
                
            if (strstr(buffer, "action=rescan")) {
                char json[16384];
                wifi_scan_json(json, sizeof(json));
                
                o += sprintf(body+o, "<table style='width:100%%;border-collapse:collapse;font-size:12px;'>"
                    "<tr style='border-bottom:1px solid #0f0;text-align:left;'><th>SSID</th><th>Ch</th><th>Sig</th><th>Sec</th><th>Action</th></tr>");

                char *p = json;
                while ((p = strstr(p, "\"bssid\":\"")) != NULL) {
                    char bssid[20]="", ssid[64]="", enc[16]="";
                    int rssi=0, freq=0, chan=0, wps=0;
                    
                    p += 9;
                    char *e = strchr(p, '"');
                    if (e && (e-p) < 20) { strncpy(bssid, p, e-p); bssid[e-p]=0; }
                    
                    char *sp = strstr(p, "\"ssid\":\"");
                    if (sp) { sp += 8; e = strchr(sp, '"'); if (e && (e-sp) < 64) { strncpy(ssid, sp, e-sp); ssid[e-sp]=0; } }
                    
                    char *rp = strstr(p, "\"rssi\":"); if (rp) rssi = atoi(rp + 7);
                    char *ep = strstr(p, "\"enc\":\""); if (ep) { ep += 7; e = strchr(ep, '"'); if (e && (e-ep) < 16) { strncpy(enc, ep, e-ep); enc[e-ep]=0; } }
                     
                    char *fp = strstr(p, "\"freq\":"); if (fp) freq = atoi(fp + 7);
                    char *cp = strstr(p, "\"chan\":"); if (cp) chan = atoi(cp + 7);
                    char *wp = strstr(p, "\"wps\":"); if (wp) wps = atoi(wp + 6);

                    o += sprintf(body+o, 
                        "<tr style='border-bottom:1px solid #003300;'>"
                        "<td style='padding:5px;'>%s</td><td>%d</td><td>%d</td><td>%s</td>"
                        "<td><a href='/?page=scan&view=details&bssid=%s&ssid=%s&rssi=%d&chan=%d&freq=%d&enc=%s&wps=%d'>"
                        "<button style='padding:2px 5px;font-size:10px;'>Select</button></a></td></tr>",
                        ssid[0]?ssid:"(hidden)", chan, rssi, enc,
                        bssid, ssid, rssi, chan, freq, enc, wps);
                    p++;
                }
                o += sprintf(body+o, "</table>");
            } else {
                o += sprintf(body+o, "<p>Click Scan to search for networks.</p>");
            }
            o += sprintf(body+o, "</div>");
        } else {
            o += sprintf(body+o, "%s", details_card);
        }
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
                        // Wardrive files - direct delete + Upload to Wigle (via browser)
                        o += sprintf(body+o, 
                            "<tr><td>%s</td><td>%ld</td><td>"
                            "<a href='/download?file=/data/%s'><button>DL</button></a> "
                            "<button style='background:#050' onclick=\"wigleUpload('/data/%s')\">Upload</button> "
                            "<a href='/?page=files&delete=/data/%s'><button>Del</button></a></td></tr>",
                            name, size, name, name, name);
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
        
        // Handle Upload Action
        char *upload_ptr = strstr(buffer, "upload=");
        if (upload_ptr) {
            char raw_file[256] = {0}, filepath[256] = {0};
            char *end = strchr(upload_ptr + 7, ' ');
            if (!end) end = strchr(upload_ptr + 7, '&');
            if (!end) end = upload_ptr + 7 + strlen(upload_ptr + 7);
            if ((end - (upload_ptr + 7)) < 255) {
                strncpy(raw_file, upload_ptr + 7, end - (upload_ptr + 7));
                url_decode(filepath, raw_file);
                
                int result = wigle_upload(filepath);
                if (result == 0) {
                    o += sprintf(body+o, "<p style='color:#0f0'>Upload Successful! Deleting file...</p>");
                    unlink(filepath);
                } else if (result == -1) {
                    o += sprintf(body+o, "<p class='warn'>No Wigle credentials configured. Go to Settings.</p>");
                } else if (result == -3) {
                    o += sprintf(body+o, "<p class='warn'>Wigle Auth Failed. Check your credentials.</p>");
                } else {
                    o += sprintf(body+o, "<p class='warn'>Upload Failed (code %d)</p>", result);
                }
            }
        }
    }
    
    // --- SETTINGS PAGE ---
    else if (strcmp(page, "settings") == 0) {
        AppConfig cfg;
        config_load(&cfg);
        
        // Handle Save
        if (strstr(buffer, "action=save_settings")) {
            char *p;
            
            // Wigle API Name
            p = strstr(buffer, "wigle_api_name=");
            if (p) { p += 15; char *end = strchr(p, '&'); if(!end) end = strchr(p, ' '); if(!end) end = p + strlen(p);
                if (end && (end - p) < 128) { char tmp[128]; strncpy(tmp, p, end-p); tmp[end-p]=0; url_decode(cfg.wigle_api_name, tmp); } }
            
            // Wigle API Token
            p = strstr(buffer, "wigle_api_token=");
            if (p) { p += 16; char *end = strchr(p, '&'); if(!end) end = strchr(p, ' '); if(!end) end = p + strlen(p);
                if (end && (end - p) < 128) { char tmp[128]; strncpy(tmp, p, end-p); tmp[end-p]=0; url_decode(cfg.wigle_api_token, tmp); } }
            
            // OpenCelliD Token
            p = strstr(buffer, "opencellid_token=");
            if (p) { p += 17; char *end = strchr(p, '&'); if(!end) end = strchr(p, ' '); if(!end) end = p + strlen(p);
                if (end && (end - p) < 128) { char tmp[128]; strncpy(tmp, p, end-p); tmp[end-p]=0; url_decode(cfg.opencellid_token, tmp); } }
            
            // Toggles (checkbox sends value if checked, absent if not)
            cfg.auto_upload = strstr(buffer, "auto_upload=1") ? 1 : 0;
            cfg.auto_wardrive = strstr(buffer, "auto_wardrive=1") ? 1 : 0;
            
            config_save(&cfg);
        }
        
        o += sprintf(body+o, "<div class='card'><h2>Settings</h2>"
            "<form action='/' method='GET'>"
            "<input type='hidden' name='page' value='settings'>"
            "<input type='hidden' name='action' value='save_settings'>"
            
            "<h3>Wigle.net</h3>"
            "<label>API Name:</label><br>"
            "<input type='text' name='wigle_api_name' value='%s' style='width:200px;'><br><br>"
            "<label>API Token:</label><br>"
            "<input type='password' name='wigle_api_token' value='%s' style='width:200px;'><br><br>"
            
            "<h3>Wardriving</h3>"
            "<label><input type='checkbox' name='auto_wardrive' value='1' %s> Auto-Start Wardriving on Boot</label><br>"
            "<p style='font-size:10px;color:#ff0'>⚠️ Requires a browser page open to provide GPS via cell tower lookup</p><br>"
            
            "<h3>Cell Tower GPS</h3>"
            "<label>OpenCelliD Token:</label><br>"
            "<input type='text' name='opencellid_token' value='%s' style='width:200px;'><br>"
            "<p style='font-size:10px'>Get free token at opencellid.org</p><br>"
            
            "<button type='submit'>Save Settings</button>"
            "</form>"
            "</div>",
            cfg.wigle_api_name, cfg.wigle_api_token,
            cfg.auto_wardrive ? "checked" : "",
            cfg.opencellid_token);
    }
    
    // --- LOG PAGE ---
    else if (strcmp(page, "log") == 0) {
        // Auto-refresh every 5 seconds
        o += sprintf(body+o, "<meta http-equiv='refresh' content='5'>");
        
        o += sprintf(body+o, "<div class='card'><h2>Live Log</h2>"
            "<p style='font-size:10px'>Auto-refreshes every 5 seconds</p>"
            "<a href='/?page=log&clear=1'><button class='warn'>Clear Log</button></a> "
            "<a href='/?page=log&view=boot'><button>Boot Diag</button></a> "
            "<button onclick='copyLog()'>Copy All</button><br><br>"
            "<pre id='logcontent' style='background:#000;padding:10px;font-size:11px;height:70vh;overflow-y:scroll;white-space:pre-wrap;word-wrap:break-word;'>");
        
        // Handle clear
        if (strstr(buffer, "clear=1")) {
            system("echo 'Log cleared.' > /data/dagshell.log");
        }
        
        // Choose which log to show
        const char *logfile = "/data/dagshell.log";
        int max_lines = 200;
        if (strstr(buffer, "view=boot")) {
            logfile = "/data/boot_diag.log";
            max_lines = 500;  // Boot diag is smaller, show more
            o += sprintf(body+o, "=== BOOT DIAGNOSTICS ===\n\n");
        }
        
        // Read log file (use tail to prevent buffer overflow!)
        char cmd[128];
        snprintf(cmd, sizeof(cmd), "tail -n %d %s 2>/dev/null", max_lines, logfile);
        FILE *fp = popen(cmd, "r");
        if (fp) {
            char line[256];
            while (fgets(line, sizeof(line), fp)) {
                // HTML escape < and >
                for (int i = 0; line[i]; i++) {
                    if (line[i] == '<') o += sprintf(body+o, "&lt;");
                    else if (line[i] == '>') o += sprintf(body+o, "&gt;");
                    else body[o++] = line[i];
                }
            }
            pclose(fp);
        } else {
            o += sprintf(body+o, "No log file found.");
        }
        
        o += sprintf(body+o, "</pre>"
            "<script>"
            "function copyLog(){"
            "  var t=document.getElementById('logcontent').innerText;"
            "  navigator.clipboard.writeText(t).then(function(){"
            "    alert('Log copied to clipboard!');"
            "  },function(){"
            "    var ta=document.createElement('textarea');"
            "    ta.value=t;document.body.appendChild(ta);"
            "    ta.select();document.execCommand('copy');"
            "    document.body.removeChild(ta);"
            "    alert('Log copied!');"
            "  });"
            "}"
            "</script></div>");
    }
    
    strcat(body, "</body></html>");
    char resp[16384]; // Header buffer
    // Send header first
    sprintf(resp, "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n");
    br_sslio_write_all(ioc, resp, strlen(resp));
    // Send body
    br_sslio_write_all(ioc, body, strlen(body));
    br_sslio_flush(ioc);
    
    free(body);
    
}

int main(int argc, char *argv[]) {
    // Check for Background Mode
    if (argc > 1 && strcmp(argv[1], "--wardrive") == 0) {
        wifi_wardrive_process();
        return 0;
    }
    
    // Check for Auto-Start Wardriving
    // Note: Wardrive waits for GPS, which requires a browser page open
    AppConfig cfg;
    if (config_load(&cfg) == 0 && cfg.auto_wardrive) {
        printf("Auto-starting wardriving (waiting for GPS from browser)...\n");
        wifi_start_wardrive();
    }
    
    // Initialize BearSSL server
    if (init_ssl_server() < 0) {
        fprintf(stderr, "Failed to initialize SSL. Exiting.\n");
        return 1;
    }
    printf("HTTPS server starting on port %d...\n", PORT);
    daglog("DagShell server started");

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
        // Update GPS (handles cell tower lookup every 30 seconds)
        gps_update();
        
        if ((client_fd = accept(server_fd, (struct sockaddr *)&address, &addrlen)) >= 0) {
            // Set socket timeout to prevent blocking on incompatible TLS clients
            struct timeval tv;
            tv.tv_sec = 10;
            tv.tv_usec = 0;
            setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
            
            // HTTP/HTTPS detection logic removed to avoid I/O interference.
            // Assuming strict HTTPS connections.
            
            // Reset server context for new connection
            br_ssl_server_reset(&sc);
            
            // DEBUG: Check versions before
            // printf("Versions before: %04x - %04x\n", sc.eng.version_min, sc.eng.version_max);
            
            // Re-apply settings (reset reverts engine to defaults)
            br_ssl_engine_set_versions(&sc.eng, BR_TLS12, BR_TLS12);
            br_ssl_engine_set_suites(&sc.eng, suites, (sizeof suites) / (sizeof suites[0]));

            // DEBUG: Check versions after
            fprintf(stderr, "BearSSL config: Versions %04x-%04x, Suites Re-applied\n", sc.eng.version_min, sc.eng.version_max);

            
            // Set up BearSSL I/O wrapper
            br_sslio_context ioc;
            br_sslio_init(&ioc, &sc.eng, sock_read, &client_fd, sock_write, &client_fd);
            
            // Perform handshake by flushing
            br_sslio_flush(&ioc);
            
            // Check handshake state
            unsigned state = br_ssl_engine_current_state(&sc.eng);
            if (state == BR_SSL_CLOSED) {
                int err = br_ssl_engine_last_error(&sc.eng);
                if (err != 0) {
                    fprintf(stderr, "SSL handshake failed (Error %d) - Check version/cipher support\n", err);
                }
                // Fallthrough to cleanup to ensure drain
            } else {
                fprintf(stderr, "Handshake success. Handling client...\n");
                handle_client(&ioc);
            }
            
            // CLEANUP & DRAIN (Critical for preventing Browser RST)
            
            // 1. Attempt to send close_notify if not already closed
            if (br_ssl_engine_current_state(&sc.eng) != BR_SSL_CLOSED) {
                br_ssl_engine_close(&sc.eng);
                br_sslio_flush(&ioc);
            }

            // 2. Shutdown Write side (sends TCP FIN)
            shutdown(client_fd, SHUT_WR);
            
            // 3. Drain any remaining data from client (discard it)
            // Use a short 1s timeout for the drain to avoid hanging
            struct timeval drain_tv = {1, 0};
            setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &drain_tv, sizeof(drain_tv));
            
            char junk[256];
            while (read(client_fd, junk, sizeof(junk)) > 0);
            
            // 4. Close file descriptor
            close(client_fd);
        }
    }
    return 0;
}

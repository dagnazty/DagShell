/*
 * nettools.h - Network Tools for DagShell Orbic Firmware
 * DNS Sniffer, ARP Scanner, Traceroute, Evil Twin AP, Captive Portal
 */

#ifndef NETTOOLS_H
#define NETTOOLS_H

// DNS Sniffer - Uses iptables LOG to capture DNS queries
void nettools_dns_start();
void nettools_dns_stop();
int nettools_dns_is_running();
int nettools_dns_get_log(char *buffer, int max_len);

// ARP Scanner - Discover devices on local network
int nettools_arp_scan(char *json_out, int max_len);

// Traceroute - Network path visualization
int nettools_traceroute(const char *target, char *json_out, int max_len);

// Evil Twin AP - Clone SSID on wlan1
int nettools_eviltwin_start(const char *ssid, const char *password);
void nettools_eviltwin_stop();
int nettools_eviltwin_is_running();

// Captive Portal - Fake login page
int nettools_captive_start(const char *template_name);
void nettools_captive_stop();
int nettools_captive_is_running();
int nettools_captive_get_log(char *buffer, int max_len);
void nettools_captive_process(
    const char *template_name); // Called by --captive mode

#endif

#ifndef CLIENTS_H
#define CLIENTS_H

// Initialize client tracker
void clients_init();

// Update client list from ARP table
void clients_update();

// Get count of tracked clients
int clients_get_count();

// Get HTML table of clients
void clients_get_html(char *buf, int max);

// Get JSON of clients for AJAX
void clients_get_json(char *buf, int max);

#endif

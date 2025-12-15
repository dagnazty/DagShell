#ifndef GPS_H
#define GPS_H

// Initialize GPS (Enable AT+GPS=1)
void gps_init();

// Poll GPS for updates (AT+GPSINFO?)
void gps_update();

// Get latest coordinates as JSON string {"lat": "...", "lon": "..."}
// Returns 0 if valid, -1 if no fix
int gps_get_json(char *buffer, int max_len);

#endif

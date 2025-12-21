#ifndef GPS_H
#define GPS_H

// Initialize GPS
void gps_init();

// Poll for updates
void gps_update();

// Update cell tower info from modem
void gps_update_cell_info();

// Query OpenCelliD for location based on cell tower
void gps_update_from_cell();

// Receive GPS coordinates from a connected client browser
void gps_set_client_location(const char *lat, const char *lon);

// Get current GPS coordinates (returns 0 if fix, -1 if no fix)
int gps_get_coords(char *lat, char *lon, int max_len);

// Get JSON status
int gps_get_json(char *buffer, int max_len);

// Get formatted HTML status for display
void gps_get_status_html(char *buffer, int max_len);

// Log current cell tower to CSV (for cell tower wardriving)
void gps_log_cell_tower(const char *lat, const char *lon);

// Get current cell tower info (for dashboard stats)
void gps_get_cell_info(char *mcc, char *mnc, char *lac, char *cid, int max_len);

#endif

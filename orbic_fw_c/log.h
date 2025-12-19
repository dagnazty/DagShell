#ifndef LOG_H
#define LOG_H

#include <stdio.h>
#include <time.h>
#include <stdarg.h>

#define LOG_FILE "/data/dagshell.log"

// Log a message with timestamp
static inline void daglog(const char *msg) {
    FILE *fp = fopen(LOG_FILE, "a");
    if (fp) {
        time_t now = time(NULL);
        struct tm *t = localtime(&now);
        fprintf(fp, "[%02d:%02d:%02d] %s\n", t->tm_hour, t->tm_min, t->tm_sec, msg);
        fclose(fp);
    }
}

// Log a formatted message with timestamp
static inline void daglogf(const char *fmt, ...) {
    FILE *fp = fopen(LOG_FILE, "a");
    if (fp) {
        time_t now = time(NULL);
        struct tm *t = localtime(&now);
        fprintf(fp, "[%02d:%02d:%02d] ", t->tm_hour, t->tm_min, t->tm_sec);
        
        va_list args;
        va_start(args, fmt);
        vfprintf(fp, fmt, args);
        va_end(args);
        
        fprintf(fp, "\n");
        fclose(fp);
    }
}

#endif

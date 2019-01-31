/** @file debug.c
    @brief Debug output routines
    @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
*/

#include <stdio.h>
#include <errno.h>
#include <syslog.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>

#include "debug.h"

debugconf_t debugconf = {
    .debuglevel = LOG_INFO,
    .log_stderr = 1,
    .log_syslog = 0,
    .syslog_facility = 0
};

/** @internal
Do not use directly, use the debug macro */
void
_debug(const char *filename, int line, int level, const char *format, ...)
{
    char buf[28];
    va_list vlist;
    time_t ts;
    sigset_t block_chld;

    time(&ts);

    if (debugconf.debuglevel >= level) {
        sigemptyset(&block_chld);
        sigaddset(&block_chld, SIGCHLD);
        sigprocmask(SIG_BLOCK, &block_chld, NULL);

        if (level <= LOG_WARNING) {
            fprintf(stderr, "[%d][%.24s][%u](%s:%d) ", level, ctime_r(&ts, buf), getpid(),
                filename, line);
            va_start(vlist, format);
            vfprintf(stderr, format, vlist);
            va_end(vlist);
            fputc('\n', stderr);
        } else if (debugconf.log_stderr) {
            fprintf(stderr, "[%d][%.24s][%u](%s:%d) ", level, ctime_r(&ts, buf), getpid(),
                filename, line);
            va_start(vlist, format);
            vfprintf(stderr, format, vlist);
            va_end(vlist);
            fputc('\n', stderr);
        }

        if (debugconf.log_syslog) {
            openlog("wifidog", LOG_PID, debugconf.syslog_facility);
            va_start(vlist, format);
            vsyslog(level, format, vlist);
            va_end(vlist);
            closelog();
        }
        
        sigprocmask(SIG_UNBLOCK, &block_chld, NULL);
    }
}

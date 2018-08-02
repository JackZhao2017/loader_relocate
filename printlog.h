#ifndef _PRINTLOG_H_
#define _PRINTLOG_H_

#include <stdio.h>

// #define debug_msg(fmt, arg...) do { } while (0)       
// #define init_msg(fmt, arg...)  do { } while (0)
// #define err_msg(fmt, arg...)   do { } while (0)
// #define info_msg(fmt, arg...)  do { } while (0)
// #define warn_msg(fmt, arg...)  do { } while (0)


#define debug_msg(fmt, arg...) do { printf("[DEBUG]\t" fmt, ## arg)} while (0)       
#define init_msg(fmt, arg...)  do { printf("[INIT ]\t" fmt, ## arg);} while (0)
#define err_msg(fmt, arg...)   do { printf("[ERR  ]\t" fmt, ## arg);} while (0)
#define info_msg(fmt, arg...)  do { printf("[INFO ]\t" fmt, ## arg);} while (0)
#define warn_msg(fmt, arg...)  do { printf("[WARN ]\t" fmt, ## arg); } while (0)

#endif


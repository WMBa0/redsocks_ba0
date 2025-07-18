#ifndef DEBUG_H
#define DEBUG_H

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>

// 颜色定义
#define COLOR_RED     "\x1B[31m"
#define COLOR_GREEN   "\x1B[32m"
#define COLOR_YELLOW  "\x1B[33m"
#define COLOR_BLUE    "\x1B[34m"
#define COLOR_MAGENTA "\x1B[35m"
#define COLOR_CYAN    "\x1B[36m"
#define COLOR_RESET   "\x1B[0m"

// 调试级别
typedef enum {
    LOG_LEVEL_QUIET = 0,
    LOG_LEVEL_ERROR,
    LOG_LEVEL_WARNING,
    LOG_LEVEL_INFO,
    LOG_LEVEL_DEBUG,
    LOG_LEVEL_VERBOSE
} LogLevel;

// 全局日志级别 声明它
extern LogLevel current_log_level;

// 获取带毫秒的时间戳字符串
static inline char* get_timestamp() {
    static char buffer[24];
    struct timeval tv;
    struct tm *tm_info;

    gettimeofday(&tv, NULL);
    tm_info = localtime(&tv.tv_sec);

    strftime(buffer, 20, "%Y-%m-%d %H:%M:%S", tm_info);
    sprintf(buffer + 19, ".%03d", (int)(tv.tv_usec / 1000));
    return buffer;
}

// 主日志宏
#define LOG(level, color, tag, fmt, ...) \
    do { \
        if (level <= current_log_level) { \
            fprintf(stdout, "%s %s[%-7s]%s %s:%d:%s(): " fmt, \
                    get_timestamp(), color, tag, COLOR_RESET, \
                    __FILE__, __LINE__, __func__, ##__VA_ARGS__); \
        } \
    } while (0)
    

// 具体日志级别
#define LOG_VERBOSE_C(fmt, ...) LOG(LOG_LEVEL_VERBOSE, COLOR_CYAN,   "VERBOSE", fmt, ##__VA_ARGS__)
#define LOG_DEBUG_C(fmt, ...)   LOG(LOG_LEVEL_DEBUG,   COLOR_BLUE,    "DEBUG",   fmt, ##__VA_ARGS__)
#define LOG_INFO_C(fmt, ...)    LOG(LOG_LEVEL_INFO,    COLOR_GREEN,   "INFO",    fmt, ##__VA_ARGS__)
#define LOG_WARN_C(fmt, ...)    LOG(LOG_LEVEL_WARNING, COLOR_YELLOW,  "WARNING", fmt, ##__VA_ARGS__)
#define LOG_ERROR_C(fmt, ...)   LOG(LOG_LEVEL_ERROR,   COLOR_RED,     "ERROR",   fmt, ##__VA_ARGS__)



#endif // DEBUG_H
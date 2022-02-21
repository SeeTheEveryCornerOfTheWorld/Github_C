#ifndef _LOG_H_
#define _LOG_H_

/**********************************************************************
函数名称: logInit
函数功能: 初始化日志
参    数：
第    一：（I）日志文件路径
返    回：无
作    者: 赵翌渊
建立时间: 20200417
**********************************************************************/
void logInit(const char * logPath);

void printLog(int logLevel, const char * filePath, int nLine, const char *format, ...);

#define LOG_DEBUG_FMT(...) \
    do { \
		printLog(5, __FILE__, __LINE__, __VA_ARGS__); \
    } while(0);

#define LOG_INFO_FMT(...) \
    do { \
		printLog(4, __FILE__, __LINE__, __VA_ARGS__); \
    } while(0);

#define LOG_WARN_FMT(...) \
    do { \
		printLog(3, __FILE__, __LINE__, __VA_ARGS__); \
    } while(0);

#define LOG_ERROR_FMT(...) \
    do { \
		printLog(2, __FILE__, __LINE__, __VA_ARGS__); \
    } while(0);

#define LOG_FATAL_FMT(...) \
    do { \
		printLog(1, __FILE__, __LINE__, __VA_ARGS__); \
    } while(0);

#define log_debug_fmt(...) LOG_DEBUG_FMT(__VA_ARGS__);

#define log_info_fmt(...) LOG_INFO_FMT(__VA_ARGS__)

#define log_warn_fmt(...) LOG_WARN_FMT(__VA_ARGS__)

#define log_error_fmt(...) LOG_ERROR_FMT(__VA_ARGS__)

#define log_fatal_fmt(...) LOG_FATAL_FMT(logs, __VA_ARGS__)

#endif

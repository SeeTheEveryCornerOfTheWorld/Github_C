#include "log.h"

#include "commonHead.h"

string gstrLog;		//日志文件全路径

long LogSize = 50 * 1024 * 1024;	//日志文件大小设为50M
long glogSize = 0;	//记录写入日志文件的大小	

int bakLogNum = 3; //备份日志个数

int glogLevel = 5;

const char *ERR[] = { "", "[FAT]", "[ERR]", "[WARN]", "[INFO]", "[DEGUG]", "[TRACE]" };

void printLog(int logLevel, const char * filePath, int nLine, const char *format, ...)
{
	if (logLevel > glogLevel)
	{
		return;
	}
	char buffer[4296];
	va_list args;
	va_start(args, format);
	vsnprintf(buffer, 4296, format, args);
	va_end(args);
	time_t now;
	struct tm *tm_now;
	char   datetime[200] = { 0 };
	time(&now);
	tm_now = localtime(&now);
	strftime(datetime, 200, "%Y%m%d %H:%M:%S", tm_now);
// 	if (logfd != NULL)
	{
// 		fprintf(logfd, "%s:%d %s\n", filePath, nLine, args1);
		int iRet = fprintf(stderr, "%s %s:%d %s %s\n\n", datetime, filePath, nLine, ERR[logLevel], buffer);
		fflush(stderr);
		glogSize += iRet;
		if (glogSize >= LogSize)
		{
			glogSize = 0;
			logInit(gstrLog.c_str());
		}
	}
// 	else
// 		printf("%s %s:%d %s %s\n\n", datetime, filePath, nLine, ERR[logLevel], buffer);
}

void logInit(const char * logPath)
{
	gstrLog = logPath;
	char zBuf[1024] = { 0 };
	for (int i = bakLogNum; i > 1; i--)
	{
		sprintf(zBuf, "cp %s.%d %s.%d", logPath, i - 1, logPath, i);
		system(zBuf);
	}
	sprintf(zBuf, "cp %s %s.1", logPath, logPath);
	system(zBuf);
	truncate(logPath, 0);
	return;
}
#ifndef __SOCKETIMPL_H__
#define __SOCKETIMPL_H__

#include <stdint.h>

int writeString(int sck_inet, const char* line, int timeout);

int readFromSocket(int sck_inet, char* buff, int len, unsigned int flags, int timeout);

/********************************************************
函数名称：listensock
函数功能：创建socket开始监听端口
输入参数：
参数一：（I）port, 端口
参数二：（I）ip, ip地址
输出参数：
返    回：-1表示出错，大于0表示监听成功
作    者: 赵翌渊
创建时间：20210224
*********************************************************/
int listensock(uint16_t port, const char* ip);

#endif

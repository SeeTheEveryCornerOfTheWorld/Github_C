#ifndef __SOCKETIMPL_H__
#define __SOCKETIMPL_H__

#include <stdint.h>

int writeString(int sck_inet, const char* line, int timeout);

int readFromSocket(int sck_inet, char* buff, int len, unsigned int flags, int timeout);

/********************************************************
�������ƣ�listensock
�������ܣ�����socket��ʼ�����˿�
���������
����һ����I��port, �˿�
����������I��ip, ip��ַ
���������
��    �أ�-1��ʾ��������0��ʾ�����ɹ�
��    ��: ����Ԩ
����ʱ�䣺20210224
*********************************************************/
int listensock(uint16_t port, const char* ip);

#endif

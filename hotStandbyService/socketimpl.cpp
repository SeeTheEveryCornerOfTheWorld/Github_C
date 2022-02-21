#include "socketimpl.h"
#include "commonHead.h"
#include "log.h"

#define BLOCKFORERVER 65535

int selectEINTR(int numfds, fd_set * readfds, fd_set * writefds, fd_set * exceptfds, struct timeval * timeout)
{
	int rc;
	while (1) {  // using the while as a restart point with continue
		rc = select(numfds, readfds, writefds, exceptfds, timeout);
		if (rc < 0) {
			if (errno == EINTR) {
				continue;  // was interupted by a signal so restart
			}
		}
		break;  // end the while
	}
	return rc;
}

int readyForOutput(int sck_inet, int timeout)
{
	fd_set fdSet;
	FD_ZERO(&fdSet);
	FD_SET(sck_inet, &fdSet);
	if (timeout == BLOCKFORERVER)
	{
		if (selectEINTR(sck_inet + 1, NULL, &fdSet, NULL, NULL) < 1)
			return -1;
	}
	struct timeval t;
	t.tv_sec = timeout;
	t.tv_usec = 0;
	if (selectEINTR(sck_inet + 1, NULL, &fdSet, NULL, &t) < 1)
	{
		return -1;  // on error or timeout
	}
	return 0;
}

int writeToSocket(int sck_inet, char* buff, int len, unsigned int flags, int timeout)
{
	int actuallysent = 0;
	int sent;
	while (actuallysent < len)
	{
		if (readyForOutput(sck_inet, timeout) == -1) //on error or timeout
			return -1;

		sent = send(sck_inet, buff + actuallysent, len - actuallysent, flags);
		if (sent < 0)
		{
			if (errno == EINTR)
			{
				continue;  // was interupted by signal so restart
			}
			return -1;
		}
		if (sent == 0)
		{
			return actuallysent; // other end is closed
		}
		actuallysent += sent;
	}
	return actuallysent;
}

int writeString(int sck_inet, const char * line, int timeout)
{
	int l = strlen(line);
	if (writeToSocket(sck_inet, (char*)line, l, 0, timeout) == -1) {
		return -1;
	}
	return 0;
}

int readFromSocket(int sck_inet, char* buff, int len, unsigned int flags, int timeout)
{
	/*the same as readFromSocket,but return -2 indicating timeout*/
	int rc;
	fd_set fdSet;
	FD_ZERO(&fdSet);
	FD_SET(sck_inet, &fdSet);
	if (timeout == BLOCKFORERVER)
	{
		if (selectEINTR(sck_inet + 1, &fdSet, NULL, NULL, NULL) < 0)
			return -1;/*error*/
	}
	struct timeval t;
	t.tv_sec = timeout;
	t.tv_usec = 0;
	rc = selectEINTR(sck_inet + 1, &fdSet, NULL, NULL, &t);
	if (rc < 0)
		return -1;/*error*/
	else if (rc == 0)
		return -2;/*timeout*/

				  /*have data to read*/
	while (1)
	{
		rc = recv(sck_inet, buff, len, flags);
		if (rc < 0)
		{
			if (errno == EINTR)
			{
				continue;
			}
		}
		break;
	}
	return rc;
}

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
int listensock(uint16_t port, const char* ip)
{
	int listenfd;
	const int on = 1;
	struct sockaddr_in addr;

	if ((listenfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		log_error_fmt("listensock: create socket error");
		return -1;
	}
	setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);

	if (ip)
	{
		addr.sin_addr.s_addr = inet_addr(ip);
		if (addr.sin_addr.s_addr < 0)
		{
			log_error_fmt("listensock: convert[%s] error", ip);
			return -1;
		}
	}
	else
	{
		addr.sin_addr.s_addr = htonl(INADDR_ANY);
	}

	if (bind(listenfd, (struct sockaddr*)&addr, sizeof(addr)) < 0)
	{
		log_error_fmt("listensock: Unable to bind socket \"%s:%u\"error", ip ? ip : "*", port);
		return -1;
	}

	if (listen(listenfd, 128) < 0)
	{
		log_error_fmt("listensock: Unable to listen socket \"%s:%u\"error", ip ? ip : "*", port);
		return -1;
	}
	return listenfd;
}

#include "commonFunc.h"

#include "commonDefine.h"
#include "log.h"
#include <iconv.h>
#include "ha_vrrp.h"

static const char *b64alpha =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
#define B64PAD '='

/**********************************************************************
函数名称: getIpFromName
函数功能: 从user指令得到host信息,用于pop3代理
参    数：
第    一：（I）str,USER指令字符串
第    二：（O）orig_msg, 邮箱信息
第    三：（I）orig_msg_size, 邮箱信息长度
第    四：（O）host, 主机信息(域名)
第    五：（I）host_size, host长度
返    回： 大于0表示成功
作    者: 赵翌渊
建立时间: 20200408
**********************************************************************/
int splitUserHost(const char *str, char *orig_msg, size_t orig_msg_size, char *host, size_t host_size)
{
	const char * pchFind = strstr(str, "\r\n");
	const char * iFind = strrchr(str, '@');
	if (iFind == NULL)
	{
		return -1;
	}
	iFind++;
	int iHostlen = 0;
	if (pchFind == NULL)
	{
		iHostlen = strlen(iFind);
	}
	else
	{
		iHostlen = pchFind - iFind;
	}
	strncpy(host, iFind, iHostlen);
	unsigned short i;
	unsigned short size = strlen(str);
	int ret = 0;
	for (i = size; i > 0; i--)
		if ((str[i] == '#') || (str[i] == '@')) {
			int orig_msg_len = MIN(i, orig_msg_size);
			if (str[i] == '@')
				ret = 1;
			else
				ret = 2;
			memcpy(orig_msg, str, orig_msg_len);
			orig_msg[orig_msg_len] = 0;
			return ret;
		}
	return ret;
}

/**********************************************************************
函数名称: setnonblocking
函数功能: 将文件描述符设置为非阻塞的
参    数：
第    一：（I）accept fd
返    回： 0表示成功
作    者: 李高文
建立时间: 20200206
**********************************************************************/
int setnonblocking(int fd)
{
	int iOldOpt;
	int iNewOpt;

	iOldOpt = fcntl(fd, F_GETFD);  //F_GETFD OR F_GETFL
	if (iOldOpt < 0)//可能是客户端已关闭造成的
	{
		log_error_fmt("fcntl F_GETFD error[%d][%s]", errno, strerror(errno)); fflush(stderr);
		//log( LVNOR, "fcntl F_GETFD error[%d][%s]", errno, strerror(errno) );
		return -1;
	}
	iNewOpt = iOldOpt | O_NONBLOCK;
	if (fcntl(fd, F_SETFD, iNewOpt) < 0)//可能是客户端已关闭造成的
	{
		log_error_fmt("fcntl F_SETFD error[%d][%s]", errno, strerror(errno)); fflush(stderr);
		//log( LVNOR, "fcntl F_SETFD error[%d][%s]", errno, strerror(errno) );
		return -1;
	}

	return 0;
}

/**********************************************************************
函数名称: setNoblock
函数功能: 设置socket为非阻塞或阻塞
参    数：
第    一：（I）sockfd
第    二：（I）mode,1为非阻塞，0为阻塞
返    回： 0表示成功
作    者: 赵翌渊
建立时间: 20200408
**********************************************************************/
int setNoblock(int sockfd, int mode)
{
	if (ioctl(sockfd, FIONBIO, &mode) != 0) 
	{
		log_error_fmt("setNoblock error %d:%s", errno, strerror(errno));
		return -1;
	}
	return 0;
}

/**********************************************************************
函数名称: getIpFromName
函数功能: 从域名获取ip
参    数：
第    一：（I）pchDomain
第    二：（O）pchIp
返    回： 0表示成功
作    者: 赵翌渊
建立时间: 20200407
**********************************************************************/
int getIpFromDomain(const char * pchDomain, char * pchIp)
{
	char domain[1024] = { 0 };
	struct hostent *host;
	if ((host = gethostbyname(pchDomain)) == NULL)
	{
		log_error_fmt("gethostbyname error %d:%s", errno, strerror(errno));
		return -1;
	}
	strcpy(pchIp, inet_ntop(host->h_addrtype, host->h_addr, domain, sizeof(domain)));
	return 0;
}

/**********************************************************************
函数名称: delSocketFromEpoll
函数功能: 从epoll删除socket
参    数：
第    一：（I）epoll fd
第    二：（I）socket fd
返    回： 0表示成功
作    者: 赵翌渊
建立时间: 20200403
**********************************************************************/
int delSocketFromEpoll(int iEpollfd, int iaSocketFd)
{
	struct epoll_event sEpollEvent;
	sEpollEvent.events = EPOLLIN;
	epoll_ctl(iEpollfd, EPOLL_CTL_DEL, iaSocketFd, &sEpollEvent);

	return 0;
}

/**********************************************************************
函数名称: addSocketToEpoll
函数功能: 将SOCKET添加到epoll事件列表
参    数：
第    一：（I）EPOLL FD
第    二：（I）socket
返    回： 0表示成功
作    者: 赵翌渊
建立时间: 20200403
**********************************************************************/
int addSocketToEpoll(int iEpollFd, int iSocketFd)
{
	struct epoll_event sEpollEvent;
	sEpollEvent.data.fd = iSocketFd;
	sEpollEvent.events = EPOLLIN;
	epoll_ctl(iEpollFd, EPOLL_CTL_ADD, iSocketFd, &sEpollEvent);

	return 0;
}

/**********************************************************************
函数名称: connectTcpServer
函数功能: tcp连接服务器
参    数：
第    一：（I）ip，服务器ip地址
第    二：（I）iPort，服务器端口
返    回： 大于0表示成功返回socket，0表示地址出错，-1表示连接失败
作    者: 赵翌渊
建立时间: 20200408
**********************************************************************/
int connectTcpServer(const char * ip, int iPort)
{
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(iPort);
	inet_pton(AF_INET, ip, &addr.sin_addr);
	if (addr.sin_addr.s_addr == 0)
		return 0;
	
	int nCount = 3;
	int iRet = 0;
	while (nCount)
	{
		int iSocket = socket(AF_INET, SOCK_STREAM, 0);
		iRet = connectTimeout(iSocket, (struct sockaddr *)(&addr), sizeof(struct sockaddr), 3);
		if (iRet == 0)
		{
			return iSocket;
		}
		close(iSocket);
		sleep(3);
		nCount--;
	}
	
	return -1;
}

/**********************************************************************
函数名称: connectTimeout
函数功能: 连接时使用超时，避免阻塞时间过长
参    数：
第    一：（I）sockfd，连接socket
第    二：（I）serv_addr，服务器地址
第    三：（I）addrlen，地址长度
第    四：（I）timeout，超时时间
返    回： 0表示成功，-1表示连接失败
作    者: 赵翌渊
建立时间: 20200408
**********************************************************************/
int connectTimeout(int sockfd, const struct sockaddr *serv_addr, socklen_t addrlen, int timeout)
{
	struct timeval	tv;
	fd_set	wset;
	int ret;
	setNoblock(sockfd, 1);
	ret = connect(sockfd, serv_addr, addrlen);
	if (ret == 0)
	{
		setNoblock(sockfd, 0);
		return 0;
	}
	tv.tv_sec = timeout;
	tv.tv_usec = 0;
	FD_ZERO(&wset);
	FD_SET(sockfd, &wset);
	ret = select(sockfd + 1, NULL, &wset, NULL, &tv);
	
	if (ret <= 0)
		return -1;
	else if (ret == 1)
	{
		int err = 0;
		socklen_t socklen = sizeof(err);
		int sockoptret = getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &err, &socklen);//成功返回0，错误返回-1
		if (sockoptret == -1)
		{
			setNoblock(sockfd, 0);
			return -1;
		}
		if (err == 0)//套接字没有错误
			ret = 0;//返回0成功未超时
		else//套接字产生错误
		{
			
			ret = -1;
		}
	}
	setNoblock(sockfd, 0);
	return ret;
}



//返回0表示地址有效
int is_valid_ipv4(const char * ipv4)
{
	struct in_addr addr;
	if (ipv4 == NULL)
		return -1;
	if (inet_pton(AF_INET, ipv4, (void*)&addr) == 1)
		return 0;
	return -1;
}

//返回命令结果
int getCmdResult(const char * szCmd)
{
	int ret = 0;
	FILE *fp;
	char line[1024] = { 0 };
	if ((fp = popen(szCmd, "r")) == NULL)
		return -1;
	if ((fgets(line, sizeof(line), fp)) != NULL)
	{
		ret = atoi(line);
	}
	fclose(fp);
	return ret;
}

int is_valid_ipv6(const char * ipv6)
{
	struct in6_addr addr;
	if (ipv6 == NULL)
		return -1;
	if (inet_pton(AF_INET6, ipv6, (void*)&addr) == 1)
		return 0;
	return -1;
}
//判断是否合法IP
int IsValidIp(const char * pchIp)
{
	if (is_valid_ipv4(pchIp) == 0)
		return 4;
	if (is_valid_ipv6(pchIp) == 0)
		return 6;
	return -1;
}

/**********************************************************************
函数名称: createTcpServer
函数功能: 创建SOCKET
参    数：
第    一：(I)iaPort,端口
第    二：(I)pchIp, ip地址
返    回： 大于0表示成功返回socket，-1表示连接失败，-2表示地址出错
作    者: 李高文
建立时间: 20200313
**********************************************************************/
int createTcpServer(int iaPort, const char * pchIp)
{
	int iSocket = 0;
	int iRet = 0;
	iRet = IsValidIp(pchIp);
	if (iRet < 0)
	{
		return -2;
	}
	if (iRet == 4)
	{
		/*建立socket*/
		sockaddr_in serAddr4;   /*服务器地址信息结构体*/
		iSocket = socket(AF_INET, SOCK_STREAM, 0);
		if (iSocket == -1)
		{
// 			COUT << "create socket error[" << errno << "][" << strerror(errno) << "]" << endl;
			log_error_fmt("create socket error %d:%s", errno, strerror(errno));
			return -1;
		}
		int    iOpt;
		/*设置socket属性*/
		iOpt = SO_REUSEADDR;
		setsockopt(iSocket, SOL_SOCKET, SO_REUSEADDR, (char *)&iOpt, sizeof(iOpt));
		memset(&serAddr4, 0x00, sizeof(serAddr4));
		serAddr4.sin_family = AF_INET;
		serAddr4.sin_port = htons(iaPort);
		iRet = inet_pton(AF_INET, pchIp, &serAddr4.sin_addr);
		/*调用bind绑定地址*/
		if (bind(iSocket, (struct sockaddr *)&serAddr4, sizeof(struct sockaddr)) == -1)
		{
// 			fprintf(stderr, "bind socket error[%d][%s]\n", errno, strerror(errno));
// 			COUT << "bind socket error[" << errno << "][" << strerror(errno) << "]" << endl;
			log_error_fmt("bind socket error %d:%s", errno, strerror(errno));
			return -1;
		}

		/*调用listen开始监听*/
		if (listen(iSocket, MAX_LINKS) == -1)
		{
// 			fprintf(stderr, "listen socket error[%d][%s]\n", errno, strerror(errno));
// 			COUT << "listen socket error[" << errno << "][" << strerror(errno) << "]" << endl;
			log_error_fmt("listen socket error %d:%s\n", errno, strerror(errno));
			return -1;
		}
		return iSocket;
	}
	
	sockaddr_in6 serAddr6;
	serAddr6.sin6_family = AF_INET6;
	serAddr6.sin6_port = htons(iaPort);
	iRet = inet_pton(AF_INET6, pchIp, &serAddr6.sin6_addr);

	/*建立socket*/
	iSocket = socket(AF_INET6, SOCK_STREAM, 0);
	if (iSocket == -1)
	{
// 		COUT << "create socket error[" << errno << "][" << strerror(errno) << "]" << endl;
		log_error_fmt("create socket error %d:%s", errno, strerror(errno));
		return -1;
	}
	int    iOpt;
	/*设置socket属性*/
	iOpt = SO_REUSEADDR;
	setsockopt(iSocket, SOL_SOCKET, SO_REUSEADDR, (char *)&iOpt, sizeof(iOpt));
	/*调用bind绑定地址*/
	if (bind(iSocket, (struct sockaddr *)&serAddr6, sizeof(serAddr6)) == -1)
	{
// 		COUT << "bind socket error[" << errno << "][" << strerror(errno) << "]" << endl;
		log_error_fmt("bind socket error %d:%s", errno, strerror(errno));
		return -1;
	}

	/*调用listen开始监听*/
	if (listen(iSocket, MAX_LINKS) == -1)
	{
// 		COUT << "listen socket error[" << errno << "][" << strerror(errno) << "]" << endl;
		log_error_fmt("listen socket error %d:%s", errno, strerror(errno));
		return -1;
	}
	//fprintf( stdout, "create socket success\n" );
	return iSocket;
}

/**********************************************************************
函数名称: str_chr
函数功能: 字符查找
参    数：
第    一：（I）s，查找源字符串
第    二：（I）c，查找的字符
返    回： 字符所在位置
作    者: 赵翌渊
建立时间: 20200408
**********************************************************************/
unsigned int str_chr(const char *s, int c)
{
	register char ch;
	register const char *t;

	ch = c;
	t = s;
	for (;;) {
		if (!*t) break; if (*t == ch) break; ++t;
		if (!*t) break; if (*t == ch) break; ++t;
		if (!*t) break; if (*t == ch) break; ++t;
		if (!*t) break; if (*t == ch) break; ++t;
	}
	return t - s;
}
/**********************************************************************
函数名称: b64decode
函数功能: 解码base64
参    数：
第    一：（I）in，待解码的字符串
第    二：（I）len，待解码的字符串的长度
第    三：（O）out，解码后的字符串
返    回： 大于0表示成功返回解码字符串的长度，0表示待解码字符串长度不正确，-1表示解码失败
作    者: 赵翌渊
建立时间: 20200408
**********************************************************************/
int b64decode(const unsigned char *in, int len, char *out)
{
	int i, j;
	int iRetLen;
	unsigned char a[4];
	unsigned char b[3];
	char *s;
	//  stringstream s;
	//	printf("in=%s\n",in);
	if (len <= 0)
	{
		return 0;
	}

	// if (!stralloc_ready(out,l + 2)) return -1; /* XXX generous */
	// s = out;//->s;
	//	out=(char *)malloc(2*l+2);
	s = out;
	for (i = 0; i < len; i += 4) {
		for (j = 0; j < 4; j++)
			if ((i + j) < len && in[i + j] != B64PAD)
			{
				a[j] = str_chr(b64alpha, in[i + j]);
				if (a[j] > 63) {
					//		printf("bad char=%c,j=%d\n",a[j],j);
					return -1;
				}
			}
			else a[j] = 0;

			b[0] = (a[0] << 2) | (a[1] >> 4);
			b[1] = (a[1] << 4) | (a[2] >> 2);
			b[2] = (a[2] << 6) | (a[3]);

			*s = b[0];
			s++;

			if (in[i + 1] == B64PAD) break;
			*s = b[1];
			s++;

			if (in[i + 2] == B64PAD) break;
			*s = b[2];
			s++;
	}

	iRetLen = s - out;
	//  printf("len=%d\n",len);
	while (iRetLen && !out[iRetLen - 1]) --iRetLen; /* XXX avoid? */
	return iRetLen;
}
/**********************************************************************
函数名称: b64encode
函数功能: base64编码
参    数：
第    一：（I）in，待编码的字符串
第    二：（I）len，待编码的字符串的长度
第    三：（O）out，编码后的字符串
返    回： 大于0表示成功返回解码字符串的长度，0表示待解码字符串长度不正确，-1表示解码失败
作    者: 赵翌渊
建立时间: 20200408
**********************************************************************/
int b64encode(const unsigned char *in, int len, char * out)
/* not null terminated */
{
	unsigned char a, b, c;
	int i;
	// char *s;
	stringstream s;
	if (len <= 0)
	{
		return 0;
	}

	// if (!stralloc_ready(out,in->len / 3 * 4 + 4)) return -1;
	// s = out->s;

	for (i = 0; i < len; i += 3) {
		a = in[i];
		b = i + 1 < len ? in[i + 1] : 0;
		c = i + 2 < len ? in[i + 2] : 0;

		s << b64alpha[a >> 2];
		s << b64alpha[((a & 3) << 4) | (b >> 4)];

		if (i + 1 >= len) s << B64PAD;
		else s << b64alpha[((b & 15) << 2) | (c >> 6)];

		if (i + 2 >= len) s << B64PAD;
		else s << b64alpha[c & 63];
	}
	//  out->len = s - out->s;
	strcpy(out, s.str().c_str());
	return s.str().length();
}

/********************************************************
函数名称：AllTrim
函数功能：去掉头尾空格
入口参数：
第    一：字符串     I
返    回：1表示该字符为空格，0表示不是
创建时间：20200219
*********************************************************/
char *AllTrim(char *pcaStr)
{
	char *pcStart;
	char *pcEnd;

	pcStart = pcaStr;
	pcEnd = pcStart + strlen(pcStart) - 1;

	/*忽略开头部分的空格*/
	while (1)
	{
		/*如果全都是空格*/
		if (pcStart == pcEnd)
		{
			return pcaStr;
		}

		/*如果是空格*/
		if (*pcStart == ' ' || *pcStart == '\t' || *pcStart == '\r' || *pcStart == '\n')
		{
			*pcStart = 0x00;
			pcStart++;
		}
		else
		{
			break;
		}
	}

	/*忽略末尾部分的空格*/
	while (1)
	{
		/*如果全都是空格*/
		if (pcEnd == pcStart)
		{
			return pcaStr;
		}
		/*如果是空格*/
		if (*pcEnd == ' ' || *pcEnd == '\t' || *pcEnd == '\r' || *pcEnd == '\n')
		{
			*pcEnd = 0x00;
			pcEnd--;
		}
		else
		{
			break;
		}
	}
	memcpy(pcaStr, pcStart, pcEnd - pcStart + 1);
	return pcaStr;
}

/********************************************************
函数名称：enterDaemon
函数功能：进入后台
参    数：
第    一：（I）isEnterBack, 是否进入后台
第    二：（I）logFile, 日志文件
返    回：0表示成功，-1表示创建进程失败
创建时间：20200219
*********************************************************/
int enterDaemon(int isEnterBack, const char * logFile)
{
	if (isEnterBack)
	{
		pid_t   pid;
		if ((pid = fork()) < 0) return(-1);
		else if (pid != 0) {/*parent*/
			exit(0);
		}
		setsid();
		chdir("/");
		umask(0);
	}
	close(0);
	close(1);
	close(2);
	int fd;
	if ((fd = open(logFile, O_APPEND | O_SYNC | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) >= 0)
	{
		dup2(fd, 0);
		dup2(fd, 1);
		dup2(fd, 2);

		freopen(logFile, "a", stdout);
		freopen(logFile, "a", stderr);

		setvbuf(stdout, NULL, _IOLBF, 0);
		setvbuf(stderr, NULL, _IOLBF, 0);

		if ((fd != 0) && (fd != 1) && (fd != 2))
			close(fd);

		logInit(LOG_FILE);
	}
	
	return 0;
}

/********************************************************
函数名称：isAddrParagraph
函数功能：地址是否在地址段中,如192.168.0.13-192.168.0.22
参    数：
第    一：（I）addr, 待查地址
第    二：（I）addrStart, 启始地址
第    三：（I）addrEnd, 结束地址
返    回：0成功，-1失败
作    者: 赵翌渊
创建时间：20200422
*********************************************************/
int isAddrParagraph(sockaddr_in & addr, const char * addrStart, const char * addrEnd)
{
	long ipHost = ntohl(addr.sin_addr.s_addr);

	struct in_addr sStart, sEnd;

	inet_pton(AF_INET, addrStart, (void *)&sStart);
	long ipStart = ntohl(sStart.s_addr);

	inet_pton(AF_INET, addrEnd, (void *)&sEnd);
	long ipEnd = ntohl(sEnd.s_addr);
	if (ipHost >= ipStart && ipHost <= ipEnd)
	{
		return 0;
	}
	return -1;
}
/********************************************************
函数名称：findAddrInList
函数功能：查询地址是否在地址列表中,如192.168.0.11,192.168.0.13-192.168.0.22
参    数：
第    一：（I）addr, 待查地址
第    二：（I）addrList, 地址字符串
返    回：0表示成功
作    者: 赵翌渊
创建时间：20200422
*********************************************************/
int findAddrInList(sockaddr_in & addr, const char * addrList)
{
	//先将地址转成字符串查找一遍
	char str[512] = { 0 };
	const char *ptr = inet_ntop(AF_INET, &addr.sin_addr, str, sizeof(str));
// 	const char * pFind = strstr(addrList, str);
// 	if (pFind == NULL)
// 	{
	const char * pFind = NULL;
		//192.168.0.11,192.168.0.13-192.168.0.22
		char addrs[1024] = { 0 };
		strcpy(addrs, addrList);
		while (1)
		{
			pFind = strchr(addrs, '-');
			if (pFind == NULL) //没有地址段，返回失败
			{
				return -1;
			}
			else
			{
				strncpy(str, addrs, pFind - addrs); //-的左边
				const char * pSearch = strchr(str, ',');
				char left[512] = { 0 }, right[512] = { 0 };
				if (pSearch != NULL)
				{
					pSearch++;
					strncpy(left, pSearch, pSearch - str);
				}
				else
				{
					strcpy(left, str);
				}
				pFind++;
				pSearch = strchr(pFind, ',');
				if (pSearch == NULL)
				{
					strcpy(right, pFind);
					return isAddrParagraph(addr, left, right);
				}
				else
				{
					strncpy(right, pFind, pSearch - pFind);
					if (isAddrParagraph(addr, left, right) == 0)
					{
						return 0;
					}
					pSearch++;
					strcpy(addrs, pSearch);
				}
			}
		}
// 	}
	return 0;
}


/********************************************************
函数名称：isFind
函数功能：检查字符串中是否有过滤条件，如邮箱zkxayyyy@163.com，过滤条件为"163.com,qq.com"，则返回0
参    数：
第    一：（I）buf, 待查字符串
第    二：（I）filter, 过滤条件
第    三：（I）separator, 过滤条件的分隔符
返    回：0为成功,-1为失败
作    者: 赵翌渊
创建时间：20200426
*********************************************************/
int isFind(const char * buf, const char * filter, int separator)
{
	const char * pFind = strchr(filter, separator);
	char tmp[1024] = { 0 };
	if (pFind == NULL)
	{
		if (strlen(filter) == 0)
		{
			return -1;
		}
		pFind = strstr(buf, filter);
		if (pFind != NULL)
		{
			return 0;
		}
		return -1;
	}
	while (pFind != NULL)
	{
		memset(tmp, 0, 1024);
		strncpy(tmp, filter, pFind - filter);
		filter = pFind + 1;
		pFind = strstr(buf, tmp);
		if (pFind != NULL)
		{
			return 0;
		}
		pFind = strchr(filter, separator);
	}
	if (filter)
	{
		if (strlen(filter) == 0)
		{
			return -1;
		}
		pFind = strstr(buf, filter);
		if (pFind != NULL)
		{
			return 0;
		}
	}
	return -1;
}

/********************************************************
函数名称：getFileSize
函数功能：获取文件的大小
参    数：
第    一：（I）pFilePath, 文件路径
返    回：文件的长度，大于等于0为成功，小于0则失败
作    者: 赵翌渊
创建时间：20200427
*********************************************************/
long getFileSize(const char * pFilePath)
{
	struct stat fStat;
	if (stat(pFilePath, &fStat)<0)
	{
		return -1;
	}
	return fStat.st_size;
}

//字符串编码转换
int code_convert(const char *from_charset, const char *to_charset, char *inbuf,
	size_t inlen, char *outbuf, size_t outlen)
{
	iconv_t cd;
	char **pin = &inbuf;
	char **pout = &outbuf;

	cd = iconv_open(to_charset, from_charset);
	if (cd == 0)
		return -1;
	memset(outbuf, 0, outlen);
	if (iconv(cd, pin, &inlen, pout, &outlen) != 0)
		return -1;
	iconv_close(cd);
	return 0;
}
//utf-8转gb2312
int u2g(char *inbuf, int inlen, char *outbuf, int outlen)
{
	return code_convert("utf-8", "gb2312", inbuf, inlen, outbuf, outlen);
}
//gb2312转utf-8
int g2u(char *inbuf, size_t inlen, char *outbuf, size_t outlen)
{
	return code_convert("gb2312", "utf-8", inbuf, inlen, outbuf, outlen);
}
//反向比较
int strrncmp(const char * s1, const char * s2, int n)
{
	int len1 = strlen(s1);
	int len2 = strlen(s2);
	if (len1 < len2)
	{
		return len1 - len2;
	}
	return strncmp(s1 + len1 - len2, s2, n);
}
//反向比较不区分大小写
int strrncasecmp(const char * s1, const char * s2, int n)
{
	int len1 = strlen(s1);
	int len2 = strlen(s2);
	if (len1 < len2)
	{
		return len1 - len2;
	}
	return strncasecmp(s1 + len1 - len2, s2, n);
}

//获取当前应用路径
int getPath(char * path)
{
	int iRet = 0;
	iRet = readlink("/proc/self/exe", path, MAXBUFSIZE);
	if (iRet < 0 || iRet >= MAXBUFSIZE)
	{
		return -1;
	}
	path[iRet] = '\0';
	char * pos = strrchr(path, '/');
	pos++;
	*pos = 0;
	return 0;
}

//去除尾部空格
char *rtrim(char *str)
{
	if (str == NULL || *str == '\0')
	{
		return str;
	}

	int len = strlen(str);
	char *p = str + len - 1;
	while (p >= str  && isspace(*p))
	{
		*p = '\0';
		--p;
	}

	return str;
}
//去除首部空格
char *ltrim(char *str)
{
	if (str == NULL || *str == '\0')
	{
		return str;
	}

	int len = 0;
	char *p = str;
	while (*p != '\0' && isspace(*p))
	{
		++p;
		++len;
	}

	memmove(str, p, strlen(str) - len + 1);

	return str;
}
//去除首尾空格
char *trim(char *str)
{
	str = rtrim(str);
	str = ltrim(str);

	return str;
}

int  write_file(const char* filename, int val)
{
	FILE * fd;
	char str[10];
	fd = fopen(filename, "w+");
	if (!fd)
	{
		log_error_fmt("read file error");
		return -1;
	}
	memset(str, '\0', sizeof(str));
	snprintf(str, sizeof(str) - 1, "%d", val);
	fwrite(str, 1, strlen(str), fd);
	fclose(fd);
	return 0;
}

const char * getIpFromInt(int nip, char * szIp, int nAddrLen)
{
	if (inet_ntop(AF_INET, &nip, szIp, nAddrLen) != NULL)
	{
		return szIp;
	}
// 	log_error_fmt("error:[%d:%s]", errno, strerror(errno));
	return NULL;
}

uint32_t getIpFromStr(const char* szIp)
{
	struct in_addr addrTmp;
	// 	inet_pton(AF_INET, "192.168.161.110", (void*)&addrTmp);
	if (inet_pton(AF_INET, szIp, (void*)&addrTmp) == 1)
		return addrTmp.s_addr;
	return 0;
}

//=0  timeout ; <0 connect error  ; >1  connect ok
int opensock_timeout(char *ip_addr, int port, int timeout)
{
	int ret;
	int sock_fd;
	socklen_t   addr_len;
	int flags;
	int error;
	struct timeval tval;
	fd_set rset, wset;
	struct sockaddr_in serv_addr;
// 	assert(ip_addr);
// 	assert(port > 0);
	memset((struct sockaddr *) &serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	if (inet_aton(ip_addr, &serv_addr.sin_addr) < 0)
	{
		log_error_fmt("opensock: Could not convert address \"%s\",", ip_addr);
		return -1;
	}
	serv_addr.sin_port = htons(port);
	if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
	{
		log_error_fmt("opensock: socket() error");
		return -1;
	}

	flags = setNoblock(sock_fd, 1);
	if ((ret = (connect(sock_fd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)))) < 0)
	{
		if (errno != EINPROGRESS)
		{
			log_error_fmt("opensock: connect() to \"%s:%u\"error", ip_addr, port);
			close(sock_fd);

			return -1;  //connect error
		}
	}
	else if (ret == 0)
	{

		return sock_fd;   //connect ok 
	}
	FD_ZERO(&rset);
	FD_SET(sock_fd, &rset);
	wset = rset;
	tval.tv_sec = timeout;
	tval.tv_usec = 0;
	if ((ret = select(sock_fd + 1, &rset, &wset, NULL, &tval)) == 0)
	{
		close(sock_fd);
		errno = ETIMEDOUT;
		return 0;
	}
	if (FD_ISSET(sock_fd, &rset) || FD_ISSET(sock_fd, &wset))
	{
		addr_len = sizeof(error);
		if (getsockopt(sock_fd, SOL_SOCKET, SO_ERROR, &error, &addr_len) < 0)
		{
			log_error_fmt("getsockopt error  ");
			close(sock_fd);
			return -1;
		}
		if (error != 0)
		{
			//err_ret("error !-0,connect error");
			close(sock_fd);
			return -1;
		}
	}
	else
	{
		//printf("sockfd not set\n");
		close(sock_fd);
		return -1;
	}
	setNoblock(sock_fd, 0);
	return sock_fd;   //connect ok
}

uint32_t VRRP_TIMER_CLK(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return tv.tv_sec*VRRP_TIMER_HZ + tv.tv_usec;
}

/********************************************************
函数名称：getNetworkAddr
函数功能：根据IP地址子网掩码串获取整形子网码
输入参数：
参数一：（I）ip, IP地址
参数二：（I）mask, 子网掩码串
输出参数：
返    回：-1表示出错，0表示计算失败，大于0为返回的子网码
作    者: 赵翌渊
创建时间：20210223
*********************************************************/
int getNetworkAddr(char* ip, char* mask)
{
	FILE* fp;
	char* p;
	char line[120];
	char cmd[100];
	char prefix_tmp[4];
	memset(cmd, '\0', sizeof(cmd));
	memset(prefix_tmp, '\0', sizeof(prefix_tmp));
	snprintf(cmd, sizeof(cmd) - 1, "ipcalc -p %s %s", ip, mask);
	log_debug_fmt("cmd:[%s]", cmd);
	if ((fp = popen(cmd, "r")) == NULL)
	{
		return -1;
	}
	memset(line, '\0', sizeof(line));
	while ((fgets(line, sizeof(line), fp)) != NULL)
	{
		if (strstr(line, "\r\n") != NULL)
		{
			line[strlen(line) - 2] = '\0';
		}
		else if (line[strlen(line) - 1] == '\r' || line[strlen(line) - 1] == '\n')
		{
			line[strlen(line) - 1] = '\0';
		}
		p = strchr(line, '=');
		memcpy(prefix_tmp, p + 1, strlen(p + 1));
		pclose(fp);
		return atoi(prefix_tmp);
	}
	pclose(fp);
	return 0;
}

/********************************************************
函数名称：get_ifdev_statu
函数功能：根据网卡名判断网卡是否在线
输入参数：
参数一：（I）ifname， 网卡名
输出参数：
返    回：-1表示出错或不在线，0表示在线
作    者: 赵翌渊
创建时间：20210224
*********************************************************/
int get_ifdev_statu(const char* ifname)
{
	FILE* fp;
	char line[60];
	char cmd[30];
	memset(line, '\0', sizeof(line));
	memset(cmd, '\0', sizeof(cmd));
	snprintf(cmd, sizeof(cmd) - 1, "ethtool %s | grep detected:", ifname);
	//err_msg("cmd = %s ",cmd);
	if ((fp = popen(cmd, "r")) == NULL)
	{
		return -1;
	}
	if ((fgets(line, sizeof(line), fp)) != NULL)
	{
		pclose(fp);
		//err_msg("line = %s ",line);
		if (strstr(line, "yes") != NULL)
			return 0;
		if (strstr(line, "no") != NULL)
			return -1;
		else
			return  0;
	}
	log_debug_fmt("get_ifdev_statu  退出");
	pclose(fp);
	return -1;
}

/********************************************************
函数名称：ifdev_offline
函数功能：根据网卡名判断网卡是否在线,重复3次
输入参数：
参数一：（I）ifname， 网卡名
输出参数：
返    回：-1表示出错或不在线，0表示在线
作    者: 赵翌渊
创建时间：20210224
*********************************************************/
int ifdev_offline(const char* ifname)
{
	int    num;
	int    ret;

	//printf("test %s ...........\n", ifname);
	for (num = 0; num < 3; num++)
	{
		ret = get_ifdev_statu(ifname);
		if (ret == -1)
		{
			sleep(1);//第一次失败后，等待1s  
			continue;
		}
		else
			break;
	}
	return  ret;
}

/*按长度接收数据
* Function: recvDataOfLength
* Input:   sock: 接收socket
*			buf: 接收缓存
*			dataLength: 接收数据的长度
* Output:
* Result: 小于dataLength: 网络出错
*			返回dataLength正常
*/
int recvDataOfLength(int sock, char* buf, int dataLength)
{
	int ret = read(sock, buf, dataLength);
	if (ret == dataLength)
	{
		return ret;
	}
	int recvLen = dataLength - ret;
	int pos = ret;
	while (recvLen > 0)
	{
		ret = read(sock, buf + pos, recvLen);
		if (ret < 0)
		{
			log_error_fmt("ret = %d %d:%s", ret, errno, strerror(errno));
			return ret;
		}
		else if (ret == 0)
		{
			return 0;
		}

		recvLen -= ret;
		pos += ret;
	}
	//到这里说明接收完了
	return dataLength;
}

int cmdHandle(const char* cmd, const char* param) {
	FILE* pf;
	char buf[1024] = { 0 };
	int bFlag = 0;
	if ((pf = popen(cmd, "r")) == NULL)
	{
		return -2;
	}
	while (fgets(buf, sizeof(buf), pf) != NULL)
	{
		if (strstr(buf, param) != NULL)
		{
			bFlag = 1;
			//log_error(cmd);
			break;
		}
	}
	pclose(pf);
	if (bFlag)
	{
		return 0;
	}
	return 1;
}

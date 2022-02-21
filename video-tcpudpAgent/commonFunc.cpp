#include "commonFunc.h"

#include "commonDefine.h"
#include "log.h"
#include <iconv.h>
#include <openssl/md5.h>
#include "mysqlImpl.h"
#include <string> 
static const char *b64alpha =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
#define B64PAD '='
extern SvideoInfo gVideoInfo;
extern int bidrect_status;
extern SzkxaInfo gZkxaInfo;
extern int glogSwitch;


std::string strToHex(std::string str, std::string separator = "")
{
	const std::string hex = "0123456789ABCDEF";
	std::stringstream ss;

	for (std::string::size_type i = 0; i < str.size(); ++i)
		ss << hex[(unsigned char)str[i] >> 4] << hex[(unsigned char)str[i] & 0xf] << separator;

	return ss.str();
}
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


void getDatas(const char *buf, const char *find_str,char *retDatas)
{
	log_debug_fmt("buf :%s",buf);
	const char *pFind = strstr(buf,find_str);
	if(pFind == NULL)
		return;
	
	pFind += strlen(find_str) + 1;
	const char *tail = strchr(pFind,'"');
	strncpy(retDatas,pFind,tail - pFind);
	log_debug_fmt("uri :%s",retDatas);
	return;
}

void md5Handle(const char *md5_str, int len, unsigned char *md5_ret_value)
{
	// log_debug_fmt("hash str %s",md5_str);
	MD5_CTX ctx;
	MD5_Init(&ctx);
	MD5_Update(&ctx, (unsigned char *)md5_str, len);
	MD5_Final(md5_ret_value, &ctx);
}

void hexToString(unsigned char *hex_buf, char *str_buf)
{
	char tmp[3] = {0};
	for(int i = 0; i < 16; i++)
	{
		sprintf(tmp,"%02x",hex_buf[i]);
		strcat(str_buf,tmp);
	}
	return;
}


void modifyIp(char *line, char *init_ip,char *modify_ip,int modify_port,char *modify_buf,int option)
{
	string tmp;
	char data[512] = { 0 };
	char int_to_str[16]= {0};
	char response[64] = {0};

	char *pFind = strstr(line,init_ip);
	strncpy(data, line, pFind - line);
	tmp.append(data);   
	tmp.append(modify_ip);  
	pFind += strlen(init_ip);	
	if(*pFind == ':')
	{
		++pFind;
		while(*pFind <= '9' && *pFind >= '0')
		{
			++pFind;
		}
		tmp.append(":");
		sprintf(int_to_str,"%d",modify_port);
		tmp.append(int_to_str);
		if(option == AUTHENTICATION && strstr(line,"Authorization"))
		{
			pFind += 2; // 找到response 下一个逗号后面数据 
			tmp.append("\",");
			log_debug_fmt("authen datas :%s",tmp.c_str());
			Authentication(tmp.c_str(),response);
			char *tail = strstr(line,"response");
			tail = tail + strlen("response=") + 1;
			char tmp_data[64] = {0};
			strncpy(tmp_data,pFind,tail-pFind);
			tmp.append(tmp_data);
			tmp.append(response);
			tmp.append("\"");
			pFind = strchr(pFind,',');
			log_debug_fmt("Authentication response :%s",response);
		}
		tmp.append(pFind);
	}
	else {
		tmp.append(pFind);
	}

	strcat(modify_buf, tmp.c_str());
	//string b = strToHex(tmp);
	//if (strstr(line, "\r\n") && !strstr(tmp.c_str(), "\r\n")) {
	//	strcat(modify_buf, tmp.c_str());
	//	strcat(modify_buf, "\r\n");
	//}
	//else {
	//	strcat(modify_buf, tmp.c_str());
	//}
	
}

void modifyBuf(char* buf, char* modify_buf, int option, bool write_log)
{
	char* head = buf;
	char* tail;
	//strcpy(gVideoInfo.inIp, "13.22.11.235");
	//strcpy(gVideoInfo.outIp, "172.168.0.252");

	//20220113 04:33 : 54 commonFunc.cpp : 175[DEGUG] 13.22.11.253  172.168.0.252   13.22.11.235  172.168.0.252   (null)
	//log_debug_fmt("%s  %s   %s  %s   ",gVideoInfo.inetMediaIp,gVideoInfo.onetMediaIp,gVideoInfo.inIp,gVideoInfo.outIp);
	char modify_buf_one[MAX_BUFLEN] = { 0 };
	while ((tail = strstr(head, "\r\n")))
	{
		tail += strlen("\r\n");
		char line[1024] = { 0 };
		strncpy(line, head, tail - head);
		head = tail;
		if (strstr(line, "IN IP4"))
		{
			char* pTmp = strstr(line, "IN IP4");
			strncat(modify_buf_one, line, pTmp + strlen("IN IP4 ") - line);
			if (gZkxaInfo.chType == 'T')
				strcat(modify_buf_one, gVideoInfo.inIp);
			else
				strcat(modify_buf_one, gVideoInfo.outIp);
			strcat(modify_buf_one, "\r\n");
			continue;
		}
		if (gZkxaInfo.chType == 'U')
		{
			if (strstr(line, gVideoInfo.inIp))
			{
				modifyIp(line, gVideoInfo.inIp, gVideoInfo.onetMediaIp, gVideoInfo.onetMediaPort, modify_buf_one, option);
				continue;
			}

			if (strstr(line, gVideoInfo.inetMediaIp))
			{
				modifyIp(line, gVideoInfo.inetMediaIp, gVideoInfo.outIp, gVideoInfo.outPort, modify_buf_one, option);
				continue;
			}
		}
		else
		{
			if (strstr(line, gVideoInfo.outIp))
			{
				modifyIp(line, gVideoInfo.outIp, gVideoInfo.inetMediaIp, gVideoInfo.inetMediaPort, modify_buf_one, option);
				continue;
			}
			//if (strstr(line, "172.168.0.253"))
			//{
			//	log_debug_fmt("here outIp:%s", gVideoInfo.outIp);
			//	modifyIp(line, "172.168.0.253", "13.22.11.121", gVideoInfo.inetMediaPort, modify_buf_one, option);
			//	continue;
			//}
			if (strstr(line, gVideoInfo.onetMediaIp))
			{
				modifyIp(line, gVideoInfo.onetMediaIp, gVideoInfo.inIp, gVideoInfo.inPort, modify_buf_one, option);
				continue;
			}
		}
		strcat(modify_buf_one, line);
	}
	if (option == OTHER_PKTS)
		strcat(modify_buf_one, head);
	char* pTmp;
	if ((pTmp = strstr(modify_buf_one, "Content-Length: "))) {
		char lenth[512] = { 0 };
		pTmp += strlen("Content-Length: ");
		strncat(modify_buf, modify_buf_one, pTmp - modify_buf_one);
		tail = strstr(pTmp, "\r\n");
		if ((pTmp = strstr(modify_buf_one, "\r\n\r\n"))) {
			pTmp += strlen("\r\n\r\n");
			char buf[32];
			snprintf(buf, sizeof(buf), "%d", strlen(pTmp));
			strcat(modify_buf, buf);
			strcat(modify_buf, tail);
		}
		else {
			strcat(modify_buf, pTmp);
		}
	}
	else {
		strcat(modify_buf, modify_buf_one);
	}

	return;
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
	int iRet = epoll_ctl(iEpollfd, EPOLL_CTL_DEL, iaSocketFd, &sEpollEvent);
	log_error_fmt("iRet = [%d], error=[%d:%s]", iRet, errno, strerror(errno));

	return 0;
}

/**********************************************************************
函数名称: addSocketToEpoll
函数功能: 将SOCKET添加到事件列表
输入参数：
参数一: iEpollFd, epoll文件描述符
参数二: iSocketFd, socket
参数三: nProtocolType, 协议类型
返    回： 0表示成功
作    者: 赵翌渊
建立时间: 20210415
**********************************************************************/
int addSocketToEpoll(int iEpollFd, int iSocketFd, int nProtocolType)
{
	struct epoll_event sEpollEvent;
	sEpollEvent.data.fd = iSocketFd;
	sEpollEvent.events = EPOLLIN | EPOLLET;
	if (nProtocolType == 2)
	{
		sEpollEvent.events = EPOLLIN;
	}

	epoll_ctl(iEpollFd, EPOLL_CTL_ADD, iSocketFd, &sEpollEvent);
// 	log_debug_fmt("add epoll socket=[%d]", iSocketFd);
	return 0;
}

int modSocketToEpoll(int iEpollFd, int iSocketFd)
{
	struct epoll_event sEpollEvent;
	sEpollEvent.data.fd = iSocketFd;
	sEpollEvent.events = EPOLLIN | EPOLLET;
	epoll_ctl(iEpollFd, EPOLL_CTL_MOD, iSocketFd, &sEpollEvent);
	// 	log_debug_fmt("add epoll socket=[%d]", iSocketFd);
	return 0;
}

/**********************************************************************
函数名称: connectTcpServer
函数功能: tcp连接服务器
参    数：
第    一：（I）ip，服务器ip地址
第    二：（I）iPort，服务器端口
第    三：（I）iCount，连接失败重试次数
返    回： 大于0表示成功返回socket，0表示地址出错，-1表示连接失败
作    者: 赵翌渊
建立时间: 20200907
**********************************************************************/
int connectTcpServer(const char * ip, int iPort, int iCount)
{
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(iPort);
	inet_pton(AF_INET, ip, &addr.sin_addr);
	if (addr.sin_addr.s_addr == 0)
		return 0;
	
	int nCount = iCount;
	int iRet = 0;
	while (nCount)
	{
		int iSocket = socket(AF_INET, SOCK_STREAM, 0);
		iRet = connectTimeout(iSocket, (struct sockaddr *)(&addr), sizeof(struct sockaddr), 3);
		if (iRet == 0)
		{
			setNoblock(iSocket, 0);
			return iSocket;
		}
		close(iSocket);
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
	{
		setNoblock(sockfd, 0);
		return -1;
	}
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

/*按长度发送数据
* Function: sendDataOfLength
* Input:   sock: 发送socket
*			buf: 发送缓存
*			dataLength: 接收数据的长度
* Output:
* Result: 小于dataLength: 网络出错
*			返回dataLength正常
*/
int sendDataOfLength(int sock, const char* buf, int dataLength)
{
	int ret = send(sock, buf, dataLength, 0);
	if (ret == dataLength)
	{
		return ret;
	}
	if (ret < 0)
	{
		if (errno != EAGAIN)
		{
			return ret;
		}
		usleep(100);
		ret = 0;
	}
	int sendLen = dataLength - ret;
	int	pos = ret;
	while (sendLen > 0)
	{
		ret = send(sock, buf + pos, sendLen, 0);
		if (ret < 0)
		{
			if (errno == EAGAIN)
			{
				usleep(100);
				continue;
			}
			log_error_fmt("ret = %d pos=[%d], sendLen=[%d] %d:%s", ret, pos, sendLen, errno, strerror(errno));
			// 			return ret;
			return -1;
		}
		else if (ret == 0)
		{
			return 0;
		}
		sendLen -= ret;
		pos += ret;
	}
	return dataLength;
}

int is_valid_ipv4(const char * ipv4)
{
	struct in_addr addr;
	if (ipv4 == NULL)
		return -1;
	if (inet_pton(AF_INET, ipv4, (void*)&addr) == 1)
		return 0;
	return -1;
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
			log_debug_fmt("create socket error %d:%s", errno, strerror(errno));
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
		log_debug_fmt("bind ip=[%s], port=[%d]", pchIp, iaPort);
		/*调用bind绑定地址*/
		if (bind(iSocket, (struct sockaddr *)&serAddr4, sizeof(struct sockaddr)) == -1)
		{
// 			fprintf(stderr, "bind socket error[%d][%s]\n", errno, strerror(errno));
// 			COUT << "bind socket error[" << errno << "][" << strerror(errno) << "]" << endl;
			log_debug_fmt("bind socket error host=[%s:%d] %d:%s", pchIp, iaPort, errno, strerror(errno));
			close(iSocket);
			return -1;
		}

		/*调用listen开始监听*/
		if (listen(iSocket, MAX_LINKS) == -1)
		{
// 			fprintf(stderr, "listen socket error[%d][%s]\n", errno, strerror(errno));
// 			COUT << "listen socket error[" << errno << "][" << strerror(errno) << "]" << endl;
			log_debug_fmt("listen socket error %d:%s\n", errno, strerror(errno));
			close(iSocket);
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
函数名称: createUdpServer
函数功能: 创建udp服务socket
输入参数：
参数一：(I)iaPort, 服务端口
参数二：(I)pcaBindIp, 服务IP
输出参数:
返    回：小于0表示创建失败, 大于0为创建绑定成功的socket
作    者: 赵翌渊
建立时间: 202001010
**********************************************************************/
int createUdpServer(int iaPort, const char* pcaBindIp)
{
	struct sockaddr_in server;   /*服务器地址信息结构体*/
	int    iOpt;
	int    iSocket;

	/*建立socket*/
	iSocket = socket(AF_INET, SOCK_DGRAM, 0);
	if (iSocket == -1)
	{
		fprintf(stderr, "create socket error[%d][%s]\n", errno, strerror(errno));
		return -1;
	}

	/*设置socket属性*/
	setNoblock(iSocket, 1);
	iOpt = SO_REUSEADDR;
 
	struct timeval timeout = {10,0};
	// setsockopt(iSocket,SOL_SOCKET,SO_SNDTIMEO,(char *)&timeout,sizeof(struct timeval));
	setsockopt(iSocket,SOL_SOCKET,SO_RCVTIMEO,(char *)&timeout,sizeof(struct timeval));

	setsockopt(iSocket, SOL_SOCKET, SO_REUSEADDR, (char*)&iOpt, sizeof(iOpt));

	memset(&server, 0x00, sizeof(server));
	server.sin_family = AF_INET;
	server.sin_port = htons(iaPort);
	server.sin_addr.s_addr = inet_addr(pcaBindIp);

	/*调用bind绑定地址*/
	if (bind(iSocket, (struct sockaddr*)&server, sizeof(struct sockaddr)) == -1)
	{
		close(iSocket);
		fprintf(stderr, "bind socket error[%d][%s]ip[%s]port[%d]\n", errno, strerror(errno), pcaBindIp, iaPort);
		return -1;
	}
	log_debug_fmt("bind ip=[%s], port=[%d]", pcaBindIp, iaPort);
	return iSocket;
}

/**********************************************************************
函数名称: createUdpSocket
函数功能: 创建udp socket
输入参数：
输出参数:
返    回：小于0表示创建失败, 大于0为创建绑定成功的socket
作    者: 赵翌渊
建立时间: 202001012
**********************************************************************/
int createUdpSocket()
{
	struct sockaddr_in server;   /*服务器地址信息结构体*/
	int    iOpt;
	int    iSocket;

	/*建立socket*/
	iSocket = socket(AF_INET, SOCK_DGRAM, 0);
	if (iSocket == -1)
	{
		fprintf(stderr, "create socket error[%d][%s]\n", errno, strerror(errno));
		return -1;
	}

	/*设置socket属性*/
	setNoblock(iSocket, 1);
	iOpt = SO_REUSEADDR;
	setsockopt(iSocket, SOL_SOCKET, SO_REUSEADDR, (char*)&iOpt, sizeof(iOpt));

	log_debug_fmt("create udp socket=[%d]", iSocket);
	return iSocket;
}

/**********************************************************************
函数名称: sendtoToAddr
函数功能: 从地址发送数据
输入参数：
参数一：iSock, 发送数据的socket
参数二：data, 发送的数据
参数三：iLen, 发送数据的长度
参数四：szDestip, 发送数据的目的IP
参数五：port, 发送数据的目的端口
输出参数:
返    回：小于0表示发送失败，大于表示实际发送数据的长度
作    者: 赵翌渊
建立时间: 202001012
**********************************************************************/
int sendtoToAddr(int iSock, char *data, int iLen, const char *szDestip, int port, bool modify, int option)
{
	struct sockaddr_in sSvrAddr;
	memset(&sSvrAddr, 0x00, sizeof(sSvrAddr));
	sSvrAddr.sin_family = AF_INET;
	sSvrAddr.sin_port = htons(port);
	sSvrAddr.sin_addr.s_addr = inet_addr(szDestip);
	char modify_buf[MAX_BUFLEN]= {0};
	if (modify == true)
	{
		modifyBuf(data, modify_buf,option);
		writeLog(gVideoInfo, modify_buf, SEND, gZkxaInfo.chType == 'T'?true:false);
// 		log_debug_fmt("modify data :%s", modify_buf);
		return sendto(iSock, modify_buf, strlen(modify_buf), 0, (const sockaddr*)&sSvrAddr, sizeof(sSvrAddr));
	}
	return sendto(iSock, data, iLen, 0, (const sockaddr*)&sSvrAddr, sizeof(sSvrAddr));
}

/**********************************************************************
函数名称: sendtoToAddr
函数功能: 从地址发送数据
输入参数：
参数一：iSock, 发送数据的socket
参数二：data, 发送的数据
参数三：iLen, 发送数据的长度
参数四：soAddr, 发送数据的目的地址
输出参数:
返    回：小于0表示发送失败，大于表示实际发送数据的长度
作    者: 赵翌渊
建立时间: 202001111
**********************************************************************/
int sendtoToAddr(int iSock, const char* data, int iLen, sockaddr_in& soAddr)
{
	return sendto(iSock, data, iLen, 0, (const sockaddr*)&soAddr, sizeof(soAddr));
}

/**********************************************************************
函数名称: getLocalRemoteIP
函数功能: 根据socket获取本地IP和端口，远程地址
输入参数：
参数一：(I)iSock, socket
输出参数:
参数一：(O)szLocalIp, 本地IP
参数二：(O)iLocalPort, 本地端口
参数三：(O)szRemoteIp, 远程IP
参数四：(O)iRemotePort, 远程端口
返    回：0表示成功
作    者: 赵翌渊
建立时间: 20200925
**********************************************************************/
int getLocalRemoteIP(int iSock, char* szLocalIp, int& iLocalPort, char* szRemoteIp, int & iRemotePort)
{
	struct sockaddr local_addr;
	socklen_t len = sizeof(sockaddr);
	if (getsockname(iSock, &local_addr, &len) == 0) {
		struct sockaddr_in* sin = (struct sockaddr_in*)(&local_addr);
		iLocalPort = ntohs(sin->sin_port);
		void* tmp = &(sin->sin_addr);
		if (inet_ntop(AF_INET, tmp, szLocalIp, INET_ADDRSTRLEN) == NULL) {
			cerr << "inet_ntop err";
			return false;
		}
		return true;
	}
	else {
		cerr << "getsockname err";
		return false;
	}
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
入口参数：
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

	FILE *log_cfg = fopen("/srv/zkxaAgent/etc/zkxaAgent.mlog","r");
	char buf[512]={0};
	char *head;
	while(fgets(buf,512,log_cfg) != NULL)
	{
		if((head =strstr(buf,"level")))
		{
			if((head = strstr(buf,"=")) != NULL)
				glogSwitch = atoi(head +1);
		}
	}
		logInit(logFile);
	}
	int nError = 0;
	if (fd < 0)
	{
		nError = errno;
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

/********************************************************
函数名称：getMd5OfString
函数功能：获取字符串的md5值
参    数：
第    一：（I）szData, 原字符串
第    二: (O) szResult, 返回的md5
返    回：0成功
作    者: 赵翌渊
创建时间：20200817
*********************************************************/
int getMd5OfString(const char * szData, char * szResult)
{
	unsigned char outmd[16];
	char tmp[3];
	memset(outmd, 0, sizeof(outmd));
	MD5_CTX ctx;
	MD5_Init(&ctx);
	MD5_Update(&ctx, szData, strlen(szData));
	MD5_Final(outmd, &ctx);
	for (int i = 0; i < 16; i < i++)
	{
		sprintf(tmp, "%02x", outmd[i]);
		strcat(szResult, tmp);
	}
	return 0;
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

uint32_t getIpToUint(const char * ip)
{
	struct in_addr tmpAddr;
	int nRet = inet_pton(AF_INET, ip, (void *)&tmpAddr);
	if(nRet == 1)
		return tmpAddr.s_addr;
	return 0; //出错返回0
}

void getIpToString(uint32_t ip, char* strIp)
{
	char str[512] = { 0 };
	inet_ntop(AF_INET, &ip, str, sizeof(str));
	strcpy(strIp, str);
}

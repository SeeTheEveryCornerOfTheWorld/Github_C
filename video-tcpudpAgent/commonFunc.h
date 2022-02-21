#ifndef _COMMONFUNC_H_
#define _COMMONFUNC_H_

#include "commonHead.h"
#include "commonDefine.h"
#include "UdpVideo.h"

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
int splitUserHost(const char *str, char *orig_msg, size_t orig_msg_size, char *host, size_t host_size);

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
int setNoblock(int sockfd, int mode);

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
int getIpFromDomain(const char * pchDomain, char * pchIp);
int createUdpServer_1(int iaPort, const char* pcaBindIp);

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
int delSocketFromEpoll(int iEpollfd, int iaSocketFd);

/**********************************************************************
函数名称: addSocketToEpoll
函数功能: 将SOCKET添加到事件列表
输入参数：
参数一: iEpollFd, epoll文件描述符
参数二: iSocketFd, socket
参数三: nProtocolType, 协议类型, 1为TCP, 2为UDP
返    回： 0表示成功
作    者: 赵翌渊
建立时间: 20210415
**********************************************************************/
int addSocketToEpoll(int iEpollFd, int iSocketFd, int nProtocolType=1);

int modSocketToEpoll(int iEpollFd, int iSocketFd);

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
int connectTimeout(int sockfd, const struct sockaddr *serv_addr, socklen_t addrlen, int timeout);

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
int connectTcpServer(const char* ip, int iPort, int iCount);

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
int createUdpServer(int iaPort, const char* pcaBindIp);

/**********************************************************************
函数名称: createTcpServer
函数功能: 创建SOCKET
参    数：
第    一：(I)iaPort,端口
第    二：(I)pchIp, ip地址
返    回： 大于0表示成功返回socket，0表示地址出错，-1表示连接失败
作    者: 李高文
建立时间: 20200313
**********************************************************************/
int createTcpServer(int iaPort, const char * pchIp);

/**********************************************************************
函数名称: createUdpSocket
函数功能: 创建udp socket
输入参数：
输出参数:
返    回：小于0表示创建失败, 大于0为创建绑定成功的socket
作    者: 赵翌渊
建立时间: 202001012
**********************************************************************/
int createUdpSocket();

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
int sendtoToAddr(int iSock, char * data, int iLen, const char * szDestip, int port, bool modify = false,int option = 0);

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
int sendtoToAddr(int iSock, const char* data, int iLen, sockaddr_in &soAddr);

/*按长度发送数据
* Function: sendDataOfLength
* Input:   sock: 发送socket
*			buf: 发送缓存
*			dataLength: 接收数据的长度
* Output:
* Result: 小于dataLength: 网络出错
*			返回dataLength正常
*/
int sendDataOfLength(int sock, const char* buf, int dataLength);

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
int getLocalRemoteIP(int iSock, char* szLocalIp, int& iLocalPort, char* szRemoteIp, int& iRemotePort);

/********************************************************
函数名称：AllTrim
函数功能：去掉头尾空格
入口参数：
第    一：字符串     I
返    回：1表示该字符为空格，0表示不是
创建时间：20200219
*********************************************************/
char *AllTrim(char *pcaStr);

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
int b64decode(const unsigned char *in, int len, char *out);

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
int b64encode(const unsigned char *in, int len, char * out);

/********************************************************
函数名称：enterDaemon
函数功能：进入后台
入口参数：
返    回：0表示成功，-1表示创建进程失败
作    者: 赵翌渊
创建时间：20200219
*********************************************************/
int enterDaemon(int isEnterBack, const char * logFile);

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
int isAddrParagraph(sockaddr_in & addr, const char * addrStart, const char * addrEnd);

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
int findAddrInList(sockaddr_in & addr, const char * addrList);


/********************************************************
函数名称：isFind
函数功能：检查字符串中是否有过滤条件，如邮箱zhaoyyyy@163.com，过滤条件为"163.com,qq.com"，则返回0
参    数：
第    一：（I）buf, 待查字符串
第    二：（I）filter, 过滤条件
第    三：（I）separator, 过滤条件的分隔符
返    回：0为成功,-1为失败
作    者: 赵翌渊
创建时间：20200426
*********************************************************/
int isFind(const char * buf, const char * filter, int separator);

/********************************************************
函数名称：getFileSize
函数功能：获取文件的大小
参    数：
第    一：（I）pFilePath, 文件路径
返    回：文件的长度，大于等于0为成功，小于0则失败
作    者: 赵翌渊
创建时间：20200427
*********************************************************/
long getFileSize(const char * pFilePath);

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
int getMd5OfString(const char * szData, char * szResult);

//字符串编码转换
int code_convert(const char *from_charset, const char *to_charset, char *inbuf,
	size_t inlen, char *outbuf, size_t outlen);
//utf-8转gb2312
int u2g(char *inbuf, int inlen, char *outbuf, int outlen);
//gb2312转utf-8
int g2u(char *inbuf, size_t inlen, char *outbuf, size_t outlen);

//反向比较
int strrncmp(const char * s1, const char * s2, int n);
//反向比较不区分大小写
int strrncasecmp(const char * s1, const char * s2, int n);

//获取当前应用路径
int getPath(char * path);

uint32_t getIpToUint(const char * ip);
void getIpToString(uint32_t ip, char* strIp);

//判断是否合法IP
int IsValidIp(const char* pchIp);

void getDatas(const char *buf, const char *find_str,char *retDatas);

void md5Handle(const char *md5_str, int len, unsigned char *md5_ret_value);

void hexToString(unsigned char *hex_buf, char *str_buf);

void modifyBuf(char *buf, char *modify_buf,int option,bool writeLog = false);

void modifyIp(char *line, char *init_ip,char *modify_ip,int modify_port,char *modify_buf,int option);


#endif


#ifndef _COMMONFUNC_H_
#define _COMMONFUNC_H_

#include "commonHead.h"
#include "commonDefine.h"

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
参    数：
第    一：（I）EPOLL FD
第    二：（I）socket
返    回： 0表示成功
作    者: 赵翌渊
建立时间: 20200403
**********************************************************************/
int addSocketToEpoll(int iEpollFd, int iSocketFd);

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

/*按长度接收数据
* Function: recvDataOfLength
* Input:   sock: 接收socket
*			buf: 接收缓存
*			dataLength: 接收数据的长度
* Output:
* Result: 小于dataLength: 网络出错
*			返回dataLength正常
*/
int recvDataOfLength(int sock, char* buf, int dataLength);

//=0  timeout ; <0 connect error  ; >1  connect ok
int opensock_timeout(char *ip_addr, int port, int timeout);

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
int connectTcpServer(const char * ip, int iPort);

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
参    数：
第    一：（I）isEnterBack, 是否进入后台
第    二：（I）logFile, 日志文件
返    回：0表示成功，-1表示创建进程失败
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
int getNetworkAddr(char* ip, char* mask);

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
int get_ifdev_statu(const char* ifname);

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
int ifdev_offline(const char* ifname);

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

//去除首尾空格
char *trim(char *str);

//是否有效ipv4地址
//返回0表示地址有效
int is_valid_ipv4(const char * ipv4);

//地址从整形转字符串
const char* getIpFromInt(int nip, char* szIp, int nAddrLen);

//地址从字符串转整形
uint32_t getIpFromStr(const char* szIp);

//返回命令结果
int getCmdResult(const char * szCmd);

int  write_file(const char* filename, int val);

// const char * getIpFromStr(int nip, char * szIp);

int cmdHandle(const char* cmd, const char* param);

#endif


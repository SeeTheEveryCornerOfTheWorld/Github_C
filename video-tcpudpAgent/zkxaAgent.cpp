#include <iostream>
#include <map>
#include <set>
#include <queue>
#include <chrono>
#include <string>
#include <thread>
using namespace std;

#include "commonHead.h"
#include "commonDefine.h"
#include "commonFunc.h"
#include "log.h"
#include "mysqlImpl.h"
#include "UdpVideo.h"
#include "xmlOperate.h"
#include "ipc.h"
#include <openssl/md5.h>

#define ZKXAAGENT_VERSION "视频交换3.0-20211008-001"


SzkxaInfo gZkxaInfo;	//配置信息、数据库信息、内部通讯信息等

SvideoInfo gVideoInfo;
SvideoInfo gVideoInfos[64];

extern int glogSwitch;

unsigned int guiFlowStatistics = 0;

extern std::string gstrDBServerIp; //数据库IP
extern int giDBServerPort;			//数据库端口
extern std::string gstrDBUser;		//数据库用户名称
extern std::string gstrDBPass;		//数据库用户密码
extern std::string gstrDBName;		//数据库名

int gEpollfd;

event ev_udp_forward, ev_udp_reverse, ev_inet_forward, ev_inet_reverse;
event ev_video_udp, ev_video_inet;
map<int, long> gmapSockToTime;
std::map<std::string, int> gmapAddrToSock; //地址到socket的映射

map<int, sockaddr_in> gmapSockVideo;	//

static struct timeval TIMER_TV = { 30, 0 };
static struct timeval FLOW_TV = { 3, 0 };

map<string, UdpVideoStream> gmapCallidToVideoStream;
map<int,UdpVideoStream> gmapSockToVideoStream;
map<int,int> gmapSrcsockToDstsock;
map<int,int> gmapLocalsockToExchangesock;
map<int,int> gmapExchangesockToLocalsock;
map<int,int> gmapSockToRtcpPort;
set<int> gsetEventSocks;				//事件集
pthread_mutex_t gMutexSetevent = PTHREAD_MUTEX_INITIALIZER;	//事件集锁

static void inet_forward(const int sock, short int which, void* arg);


void handle(int arg)
{
	log_debug_fmt("sigpipe");
}


int lock_file(int fd)
{
	struct flock fl;

	fl.l_type = F_WRLCK;
	fl.l_start = 0;
	fl.l_whence = SEEK_SET;
	fl.l_len = 0;

	return(fcntl(fd, F_SETLK, &fl));   //F_SETLK在指定的字节范围获取锁
}



bool accept_request(char *buf)
{
	if (gVideoInfo.direct == OUT_TO_IN && gZkxaInfo.chType != 'U')
	{
		writeLog(gVideoInfo, buf, REJECT, gZkxaInfo.chType == 'T'?true:false);
		return false;
	}
	if (gVideoInfo.direct == IN_TO_OUT && gZkxaInfo.chType != 'T')
	{
		writeLog(gVideoInfo, buf, REJECT, gZkxaInfo.chType == 'T'?true:false);
		return false;
	}
	return true;
}

//判断进程是否正在运行
int already_running()
{
	int					fd;
	char			buf[16];

#define LOCKMODE					(S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH)
	char szPidPath[512] = { 0 };
	switch (gZkxaInfo.eServiceType)
	{
	case TYPE_TCP:
		snprintf(szPidPath, 512, PIDFILE, "tcp");
		break;
	case TYPE_UDP:
		snprintf(szPidPath, 512, PIDFILE, "udp");
		break;
	default:
		break;
	}
	
	fd = open(szPidPath, O_RDWR | O_CREAT, LOCKMODE);
	if (fd < 0)
	{
		log_error_fmt( "can't open szPidPath[%s] [%d:%s]", szPidPath, errno, strerror(errno));
		exit(1);
	}
	// 锁住pid文件
	if (lock_file(fd) < 0)
	{
		if (errno == EACCES || errno == EAGAIN)
		{
			close(fd);
			return 1;
		}
		//syslog(LOG_ERR, "can't lock %s: %s", lock_file, strerror(errno));
		exit(1);
	}
	// 初始化文件并写入进程pid
	ftruncate(fd, 0);
	sprintf(buf, "%ld", (long)getpid());
	write(fd, buf, strlen(buf) + 1);
	return 0;

}


void video_rtcp_handle(UdpVideoStream  udpVideoObj_)
{
	int nEpollfd = epoll_create(MAX_LINKS);
	struct epoll_event epollEvent[MAX_LINKS];
	int dstSock = 0;
	int srcSock;
	int iRet;
	char buf[MAX_BUFLEN];
	struct sockaddr_in sSvrAddr,clientaddr;
	socklen_t addrlen = sizeof(clientaddr);
	memset(&sSvrAddr, 0x00, sizeof(sSvrAddr));
	sSvrAddr.sin_family = AF_INET;
	UdpVideoStream  udpVideoObj;
	while(true)
	{
		for(auto &it:gmapCallidToVideoStream)
		{
		    udpVideoObj = it.second;
			if(udpVideoObj.rtcp_call_status != 1)
			{
				continue;
			}
			else
			{
				it.second.rtcp_call_status = 2;
				string local_ip = udpVideoObj.local_ip;
				string exchange_ip = udpVideoObj.exchange_ip;
				int low_rtcp_port, up_rtcp_port;
				if (udpVideoObj.upper_or_lower == UPPER)
				{
					low_rtcp_port = udpVideoObj.low_rtcp_port;
					up_rtcp_port = udpVideoObj.up_rtcp_port;
				}
				else
				{
					low_rtcp_port = udpVideoObj.up_rtcp_port;
					up_rtcp_port = udpVideoObj.low_rtcp_port;
				}
				
				int local_rtcp_sock = createUdpServer(low_rtcp_port, local_ip.c_str());
				int exchange_rtcp_sock = createUdpServer(up_rtcp_port, exchange_ip.c_str());
				log_debug_fmt("rtcp low_rtcp_port=[%d],up_rtcp_port=[%d]", udpVideoObj.low_rtcp_port, udpVideoObj.up_rtcp_port);

			// 	sSvrAddr.sin_port = htons(rtcp_port);

				addSocketToEpoll(nEpollfd, local_rtcp_sock,2);
				addSocketToEpoll(nEpollfd, exchange_rtcp_sock,2);
				gmapLocalsockToExchangesock[local_rtcp_sock] = exchange_rtcp_sock;
				gmapExchangesockToLocalsock[exchange_rtcp_sock] = local_rtcp_sock;
				gmapSockToVideoStream[local_rtcp_sock] = udpVideoObj;
				gmapSockToVideoStream[exchange_rtcp_sock] = udpVideoObj;
				gmapSockToRtcpPort[local_rtcp_sock] = low_rtcp_port;
				gmapSockToRtcpPort[exchange_rtcp_sock] = up_rtcp_port;
			}
		}
		int i;
		int sRet;
		sRet = epoll_wait(nEpollfd, epollEvent, MAX_LINKS, 1);		
		for(i=0; i<sRet; i++)
		{
			memset(buf,0,sizeof(buf));
			udpVideoObj = gmapSockToVideoStream[epollEvent[i].data.fd];
			// if(epollEvent[i].data.fd == local_rtcp_sock)
			if(gmapLocalsockToExchangesock.find(epollEvent[i].data.fd) != gmapLocalsockToExchangesock.end())
			{
				srcSock = epollEvent[i].data.fd;
				sSvrAddr.sin_addr.s_addr = inet_addr(udpVideoObj.exchange_peer_ip.c_str());
				sSvrAddr.sin_port = htons(gmapSockToRtcpPort[srcSock]);
				dstSock = gmapLocalsockToExchangesock[srcSock];
			}
			else if(gmapExchangesockToLocalsock.find(epollEvent[i].data.fd) != gmapExchangesockToLocalsock.end())
			{
				srcSock = epollEvent[i].data.fd;
				sSvrAddr.sin_addr.s_addr = inet_addr(udpVideoObj.video_ip.c_str());
				sSvrAddr.sin_port = htons(gmapSockToRtcpPort[srcSock]);
				dstSock = gmapExchangesockToLocalsock[srcSock];
			}

			if ((iRet = recvfrom(srcSock, buf, DATA_PACK_LEN, 0, (sockaddr*)&clientaddr, &addrlen)) <= 0)
			{
				if (errno == EAGAIN)
				{
					continue;
				}
				log_debug_fmt("sock:[%d], error:[%d:%s]", srcSock, errno, strerror(errno));
				delSocketFromEpoll(gEpollfd, srcSock);
				close(srcSock);
				continue;
// 				goto EXITWHILE;
			}
// 			log_debug_fmt("rtcp buf=[%d:%s]", iRet, buf);
			// log_debug_fmt("video_recv_handle sock:%s   recv datas len :%d[dst_port:%d]",srcSock == local_ip_sock?"local_ip_sock":"exchange_ip_sock",iRet,dst_port);
			if(sendto(dstSock, buf, iRet, 0, (const sockaddr*)&sSvrAddr, sizeof(sSvrAddr)) <=0)
			{
				// log_debug_fmt("sendto datas error %s",strerror(errno));
				delSocketFromEpoll(nEpollfd, srcSock);
				delSocketFromEpoll(nEpollfd, dstSock);
				close(srcSock);
				close(dstSock);
// 			    return;
				// goto EXITWHILE;
			}
		}
		
	}

EXITWHILE:
	// log_debug_fmt("rtcp close low_rtcp_port=[%d], up_rtcp_port=[%d]", low_rtcp_port, up_rtcp_port);
	// delSocketFromEpoll(nEpollfd, local_rtcp_sock);
	// delSocketFromEpoll(nEpollfd, exchange_rtcp_sock);
	// iRet = close(local_rtcp_sock);
	// if (iRet < 0)
	// {
	// 	log_debug_fmt("rtcp close local_rtcp_sock=[%d] error:[%d:%s]", local_rtcp_sock, errno, strerror(errno));
	// }
	// iRet = close(exchange_rtcp_sock);
	// if (iRet < 0)
	// {
	// 	log_debug_fmt("rtcp close exchange_rtcp_sock=[%d] error:[%d:%s]", exchange_rtcp_sock, errno, strerror(errno));
	// }
	close(nEpollfd);
}

int buf_handle(UdpVideoStream  udpVideoObj,int srcSock,int dstSock)
{
	char buf[DATA_PACK_LEN] = {0};
	struct sockaddr_in clientaddr,srvaddr;
	socklen_t addrlen = sizeof(clientaddr);
	memset(&srvaddr, 0x00, sizeof(clientaddr));
	srvaddr.sin_family = AF_INET;
	
	int iRet = 0;
	int sock_close = 0;
	if(udpVideoObj.upper_or_lower == UPPER)
	{
		srvaddr.sin_port = htons(udpVideoObj.up_rtp_port);
		srvaddr.sin_addr.s_addr = inet_addr(udpVideoObj.video_ip.c_str());
		while(true)
		{
			iRet = recvfrom(srcSock, buf, DATA_PACK_LEN, 0, (sockaddr*)&clientaddr, &addrlen);
			if(iRet < 0)
			{
				if(errno == EAGAIN)
					continue;
				break;
			}
// 			log_debug_fmt("zyy buf=[%d:%s]", iRet, buf);
			// log_debug_fmt("recv rtp datas[%d] dstip:%s  port:%d,dstssock  %d",iRet,udpVideoObj.video_ip.c_str(),udpVideoObj.rtp_port,dstSock);
			if(udpVideoObj.rtp_is_tcp_or_udp == TYPE_TCP)
			{
				if(send(dstSock,buf,iRet,0) < 0)
				{
					log_debug_fmt("send error %s",strerror(errno));
					sock_close = 1;
					break;
				}
			}	
			else
			{
				sendto(dstSock, buf, iRet, 0, (const sockaddr*)&srvaddr, sizeof(srvaddr));
				return 0;
			}
		}
	}
	else
	{
		srvaddr.sin_port = htons(udpVideoObj.up_rtp_port);
		srvaddr.sin_addr.s_addr = inet_addr(udpVideoObj.exchange_peer_ip.c_str());
		while(true)
		{
			if(udpVideoObj.rtp_is_tcp_or_udp == TYPE_TCP)
			{
				iRet = recv(srcSock,buf,DATA_PACK_LEN,0);
				log_debug_fmt("lower iret =%d",iRet);
			}
			else
				iRet = recvfrom(srcSock, buf, DATA_PACK_LEN, 0, (sockaddr*)&clientaddr, &addrlen);
			if(iRet <= 0)
			{
				if(errno == EAGAIN)
					continue;
				break;
			}
// 			log_debug_fmt("zyy sendto:[%s:%d] buf=[%d:%s]", udpVideoObj.exchange_peer_ip.c_str(), udpVideoObj.up_rtp_port, iRet, buf);
			// log_debug_fmt("recv rtp datas[%d] dstip:%s  port:%d,dstssock  %d",iRet,udpVideoObj.exchange_peer_ip.c_str(),udpVideoObj.rtp_port,dstSock);
			sendto(dstSock, buf, iRet, 0, (const sockaddr*)&srvaddr, sizeof(srvaddr));
			if(udpVideoObj.rtp_is_tcp_or_udp == TYPE_UDP)
				return 0;
		}
	}
	log_debug_fmt("close srcsock:%d  dstsock:%d upper_sock_close:%d",srcSock,dstSock,sock_close);
	return sock_close;
}


void video_rtp_handle(UdpVideoStream  udpVideoObj_)
{
	UdpVideoStream  udpVideoObj;
	int nEpollfd = epoll_create(MAX_LINKS);
	int srcSock,dstSock,exchangeSock;
	int eRet = 0;
	char buf[MAX_BUFLEN];
	struct epoll_event epollEvent[MAX_LINKS];
	struct sockaddr_in bind_addr;
	memset(&bind_addr, 0x00, sizeof(bind_addr));
	log_debug_fmt("enter video_rtp_handle");
	while(true)
	{
		for(auto &it:gmapCallidToVideoStream)
		{
			udpVideoObj = it.second;
			// log_debug_fmt("rtpstatus:%d   rtcpstatus:%d  upport:%d    lowport:%d",udpVideoObj.rtp_call_status,udpVideoObj.rtcp_call_status,udpVideoObj.up_rtp_port,udpVideoObj.low_rtp_port);
			if(udpVideoObj.rtp_call_status != 1)
			{
				continue;
			}
			else
			{
				it.second.rtp_call_status = 2;
				bind_addr.sin_family = AF_INET;
				bind_addr.sin_addr.s_addr = inet_addr(udpVideoObj.local_ip.c_str());
				// log_debug_fmt("zyy upper_or_lower=[%d], up_rtp_port=[%d], low_rtp_port=[%d]", udpVideoObj.upper_or_lower, udpVideoObj.up_rtp_port, udpVideoObj.low_rtp_port);
				if(udpVideoObj.upper_or_lower == LOWER)
				{
					if(udpVideoObj.rtp_is_tcp_or_udp == TYPE_UDP)
						srcSock = createUdpServer(udpVideoObj.up_rtp_port,udpVideoObj.local_ip.c_str());
					else
					{
						if((srcSock = (connectTcpServer(udpVideoObj.video_ip.c_str(),udpVideoObj.up_rtp_port,3))) < 0)
						{
							log_debug_fmt("connect error %s",strerror(errno));
							return;
						}
					}
					dstSock = socket(AF_INET, SOCK_DGRAM, 0);
					bind_addr.sin_port = htons(udpVideoObj.low_rtp_port);
					bind_addr.sin_addr.s_addr = inet_addr(udpVideoObj.exchange_ip.c_str());
					bind(dstSock, (struct sockaddr*)&bind_addr, sizeof(struct sockaddr));
				}
				else
				{
					// log_debug_fmt("zyy up_rtp_port=[%d], exchange_ip=[%s]", udpVideoObj.up_rtp_port, udpVideoObj.exchange_ip.c_str());
					srcSock = createUdpServer(udpVideoObj.up_rtp_port,udpVideoObj.exchange_ip.c_str());
					if(udpVideoObj.rtp_is_tcp_or_udp == TYPE_TCP)
					{
						srcSock = createTcpServer(udpVideoObj.up_rtp_port,udpVideoObj.local_ip.c_str());
			// 			addSocketToEpoll(nEpollfd,exchangeSock,2);
					}
					else
					{
			// 			srcSock = exchangeSock;
						dstSock = socket(AF_INET, SOCK_DGRAM, 0);
						bind_addr.sin_port = htons(udpVideoObj.low_rtp_port);
						log_debug_fmt("zyy low_rtp_port=[%d]", udpVideoObj.low_rtp_port);
						bind(dstSock, (struct sockaddr*)&bind_addr, sizeof(struct sockaddr));
					}
				}
				addSocketToEpoll(nEpollfd,srcSock,2);
				gmapSockToVideoStream[srcSock] = udpVideoObj;
				gmapSrcsockToDstsock[srcSock] = dstSock;
			}
		}
		struct sockaddr_in clientaddr;
		socklen_t addrlen = sizeof(clientaddr);
		// map<string, UdpVideoStream>::iterator it;

		if((eRet = epoll_wait(nEpollfd,epollEvent,MAX_LINKS,5)) < 0)
		{
// 			log_debug_fmt("no epoll event");
			continue;
		}
// 		log_debug_fmt("zyy eRet=[%d]", eRet);
		for(int i=0; i<eRet; i++)
		{
// 			if(udpVideoObj.upper_or_lower == UPPER && udpVideoObj.rtp_is_tcp_or_udp == TYPE_TCP && epollEvent[i].data.fd == srcSock)
// 			{
// 				dstSock = accept(epollEvent[i].data.fd,(sockaddr*)&clientaddr, &addrlen);
// 				continue;
// 			}
// 			log_debug_fmt("zyy event fd=[%d], srcsock=[%d]", epollEvent[i].data.fd, srcSock);
			// if(epollEvent[i].data.fd == srcSock || udpVideoObj.rtp_is_tcp_or_udp == TYPE_TCP)
			{
				// log_debug_fmt("zyy recv event");
				if(buf_handle(gmapSockToVideoStream[epollEvent[i].data.fd],epollEvent[i].data.fd,gmapSrcsockToDstsock[epollEvent[i].data.fd]) == 1)
				{
// 					log_debug_fmt("close sock ,rtpport =%d",udpVideoObj.rtp_port);
					delSocketFromEpoll(nEpollfd,srcSock);
					delSocketFromEpoll(nEpollfd, dstSock);
					close(srcSock);
					close(dstSock);
// 					return;
					// goto EXITEPOLL;
				}
			}
		}
	}
	
EXITEPOLL:
	log_debug_fmt("zyy close socket up_rtp_port:[%d], low_rtp_port:[%d]", udpVideoObj.up_rtp_port, udpVideoObj.low_rtp_port);
	delSocketFromEpoll(nEpollfd, srcSock);
	delSocketFromEpoll(nEpollfd, dstSock);
	close(srcSock);
	close(dstSock);
	close(nEpollfd);
	return;
}

void getCallid(char* szBuf, string& strCallid)
{
	char* pTmp, * tail;
	if ((pTmp = strstr(szBuf, "Call-ID: ")))
	{
		char szCallid[512] = { 0 };
		char szTmpid[512] = { 0 };
		pTmp += strlen("Call-ID: ");
		tail = strstr(pTmp, "\r\n");
		strncpy(szCallid, pTmp, tail - pTmp);
		pTmp = szCallid;
		tail = strchr(pTmp, '@');
		if (NULL != tail)
		{
			strncpy(szTmpid, pTmp, tail - pTmp);
			strCallid = szTmpid;
			return;
		}

		strCallid = szCallid;
	}
}

static void udp_forward(const int sock, short int which, void *arg)
{
	UdpVideoStream udpVideoObj = *(UdpVideoStream *)arg;
	struct sockaddr_in clientaddr;
	socklen_t addrlen = sizeof(clientaddr);
	char buf[MAX_BUFLEN] = {0};
	int iRet = 0;
	memset(buf, 0, DATA_PACK_LEN);
	memset(&clientaddr, 0, sizeof(clientaddr));
	static int first_call = 0;
	if ((iRet = recvfrom(sock, buf, DATA_PACK_LEN, 0, (sockaddr*)&clientaddr, &addrlen)) < 0)
	{
		log_error_fmt("sock:[%d], error:[%d:%s]", sock, errno, strerror(errno));
		return;
	}	
	log_debug_fmt("udp_forward recvfrom buf=[%d:%s]", iRet, buf);
	if (strncmp(buf, "INVITE", 6) == 0)
	{
		if(accept_request(buf) == false)
			return;
		udpVideoObj.getRtpPort(buf,GETIP);
		udpVideoObj.upper_or_lower = UPPER;
		udpVideoObj.up_rtp_port = udpVideoObj.rtp_port;
		udpVideoObj.up_rtcp_port = udpVideoObj.rtp_port + 1;
		udpVideoObj.rtp_call_status = 0;
		udpVideoObj.rtcp_call_status = 0;
		getCallid(buf, udpVideoObj.strCallid);
		log_debug_fmt("zyy callid=[%s], rtp_port=[%d]", udpVideoObj.strCallid.c_str(), udpVideoObj.rtp_port);
		gmapCallidToVideoStream[udpVideoObj.strCallid] = udpVideoObj;
		writeLog(gVideoInfo, buf, RECV, gZkxaInfo.chType == 'T'?true:false);
	}
	if (strncmp(buf, "SIP/2.0 200 OK", strlen("SIP/2.0 200 OK")) == 0)
	{
		writeLog(gVideoInfo, buf, RECV, gZkxaInfo.chType == 'T'?true:false);
		if(udpVideoObj.getRtpPort(buf,GETIP) == -1)
		{
			sendtoToAddr(udpVideoObj.exchange_socket, buf, iRet, udpVideoObj.exchange_peer_ip.c_str(),udpVideoObj.invite_swap_port);
			return;
		}
		udpVideoObj.upper_or_lower = LOWER;
		getCallid(buf, udpVideoObj.strCallid);
		log_debug_fmt("zyy callid=[%s], ok_port=[%d]", udpVideoObj.strCallid.c_str(), udpVideoObj.rtp_port);
		udpVideoObj.rtcp_port = udpVideoObj.rtp_port + 1;
		map<string, UdpVideoStream>::iterator itFind = gmapCallidToVideoStream.find(udpVideoObj.strCallid);
		if (itFind != gmapCallidToVideoStream.end())
		{
			itFind->second.rtp_call_status = 1;
			itFind->second.rtcp_call_status = 1;
			UdpVideoStream& udpVideoTmp = itFind->second;
			udpVideoTmp.low_rtp_port = udpVideoObj.rtp_port;
			udpVideoTmp.low_rtcp_port = udpVideoObj.rtcp_port;
			if(first_call == 0)
			{
				first_call = 1;
				if (udpVideoObj.rtp_is_tcp_or_udp == TYPE_UDP)
				{
					thread t1(video_rtcp_handle, udpVideoTmp);
					t1.detach();
					thread t2(video_rtp_handle, udpVideoTmp);
					t2.detach();
				}
				else {
					thread t2(video_rtp_handle, udpVideoTmp);
					t2.detach();
				}
			}
		}
	}
	else if (strncmp(buf, "BYE sip:", strlen("BYE sip:")) == 0)
	{
		string strCallid;
		getCallid(buf, strCallid);
		gmapCallidToVideoStream.erase(strCallid.c_str());
	}
	log_debug_fmt("exchange_socket=[%d], exchange_peer_ip=[%s],port=[%d]", udpVideoObj.exchange_socket, udpVideoObj.exchange_peer_ip.c_str(),udpVideoObj.invite_swap_port);
	sendtoToAddr(udpVideoObj.exchange_socket, buf, iRet, udpVideoObj.exchange_peer_ip.c_str(),udpVideoObj.invite_swap_port);
	
	return;
}

static void inet_forward(const int sock, short int which, void* arg)
{
	UdpVideoStream udpVideoObj = *(UdpVideoStream*)arg;
	char buf[MAX_BUFLEN] = { 0 };
	int iRet = 0;
	struct sockaddr_in clientaddr;
	socklen_t server_sz = sizeof(clientaddr);
	static int first_call = 0;
	if ((iRet = recvfrom(sock, &buf, MAX_BUFLEN - 1, 0, (struct sockaddr*)&clientaddr, &server_sz)) == -1) {
		log_error_fmt("recvfrom() error:[%d:%s]", errno, strerror(errno));
		return;
	}

	log_debug_fmt("inet_forward recvfrom buf=[%d:%s]", iRet, buf);
	log_debug_fmt("medio_ip ip :%s  port:%d  sip_socket :%d",udpVideoObj.medio_ip.c_str(),udpVideoObj.media_port,udpVideoObj.sip_socket);
	if (strncmp(buf, "INVITE", 6) == 0)
	{
		udpVideoObj.getRtpPort(buf);
		getCallid(buf, udpVideoObj.strCallid);
		log_debug_fmt("zyy callid=[%s], rtp_port=[%d]", udpVideoObj.strCallid.c_str(), udpVideoObj.rtp_port);
		udpVideoObj.getRtpPort(buf);
		udpVideoObj.upper_or_lower = LOWER;
		udpVideoObj.up_rtp_port = udpVideoObj.rtp_port;
		udpVideoObj.up_rtcp_port = udpVideoObj.rtp_port + 1;
		udpVideoObj.rtp_call_status = 0;
		udpVideoObj.rtcp_call_status = 0;
		gmapCallidToVideoStream[udpVideoObj.strCallid] = udpVideoObj;
		sendtoToAddr(udpVideoObj.sip_socket, buf, strlen(buf), udpVideoObj.medio_ip.c_str(), udpVideoObj.media_port,MODIFY,SEND);
		return;
	}

	if (strncmp(buf, "SIP/2.0 200 OK", strlen("SIP/2.0 200 OK")) == 0)
	{
		if (udpVideoObj.getRtpPort(buf) == -1)
		{
			sendtoToAddr(udpVideoObj.sip_socket, buf, strlen(buf), udpVideoObj.medio_ip.c_str(), udpVideoObj.media_port, MODIFY, SEND);
			return;
		}
		getCallid(buf, udpVideoObj.strCallid);
		log_debug_fmt("zyy callid=[%s], ok_port=[%d]", udpVideoObj.strCallid.c_str(), udpVideoObj.rtp_port);
		udpVideoObj.rtcp_port = udpVideoObj.rtp_port + 1;
		map<string, UdpVideoStream>::iterator itFind = gmapCallidToVideoStream.find(udpVideoObj.strCallid);
		if (itFind != gmapCallidToVideoStream.end())
		{
			itFind->second.rtp_call_status = 1;
			itFind->second.rtcp_call_status = 1;
			UdpVideoStream& udpVideoTmp = itFind->second;
			udpVideoTmp.low_rtp_port = udpVideoObj.rtp_port;
			udpVideoTmp.low_rtcp_port = udpVideoObj.rtcp_port;
			if(first_call == 0)
			{
				first_call = 1;
				if (udpVideoObj.rtp_is_tcp_or_udp == TYPE_UDP)
				{
					thread t1(video_rtcp_handle, udpVideoTmp);
					t1.detach();
					thread t2(video_rtp_handle, udpVideoTmp);
					t2.detach();
				}
				else {
					udpVideoObj.upper_or_lower = UPPER;
					thread t2(video_rtp_handle, udpVideoTmp);
					t2.detach();
				}
			}
		}
		sendtoToAddr(udpVideoObj.sip_socket, buf, strlen(buf), udpVideoObj.medio_ip.c_str(), udpVideoObj.media_port,MODIFY,SEND);
		return;
	}
	else if (strncmp(buf, "BYE sip:", strlen("BYE sip:")) == 0)
	{
		string strCallid;
		getCallid(buf, strCallid);
		gmapCallidToVideoStream.erase(strCallid.c_str());
	}
	if (strncmp(buf, "REGISTER sip", strlen("REGISTER sip")) == 0 && strstr(buf, "response"))
	{
		sendtoToAddr(udpVideoObj.sip_socket, buf, strlen(buf), udpVideoObj.medio_ip.c_str(), udpVideoObj.media_port, 0,AUTHENTICATION);
		return;
	}
	sendtoToAddr(udpVideoObj.sip_socket, buf, strlen(buf), udpVideoObj.medio_ip.c_str(), udpVideoObj.media_port, MODIFY,OTHER_PKTS);      //来包
}
	

int main(int argc, char *argv[])
{
	if (argc < 2)
	{
		log_debug_fmt("使用: zkxaAgent [tcp|udp]");
		exit(0);
	}
	char szLogPath[512] = { 0 };
	snprintf(szLogPath, 512, LOG_FILE, argv[1]);
	enterDaemon(1, szLogPath);
	if (strcmp(argv[1], "tcp") == 0)
	{
		gZkxaInfo.eServiceType = TYPE_TCP;
	}
	else if (strcmp(argv[1], "udp") == 0)
	{
		gZkxaInfo.eServiceType = TYPE_UDP;
	}
	else
	{
		log_debug_fmt("使用: zkxaAgent [tcp|udp]");
		exit(0);
	}
	
	system("mkdir -p /srv/zkxaAgent/tmp/");
	if (already_running())
	{
		log_info_fmt("already runging.");
		exit(0);
	}

	signal(SIGPIPE, handle);

	log_info_fmt("zkxaagent server version=[%s]", ZKXAAGENT_VERSION);

	while (readBasicInfo(gZkxaInfo))
		sleep(3);

	int iRet;
	gstrDBServerIp = gZkxaInfo.strDbServerIp;
	giDBServerPort = gZkxaInfo.nDbServerPort;
	gstrDBUser = gZkxaInfo.strDbUser;
	gstrDBPass = gZkxaInfo.strDbPass;
	gstrDBName = gZkxaInfo.strDbName;

	while (true)
	{
		iRet = connectDb(gZkxaInfo.strDbServerIp.c_str(), gZkxaInfo.nDbServerPort, gZkxaInfo.strDbUser.c_str(), gZkxaInfo.strDbPass.c_str(), gZkxaInfo.strDbName.c_str());
		if (iRet < 0)
		{
			sleep(3);
			continue;
		}
		break;
	}
	{
		int task_counts = getVideoInfo(gVideoInfos);
		pid_t pid = getpid();
		for(int i = 0; i<task_counts; i++)
		{
			if(gVideoInfos[i].status == 0)
				continue;
			
			if(fork() > 0)
				continue;
			else
			{
				setsid();
				umask(0);
				gVideoInfo = gVideoInfos[i];
				break;
			}
		}
		if(pid == getpid())
		{
			exit(0);
		}
		UdpVideoStream udpVideoObj(gVideoInfo,gZkxaInfo);
		udpVideoObj.exchange_socket = createUdpServer(udpVideoObj.invite_swap_port,udpVideoObj.exchange_ip.c_str());
		udpVideoObj.sip_socket = createUdpServer(udpVideoObj.sip_port, udpVideoObj.local_ip.c_str());
		log_debug_fmt("UDP SipIp %s   port %d",udpVideoObj.local_ip.c_str(),udpVideoObj.sip_port);

		gEpollfd = epoll_create(MAX_LINKS);
		event_init();
		event_set(&ev_inet_forward, udpVideoObj.exchange_socket, EV_READ | EV_PERSIST, inet_forward, (void *)&udpVideoObj);
		event_set(&ev_udp_forward, udpVideoObj.sip_socket, EV_READ | EV_PERSIST, udp_forward, (void *)&udpVideoObj);
		event_add(&ev_inet_forward, 0);
		event_add(&ev_udp_forward, 0);

		log_debug_fmt("event_dispatch before");
		event_dispatch();
		return 0;
	}
	
	return 0;
}




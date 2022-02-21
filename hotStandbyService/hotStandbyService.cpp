#include <iostream>
#include <chrono>
#include <thread>
#include <atomic>
#include <event.h>
using namespace std;

#include "commonHead.h"
#include "commonDefine.h"
#include "commonFunc.h"
#include "log.h"
#include "configoption.h"
#include "ha_vrrp.h"
#include "socketimpl.h"

#include "mysqlImpl.h"

#include "ipaddr.h"

#define VERION "usi2.0-20211108-001"

static VrrpInfo	gVsrv;

static HaConfig *ptr_ha_conf;

// std::atomic<bool> gbRecvRockmq(false);

int ip_id = 0;
char vrrp_virtrual_mac[6];	// 存放虚拟MAC 地址

int gGapSpace = GAP_IN;			//内网是GAP_IN，外网是GAP_OUT,默认是GAP_IN

int exchangeSock; //交换口socket

int priorityHigh = 0;//出现了更高的优先纄1�7 =1
int gPriorityBak = 0;	//优先级备仄1�7

// bool gbSendAdv = false;

int master_ipaddr = 0;//存放当前master 的ip

					  //判断有没有启动应用程庄1�7
int g_AppStar = 0;

int gnRocketPort = 9876;

int gInnerPort = 55666;

char exchangeIp[] = "10.0.1.1";

// class NatctlMessageListener : public MessageListenerConcurrently {
// public:
// 	ConsumeStatus consumeMessage(const std::vector<MQMessageExt>& msgs) {
// 		for (auto item = msgs.begin(); item != msgs.end(); item++) {
// 			if (item->getTags().compare("tag_hot_standby") == 0)
// 			{
// 				log_debug_fmt("recv rocketmq message >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");
// 				gbRecvRockmq = true;
// 			}
// 		}
// 		return CONSUME_SUCCESS;
// 	}
// };

// void startConsume(const char* szServerip, int port)
// {
// 	DefaultMQPushConsumer consumer("FileSyncTas");
// 	char szAddr[512] = { 0 };
// 	snprintf(szAddr, 512, "%s:%d", szServerip, port);
// 	log_debug_fmt("rocket add=[%s]", szAddr);
// 	consumer.setNamesrvAddr(szAddr);
// 	NatctlMessageListener* messageListener = new NatctlMessageListener();
// 	consumer.subscribe("TOPIC_HOT_STANDBY", "*");
// 	consumer.setMessageModel(BROADCASTING);
// 	consumer.registerMessageListener(messageListener);
// 	try {
// 		log_info_fmt("start natctrl consumer");
// 		consumer.start();
// 		while (true)
// 			this_thread::sleep_for(chrono::seconds(1));
// 	}
// 	catch (MQClientException& e) {
// 		std::cout << e << std::endl;
// 	}
// }

//棢�查主机是否存圄1�7
bool checkHostIsExist(const std::string& ip);

/****************************************************************
NAME	: get_ip_from_dev
AIM	: 根据网卡名获取IP
REMARK	:
****************************************************************/
static uint32_t ifname_to_ip(char* ifname)
{
	struct ifreq	ifr;
	int		fd = socket(AF_INET, SOCK_DGRAM, 0);
	uint32_t	addr = 0;
	if (fd < 0) 	return (-1);
	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(fd, SIOCGIFADDR, (char*)&ifr) == 0)
	{
		struct sockaddr_in* sin = (struct sockaddr_in*)&ifr.ifr_addr;
		addr = ntohl(sin->sin_addr.s_addr);
	}
	close(fd);
	return addr;
}

//初始化虚拟热备参敄1�7
static void initVirtualHa(VrrpInfo *vsrv)
{
	log_debug_fmt("init_virtual_ha");	
	if (vsrv->init_master == 1) {
		vsrv->state = VRRP_STATE_INIT;
		vsrv->wantstate = VRRP_STATE_MAST;
	}
	else if (vsrv->init_master == -1) {
		vsrv->state = VRRP_STATE_BACK;
		vsrv->wantstate = VRRP_STATE_INIT;
	}
	else {
		vsrv->state = VRRP_STATE_INIT;
	}

// 	vsrv->priority = VRRP_PRIO_DFL;
	vsrv->adver_int = VRRP_ADVER_DFL*VRRP_TIMER_HZ;
// 	vsrv->preempt = VRRP_PREEMPT_DFL;
}

/****************************************************************
NAME	: in_csum
AIM		: compute a IP checksum
REMARK	: from kuznet's iputils
****************************************************************/
static u_short computeIpChecksum(uint16_t *addr, int len, uint16_t csum)
{
	register int nleft = len;
	const uint16_t *w = addr;
	register uint16_t answer;
	register int sum = csum;

	/*
	*  Our algorithm is simple, using a 32 bit accumulator (sum),
	*  we add sequential 16 bit words to it, and at the end, fold
	*  back all the carry bits from the top 16 bits into the lower
	*  16 bits.
	*/
	while (nleft > 1)
	{
		sum += *w++;
		nleft -= 2;
	}

	/* mop up an odd byte, if necessary */
	if (nleft == 1)
		sum += htons(*(u_char *)w << 8);

	/*add back carry outs from top 16 bits to low 16 bits*/
	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum;				/* truncate to 16 bits */
	return (answer);
}

//返回ether hdr 的长庄1�7
static int vrrpDltLen(VrrpInfo *rt)
{
	return ETHER_HDR_LEN;	/* hardcoded for ethernet */
}

//返回iphdr结构的大射1�7
static int vrrpIphdrLen(VrrpInfo *vsrv)
{
	return sizeof(struct iphdr);
}

static int vrrpHeadLen(VrrpInfo *vsrv)
{
	return sizeof(VrrpInfo) + vsrv->vecAddr.size() * sizeof(uint32_t) + VRRP_AUTH_LEN;
}

/****************************************************************
NAME	: hwaddr_set
AIM	:
REMARK	: linux refuse to change the hwaddress if the interface is up
****************************************************************/
static int setVirtualMac(char *ifname, char *addr, int addrlen)
{
	struct ifreq	ifr;
	int		fd = socket(AF_INET, SOCK_DGRAM, 0);
	int		ret;
	unsigned long	flags;
	if (fd < 0) 	return (-1);
	//延缓子进程信号的发��，会��成操作中断
	//printf("rrrrrrrrrrrrrrrrrrrrrrrrr\n");
	write_file(SIGNLE_SYNC_PATH, 1);
	//get_ifdev_statu(ifname);
	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	/* get the flags */
	ret = ioctl(fd, SIOCGIFFLAGS, (char *)&ifr);
	if (ret)	goto end;
	flags = ifr.ifr_flags;
	//get_ifdev_statu(ifname);
	/* set the interface down */
	ifr.ifr_flags &= ~IFF_UP;
	ret = ioctl(fd, SIOCSIFFLAGS, (char *)&ifr);
	if (ret)	goto end;
	//get_ifdev_statu(ifname);
	/* change the hwaddr */
	memcpy(ifr.ifr_hwaddr.sa_data, addr, addrlen);
	ifr.ifr_hwaddr.sa_family = AF_UNIX;
	ret = ioctl(fd, SIOCSIFHWADDR, (char *)&ifr);
	if (ret)	goto end;
	/* set the interface up */
	//get_ifdev_statu(ifname);
	ifr.ifr_flags = flags;
	ret = ioctl(fd, SIOCSIFFLAGS, (char *)&ifr);
	if (ret)	goto end;
end:;
	if (ret)	
		log_error_fmt("error errno=%d,%s", errno, strerror(errno));
	//放开，允许子进程 发��用户信叄1�7
	write_file(SIGNLE_SYNC_PATH, 0);
	//printf("nnnnnnnnnnnnnnnnnnnnn\n");
	close(fd);
	return ret;
}

/****************************************************************
NAME	: hwaddr_get
AIM	:
REMARK	:
****************************************************************/
static int getVirtualMac(char *ifname, unsigned char *addr, int addrlen)
{
	struct ifreq	ifr;
	int		fd = socket(AF_INET, SOCK_DGRAM, 0);
	int		ret;
	if (fd < 0) 	return (-1);
	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	ret = ioctl(fd, SIOCGIFHWADDR, (char *)&ifr);
	memcpy(addr, ifr.ifr_hwaddr.sa_data, addrlen);
	log_debug_fmt("%02X:%02X:%02X:%02X:%02X:%02X", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
	close(fd);
	return ret;
}

/********************************************************
函数名称：vrrpCheckIncoming
函数功能：检查进来的vrrp匄1�7
叄1�7    数：
笄1�7    丢�：（I）vsrv, vrrp协议信息
笄1�7    二：（I）prio, 热备优先纄1�7
迄1�7    回：旄1�7
佄1�7    耄1�7: 赵翌渄1�7
创建时间＄1�720200715
*********************************************************/
static int vrrpCheckIncoming(VrrpInfo *vsrv, struct iphdr * ip)
{
	int		ihl = ip->ihl << 2;
	VrrpPkt *	vrrpPkt = (VrrpPkt *)((char *)ip + ihl);
	VrrpIfname 	*vif = &vsrv->vif;
	/* MUST verify that the IP TTL is 255 */
	if (ip->ttl != VRRP_IP_TTL)
	{
		//err_msg(("invalid ttl. %d and expect %d", ip->ttl,VRRP_IP_TTL));
		return 1;
	}
	/* MUST verify the VRRP version */
	if ((vrrpPkt->vers_type >> 4) != VRRP_VERSION)
	{
		//err_msg(("invalid version. %d and expect %d", (hd->vers_type >> 4), VRRP_VERSION));
		return 1;
	}
	/* MUST verify that the received packet length is greater than or
	** equal to the VRRP header */
	if ((ntohs(ip->tot_len) - ihl) <= sizeof(VrrpPkt))
	{
		//err_msg(("ip payload too short. %d and expect at least %d", ntohs(ip->tot_len)-ihl, sizeof(vrrp_pkt) ));
		return 1;
	}
	/* WORK: MUST verify the VRRP checksum */
	if (computeIpChecksum((uint16_t*)vrrpPkt, vrrpHeadLen(vsrv), 0))
	{
// 		log_error_fmt("Invalid vrrp checksum");
		return 1;
	}
	/* MUST perform authentication specified by Auth Type */
	/* check the authentication type */
	if (vif->auth_type != vrrpPkt->auth_type)
	{
		//err_msg(("receive a %d auth, expecting %d!", vif->auth_type, hd->auth_type));
		return 1;
	}
	/* check the authentication if it is a passwd */
	if (vrrpPkt->auth_type != VRRP_AUTH_PASS)
	{
		char	*pw = (char *)ip + ntohs(ip->tot_len) - sizeof(vif->auth_data);
		if (memcmp(pw, vif->auth_data, sizeof(vif->auth_data)))
		{
			log_error_fmt(("receive an invalid passwd!"));
			return 1;
		}
	}

	/* MUST verify that the VRID is valid on the receiving interface */
	if (vsrv->vrid != vrrpPkt->vrid)
	{
		return 1;
	}

	/* MAY verify that the IP address(es) associated with the VRID are
	** valid */
	/* WORK: currently we don't */

	/* MUST verify that the Adver Interval in the packet is the same as
	** the locally configured for this virtual router */
	if (vsrv->adver_int / VRRP_TIMER_HZ != vrrpPkt->adver_int)
	{
		log_info_fmt("advertissement interval mismatch mine=%d rcved=%d", vsrv->adver_int, vrrpPkt->adver_int);
		return 1;
	}
	master_ipaddr = ip->saddr;
	return 0;
}

/****************************************************************
NAME	: vrrp_build_dlt
AIM	:
REMARK	: rfc2338   7.3
****************************************************************/
static void vrrpBuildDlt(VrrpInfo *vsrv, char *buffer, int buflen)
{
	/* hardcoded for ethernet */
	struct ether_header *	eth = (struct ether_header *)buffer;
	/* destination address --rfc1122.6.4*/
	eth->ether_dhost[0] = 0x01;
	eth->ether_dhost[1] = 0x00;
	eth->ether_dhost[2] = 0x5E;
	eth->ether_dhost[3] = (INADDR_VRRP_GROUP >> 16) & 0x7F;
	eth->ether_dhost[4] = (INADDR_VRRP_GROUP >> 8) & 0xFF;
	eth->ether_dhost[5] = INADDR_VRRP_GROUP & 0xFF;
	/* source address --rfc2338.7.3 */
	memcpy(eth->ether_shost, vrrp_virtrual_mac, sizeof(vrrp_virtrual_mac));
	/* type */
	eth->ether_type = htons(ETHERTYPE_IP);
}

/********************************************************
函数名称：vrrpBuildIp
函数功能：构建vrrp iphdr
叄1�7    数：
笄1�7    丢�：（I）vsrv, vrrp协议信息
笄1�7    二：（O）buffer, vrrp数据
笄1�7    三：（I）buflen, 数据的长庄1�7
迄1�7    回：旄1�7
佄1�7    耄1�7: 赵翌渄1�7
创建时间＄1�720200717
*********************************************************/
static void vrrpBuildIp(VrrpInfo *vsrv, char *buffer, int buflen)
{
	struct iphdr * ip = (struct iphdr *)(buffer);
	ip->ihl = 5;
	ip->version = 4;
	ip->tos = 0;
	ip->tot_len = ip->ihl * 4 + vrrpHeadLen(vsrv);
	ip->tot_len = htons(ip->tot_len);
	ip->id = ++ip_id;
	ip->frag_off = 0;
	ip->ttl = VRRP_IP_TTL;
	ip->protocol = IPPROTO_VRRP;
// 	ip->saddr = htonl(vsrv->vif.ipaddr);
	log_debug_fmt("heartbeat name = [%s]", ptr_ha_conf->heartbeat_ifname);
	ip->saddr = htonl(ifname_to_ip(ptr_ha_conf->heartbeat_ifname));
	ip->daddr = htonl(INADDR_VRRP_GROUP);
	/* checksum must be done last */
	ip->check = computeIpChecksum((u_short*)ip, ip->ihl * 4, 0);
}

/********************************************************
函数名称：vrrpBuildPkt
函数功能：构建vrrp匄1�7
叄1�7    数：
笄1�7    丢�：（I）vsrv, vrrp协议信息
笄1�7    二：（I）prio, 优先纄1�7
笄1�7    三：（O）buffer, vrrp数据
笄1�7    三：（I）buflen, 数据的长庄1�7
迄1�7    回：旄1�7
佄1�7    耄1�7: 赵翌渄1�7
创建时间＄1�720200717
*********************************************************/
static int vrrpBuildVrrp(VrrpInfo *vsrv, int prio, bool bInit, char *buffer, int buflen)
{
	int	i;
	VrrpIfname	 *vif = &vsrv->vif;
	VrrpPkt *hd = (VrrpPkt *)buffer;
	uint32_t *iparr = (uint32_t *)((char *)hd + sizeof(*hd));

	hd->vers_type = (VRRP_VERSION << 4) | VRRP_PKT_ADVERT;
	hd->vrid = vsrv->vrid;
	hd->priority = prio;
	if (bInit)
	{
		hd->naddr = 0;
	}
	else
		hd->naddr = vsrv->vecAddr.size();
	hd->auth_type = vsrv->vif.auth_type;
	hd->adver_int = vsrv->adver_int / VRRP_TIMER_HZ;
	/* copy the ip addresses */
	for (i = 0; i < vsrv->vecAddr.size(); i++)
	{
		iparr[i] = htonl(vsrv->vecAddr[i].addr);
	}
	/* copy the passwd if the authentication is VRRP_AH_PASS */
	if (vif->auth_type == VRRP_AUTH_PASS)
	{
		char	*pw = (char *)hd + sizeof(*hd) + vsrv->vecAddr.size() * 4;
		memcpy(pw, vif->auth_data, sizeof(vif->auth_data));
	}
	/* Must perform the checksum AFTER we copy the password */
	hd->chksum = computeIpChecksum((u_short*)hd, vrrpHeadLen(vsrv), 0);
	return(0);
}

/********************************************************
函数名称：vrrpBuildPkt
函数功能：构建vrrp匄1�7
叄1�7    数：
笄1�7    丢�：（I）vsrv, vrrp协议信息
笄1�7    二：（I）prio, 优先纄1�7
笄1�7    三：（I）buffer, vrrp数据
笄1�7    三：（I）buflen, 数据的长庄1�7
迄1�7    回：旄1�7
佄1�7    耄1�7: 赵翌渄1�7
创建时间＄1�720200717
*********************************************************/
static void vrrpBuildPkt(VrrpInfo *vsrv, int prio, bool bInit, char *buffer, int buflen)
{
	//	printf("dltlen=%d iplen=%d", vrrp_dlt_len(vsrv), vrrp_iphdr_len(vsrv) );
	/* build the ethernet header */
	vrrpBuildDlt(vsrv, buffer, buflen);
	buffer += vrrpDltLen(vsrv);
	buflen -= vrrpDltLen(vsrv);
	/* build the ip header */
	vrrpBuildIp(vsrv, buffer, buflen);
	buffer += vrrpIphdrLen(vsrv);
	buflen -= vrrpIphdrLen(vsrv);
	/* build the vrrp header */
	vrrpBuildVrrp(vsrv, prio, bInit, buffer, buflen);
}

/********************************************************
函数名称：vrrpSendPkt
函数功能：发送vrrp包数捄1�7
叄1�7    数：
笄1�7    丢�：（I）vsrv, vrrp协议信息
笄1�7    二：（I）buffer, vrrp数据
笄1�7    三：（I）buflen, 数据的长庄1�7
迄1�7    回：旄1�7
佄1�7    耄1�7: 赵翌渄1�7
创建时间＄1�720200717
*********************************************************/
static int vrrpSendPkt(VrrpInfo *vsrv, char *buffer, int buflen)
{
	struct sockaddr from;
	int	len;
	int	fd = socket(PF_PACKET, SOCK_PACKET, 0x300); /* 0x300 is magic */
	if (fd < 0)
	{
		log_error_fmt("create socket");
		return -1;
	}
	/* build the address */
	memset(&from, 0, sizeof(from));
// 	strcpy(from.sa_data, vsrv->vif.ifname);
	strcpy(from.sa_data, ptr_ha_conf->heartbeat_ifname);
	//err_ret( "aaaaaaaaaaaa[%s]\n", vsrv->vif.ifname);
	//strcpy( from.sa_data, "eth5" );
	/* send the data */
	len = sendto(fd, buffer, buflen, 0, &from, sizeof(from));
// 	log_debug_fmt("sendlen=[%d], len=[%d]", buflen, len);
	//printf("len=%d\n",len);
	close(fd);
	return len;
}

/********************************************************
函数名称：vrrpSendAdv
函数功能：发送vrrp匄1�7
叄1�7    数：
笄1�7    丢�：（I）vsrv, vrrp协议信息
笄1�7    二：（I）prio, 热备优先纄1�7
笄1�7    丄1�7: (I) bInit, 初始状��为true
迄1�7    回：旄1�7
佄1�7    耄1�7: 赵翌渄1�7
创建时间＄1�720200715
*********************************************************/
static int vrrpSendAdv(VrrpInfo *vsrv, int prio, bool bInit=false)
{
// 	if (gbSendAdv)
// 	{
// 		return 0;
// 	}
// 	gbSendAdv = true;
	int	buflen, ret;
	char *	buffer;
#if 0	/* just for debug */
	struct in_addr in;
	in.s_addr = htonl(vsrv->vif.ipaddr);
	printf("send an advertissement on %s\n", inet_ntoa(in));
#endif
	/* alloc the memory */
	buflen = vrrpDltLen(vsrv) + vrrpIphdrLen(vsrv) + vrrpHeadLen(vsrv);
// 	log_debug_fmt("vrrpSendAdv buflen=[%d]", buflen);
	buffer = (char*)calloc(buflen, 1);
// 	assert(buffer);
	/* build the packet  */
	vrrpBuildPkt(vsrv, prio, bInit, buffer, buflen);
	/* send it */
	ret = vrrpSendPkt(vsrv, buffer, buflen);
	/* build the memory */
	free(buffer);
	return ret;
}

/********************************************************
函数名称：vrrpRead
函数功能：读取vrrp协议
叄1�7    数：
笄1�7    丢�：（I）vsrv, vrrp协议信息
笄1�7    二：（I）prio, 热备优先纄1�7
迄1�7    回：旄1�7
佄1�7    耄1�7: 赵翌渄1�7
创建时间＄1�720200715
*********************************************************/
static int vrrpRead(VrrpInfo *vsrv, char *buf, int buflen)
{
	const int recvLen = vrrpDltLen(vsrv) + vrrpIphdrLen(vsrv) + vrrpHeadLen(vsrv);
	char bufRecv[300];
	fd_set		readfds;
	struct timeval	timeout;
	uint32_t	next = 0xFFFFFFFF;
	int		len = 0;
	if (VRRP_TIMER_IS_RUNNING(vsrv->adver_timer))
	{
		int32_t	delta = VRRP_TIMER_DELTA(vsrv->adver_timer);
		if (delta < 0)		delta = 0;
		next = VRRP_MIN(next, delta);
	}
	else
	{	/* here vsrv->ms_down_timer is assumed running */
		int32_t	delta = VRRP_TIMER_DELTA(vsrv->ms_down_timer);
		if (VRRP_TIMER_IS_RUNNING(vsrv->ms_down_timer))
			;
		if (delta < 0)	 delta = 0;
		next = VRRP_MIN(next, delta);
	}
	bool bValidFlag = false;
	int nValidLen = 0;
	int nCount = 0;
	while (true)
	{
		/* setup the select() */
		FD_ZERO(&readfds);
		FD_SET(vsrv->sockfd, &readfds);
		timeout.tv_sec = next / VRRP_TIMER_HZ;
		timeout.tv_usec = next % VRRP_TIMER_HZ;
		if ((timeout.tv_usec == 0 && timeout.tv_sec == 0) || (timeout.tv_sec > 1))
		{
			timeout.tv_sec = 1;
		}
		if (select(vsrv->sockfd + 1, &readfds, NULL, NULL, &timeout) > 0)
		{
			len = read(vsrv->sockfd, bufRecv, 144);
			if (vrrpCheckIncoming(vsrv, (struct iphdr*)bufRecv))
			{
				if (bValidFlag)
				{
					len = nValidLen;
				}
				continue;
			}
			if (len >= 0)
			{
				bValidFlag = true;
				nValidLen = len;
				memcpy(buf, bufRecv, len);
				nCount++;
				if (nCount >= 3)
				{
					break;
				}
			}
			else
			{
				if (bValidFlag)
				{
					len = nValidLen;
				}
				break;
			}
		}
		else  //超时则表示没有数据过来，返回
		{
			log_debug_fmt("timeout, len=[%d], nValidLen=[%d]", len, nValidLen);
			if (len == 0)
			{
				nCount++;
				if (nCount>=3)
				{
					break;
				}
			}
			break;
		}
	}
	
	return len;
}

/****************************************************************
NAME	: get_index_from_dev
AIM	: 根据网卡名获取网卡索弄1�7
REMARK	:
****************************************************************/
static int ifname_to_idx(char *ifname)
{
	struct ifreq	ifr;
	int		fd = socket(AF_INET, SOCK_DGRAM, 0);
	int		ifindex = -1;
	if (fd < 0) 	return (-1);
	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(fd, SIOCGIFINDEX, (char *)&ifr) == 0)
		ifindex = ifr.ifr_ifindex;
	close(fd);
	return ifindex;
}

/****************************************************************
NAME	: rcvhwaddr_op
AIM		: addF  =0  del      addF=1  add
REMARK	:op  Multicast address   :  add   or   del
****************************************************************/
static int rcvhwaddr_op(char *ifname, char *addr, int addrlen, int addF)
{
	struct ifreq	ifr;
	int		fd = socket(AF_INET, SOCK_DGRAM, 0);
	int		ret;
	if (fd < 0) 	return (-1);
	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	memcpy(ifr.ifr_hwaddr.sa_data, addr, addrlen);
	ifr.ifr_hwaddr.sa_family = AF_UNSPEC;
	ret = ioctl(fd, addF ? SIOCADDMULTI : SIOCDELMULTI, (char *)&ifr);
	if (ret)
	{
		log_error_fmt("Can't %s on %s. errno=%d\n", addF ? "SIOCADDMULTI" : "SIOCDELMULTI", ifname, errno);
	}
	close(fd);
	return ret;
}

/****************************************************************
NAME	: ipaddr_ops
AIM		: addF=0,del; addF=1,add
REMARK	:err =1 ops error, 增加删除vsrv->vif.ifname网卡的vsrv->vaddr地址
****************************************************************/
static int ipaddr_ops(VrrpInfo *vsrv, int addF)
{
	int	i, err = 0;
	int	ifidx;
	struct in_addr in;
	char cmd[512] = { 0 };
	char addrTmp[32] = { 0 };
	const char* pszOperate = addF == 1 ? "add" : "del";
	ifidx = ifname_to_idx(vsrv->vif.ifname);
	for (i=0; i<vsrv->vecAddr.size(); i++)
	{
		VipAddr* vadd = &vsrv->vecAddr[i];
// 		log_debug_fmt("addr=[%d]", vadd->addr);
		getIpFromInt(vadd->addr, addrTmp, 32);
		snprintf(cmd, 511, "ip a %s %s/%d dev %s", pszOperate, addrTmp, vadd->prefix, vsrv->vif.ifname);
		log_debug_fmt("cmd=[%s], addrTmp=[%s]", cmd, addrTmp);
		system(cmd);
// 		if (!addF && !vadd->deletable)
// 			continue;
// 
// 		err = ipaddr_op(ifidx, vadd->addr, vadd->prefix, addF);
// 		if (err)
// 		{
// 			err = 1;
// 			vadd->deletable = 0;
// 			in.s_addr = htonl(vadd->addr);
// 			log_info_fmt("cant %s the address %s to %s", addF ? "set" : "remove", inet_ntoa(in), vsrv->vif.ifname);
// 		}
// 		else
// 		{
// 			vadd->deletable = 1;
// 		}
	}
// 	for (i = 0; i < vsrv->naddr; i++)
// 	{
// 		VipAddr	*vadd = &vsrv->vaddr[i];
// 		if (!addF && !vadd->deletable)
// 			continue;
// 
// 		err = ipaddr_op(ifidx, vadd->addr, vadd->prefix, addF);
// 		if (err)
// 		{
// 			err = 1;
// 			vadd->deletable = 0;
// 			in.s_addr = htonl(vadd->addr);
// 			printf("cant %s the address %s to %s\n", addF ? "set" : "remove", inet_ntoa(in), vsrv->vif.ifname);
// 		}
// 		else
// 		{
// 			vadd->deletable = 1;
// 		}
// 	}
	return err;
}

/****************************************************************
NAME	: send_gratuitous_arp
AIM	:
REMARK	: rfc0826    免费ARP
(免费ARP  : 通告 和询闄1�7)
****************************************************************/
static int send_gratuitous_arp(VrrpInfo *vsrv, int addr, int vAddrF)
{
	struct m_arphdr
	{
		unsigned short int ar_hrd;                   /* Format of hardware address.  */
		unsigned short int ar_pro;                   /* Format of protocol address.  */
		unsigned char ar_hln;                         /* Length of hardware address.  */
		unsigned char ar_pln;                         /* Length of protocol address.  */
		unsigned short int ar_op;                     /* ARP opcode (command).  */
													  /* Ethernet looks like this : This bit is variable sized however...  */
		unsigned char __ar_sha[ETH_ALEN];   /* Sender hardware address.  */
		unsigned char __ar_sip[4];                 /* Sender IP address.  */
		unsigned char __ar_tha[ETH_ALEN];    /* Target hardware address.  */
		unsigned char __ar_tip[4];                  /* Target IP address.  */
	};
	char	buf[sizeof(struct m_arphdr) + ETHER_HDR_LEN];
	char	buflen = sizeof(struct m_arphdr) + ETHER_HDR_LEN;
	struct ether_header 	*eth = (struct ether_header *)buf;
	struct m_arphdr	*arph = (struct m_arphdr *)(buf + vrrpDltLen(vsrv));
	char	*hwaddr = vAddrF ? vrrp_virtrual_mac : vsrv->vif.hwaddr;
	int	hwlen = ETH_ALEN;

	/* hardcoded for ethernet */
	memset(eth->ether_dhost, 0xFF, ETH_ALEN);
	memcpy(eth->ether_shost, hwaddr, hwlen);
	eth->ether_type = htons(ETHERTYPE_ARP);

	/* build the arp payload */
	memset(arph, 0, sizeof(*arph));
	arph->ar_hrd = htons(ARPHRD_ETHER);
	arph->ar_pro = htons(ETHERTYPE_IP);
	arph->ar_hln = 6;
	arph->ar_pln = 4;
	arph->ar_op = htons(ARPOP_REQUEST);
	memcpy(arph->__ar_sha, hwaddr, hwlen);
	addr = htonl(addr);
	memcpy(arph->__ar_sip, &addr, sizeof(addr));
	memcpy(arph->__ar_tip, &addr, sizeof(addr));
	return vrrpSendPkt(vsrv, buf, buflen);
}

int set_stat(const char *stat)
{
	FILE *pf;

	if ((pf = fopen(HA_STAT, "wb")) == NULL)
	{
		log_error_fmt("open %s error..", HA_STAT);
		return -1;
	}

	if (fwrite(stat, 1, strlen(stat), pf) != strlen(stat))
		log_error_fmt("write error..");

	fclose(pf);
	return 0;
}

//变主机，启动应用程序
void ApplicationStartup()
{
	if (g_AppStar == 0)
		return;

	///system("iptables -t nat -D PREROUTING ! -i eth1 ! -d 224.0.0.18 --j RETURN");
	//	system("iptables -D FORWARD ! -i eth1 ! -d 224.0.0.18 --j DROP");
	//	system("iptables -D INPUT ! -i eth1 ! -d 224.0.0.18 --j DROP");
	//	system("/sbin/arptables -F OUTPUT");
	g_AppStar = 0;

	// 弢�启应用程庄1�7
	log_info_fmt("启动应用 >>>>");
	system("/srv/bin/ha_appcontrl start &");
}

//变备机，关闭应用程序
void ApplicationShutdown()
{
	if (g_AppStar)
		return;

	///system("iptables -t nat -A PREROUTING ! -i eth1 ! -d 224.0.0.18 --j RETURN");
	//	system("iptables -I FORWARD ! -i eth1 ! -d 224.0.0.18 --j DROP");
	//	system("iptables -I INPUT ! -i eth1 ! -d 224.0.0.18 --j DROP");
	//	system("/sbin/arptables -A OUTPUT -o eth1 --j ACCEPT");
	//	system("/sbin/arptables -A OUTPUT --j DROP");
	g_AppStar = 1;

	// 关闭应用程序
	log_info_fmt("关闭应用 >>>>");
	system("/srv/bin/ha_appcontrl stop &");
}

/********************************************************
函数名称：stateLeaveMaster
函数功能：状态离弢�主机
叄1�7    数：
笄1�7    丢�：（I）vsrv, vrrp协议信息
笄1�7    二：（I）ha_conf_str, 热备参数信息
笄1�7    三：（I）advF, 是否vrrp_send_adv
迄1�7    回：旄1�7
佄1�7    耄1�7: 赵翌渄1�7
创建时间＄1�720200715
*********************************************************/
static void stateLeaveMaster(VrrpInfo *vsrv, HaConfig *ha_conf_str, int advF)
{
	uint32_t		addr[1024];
	VrrpIfname		*vif = &vsrv->vif;
	/* restore the original MAC addresses */
	if (!vsrv->no_vmac)
	{
		log_debug_fmt("尝试去除  IP MAC");
		setVirtualMac(vif->ifname, vif->hwaddr, sizeof(vif->hwaddr));
		rcvhwaddr_op(vif->ifname, vif->hwaddr, sizeof(vif->hwaddr), 0);
	}

	/* remove the ip addresses */
	ipaddr_ops(vsrv, 0);

	write_file(NET_STATU_PATH, 0);
	/* send  message to peer host*/
// 	ha_conf_str->peer_sockfd = opensock_timeout(ha_conf_str->peer_ip, EXCHANGE_PORT, 2);
// 	if (ha_conf_str->peer_sockfd >0)
// 	{
// 		if (priorityHigh == 0)
// 		{
// 			writeString(ha_conf_str->peer_sockfd, "HA_BACKUP", 1);
// 			log_debug_fmt("send  HA_BACKUP  to  peer host");
// 			close(ha_conf_str->peer_sockfd);
// 		}
// 		else
// 		{
// 			log_debug_fmt("priority_h =1   扢�仄1�7 不发生信息给对端");
// 			//priority_h =0;
// 			close(ha_conf_str->peer_sockfd);
// 		}
// 	}
	/* if we stop ha_vrrpd, warn the other routers to speed up the recovery */
	if (advF)
	{
		vrrpSendAdv(vsrv, VRRP_PRIO_STOP);
	}

	/* send gratuitous ARP for all the non-vrrp ip addresses to update the cache of remote hosts using these addresses */
	if (!vsrv->no_vmac)
	{
		int		i, naddr;
		naddr = ipaddr_list(ifname_to_idx(vif->ifname), addr, sizeof(addr) / sizeof(addr[0]));
// 		printf("addr num=%d  \n", naddr);
		for (i = 0; i < naddr; i++)
		{
			send_gratuitous_arp(vsrv, addr[i], 0);
		}
	}
	//write_file(NET_STATU_PATH,0);
}

static void state_goto_master(VrrpInfo *vsrv, HaConfig *ha_conf_str)
{
	int	i;
	char  buf[200];
	VrrpIfname	*vif = &vsrv->vif;
	memset(buf, '\0', sizeof(buf));

	//i= vrrp_read_test( vsrv, buf, sizeof(buf) );
	//struct iphdr	*iph	= (struct iphdr *)buf;
	//vrrp_pkt	*hd	= (vrrp_pkt *)((char *)iph + (iph->ihl<<2));
	//if(i >1)
	//{
	//	if(hd->priority > vsrv->priority)
	//		return ;
	//}
	/* send  message to peer host*/
	//memset(buf,'\0',sizeof(buf));


	//2009-06-02
// 	i = GetLocalMac(ha_conf_str->ifname);
// 	if (i == -1)
// 	{
// 		log_error_fmt("网卡 down 了吧 ???");
// 		ha_conf_str->peer_sockfd = -1;
// 		return;
// 	}

	// if (GAP_IN == gCommonInfo.nPosition)
	// {
	// 	//T端发送对端是否正常
	// 	ha_conf_str->peer_sockfd = opensock_timeout(ha_conf_str->peer_ip, EXCHANGE_PORT, 3);
	// 	if (ha_conf_str->peer_sockfd > 0)//和对端机进行通讯，询问状态可行
	// 	{
	// 		writeString(ha_conf_str->peer_sockfd, "HA_MAST", 1);
	// 		i = readFromSocket(ha_conf_str->peer_sockfd, buf, sizeof(buf) - 1, 0, 3);
	// 		if (i > 0)
	// 		{
	// 			if (strstr(buf, "MAST_ERROR") != NULL)
	// 			{
	// 				log_error_fmt("recv  MAST_ERROR 说明对端机器 网络不正常");
	// 				close(ha_conf_str->peer_sockfd);
	// 				ha_conf_str->peer_sockfd = -1;
	// 				return;
	// 			}
	// 		}
	// 		else//没有回应
	// 		{
	// 			close(ha_conf_str->peer_sockfd);
	// 			log_error_fmt("无任何回应 ");
	// 			ha_conf_str->peer_sockfd = -1;
	// 			return;
	// 		}
	// 		close(ha_conf_str->peer_sockfd);
	// 	}
	// 	else
	// 	{
	// 		log_error_fmt("can not connect to peer host ,change to backup");
	// 		ApplicationShutdown();
	// 		return;
	// 	}
	// }

	//system("/usr/sysbin/natwatch");
	log_info_fmt("切换到主机>>>>>");
// 	set_stat(HASTAT_MAST);
	updateStatus(HASTAT_MAST);
	ApplicationStartup();

	/* set the VRRP MAC address -- rfc2338  7.3 */
	if (!vsrv->no_vmac)
	{
		log_debug_fmt("尝试设置   IP  MAC\n");
		setVirtualMac(vif->ifname, vrrp_virtrual_mac, sizeof(vrrp_virtrual_mac));
		rcvhwaddr_op(vif->ifname, vif->hwaddr, sizeof(vif->hwaddr), 1);
	}

	/* add the ip addresses */
	ipaddr_ops(vsrv, 1);

	/* send an advertisement */
	vrrpSendAdv(vsrv, vsrv->priority);
	/* send gratuitous arp for each virtual ip */
	for (i = 0; i < vsrv->vecAddr.size(); i++)
	{
		//printf("send_gratuitous_arp =%s\n",ipaddr_to_str(vsrv->vaddr[i].addr));
		send_gratuitous_arp(vsrv, vsrv->vecAddr[i].addr, 1);
	}
	/* init the struct */
	VRRP_TIMER_SET(vsrv->adver_timer, vsrv->adver_int);
	vsrv->state = VRRP_STATE_MAST;
	vsrv->wantstate = VRRP_STATE_MAST;
	write_file(NET_STATU_PATH, 1);
	char szMasterIp[32] = { 0 };
	log_debug_fmt("HA_VRRP_ID %d on %s: %s%s we are the master router.", vsrv->vrid, vif->ifname, master_ipaddr ? getIpFromInt(master_ipaddr, szMasterIp, 32) : "", master_ipaddr ? " is down, " : "");
	//EnabledDisabledGapApplications(1);
	//system("/usr/sysbin/natwatch");

	//kill(getppid(), SIGTERM);
	//system("/usr/sysbin/resha 1");
	//signal(SIGTERM, NULL);

}

/****************************************************************
NAME	: state_leave_master
AIM	:
REMARK	: 离开主机模式
****************************************************************/
static void state_leave_master(VrrpInfo *vsrv, HaConfig *ha_conf_str, int advF)
{
	uint32_t		addr[1024];
	VrrpIfname		*vif = &vsrv->vif;
	/* restore the original MAC addresses */
	if (!vsrv->no_vmac)
	{
		log_debug_fmt("尝试去除  IP MAC");
		setVirtualMac(vif->ifname, vif->hwaddr, sizeof(vif->hwaddr));
		rcvhwaddr_op(vif->ifname, vif->hwaddr, sizeof(vif->hwaddr), 0);
	}

	/* remove the ip addresses */
	ipaddr_ops(vsrv, 0);

	write_file(NET_STATU_PATH, 0);
	/* send  message to peer host*/
// 	ha_conf_str->peer_sockfd = opensock_timeout(ha_conf_str->peer_ip, EXCHANGE_PORT, 2);
// 	if (ha_conf_str->peer_sockfd >0)
// 	{
// 		if (priorityHigh == 0)
// 		{
// 
// 			writeString(ha_conf_str->peer_sockfd, "HA_BACKUP", 1);
// 			log_info_fmt("send  HA_BACKUP  to  peer host");
// 			close(ha_conf_str->peer_sockfd);
// 		}
// 		else
// 		{
// 			log_info_fmt("priority_h =1   扢�仄1�7 不发生信息给对端");
// 			//priority_h =0;
// 			close(ha_conf_str->peer_sockfd);
// 		}
// 	}
	/* if we stop ha_vrrpd, warn the other routers to speed up the recovery */
	if (advF)
	{
		vrrpSendAdv(vsrv, VRRP_PRIO_STOP);
	}

	/* send gratuitous ARP for all the non-vrrp ip addresses to update the cache of remote hosts using these addresses */
	if (!vsrv->no_vmac)
	{
		int		i, naddr;
		naddr = ipaddr_list(ifname_to_idx(vif->ifname), addr, sizeof(addr) / sizeof(addr[0]));
		printf("addr num=%d  \n", naddr);
		for (i = 0; i < naddr; i++)
		{
			send_gratuitous_arp(vsrv, addr[i], 0);
		}
	}
	//write_file(NET_STATU_PATH,0);
}

int ifname_is_bridge(const char* ifname)
{
	FILE* pFile;
	char zBuf[1024];

	zBuf[0] = 0;
	sprintf(zBuf, "brctl show |grep %s", ifname);

	if ((pFile = popen(zBuf, "r")) == NULL)
	{
		printf("popen %s failed\n", zBuf);
		return -1;
	}

	if ((fgets(zBuf, sizeof(zBuf), pFile)) == NULL)
	{
		pclose(pFile);
		return 0;
	}

	pclose(pFile);
	return 1;
}

/****************************************************************
 NAME	: open_sock
 AIM		: open the socket and join the multicast group.
 REMARK	:
****************************************************************/
static int open_sock(VrrpInfo* vsrv)
{
	if (vsrv->sockfd > 0)
	{
		close(vsrv->sockfd);
		vsrv->sockfd = 0;
	}
	struct	ip_mreq req;
	int	ret;
	/* open the socket */
	vsrv->sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_VRRP);
	if (vsrv->sockfd < 0) {
		return -1;
	}
	/* join the multicast group */
	memset(&req, 0, sizeof(req));
	req.imr_multiaddr.s_addr = htonl(INADDR_VRRP_GROUP);
// 	if (ifname_is_bridge(vsrv->vif.ifname))
// 		req.imr_interface.s_addr = htonl(ifname_to_ip("bri0"));
// 	else
// 		req.imr_interface.s_addr = htonl(vsrv->vif.ipaddr);
	if (ifname_is_bridge(ptr_ha_conf->heartbeat_ifname))
	{
		req.imr_interface.s_addr = htonl(ifname_to_ip("bri0"));
	}
	else
	{
		req.imr_interface.s_addr = htonl(ifname_to_ip(ptr_ha_conf->heartbeat_ifname));
		log_debug_fmt("open %s", ptr_ha_conf->heartbeat_ifname);
	}
	ret = setsockopt(vsrv->sockfd, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char*)&req, sizeof(struct ip_mreq));
	if (ret < 0) {
		return -1;
	}
	return 0;
}

/****************************************************************
NAME	: state_init
AIM	:初始匄1�7
REMARK	: rfc2338   6.4.1
****************************************************************/
static void stateInit(VrrpInfo *vsrv, HaConfig *ha_conf_str)
{
	log_debug_fmt("*****priority=%d  wantstate=%d\n", vsrv->priority, vsrv->wantstate);

	if (vsrv->priority == VRRP_PRIO_OWNER || vsrv->wantstate == VRRP_STATE_MAST)
	{
		log_info_fmt("*****priority=%d  wantstate=%d\n", vsrv->priority, vsrv->wantstate);
		updateStatus(HASTAT_MAST);
		state_goto_master(vsrv, ha_conf_str);
	}
	else
	{
		ApplicationShutdown();
		int delay = 3 * vsrv->adver_int + VRRP_TIMER_SKEW(vsrv);
		VRRP_TIMER_SET(vsrv->ms_down_timer, delay);
		vsrv->state = VRRP_STATE_BACK;
		char szMasterIpaddr[32] = { 0 };
		log_debug_fmt("state_init:HA_VRRP_ID %d on %s: [%d] %s %s we are a backup router.", vsrv->vrid, vsrv->vif.ifname, master_ipaddr, master_ipaddr ? getIpFromInt(master_ipaddr, szMasterIpaddr, 32) : "NULL",
			master_ipaddr ? " is up," : "is down,");
	}
}

//自检
int selfCheck(HaConfig* ha_conf_str, int isMaster = 0)
{
	int nRet = 0;
	//测试热备叄1�7 是否正常状��1�7
	nRet = get_ifdev_statu(ha_conf_str->ha_ifname[0]);
	if (nRet < 0)
	{
		log_info_fmt("热备口[%s]断线", ha_conf_str->ha_ifname[0]);
		return -1;
	}
	log_info_fmt("热备口[%s]正常", ha_conf_str->ha_ifname[0]);
	//测试应用叄1�7 是否正常状��1�7
	nRet = get_ifdev_statu(ha_conf_str->heartbeat_ifname);
	if (nRet < 0)
	{
		log_info_fmt("心跳口[%s]断线", ha_conf_str->heartbeat_ifname);
		return 1;
	}
	log_info_fmt("心跳口[%s]正常", ha_conf_str->heartbeat_ifname);
	return 0;
	//单向的不霢�要内网检柄1�7
	if (GAP_IN == gCommonInfo.nPosition || 1 == isMaster)
	{
		ha_conf_str->peer_sockfd = opensock_timeout(ha_conf_str->peer_ip, EXCHANGE_PORT, 3);
		if (ha_conf_str->peer_sockfd < 1)
		{
			log_error_fmt("对端不可辄1�7, 棢�测失贄1�7 ");
			return -1;
		}
		writeString(ha_conf_str->peer_sockfd, "HA_SELF", 2);
		char		buff[20];
		memset(buff, '\0', sizeof(buff));
		nRet = readFromSocket(ha_conf_str->peer_sockfd, buff, sizeof(buff) - 1, 0, 2);
		if (strstr(buff, "U_ERROR") != NULL)//HA_BACKUP
		{
			log_error_fmt("对端自检出错，不能做主机");
			close(ha_conf_str->peer_sockfd);
			return -1;
		}
		//err_msg("MASTER 状��循玄1�7 棢�浄1�7, 测试eth1 OK\n ");
		close(ha_conf_str->peer_sockfd);
		log_info_fmt("对端正常>>>>>>>>>");
	}
	return 0;
}

/****************************************************************
NAME	: state_back
AIM	:备份朄1�7
REMARK	: rfc2338  6.4.2
****************************************************************/
static void stateBack(VrrpInfo *vsrv, HaConfig *ha_conf_str)
{
	int  	ret;
	int		len;
	char	buf[300];

	static int nCount = 0;
	static bool is_elected = false;

	memset(buf, '\0', sizeof(buf));

	//自检端口
	ret = selfCheck(ha_conf_str);
	if (ret == -1)
	{
		int delay = 3 * vsrv->adver_int + VRRP_TIMER_SKEW(vsrv);
		VRRP_TIMER_SET(vsrv->ms_down_timer, delay);
		log_error_fmt("NO-CARRIER");
		sleep(1);
		return;
	}
	else if (ret == 1)	//心跳口断线
	{
		len = vrrpRead(vsrv, buf, sizeof(buf));
		nCount++;
		if (nCount >= 3)
		{
			nCount = 0;
			if (strlen(ha_conf_str->gateway3rd_ip) > 0 )
			{
				if (checkHostIsExist(ha_conf_str->gateway3rd_ip))
				{
					state_goto_master(vsrv, ha_conf_str);
				}
			}
			else
				state_goto_master(vsrv, ha_conf_str);
		}

		return;
	}


	log_info_fmt("本机正常，申请做主机, vsrv->priority=[%d]", vsrv->priority);
	if (vsrv->wantstate == VRRP_STATE_INIT)
	{
		log_debug_fmt("发送初始包");
		vrrpSendAdv(vsrv, vsrv->priority, true);
	}
	
	len = vrrpRead(vsrv, buf, sizeof(buf));
	struct iphdr	*iph = (struct iphdr *)buf;
	VrrpPkt	*hd = (VrrpPkt *)((char *)iph + (iph->ihl << 2));
	log_debug_fmt("recv len=%d priorityHigh=%d hd->priority=%d vsrv->wantstate=[%d] preempt=[%d]", len, priorityHigh, hd->priority, vsrv->wantstate, vsrv->preempt);
	if (len <1)
	{
// 		log_debug_fmt("没有收到通知广播");
		nCount++;
		if (nCount >= 3)
		{
			nCount = 0;
			state_goto_master(vsrv, ha_conf_str);
		}
		if (is_elected && GAP_OUT == gCommonInfo.nPosition)  //发送信号让对端变成主机
		{
			log_debug_fmt("发送信号对内网变主机");
			is_elected = false;
			int srv_sock = socket(AF_INET,SOCK_DGRAM,0);
			char signal_datas[] = "HA_MASTER";
			struct sockaddr_in srv_addr;
			srv_addr.sin_port = htons(gInnerPort);
			srv_addr.sin_family = AF_INET;
			srv_addr.sin_addr.s_addr = inet_addr(gCommonInfo.strPeerip.c_str());
			sendto(srv_sock,signal_datas,sizeof(signal_datas),0,(struct sockaddr *)&srv_addr,sizeof(struct sockaddr));
		}
		return;
	}
	is_elected = true;
	if (hd->priority == 0 && len > 0)
	{
// 		vsrv->priority = gPriorityBak;
		priorityHigh = 0;
// 		VRRP_TIMER_SET(vsrv->ms_down_timer, VRRP_TIMER_SKEW(vsrv));
		nCount++;
		if (nCount >= 3)
		{
			nCount = 0;
			state_goto_master(vsrv, ha_conf_str);
		}
// 		state_goto_master(vsrv, ha_conf_str);
	}
	//vrrp 处于非抢占状态 or   本机的优先级不够高；preempt =2 非抢占
	else if (2 == vsrv->preempt)
	{
		if (hd->naddr == 0 || vsrv->priority == 255)	//初始状��1�7
		{
			if (hd->priority < vsrv->priority)
			{
				state_goto_master(vsrv, ha_conf_str);
				return;
			}
		}
		
		priorityHigh = 0;
		int delay = 3 * vsrv->adver_int + VRRP_TIMER_SKEW(vsrv);
		VRRP_TIMER_SET(vsrv->ms_down_timer, delay);
	}
	else if (1 == vsrv->preempt && hd->priority < vsrv->priority)
	{
		log_debug_fmt("state_goto_master vsrv->preempt=[%d], hd->priority=[%d], vsrv->priority=[%d]", vsrv->preempt, hd->priority, vsrv->priority);
		priorityHigh = 0;
		state_goto_master(vsrv, ha_conf_str);
	}

	if (vsrv->wantstate == VRRP_STATE_INIT && hd->priority > 0)
	{
		vsrv->wantstate = VRRP_STATE_BACK;
	}
	log_debug_fmt("wantstate=[%d]", vsrv->wantstate);
}

/****************************************************************
NAME	: state_mast
AIM	:主机
REMARK	: rfc2338   6.4.3
****************************************************************/
static void stateMaster(VrrpInfo *vsrv, HaConfig *ha_conf_str)
{
	char	   buf[300];	/* WORK: lame ! */
	int 	   len;
	int 	   ret;
	int 	   delay;

	struct iphdr* iph = NULL;
	VrrpPkt* hd = NULL;

	static int nCount = 0;

	ret = selfCheck(ha_conf_str, 1);
	if (ret == -1)
	{
		goto be_backup;
	}
	else if (ret == 1)	
	{
		if (strlen(ha_conf_str->gateway3rd_ip) > 0)
		{
			if (!checkHostIsExist(ha_conf_str->gateway3rd_ip))
			{
				nCount++;
				if (nCount >= 3)
				{
					nCount = 0;
					goto be_backup;
				}
				
			}
		}
	}
	updateStatus(HASTAT_MAST);
	vrrpSendAdv(vsrv, vsrv->priority);


	len = vrrpRead(vsrv, buf, sizeof(buf));
	iph = (struct iphdr *)buf;
	hd = (VrrpPkt *)((char *)iph + (iph->ihl << 2));

	if (len > 1 && hd->priority > vsrv->priority)
	{
		priorityHigh = 0;
		nCount++;
		if (nCount >= 3)
		{
			nCount = 0;
			goto be_backup;
		}
	}
	
	return;
	if (vsrv->wantstate == VRRP_STATE_BACK)
	{
		goto be_backup;
	}

	be_backup:
		log_info_fmt("切换到备机>>>>");
		updateStatus(HASTAT_BACK);
		ApplicationShutdown();
		delay = 3 * vsrv->adver_int + VRRP_TIMER_SKEW(vsrv);
		VRRP_TIMER_SET(vsrv->ms_down_timer, delay);
		VRRP_TIMER_CLR(vsrv->adver_timer);
		state_leave_master(vsrv, ptr_ha_conf, 0);
		vsrv->state = VRRP_STATE_BACK;
		char szMasterIpaddr[32] = { 0 };
		log_debug_fmt("state_mast:HA_VRRP_ID %d on %s: %s%s we are a backup router.", vsrv->vrid, vsrv->vif.ifname, master_ipaddr ? getIpFromInt(master_ipaddr, szMasterIpaddr, 32) : "NULL", master_ipaddr ? " is up," : "is down,");
	
}

int get_conf_count(const char* filename)
{
	FILE * fd;
	char str[100];
	fd = fopen(filename, "r");
	if (!fd)
	{
		log_error_fmt("get conf  count  error");
		return -1;
	}
	while (fgets(str, sizeof(str), fd) != NULL)
	{
		fclose(fd);
		return atoi(str);
	}
	return 0;
}

void process_sock(int sock)
{
	int   		ret;
	char		buff[20];
	memset(buff, '\0', sizeof(buff));
	ret = readFromSocket(sock, buff, sizeof(buff) - 1, 0, 2);
	if (ret < 1)
	{
		close(sock);
		return;
	}

	if (strstr(buff, "HA_BACK") != NULL)//HA_BACKUP
	{
		log_debug_fmt("recv HA_BACKUP");

		if (get_conf_count(SIGNLE_SYNC_PATH) == 0 && get_conf_count(NET_STATU_PATH) == 1)
		{
			log_info_fmt("给本机发送一个backup信号");//if(get_conf_count(NET_STATU_PATH)==1)//说明系统在master
// 			kill(ha_conf_str->main_pid, SIGUSR2);
		}
		close(sock);
		return;
	}
	else if (strstr(buff, "HA_MAST") != NULL)//HA_MASTER
	{
		log_debug_fmt("recv HA_MASTER");

		log_debug_fmt("Check device statu %s", ptr_ha_conf->ha_ifname[0]);
		//2009-06-02
		if (get_ifdev_statu(ptr_ha_conf->ha_ifname[0]) != -1
			&& get_ifdev_statu(ptr_ha_conf->heartbeat_ifname) != -1)
// 			&& GetLocalMac(ha_conf_str->ha_ifname[0]) == 0)
		{
			writeString(sock, "MAST_OK", 2);
			log_info_fmt("send  MAST_OK  给对端机");
		}
		else
		{
			writeString(sock, "MAST_ERROR", 2);
			log_info_fmt("send  MAST_ERROR  给对端机");
			close(sock);
			return;
		}

		//while(1)//本地机器 ，准备就组1�7
		//{
// 		if (get_conf_count(SIGNLE_SYNC_PATH) == 0 && get_conf_count(NET_STATU_PATH) == 0)
// 		{
// 			log_info_fmt("给本机发送一丄1�7 master 信号");
// 			kill(ha_conf_str->main_pid, SIGUSR1);
// 		}
		close(sock);
		state_goto_master(&gVsrv, ptr_ha_conf);
		return;
		//err_msg("SIGNLE_SYNC_PATH  ");
		//}
	}
	else if (strstr(buff, "HA_SELF") != NULL)//HA_MASTER
	{
		if (!selfCheck(ptr_ha_conf))
		{
			writeString(sock, "U_OK", 2);
			log_info_fmt("send  U_OK  给对端机");
			close(sock);
			return;
		}
		else
		{
			writeString(sock, "U_ERROR", 2);
			log_info_fmt("send  U_ERROR  给对端机");
			close(sock);
			return;
		}
	}


	close(sock);
	return;
}

void * internalWork(void * arg)
{
	int listenfd = *(int*)arg;
	int peerSock;
	socklen_t 	len;
	struct sockaddr_in	  ipaddr;
	while (true)
	{
		peerSock = accept(listenfd, (struct sockaddr *) &ipaddr, &len);
		if (peerSock < 0)
		{
			log_error_fmt("internalWork accept error=[%d:%s]", errno, strerror(errno));
			continue;
		}
		process_sock(peerSock);
	}
	return NULL;
}

int lock_file(int fd)
{
	struct flock fl;

	fl.l_type = F_WRLCK;
	fl.l_start = 0;
	fl.l_whence = SEEK_SET;
	fl.l_len = 0;

	return(fcntl(fd, F_SETLK, &fl));   //F_SETLK在指定的字节范围获取锄1�7
}

//判断进程是否正在运行
int already_running()
{
	int					fd;
	char			buf[16];

#define LOCKMODE					(S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH)
// 	string strPid = string(WORK_PATH) + PIDFILE;
	fd = open(PIDFILE, O_RDWR | O_CREAT, LOCKMODE);
	if (fd < 0)
	{
		//syslog(LOG_ERR, "can't open %s: %s", lock_file, strerror(errno));
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

void OutToInForward(int sock,short event, void *arg)
{
	log_debug_fmt("OutToInForward");
	char buf[64] = {0};
	struct sockaddr_in cli_addr;
	socklen_t addrlen = sizeof(struct sockaddr);
	recvfrom(sock,buf,sizeof(buf),0,(struct sockaddr *)&cli_addr,&addrlen);
	VrrpInfo *vsrv = (VrrpInfo *)arg;
	char gotoMaster[] = "HA_MASTER";
	if(strncmp(buf,gotoMaster,strlen(gotoMaster)) == 0)
	{
		vsrv->priority = 255;
	}
	return;
}
//单向监听外网
void *listenOutnet(void *vsrv)
{
	struct sockaddr_in srv_addr;
	srv_addr.sin_family = AF_INET;
	srv_addr.sin_port = htons(gInnerPort);
	srv_addr.sin_addr.s_addr = inet_addr(exchangeIp);
	int srv = socket(AF_INET,SOCK_DGRAM,0);
	setNoblock(srv,1);
	int on=1;	
	if((setsockopt(srv,SOL_SOCKET,SO_REUSEADDR,&on,sizeof(on))) != 0)
		log_debug_fmt("setsockopt error!%s", strerror(errno));

	while (bind(srv,(struct sockaddr *)&srv_addr,sizeof(struct sockaddr)) < 0)
	{
		log_debug_fmt("bind error %s",strerror(errno));
		continue;
	}
	struct event ev;
	event_init();
	event_set(&ev,srv,EV_READ |EV_PERSIST,OutToInForward,vsrv);
	event_add(&ev,0);
	log_debug_fmt("event_dispatch before");
	event_dispatch();
	log_debug_fmt("event_dispatch after");
}


int main(int argc, char *argv[])
{
	enterDaemon(1, LOG_FILE);
	log_info_fmt("VERSION:%s", VERION);

	if (already_running())
	{
		log_error_fmt("already runging.");
		exit(0);
	}

	int ret = 0;
	HaConfig haConfig;
	memset(&haConfig, 0, sizeof(HaConfig));
	VrrpInfo &vsrv = gVsrv;
	memset(&vsrv, 0, sizeof(VrrpInfo));


	ptr_ha_conf = &haConfig;
	//读取公共配置文件
	char exchangeIfname[20] = SWAP_DEV;
	if (readGsiini(GSI_CFG))
	{
		return -1;
	}
	
	haConfig.action = 0;
	strcpy(haConfig.exchange_ip, gCommonInfo.strLocalip.c_str());
	strcpy(haConfig.peer_ip, gCommonInfo.strPeerip.c_str());
	log_info_fmt("exchange ip=[%s], peer ip=[%s]", haConfig.exchange_ip, haConfig.peer_ip);

	while (connectDb())
	{

	}
	
	while (true)
	{
		ret = getHotStandbyConfig(&haConfig, &vsrv);
		if (haConfig.action == 1)
		{
			break;
		}
		log_info_fmt("本机未启动");
		updateStatus(0);
		exit(0);
	}
	log_debug_fmt("gateway3rd=[%s]", haConfig.gateway3rd_ip);
	//保存热备信息到文件中
	if (strlen(haConfig.ha_ifname[0]) > 0)
	{
		char cmd[1024] = { 0 };
		snprintf(cmd, 1024, "echo \"eth=%s\" > %s", haConfig.ha_ifname[0], HOTINFO_ini);
		system(cmd);
		snprintf(cmd, 1024, "echo \"vip=%s/%d\" >> %s", haConfig.vectorVirtualIp[0].v_server_ip, haConfig.vectorVirtualIp[0].net_prefix, HOTINFO_ini);
		system(cmd);
	}
	if (access(HOTINFO_ini, F_OK) == 0)
	{
		FILE* fd = fopen(HOTINFO_ini, "r");
		char buf[1024];
		string strEth, strVip;
		while (fgets(buf, 1024, fd) != NULL)
		{
			if (strncmp(buf, "eth=", 4) == 0)
			{
				buf[strlen(buf) - 1] = 0;
				strEth = buf + 4;
			}
			if (strncmp(buf, "vip=", 4) == 0)
			{
				buf[strlen(buf) - 1] = 0;
				strVip = buf + 4;
			}
		}
		fclose(fd);
		snprintf(buf, 1024, "ip a del %s dev %s", strVip.c_str(), strEth.c_str());
		log_debug_fmt("buf=[%s]", buf);
		system(buf);
	}
	vsrv.init_master = -1;
	initVirtualHa(&vsrv);
	if (open_sock(&vsrv))
	{
		log_error_fmt("open_sock error [%d:%s]", errno, strerror(errno));
		return -1;
	}

	vsrv.initF = 1;
	log_debug_fmt("inet listen thread start 11111");
	updateStatus(HASTAT_BACK);
	if(gCommonInfo.nPosition == GAP_IN)
	{
		log_debug_fmt("inet listen thread start");
		pthread_t pth_listenOutnet;
		pthread_create(&pth_listenOutnet,NULL,listenOutnet,&vsrv);
	}
	while (1)
	{
		switch (vsrv.state)
		{
		case VRRP_STATE_INIT:	stateInit(&vsrv, &haConfig);	break;
		case VRRP_STATE_BACK:	stateBack(&vsrv, &haConfig);	break;
		case VRRP_STATE_MAST:	stateMaster(&vsrv, &haConfig);	break;
		}
		log_debug_fmt("state: %d, priority=[%d]", vsrv.state, vsrv.priority);
		sleep(3);
	}
	log_info_fmt("over");
	return 0;
}

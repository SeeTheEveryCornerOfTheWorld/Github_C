#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip_icmp.h> //struct icmp
#include <netinet/in.h> //sockaddr_in
#include <netinet/ip.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/time.h>
#include <string.h>
#include <string>

#include "commonFunc.h"
#include "log.h"

//校验和计算
unsigned short calc_cksum(char* buff, int len)
{
	int blen = len;
	unsigned short* mid = (unsigned short*)buff;
	unsigned short te = 0;
	unsigned int sum = 0;

	while (blen > 1)
	{
		sum += *mid++;
		blen -= 2;
	}
	//数据长度为奇数比如65 上面的while是按16计算的 最后就会剩下一字节不能计算 	
	if (blen == 1)
	{
		//将多出的一字节放入short类型的高位 低8位置0 加入到sum中
		te = *(unsigned char*)mid;
		te = (te << 8) & 0xff;
		sum += te;
	}
	sum = (sum >> 16) + (sum & 0xffff);
	sum += sum >> 16;
	return (unsigned short)(~sum);
}

static void icmp_packet(char* buff, int len, int id, int seq)
{
	struct timeval* tval = NULL;
	struct icmp* icmp = (struct icmp*)buff;

	icmp->icmp_type = 8; //ECHO REQUEST
	icmp->icmp_code = 0;
	icmp->icmp_cksum = 0;  //first set zero
	icmp->icmp_id = id & 0xffff;
	icmp->icmp_seq = seq;

	tval = (struct timeval*)icmp->icmp_data;
	gettimeofday(tval, NULL);//获得传输时间作为数据

	//计算校验和
	icmp->icmp_cksum = calc_cksum(buff, len);
	return;
}

int parse_packet(char* buff, int len)
{
	struct timeval* val;
	struct timeval nv;
	struct icmp* icmp;
	struct iphdr* iphead = (struct iphdr*)buff;
	struct in_addr addr;
	addr.s_addr = iphead->saddr;

// 	printf("comefrom ip=%s  ", inet_ntoa(addr));
	//跳过ip头
	icmp = (struct icmp*)(buff + sizeof(struct iphdr));

	//看传输回的包校验和是否正确
	if (calc_cksum((char*)icmp, len - sizeof(sizeof(struct iphdr))) > 1)
	{
// 		printf("receiver error\n");
		return -1;
	}
	gettimeofday(&nv, NULL);
	val = (struct timeval*)icmp->icmp_data;

// 	printf("type=%d  seq=%d id=%d pid=%d usec=%d \n", icmp->icmp_type, icmp->icmp_seq, icmp->icmp_id, (getpid() & 0xffff), nv.tv_usec - val->tv_usec);
	return 0;
}

int pingImpl(const char * pchDstip)
{
	int skfd;
	struct sockaddr_in addr = { 0 };
	struct sockaddr_in saddr = { 0 };
	char buff[64] = { 0 };
	char recvbuff[512] = { 0 };
	int ret;
	int len = 0;
	socklen_t addrlen = 0;
	int count = 3;
	int i = 1;

	skfd = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (skfd < 0)
	{
		return -1;
	}

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(pchDstip);

	//每一秒发送一次 共发送count次    
	while (count > 0)
	{
		//序列号seq 从1 开始传输  buff的大小为64
		memset(buff, 0, sizeof(buff));
		icmp_packet(buff, 64, getpid(), i);
		i++;
		count--;

		//将数据发送出去
		len = sendto(skfd, buff, 64, 0, (struct sockaddr*)&addr, sizeof(addr));
		if (len <= 0)
		{
			ret = -1;
// 			printf("send error\n");
			goto out;
		}
// 		else
// 			printf("send success ret=%d\n", ret);

		//接收echo replay
		memset(recvbuff, 0, sizeof(recvbuff));
		memset(&saddr, 0, sizeof(saddr));
		addrlen = sizeof(saddr);
		len = recvfrom(skfd, recvbuff, sizeof(recvbuff), 0, (struct sockaddr*)&saddr, &addrlen);
		if (len <= 0)
		{
// 			printf("recv error\n");
			ret = -1;
			goto out;
		}
		ret = parse_packet(recvbuff, len);
		if (ret == 0)
		{
			break;
		}
		sleep(1);
	}
out:
	close(skfd);
	return ret;
}

//检查主机是否存在
bool checkHostIsExist(const std::string& ip)
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
	memset((struct sockaddr*)&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	if (inet_aton(ip.c_str(), &serv_addr.sin_addr) < 0)
	{
		log_error_fmt("opensock: Could not convert address \"%s\",", ip.c_str());
		return false;
	}
	serv_addr.sin_port = htons(5000);
	if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
	{
		log_error_fmt("opensock: socket() error [%d:%s]", errno, strerror(errno));
		return false;
	}

	flags = setNoblock(sock_fd, 1);
	if ((ret = (connect(sock_fd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)))) < 0)
	{
		if (errno != EINPROGRESS)
		{
			log_error_fmt("opensock: connect() to \"%s:%u\"error [%d:%s]", ip.c_str(), 5000, errno, strerror(errno));
			close(sock_fd);

			return false;  //connect error
		}
	}
	else if (ret == 0)
	{
		close(sock_fd);
		return true;   //connect ok 
	}
	FD_ZERO(&rset);
	FD_SET(sock_fd, &rset);
	wset = rset;
	tval.tv_sec = 0;
	tval.tv_usec = 500000;
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
		if (error == ECONNREFUSED)
		{
			close(sock_fd);
			return true;
		}
		if (error != 0)
		{
			//err_ret("error !-0,connect error");
			close(sock_fd);
			return false;
		}
	}
	else
	{
		//printf("sockfd not set\n");
		close(sock_fd);
		return false;
	}
	close(sock_fd);
	return true;
}

#include<stdio.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<string.h>
#include<netinet/in.h>
#include<stdlib.h>
#include<net/ethernet.h>
#include<netinet/ip.h>
struct vrrppkt
{
	unsigned char vers_type;
	unsigned char vrid;	
	unsigned char  priority;
	unsigned char  naddrs;
	unsigned char auth_type;
	unsigned char addv_time;
	unsigned short check_num;
	
};

int counts =0;

unsigned short check_sum(unsigned short *buffer,int buflen)
{

	unsigned short *data = (unsigned short *)buffer;
	int len =buflen;
	int sum =0;
	while(len>1)
	{
		sum+= *data++;
		len-=2;	
	}
	if(len==1)
	{
		sum+=*(unsigned char *)data;
	}
	sum= (sum>>16)+(sum&0xffff);
	sum+=(sum>>16);
	unsigned short ret = ~sum;
	return ret;
}

int main(void)
{
	int raw_socket = socket(AF_INET,SOCK_RAW,112);
	if(raw_socket<0)
	{
		printf("create socket_raw error\n");
	}
	struct ip_mreq req;
	memset(&req,0,sizeof(req));
	req.imr_multiaddr.s_addr =htonl(0xe0000012);
	req.imr_interface.s_addr = htonl(0xaca8005f);
	int ret =setsockopt(raw_socket,IPPROTO_IP,IP_ADD_MEMBERSHIP,(char *)&req,sizeof(struct ip_mreq));
	if(ret <0)
	{
		printf("ret <0");
		return 0;
	}
	

	//build  ether  packct
	int buflen = ETHER_HDR_LEN + sizeof(struct vrrppkt) + sizeof(struct iphdr);
	char *buffer = (char *)calloc(buflen,1);
	char *tmpbuf = buffer;
	printf("buflen :%d        %d       %d             %d/n",buflen,ETHER_HDR_LEN,sizeof(struct vrrppkt),sizeof(struct iphdr));
	struct ether_header *eth = (struct ether_header*)buffer;
	eth->ether_dhost[0]=0x01;	
	eth->ether_dhost[1]=0x00;
	eth->ether_dhost[2]=0x5e;
	eth->ether_dhost[3]=0x00;
	eth->ether_dhost[4]=0x00;
	eth->ether_dhost[5]=0x12;
	
	eth->ether_shost[0]=0x00;	
	eth->ether_shost[1]=0x00;
	//eth->ether_shost[2]=0x5e;
	//eth->ether_shost[3]=0x00;
	//eth->ether_shost[4]=0x01;
	//eth->ether_shost[5]=0x14;

	eth->ether_shost[2]=0x00;
	eth->ether_shost[3]=0x00;
	eth->ether_shost[4]=0x00;
	eth->ether_shost[5]=0x00;
	eth->ether_type=htons(ETHERTYPE_IP);

	//build  ip packet
	
	struct iphdr *ip = (struct iphdr *)(buffer+ETHER_HDR_LEN);
	ip->ihl = 5;
	ip->version =4;
	ip->tos = 0;
	ip->tot_len = 20 + sizeof(struct vrrppkt);
	ip->tot_len = htons(ip->tot_len);
	ip->id =1;
	ip->frag_off =0;
	ip->ttl =255;
	ip->protocol=112;
	ip->saddr= htonl(0xaca8005f);
	ip->daddr= htonl(0xe0000012);
	ip->check=0;

	ip->check = check_sum((unsigned short *)ip,20);
	printf("check:%d\n",ip->check);
	//printf("saddr:%s daddr:%s  check :%d\n",inet_addr(ip->saddr),inet_addr(ip->daddr),ip->check);
	//build vrrp pkt	
	struct vrrppkt *vp =(struct vrrppkt*) (buffer +ETHER_HDR_LEN+sizeof(struct iphdr));
	vp->vers_type = (2<<4) | 1;
	vp->vrid = 0x14;
	vp->priority=162;
	vp->naddrs = 0;
	vp->auth_type = 0;
	vp->addv_time = 1;
	vp->check_num = 0;
	vp->check_num = check_sum((unsigned short *)vp,sizeof(struct vrrppkt));
	
	struct sockaddr from;
	int fd = socket(PF_PACKET,SOCK_PACKET,0x300);
	memset(&from,0,sizeof(from));
	strcpy(from.sa_data,"eth0");
	if(fd<0)
	{
		printf("fd error\n");
	}
	while(1)
	{
		sleep(1);
		sendto(fd,tmpbuf,buflen,0,&from,sizeof(from));		
	}

}

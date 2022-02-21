#include "UdpVideo.h"
#include <stdlib.h>
#include <string.h>
#include "log.h"

UdpVideoStream::UdpVideoStream(SvideoInfo &videoInfo,SzkxaInfo gZkxaInfo)
{
    if(gZkxaInfo.chType == 'T')
    {
        exchange_ip = gZkxaInfo.strInetTasIp;
        exchange_peer_ip = gZkxaInfo.strInetUasIp;
        medio_ip = videoInfo.inetMediaIp;
        local_ip = videoInfo.inIp;
        media_port = videoInfo.inetMediaPort;
        sip_port = videoInfo.inPort;
    }
    else
    {
        exchange_ip = gZkxaInfo.strInetUasIp;
        exchange_peer_ip = gZkxaInfo.strInetTasIp;
        medio_ip = videoInfo.onetMediaIp;
        local_ip = videoInfo.outIp;
        media_port = videoInfo.onetMediaPort;
        sip_port = videoInfo.outPort;
    }
    rtp_is_tcp_or_udp = gZkxaInfo.eServiceType;
    invite_swap_port = videoInfo.inPort;
}

int UdpVideoStream::getRtpPort(char *buf,bool getVideoIP)
{
    char *pTmp,*tail;
    if((pTmp = strstr(buf,"m=video ")))
    {
        rtp_port = atoi(pTmp+ strlen("m=video "));
    }
    else
        return -1;

    if(getVideoIP == true && (pTmp = strstr(buf,"c=IN IP4 ")))
    {
        char videoIp[16] = {0};
        pTmp += strlen("c=IN IP4 ");
        tail = strstr(pTmp,"\r\n");
        strncpy(videoIp,pTmp,tail-pTmp);
        video_ip = videoIp;
    }
}
std::string UdpVideoStream::video_ip = "";
int UdpVideoStream::rtp_socket = -1;
int UdpVideoStream::exchange_rtp_socket = -1;
unsigned short UdpVideoStream::OK_port = 0;


void Authentication(const char *buf,char *response)
{
	std::string user = "luoap123";
	std::string password = "luoap123";
	char tmp[64] = {0};
	getDatas(buf,"realm=",tmp);
	std::string md5_str = user + ":" + tmp + ":" + password;
	unsigned char md5_hash_value[16] = {0};
	md5Handle(md5_str.c_str(),md5_str.size(),md5_hash_value);
	char final_md5[MAX_BUFLEN] = {0};
	hexToString(md5_hash_value,final_md5);
	memset(tmp,0,sizeof(tmp));
	getDatas(buf,"nonce=",tmp);
	strcat(final_md5,":");
	strcat(final_md5,tmp);
	strcat(final_md5,":");
	memset(tmp,0,sizeof(tmp));
	getDatas(buf,"uri=",tmp);
	std::string md5_str_2;
    std::string tmp_regist = "REGISTER:";
	md5_str_2 = tmp_regist + tmp;
    memset(md5_hash_value,0,sizeof(md5_hash_value));
	md5Handle(md5_str_2.c_str(),md5_str_2.size(),md5_hash_value);
	hexToString(md5_hash_value,final_md5);
	md5Handle(final_md5,strlen(final_md5),md5_hash_value);
	hexToString(md5_hash_value,response);
	return;
}

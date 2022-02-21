#ifndef __UDPVIDEO_H__
#define __UDPVIDEO_H__

#include <string>
#include "commonDefine.h"
#include "commonFunc.h"
using namespace std;
class UdpVideoStream
{
public:
    string exchange_ip;
    string exchange_peer_ip;
    string medio_ip;
    string local_ip;
    static string video_ip;

    string strCallid;

    unsigned short  media_port;
	unsigned short  rtp_port;
	unsigned short  rtcp_port;
    unsigned short  sip_port;
    unsigned short  invite_swap_port;
    static unsigned short  OK_port;

    unsigned short up_rtp_port;
    unsigned short up_rtcp_port;

    unsigned short low_rtp_port;
    unsigned short low_rtcp_port;

    int exchange_socket;
    int sip_socket;
    static int rtp_socket;
    static int exchange_rtp_socket;

    unsigned char upper_or_lower;
    unsigned char rtp_is_tcp_or_udp;
    int rtp_call_status; 
    int rtcp_call_status; 

public:
    UdpVideoStream() {};
	UdpVideoStream(SvideoInfo &videoInfo,SzkxaInfo gZkxaInfo);
    int getRtpPort(char *buf,bool getVideoIp = false);
};

void Authentication(const char *buf, char *response);
#endif
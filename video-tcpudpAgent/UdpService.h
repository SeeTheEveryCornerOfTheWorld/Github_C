#ifndef __UDPSERVICE_H__
#define __UDPSERVICE_H__

#include "commonHead.h"

class UdpService
{
public:
	UdpService();
	~UdpService();

	int init(int nSock, sockaddr_in& destAddr, sockaddr_in& srcAddr, const char * szAddr, const std::string &strUsername, int nType, const std::string& strDstip, int nDstPort);

	int getClientSocket();

	int sendData(int nSock, const char* data, int nDataLen);

	void getIndexAddr(string& strAddr);

private:
	int nClientSock_;			//�ͻ���sock
	sockaddr_in clientAddr_;	//�ͻ��˵�ַ

	int nServerSock_;
	sockaddr_in serverAddr_;

	string strAddr_;

	std::string strUsername_;
	int nType_;
	std::string strDstip_;
	int nDstPort_;
};

#endif

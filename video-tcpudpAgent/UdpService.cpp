#include "UdpService.h"
#include "commonFunc.h"
#include "mysqlImpl.h"

UdpService::UdpService():nType_(0)
{

}

UdpService::~UdpService()
{
	if (nType_)
	{
		char szSrcIp[16] = { 0 };
		int nSrcPort;
		getIpToString(serverAddr_.sin_addr.s_addr, szSrcIp);
		nSrcPort = ntohs(serverAddr_.sin_port);
		writeLog(strUsername_.c_str(), 2, szSrcIp, nSrcPort, strDstip_.c_str(), nDstPort_, "已断开");
	}
}

int UdpService::init(int nSock, sockaddr_in& destAddr, sockaddr_in& srcAddr, const char* szAddr, const std::string& strUsername, int nType, const std::string& strDstip, int nDstPort)
{
	nServerSock_ = nSock;
	serverAddr_ = srcAddr;
	nClientSock_ = createUdpSocket();
	clientAddr_ = destAddr;
	strAddr_ = szAddr;
	strUsername_ = strUsername;
	nType_ = nType;
	strDstip_ = strDstip;
	nDstPort_ = nDstPort;
	return nClientSock_;
}

int UdpService::getClientSocket()
{
	return nClientSock_;
}

int UdpService::sendData(int nSock, const char* data, int nDataLen)
{
	if (nSock == nClientSock_)
	{
		return sendtoToAddr(nServerSock_, data, nDataLen, serverAddr_);
	}
	return sendtoToAddr(nClientSock_, data, nDataLen, clientAddr_);
}

void UdpService::getIndexAddr(string& strAddr)
{
	strAddr = strAddr_;
}

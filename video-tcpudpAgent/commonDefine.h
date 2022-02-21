#ifndef _COMMONDEFINE_H_
#define _COMMONDEFINE_H_

#include <string>
#include <vector>
#include <sys/types.h>

#define GAP_IN 1	//内网
#define GAP_OUT 2	//外网


#define SWAP_DEV  "swap0"

#define MAX_LINKS  2048            //侦听的最大数量

#define DATA_PACK_LEN 4096			//一个数据包的长度

#define MAXBUFSIZE 1024	//最大缓冲

#define IP_LEN   16       //IP地址最大长度
#define PORT_LEN 5        //端口最大长度
#define NAMELEN  64       //名称最大长度

#define DB_CONNECT_TIMEOUT 5    //连接超时时间设定为 5 秒

#if	!defined(MIN) 
#define	MIN(a,b)		((a)>(b)?(b):(a))
#endif

#define GSI_CFG  "/srv/conf/gsi.properties"

#define LOG_FILE "/srv/zkxaAgent/log/zkxaagent_%s.log"

#define PIDFILE "/srv/zkxaAgent/tmp/zkxaagent_%s.pid"

#define BASICINFO_FILE "/srv/zkxaAgent/zkxaBasicInfo.xml"
#define MODIFY true
#define UPPER 1
#define LOWER 2
#define GETIP true
#define MAX_BUFLEN 4096
#define AUTHENTICATION 3
#define CLOSE_RTP_SOCK 1
#define TABLE_SIGN_PACKET_DETAIL 1
#define WRITE_LOG true
#define OUT_TO_IN 1
#define IN_TO_OUT 2
#define SEND 1
#define RECV 2
#define REJECT 0
#define IN_LOG "in_sign_packet_detail"
#define OUT_LOG "out_sign_packet_detail"
#define OTHER_PKTS 4   

enum EServiceType
{
	TYPE_UNKOWN = 0,
	TYPE_TCP,
	TYPE_UDP,
};

struct 	SvideoInfo
{
	char inIp[32];
	char outIp[32];
	char onetMediaIp[32];
	char inetMediaIp[32];
	int inPort;
	int outPort;
	int direct;
	int inetMediaPort;
	int onetMediaPort;
	int status;
	int src_id;
	int dst_id;
};
		

//配置信息、数据库信息、内部通讯信息等
struct SzkxaInfo
{
	EServiceType eServiceType;	//服务类型
	char chType;				//主机类型，在T端还是U端, 
	std::string strEth;			//内部交换口
	std::string strInetTasIp;	//T端的内部通讯IP
	std::string strInetUasIp;	//U端的内部通讯IP

	//配置文件信息
	std::string strInfoDir;		//配置目录
	std::string strWhblFile;	//白名单黑名单配置文件名称
	std::string strConfigFile;	//代理配置文件名称

	//数据库信息
	std::string strDbServerIp;	//数据库IP地址
	int nDbServerPort;	//数据库侦听端口
	std::string strDbUser;		//数据库用户名称
	std::string strDbPass;		//数据库用户密码
	std::string strDbName;		//数据库名称

	//TCP、UDP、TNS代理内部通讯子进程信息
	std::string strInetTasLogLevel;	//内部通讯T端日志级别
	int nInetTasPort;		//内部通讯T端端口
	std::string strInetUasLogLevel;	//内部通讯U端日志级别
	int nInetUasPort;		//内部通讯U端端口

	std::string strRockServerip;	//rocketmq服务器地址
	int nRocketPort;				//rocketmq服务器端口

};


#endif

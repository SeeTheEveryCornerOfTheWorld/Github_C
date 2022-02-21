#ifndef _COMMONDEFINE_H_
#define _COMMONDEFINE_H_

#define GAP_IN 1	//内网
#define GAP_OUT 2	//外网

#define IN_IP		"1.1.1.1"
#define OUT_IP		"1.1.1.2"
#define SWAP_DEV    "swap0"

#define MAX_LINKS  1024            //侦听的最大数量

#define MAXBUFSIZE 1024	//最大缓冲

#define IP_LEN   16       //IP地址最大长度
#define PORT_LEN 5        //端口最大长度
#define NAMELEN  64       //名称最大长度

#define EXCHANGE_PORT   15710

#define BLOCKFORERVER 65535

#define DB_CONNECT_TIMEOUT 5    //连接超时时间设定为 5 秒

// #define HASTAT_MAST		"mast"
// #define HASTAT_BACK		"back"
#define HASTAT_MAST 1
#define HASTAT_BACK 2

#define WORK_PATH	"/srv/hotStandbyService"

#define HOTINFO_ini	"/tmp/hotinfo.ini"

#if	!defined(MIN) 
#define	MIN(a,b)		((a)>(b)?(b):(a))
#endif

#define LOG_FILE	WORK_PATH"/log/hotstandby.log"

#define PIDFILE		WORK_PATH"/tmp/hotstandby.pid"

#define CONFIG_FIL	WORK_PATH"/hotstandby.ini"

#define GSI_CFG     "/srv/conf/gsi.properties"

#define HA_STAT		WORK_PATH"/tmp/ha_stat"

#define  SIGNLE_SYNC_PATH  WORK_PATH"/tmp/ha_signle" 
#define  NET_STATU_PATH  WORK_PATH"/tmp/net_statu" 

#endif

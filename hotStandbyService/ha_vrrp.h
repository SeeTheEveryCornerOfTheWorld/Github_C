#ifndef __VRRP_H__
#define __VRRP_H__

#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <vector>

// 构造此结构 参考rfc2338   5.1 section 
typedef struct
{
	uint8_t		vers_type;		// 0-3=type, 4-7=version 
	uint8_t		vrid;			//虚拟路由ID
	uint8_t		priority;		//路由优先级
	uint8_t		naddr;			//地址计数器
	uint8_t		auth_type;		/* authentification type */
	uint8_t		adver_int;		/* advertissement interval(in sec) */
	uint16_t		chksum;		/* checksum (ip-like one) */
								/* here <naddr> ip addresses */
								/* here authentification infos */
} VrrpPkt;
/*数据包的前面部分*/

typedef struct /* 存放每个网络接口 -- 参见rfc2338  6.1.1 章节*/
{
	int			auth_type;		/* authentification type. VRRP_AUTH_* */
	uint8_t		auth_data[8];	/* authentification data */
	uint32_t	ipaddr;			/* the address of the interface */
	char		hwaddr[6];		/* save really mac  */
	char		*ifname;		/* the device name for this ipaddr */
} VrrpIfname;

typedef struct
{
	uint32_t	 addr;		/* the ip address */
	int 		 prefix;		/* the mask address */
	int		 deletable;	/* =1  ip has add to ifdev  ；=0   ip remove  */
} VipAddr;/*虚拟IP地址*/

typedef struct /* save infomation of  every one virtual router  -- rfc2338  6.1.2 */
{
	int		 vrid;		//虚拟id，从1到255
	int		 priority;	//主机选举时的优先级
	int      init_master; //初始化是主机还是备机
// 	int		 naddr;		/* number of ip addresses */
// 	VipAddr  *vaddr;		/* point on the ip address array */
	std::vector<VipAddr> vecAddr;
	int		 adver_int;	/* delay between advertisements(in sec) */
	int		 preempt;	//主机重新上线时是抢占模式还是被动模式
	int		 state;		//网闸状态 init,backup,master
						/*网闸专门设计的变量，关联内外网*/
	int		 wantstate;	/* user explicitly wants a state (back/mast) */
	int		 sockfd;		/* the socket descriptor */
	int		 initF;		/* true if the struct is init */
	int		 no_vmac;	//是否启用虚拟mac地址，1使用，0不使用
						/* rfc2336  6.2 */
	uint32_t	ms_down_timer;
	uint32_t	adver_timer;//通告计时器
	VrrpIfname	vif;
} VrrpInfo;/*加密数据串*/

typedef struct virtual_ip_t
{
	char		v_server_ip[16];	//虚拟服务器IP
	char		v_mask[16];			//虚拟服务器mask
	int			net_prefix;
}virtual_ip;

//读取 网卡信息 和配置文件信息
//然后把相关的值赋给 vrrp_rt
typedef struct SHaConfig
{
	int         action; 		//=1 启用HA  ； =0  不启用
	int			ha_id;			//备份组的ID 
	int         no_virtual_mac;		//是否启用虚拟MAC
	int         ha_priority;		//本机的优先级
	int 		is_preempt;		//是否抢占机制
	int			addr_num;
	int			peer_sockfd;	//和对端通讯的套接口
	pid_t       main_pid; 		//ha 主进程的pid
	char		heartbeat_ifname[10]; 		//主备机之间心跳口
	char		ha_ifname[6][6];   //热备接口名称
	char        exchange_ip[16];	//内外网交换口的IP
	char		peer_ip[16];	//对端交换口的IP
	char		gateway3rd_ip[16];	//第三方网关
	std::vector<virtual_ip>		vectorVirtualIp;
}HaConfig;

enum VRRP_STATE
{
	VRRP_STATE_NONE = 0,
	VRRP_STATE_INIT,		//rfc2338  6.4.1
	VRRP_STATE_BACK,		//rfc2338  6.4.2
	VRRP_STATE_MAST,		//rfc2338  6.4.3
};

#define VRRP_AUTH_LEN	8

#define VRRP_VRID			3
/* protocol constants */
#define INADDR_VRRP_GROUP   0xe0000012	/* multicast addr - rfc2338   5.2.2 */
#define VRRP_IP_TTL			255			/* in and out pkt ttl -- rfc2338  5.2.3 */
#define IPPROTO_VRRP		112			/* IP protocol number -- rfc2338  5.2.4*/
#define VRRP_VERSION		2			/* current version -- rfc2338   5.3.1 */
#define VRRP_PKT_ADVERT		1			/* packet type -- rfc2338  5.3.2 */
#define VRRP_PRIO_OWNER		255			/* priority of the ip owner -- rfc2338  5.3.4 */
#define VRRP_PRIO_DFL		100			/* default priority -- rfc2338  5.3.4 */
#define VRRP_PRIO_STOP		0			/* priority to stop -- rfc2338  5.3.4 */
#define VRRP_AUTH_NONE		0			/* no authentification -- rfc2338  5.3.6 */
#define VRRP_AUTH_PASS		1			/* password authentification -- rfc2338  5.3.6 */
#define VRRP_AUTH_AH		2			/* AH(IPSec) authentification - rfc2338   5.3.6 */
#define VRRP_ADVER_DFL		1			/* advert. interval (in sec) -- rfc2338  5.3.7 */
#define VRRP_PREEMPT_DFL 	1			/* rfc2338   6.1.2.Preempt_Mode(抢占模式) */

//重新设置定时器
#define VRRP_TIMER_SET( val, delta )	(val) = VRRP_TIMER_CLK() + (delta)
#define VRRP_TIMER_SUB( t1, t2 ) 		((int32_t)(((uint32_t)t1)-((uint32_t)t2)))
#define VRRP_TIMER_DELTA( val )		VRRP_TIMER_SUB( val, VRRP_TIMER_CLK() )
//是否计时 时间到了
#define VRRP_TIMER_EXPIRED( val )	((val) && VRRP_TIMER_DELTA(val)<=0)
#define VRRP_TIMER_CLR( val ) 		(val) = 0
#define VRRP_TIMER_IS_RUNNING( val )	(val)
#define VRRP_TIMER_HZ				1000000

uint32_t VRRP_TIMER_CLK(void);

#define VRRP_IS_BAD_VID(id) ((id)<1 || (id)>255)	/* rfc2338    6.1.vrid */
#define VRRP_IS_BAD_PRIORITY(p) ((p)<1 || (p)>255)	/* rfc2338   6.1.prio */

#define VRRP_TIMER_SKEW( srv ) ((256-(srv)->priority)*VRRP_TIMER_HZ/256)
#define VRRP_MIN( a , b )	( (a) < (b) ? (a) : (b) )
#define VRRP_MAX( a , b )	( (a) > (b) ? (a) : (b) )

#endif //__VRRP_H__

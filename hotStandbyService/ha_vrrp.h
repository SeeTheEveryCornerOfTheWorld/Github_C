#ifndef __VRRP_H__
#define __VRRP_H__

#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <vector>

// ����˽ṹ �ο�rfc2338   5.1 section 
typedef struct
{
	uint8_t		vers_type;		// 0-3=type, 4-7=version 
	uint8_t		vrid;			//����·��ID
	uint8_t		priority;		//·�����ȼ�
	uint8_t		naddr;			//��ַ������
	uint8_t		auth_type;		/* authentification type */
	uint8_t		adver_int;		/* advertissement interval(in sec) */
	uint16_t		chksum;		/* checksum (ip-like one) */
								/* here <naddr> ip addresses */
								/* here authentification infos */
} VrrpPkt;
/*���ݰ���ǰ�沿��*/

typedef struct /* ���ÿ������ӿ� -- �μ�rfc2338  6.1.1 �½�*/
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
	int		 deletable;	/* =1  ip has add to ifdev  ��=0   ip remove  */
} VipAddr;/*����IP��ַ*/

typedef struct /* save infomation of  every one virtual router  -- rfc2338  6.1.2 */
{
	int		 vrid;		//����id����1��255
	int		 priority;	//����ѡ��ʱ�����ȼ�
	int      init_master; //��ʼ�����������Ǳ���
// 	int		 naddr;		/* number of ip addresses */
// 	VipAddr  *vaddr;		/* point on the ip address array */
	std::vector<VipAddr> vecAddr;
	int		 adver_int;	/* delay between advertisements(in sec) */
	int		 preempt;	//������������ʱ����ռģʽ���Ǳ���ģʽ
	int		 state;		//��բ״̬ init,backup,master
						/*��բר����Ƶı���������������*/
	int		 wantstate;	/* user explicitly wants a state (back/mast) */
	int		 sockfd;		/* the socket descriptor */
	int		 initF;		/* true if the struct is init */
	int		 no_vmac;	//�Ƿ���������mac��ַ��1ʹ�ã�0��ʹ��
						/* rfc2336  6.2 */
	uint32_t	ms_down_timer;
	uint32_t	adver_timer;//ͨ���ʱ��
	VrrpIfname	vif;
} VrrpInfo;/*�������ݴ�*/

typedef struct virtual_ip_t
{
	char		v_server_ip[16];	//���������IP
	char		v_mask[16];			//���������mask
	int			net_prefix;
}virtual_ip;

//��ȡ ������Ϣ �������ļ���Ϣ
//Ȼ�����ص�ֵ���� vrrp_rt
typedef struct SHaConfig
{
	int         action; 		//=1 ����HA  �� =0  ������
	int			ha_id;			//�������ID 
	int         no_virtual_mac;		//�Ƿ���������MAC
	int         ha_priority;		//���������ȼ�
	int 		is_preempt;		//�Ƿ���ռ����
	int			addr_num;
	int			peer_sockfd;	//�ͶԶ�ͨѶ���׽ӿ�
	pid_t       main_pid; 		//ha �����̵�pid
	char		heartbeat_ifname[10]; 		//������֮��������
	char		ha_ifname[6][6];   //�ȱ��ӿ�����
	char        exchange_ip[16];	//�����������ڵ�IP
	char		peer_ip[16];	//�Զ˽����ڵ�IP
	char		gateway3rd_ip[16];	//����������
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
#define VRRP_PREEMPT_DFL 	1			/* rfc2338   6.1.2.Preempt_Mode(��ռģʽ) */

//�������ö�ʱ��
#define VRRP_TIMER_SET( val, delta )	(val) = VRRP_TIMER_CLK() + (delta)
#define VRRP_TIMER_SUB( t1, t2 ) 		((int32_t)(((uint32_t)t1)-((uint32_t)t2)))
#define VRRP_TIMER_DELTA( val )		VRRP_TIMER_SUB( val, VRRP_TIMER_CLK() )
//�Ƿ��ʱ ʱ�䵽��
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

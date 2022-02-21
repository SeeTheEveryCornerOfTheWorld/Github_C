#include "configoption.h"
#include "commonHead.h"
#include "commonFunc.h"
#include "log.h"
#include "mysqlImpl.h"

extern int gGapSpace;

CommonInfo gCommonInfo;

int parse_value(char* str, char** key, char** value)
{
	char* p = NULL;
	int len = 0, i;

	*key = str;
	if ((p = strchr(str, '=')) == NULL)
	{
		printf("invalid key value:%s\n", str);
		return -1;
	}

	*p = 0;
	*value = p + 1;

	while (**value == ' ' || **value == '\t')
	{
		(*value)++;
	}

	len = strlen(str);
	for (i = len - 1; i > 0; i--)
	{
		if ((*key)[len] == ' ' || (*key)[len] == '\t')
			(*key)[len] = '\0';
	}

	return 0;

}

void splitString(const std::string& s, std::vector<std::string>& v, const std::string& c)
{
	std::string::size_type pos1, pos2;
	pos2 = s.find(c);
	pos1 = 0;
	while (std::string::npos != pos2)
	{
		v.push_back(s.substr(pos1, pos2 - pos1));

		pos1 = pos2 + c.size();
		pos2 = s.find(c, pos1);
	}
	if (pos1 != s.length())
		v.push_back(s.substr(pos1));
}

int get_local_ip(char * ifname, char* ip) {
	struct ifaddrs* ifAddrStruct;
	void* tmpAddrPtr = NULL;
	getifaddrs(&ifAddrStruct);
	int nFind = 0;
	ifaddrs* pIfaddrs = ifAddrStruct;
	while (pIfaddrs != NULL) {
		if (strncmp(pIfaddrs->ifa_name, ifname, strlen(ifname)) == 0 && pIfaddrs->ifa_addr->sa_family == AF_INET)
		{
			tmpAddrPtr = &((struct sockaddr_in*)pIfaddrs->ifa_addr)->sin_addr;
			inet_ntop(AF_INET, tmpAddrPtr, ip, INET_ADDRSTRLEN);
			nFind = 1;
			break;
// 			printf("%s IP Address:%s\n", ifAddrStruct->ifa_name, ip);
		}
		pIfaddrs = pIfaddrs->ifa_next;
	}
	//free ifaddrs
	freeifaddrs(ifAddrStruct);
	if (nFind)
	{ 
		return 0;
	}
	return -1;
}

//网口查找IP
uint32_t ifnameToIp(char *ifname)
{
	struct ifreq	ifr;
	int		fd = socket(AF_INET, SOCK_DGRAM, 0);
	uint32_t	addr = 0;
	if (fd < 0) 	return (-1);
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(fd, SIOCGIFADDR, (char*)&ifr) == 0)
	{
		struct sockaddr_in* sin = (struct sockaddr_in*)&ifr.ifr_addr;
		addr = ntohl(sin->sin_addr.s_addr);
		char ipaddr[16] = { 0 };
		inet_ntop(AF_INET, &(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr), ipaddr, INET_ADDRSTRLEN);
		log_debug_fmt("%s:%s", ifname, ipaddr);
	}
	else
	{
		log_error_fmt("error:[%d:%s]", errno, strerror(errno));
		char ipaddr[16] = { 0 };
		if (get_local_ip(ifname, ipaddr) == 0)
		{
			addr = getIpFromStr(ipaddr);
		}
	}
	close(fd);
	return addr;
}
/*
static char* get_ipaddr(const char* dev)
{
	int sfd, saved_errno, ret;
	struct ifreq ifr;
	char* ipaddr;

	ipaddr = (char*)malloc(INET_ADDRSTRLEN);
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, dev, IFNAMSIZ);

	sfd = socket(AF_INET, SOCK_DGRAM, 0);

	errno = saved_errno;
	ret = ioctl(sfd, SIOCGIFADDR, &ifr);
	if (ret == -1) {
		if (errno == 19) {
			fprintf(stderr, "Interface %s : No such device.\n", dev);
			exit(EXIT_FAILURE);
		}
		if (errno == 99) {
			fprintf(stderr, "Interface %s : No IPv4 address assigned.\n", dev);
			exit(EXIT_FAILURE);
		}
	}
	saved_errno = errno;

	inet_ntop(AF_INET, &(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr), ipaddr, INET_ADDRSTRLEN);

	close(sfd);
	return ipaddr;
}*/

//获取网口mac地址
int getIfnameMacToStr(char *ifname, unsigned char *addr, int addrlen)
{
	struct ifreq	ifr;
	int		fd = socket(AF_INET, SOCK_DGRAM, 0);
	int		ret;
	if (fd < 0) 	return (-1);
	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	ret = ioctl(fd, SIOCGIFHWADDR, (char *)&ifr);
	memcpy(addr, ifr.ifr_hwaddr.sa_data, addrlen);
	printf("%02X:%02X:%02X:%02X:%02X:%02X\n", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
	close(fd);
	return ret;
}

int trans_ini_to_int(char* str, char argu)
{
	char* p;
	char  temp[8];
	memset(temp, '\0', sizeof(temp));
	p = strchr(str, argu);
	if (p == NULL)
	{
		log_error_fmt("not find the %c\n", argu);
		return -1;
	}
	if (strlen(p + 1) < 1)    return 0;
	memcpy(temp, p + 1, strlen(p + 1));
	//printf("取到的用户序号=%s,len=%d\n",temp,strlen(temp));
	return atoi(temp);
}

/**********************************************************************
函数名称: getConfigToInt
函数功能: 从ini文件中读取某个选项的数值
参    数：
第    一：（I）conf_file, ini配置文件
第    二：（I）section, ini的区域
第    三：（I）key, 键
返    回： 0表示空, -1表示出错, -2表示没有选项, 大于0表示成功
作    者: 赵翌渊
建立时间: 20200710
**********************************************************************/
int getConfigToInt(const char * conf_file, const char* section, const char* key)
{
	FILE * fd;
	int    ret;
	char str[100];
	char  temp[25];
	memset(str, '\0', sizeof(str));
	memset(temp, '\0', sizeof(temp));
	snprintf(temp, sizeof(temp) - 1, "[%s]", section);	//查找[]
	fd = fopen(conf_file, "r");
	if (!fd)
	{
		log_error_fmt("open config file [%s] error.. [%d:%s]", conf_file, errno, strerror(errno));
		return -1;
	}
	while (fgets(str, sizeof(str), fd) != NULL)
	{
		//printf("str =%s  \n",str);
		if (str[0] == '#' || str[0] == ';')
		{
			//printf("str=%s len=%d\n",str,strlen(str));
			memset(str, '\0', sizeof(str));
			continue;
		}
		if (strstr(str, temp) != NULL)
		{	 // printf("str =%s      temp =%s     \n", str,temp);
			memset(str, '\0', sizeof(str));
			while (fgets(str, sizeof(str), fd) != NULL)
			{
				if (str[0] == '#' || str[0] == ';')
				{
					continue;
				}
				else if (strchr(str, '=') == NULL && strlen(str) > 2)
				{
					// printf("xxxxxxxxx  str=%s\n",str);	
					break;
				}
				else if (strstr(str, key) != NULL)
				{
					fclose(fd);
					// printf("str=%s key =%s\n",str,key); 		 
					if (strstr(str, "\r\n") != NULL)
					{
						str[strlen(str) - 2] = '\0';
					}
					else if (str[strlen(str) - 1] == '\r' || str[strlen(str) - 1] == '\n')
					{
						str[strlen(str) - 1] = '\0';
					}

					//printf("str=%s len=%d\n",str,strlen(str));
					ret = trans_ini_to_int(str, '=');
					return ret;
				}
				memset(str, '\0', sizeof(str));
			}
			//fclose(fd);
		}
	}
	fclose(fd);
	return -2;
}

/**********************************************************************
函数名称: getConfigToStr
函数功能: 从ini文件中读取某个选项的设置
参    数：
第    一：（I）conf_file, ini配置文件
第    二：（I）section, ini的区域
第    三：（I）key, 键
第    四：（O）szResult, 返回字符串
返    回： 0表示空, -1表示出错, -2表示没有选项, 大于0表示成功
作    者: 赵翌渊
建立时间: 20200710
**********************************************************************/
int getConfigToStr(const char * configFile, char* section, char* key, char* szResult)
{
	FILE * fd;
	char*  p;
	char  str[100];
	char  temp[25];
	memset(str, '\0', sizeof(str));
	memset(temp, '\0', sizeof(temp));
	snprintf(temp, sizeof(temp) - 1, "[%s]", section);	//查找[]
	fd = fopen(configFile, "r");
	if (!fd)
	{
		log_error_fmt("open config file [%s] error.. [%d:%s]", configFile, errno, strerror(errno));
		return -1;
	}
	while (fgets(str, sizeof(str), fd) != NULL)
	{
		//printf("str =%s  \n",str);
		if (str[0] == '#' || str[0] == ';')
		{
			memset(str, '\0', sizeof(str));
			continue;
		}
		if (strstr(str, temp) != NULL)
		{
			memset(str, '\0', sizeof(str));
			while (fgets(str, sizeof(str), fd) != NULL)
			{
				if (str[0] == '#' || str[0] == ';')
				{
					memset(str, '\0', sizeof(str));
					continue;
				}
				else if (strchr(str, '=') == NULL && strlen(str) > 2)
				{
					break;
				}
				else if (strstr(str, key) != NULL)
				{
					fclose(fd);
					if (strstr(str, "\r\n") != NULL)
					{
						str[strlen(str) - 2] = '\0';
					}
					else if (str[strlen(str) - 1] == '\r' || str[strlen(str) - 1] == '\n')
					{
						str[strlen(str) - 1] = '\0';
					}
					p = strchr(str, '=');
					if (strlen(p + 1) < 1)   return 0;
					memcpy(szResult, p + 1, strlen(p) - 1);
					return  1;
				}
				memset(str, '\0', sizeof(str));
			}
			//fclose(fd);
		}
	}
	fclose(fd);
	return -2;
}

/**********************************************************************
函数名称: readCommonConfigInfo
函数功能: 从公共ini文件中读取配置信息
参    数：
第    一：（I）szCommonConfigFile, 公共ini配置文件
第    二：（O）exchangeIfname, 交换口名称
第    三：（O）exchangeInip, 交换口内网IP
第    四：（O）exchangeOutip, 交换口外网IP
返    回： 0表示成功, -1表示出错
作    者: 赵翌渊
建立时间: 20200713
**********************************************************************/
int readCommonConfigInfo(const char * szCommonConfigFile, char * exchangeIfname, char* exchangeInip, char* exchangeOutip)
{
	int ret = 0;
	int sectionFlag = 0;
	FILE * fd;
	char  str[1024] = { 0 };
	char * pFind = NULL;
	fd = fopen(szCommonConfigFile, "r");
	if (!fd)
	{
		log_error_fmt("打开公共配置文件[%s] 失败=[%d:%s]", szCommonConfigFile, errno, strerror(errno));
		return -1;
	}
	while (fgets(str, sizeof(str), fd) != NULL)
	{
		if (str[0] == '#' || str[0] == ';')
		{
			memset(str, '\0', sizeof(str));
			continue;
		}
		if (sectionFlag == 0)
		{
			if (strcasestr(str, "COMMON") != NULL)
			{
				sectionFlag = 1;
			}
		}
		else
		{
			if ((pFind = strcasestr(str, "EXCHANGE_IFNAME")) != NULL)
			{
				pFind += strlen("EXCHANGE_IFNAME");
				if (strstr(pFind, "\r\n") != NULL)
				{
					pFind[strlen(pFind) - 2] = '\0';
				}
				else if (pFind[strlen(pFind) - 1] == '\r' || pFind[strlen(pFind) - 1] == '\n')
				{
					pFind[strlen(pFind) - 1] = '\0';
				}
				char * pTmp = strchr(pFind, '=');
				if (pTmp == NULL)
				{
					log_error_fmt("EXCHANGE_IFNAME 不完整");
					ret = -1;
					break;
				}
				pTmp++;
				pTmp = trim(pTmp);
				//检查网口是否存在
				char cmd[1024] = { 0 };
				snprintf(cmd, 1023, "ip a |grep %s | wc -l", pTmp);
				if (getCmdResult(cmd) == 0)
				{
					log_error_fmt("网口[%s]不存在", pTmp);
					ret = -1;
					break;
				}
				strcpy(exchangeIfname, pTmp);
			}
			else if ((pFind = strcasestr(str, "EXCHANGE_IN_IP")) != NULL)
			{
				pFind += strlen("EXCHANGE_IN_IP");
				if (strstr(pFind, "\r\n") != NULL)
				{
					pFind[strlen(pFind) - 2] = '\0';
				}
				else if (pFind[strlen(pFind) - 1] == '\r' || pFind[strlen(pFind) - 1] == '\n')
				{
					pFind[strlen(pFind) - 1] = '\0';
				}
				char * pTmp = strchr(pFind, '=');
				if (pTmp == NULL)
				{
					log_error_fmt("EXCHANGE_IN_IP 不完整");
					ret = -1;
					break;
				}
				pTmp++;
				pTmp = trim(pTmp);
				//检查地址是否网口的地址
				if (is_valid_ipv4(pTmp) != 0)
				{
					log_error_fmt("地址[%s]无效", pTmp);
					ret = -1;
					break;
				}
				strcpy(exchangeInip, pTmp);
				//确定内外网
				char cmd[1024] = { 0 };
				snprintf(cmd, 1023, "ip a show %s |grep %s | wc -l", exchangeIfname, exchangeInip);
				if (getCmdResult(cmd) == 0)
				{
					gGapSpace = GAP_OUT;
				}
				else
					gGapSpace = GAP_IN;
			}
			else if ((pFind = strcasestr(str, "EXCHANGE_OUT_IP")) != NULL)
			{
				pFind += strlen("EXCHANGE_OUT_IP");
				if (strstr(pFind, "\r\n") != NULL)
				{
					pFind[strlen(pFind) - 2] = '\0';
				}
				else if (pFind[strlen(pFind) - 1] == '\r' || pFind[strlen(pFind) - 1] == '\n')
				{
					pFind[strlen(pFind) - 1] = '\0';
				}
				char * pTmp = strchr(pFind, '=');
				if (pTmp == NULL)
				{
					log_error_fmt("EXCHANGE_OUT_IP 不完整");
					return -1;
				}
				pTmp++;
				pTmp = trim(pTmp);
				if (is_valid_ipv4(pTmp) != 0)
				{
					log_error_fmt("地址[%s]无效", pTmp);
					ret = -1;
					break;
				}
				strcpy(exchangeOutip, pTmp);
			}
		}
	}
	fclose(fd);
	if (ret)
	{
		return ret;
	}
	if (!sectionFlag)
	{
		log_error_fmt("没有块 [COMMON]");
		return -2;
	}
	return 0;
}

/**********************************************************************
函数名称: readConfigFromIni
函数功能: 从ini配置文件中读取配置信息
参    数：
第    一：（O）pHaConfig, 热备配置信息
第    二：（O）vsrv, vrrp协议信息
返    回： 0表示成功
作    者: 赵翌渊
建立时间: 20200713
**********************************************************************/
int readConfigFromIni(HaConfig * pHaConfig, VrrpInfo *vsrv)
{
	int   ret = 0;
	int	  i;
	int   net_flag;//内网=0     外网 =1
				   //uint32_t ipaddr=0;
	int	  iflist;
	int sectionFlag = 0;
	FILE * fd;
	char  str[1024] = { 0 };
	char * pFind = NULL;
	fd = fopen(CONFIG_FIL, "r");
	if (!fd)
	{
		log_error_fmt("打开配置文件 [%s] 失败... [%d:%s]", CONFIG_FIL, errno, strerror(errno));
		return -1;
	}
	std::string strVipnum = "IN_VIP_NUM";
	std::string strVipHead = "IN_VIRTUAL_IP";
	std::string strVmaskHead = "IN_VIRTUAL_MASK";
	char szVip[20] = { 0 }, szVmask[20] = { 0 };
	if (gGapSpace == GAP_OUT)
	{
		strVipnum = "OUT_VIP_NUM";
		strVipHead = "OUT_VIRTUAL_IP";
		strVmaskHead = "OUT_VIRTUAL_MASK";
	}
	int index = 0;
	char v_server_ip[16];	//虚拟服务器IP
	char v_mask[16];			//虚拟服务器mask
	while (fgets(str, sizeof(str), fd) != NULL)
	{
		if (str[0] == '#' || str[0] == ';')
		{
			memset(str, '\0', sizeof(str));
			continue;
		}
		if (sectionFlag == 0)
		{
			if (strcasestr(str, "HACONFIG") != NULL)
			{
				sectionFlag = 1;
			}
		}
		else
		{
			if ((pFind = strcasestr(str, "INIT_MASTER")) != NULL) //是否主机
			{
				pFind += strlen("INIT_MASTER");
				if (strstr(pFind, "\r\n") != NULL)
				{
					pFind[strlen(pFind) - 2] = '\0';
				}
				else if (pFind[strlen(pFind) - 1] == '\r' || pFind[strlen(pFind) - 1] == '\n')
				{
					pFind[strlen(pFind) - 1] = '\0';
				}
				char * pTmp = strchr(pFind, '=');
				if (pTmp == NULL)
				{
					log_error_fmt("INIT_MASTER 不完整");
					return -1;
				}
				pTmp++;
				pTmp = trim(pTmp);
				if (strlen(pTmp) <= 0)
				{
					log_error_fmt("INIT_MASTER 未设置值");
					ret = -1;
					break;
				}
				vsrv->init_master = atoi(pTmp);
			}
			else if ((pFind = strcasestr(str, "ACTION")) != NULL) //是否启用热备
			{
				pFind += strlen("ACTION");
				if (strstr(pFind, "\r\n") != NULL)
				{
					pFind[strlen(pFind) - 2] = '\0';
				}
				else if (pFind[strlen(pFind) - 1] == '\r' || pFind[strlen(pFind) - 1] == '\n')
				{
					pFind[strlen(pFind) - 1] = '\0';
				}
				char * pTmp = strchr(pFind, '=');
				if (pTmp == NULL)
				{
					log_error_fmt("ACTION 不完整");
					ret = -1;
					break;
				}
				pTmp++;
				pTmp = trim(pTmp);
				if (strlen(pTmp) <= 0)
				{
					log_error_fmt("ACTION 未设置值");
					ret = -1;
					break;
				}
				pHaConfig->action = atoi(pTmp);
				if (!(pHaConfig->action == 1 || pHaConfig->action == 0))
				{
					log_error_fmt("ACTION[%d]值无效, 取值为0或者1", pHaConfig->action);
					ret = -1;
					break;
				}
			}
			else if ((pFind = strcasestr(str, "HA_ID")) != NULL) //热备ID
			{
				pFind += strlen("HA_ID");
				if (strstr(pFind, "\r\n") != NULL)
				{
					pFind[strlen(pFind) - 2] = '\0';
				}
				else if (pFind[strlen(pFind) - 1] == '\r' || pFind[strlen(pFind) - 1] == '\n')
				{
					pFind[strlen(pFind) - 1] = '\0';
				}
				char * pTmp = strchr(pFind, '=');
				if (pTmp == NULL)
				{
					log_error_fmt("HA_ID 不完整");
					return -1;
				}
				pTmp++;
				pTmp = trim(pTmp);
				if (strlen(pTmp) <= 0)
				{
					log_error_fmt("HA_ID 未设置值");
					ret = -1;
					break;
				}
				pHaConfig->ha_id = atoi(pTmp);
				if (VRRP_IS_BAD_VID(pHaConfig->ha_id))
				{
					log_error_fmt("HA_ID[%d]值无效,取值范围[1-255]", pHaConfig->ha_id);
					ret = -1;
					break;
				}
			}
			else if ((pFind = strcasestr(str, "NO_VIRTRUALMAC")) != NULL) //是否使用虚拟mac
			{
				pFind += strlen("NO_VIRTRUALMAC");
				if (strstr(pFind, "\r\n") != NULL)
				{
					pFind[strlen(pFind) - 2] = '\0';
				}
				else if (pFind[strlen(pFind) - 1] == '\r' || pFind[strlen(pFind) - 1] == '\n')
				{
					pFind[strlen(pFind) - 1] = '\0';
				}
				char * pTmp = strchr(pFind, '=');
				if (pTmp == NULL)
				{
					log_error_fmt("NO_VIRTRUALMAC 不完整");
					return -1;
				}
				pTmp++;
				pTmp = trim(pTmp);
				if (strlen(pTmp) <= 0)
				{
					log_error_fmt("NO_VIRTRUALMAC 未设置值");
					ret = -1;
					break;
				}
				pHaConfig->no_virtual_mac = atoi(pTmp);
				if (!(pHaConfig->no_virtual_mac == 1 || pHaConfig->no_virtual_mac == 0))
				{
					log_error_fmt("NO_VIRTRUALMAC[%d]值无效, 取值为0或者1", pHaConfig->no_virtual_mac);
					ret = -1;
					break;
				}
			}
			else if ((pFind = strcasestr(str, "HA_PRIORITY")) != NULL) //热备优先级
			{
				pFind += strlen("HA_PRIORITY");
				if (strstr(pFind, "\r\n") != NULL)
				{
					pFind[strlen(pFind) - 2] = '\0';
				}
				else if (pFind[strlen(pFind) - 1] == '\r' || pFind[strlen(pFind) - 1] == '\n')
				{
					pFind[strlen(pFind) - 1] = '\0';
				}
				char * pTmp = strchr(pFind, '=');
				if (pTmp == NULL)
				{
					log_error_fmt("HA_PRIORITY 不完整");
					return -1;
				}
				pTmp++;
				pTmp = trim(pTmp);
				if (strlen(pTmp) <= 0)
				{
					log_error_fmt("HA_PRIORITY 未设置值");
					ret = -1;
					break;
				}
				pHaConfig->ha_priority = atoi(pTmp);
				if (VRRP_IS_BAD_PRIORITY(pHaConfig->ha_priority))
				{
					log_error_fmt("HA_PRIORITY[%d]值无效,取值范围[1-255]", pHaConfig->ha_priority);
					ret = -1;
					break;
				}
			}
			else if ((pFind = strcasestr(str, "IS_PREEMPT")) != NULL) //抢占模式还是被动模式
			{
				pFind += strlen("IS_PREEMPT");
				if (strstr(pFind, "\r\n") != NULL)
				{
					pFind[strlen(pFind) - 2] = '\0';
				}
				else if (pFind[strlen(pFind) - 1] == '\r' || pFind[strlen(pFind) - 1] == '\n')
				{
					pFind[strlen(pFind) - 1] = '\0';
				}
				char * pTmp = strchr(pFind, '=');
				if (pTmp == NULL)
				{
					log_error_fmt("IS_PREEMPT 不完整");
					return -1;
				}
				pTmp++;
				pTmp = trim(pTmp);
				if (strlen(pTmp) <= 0)
				{
					log_error_fmt("IS_PREEMPT 未设置值");
					ret = -1;
					break;
				}
				pHaConfig->is_preempt = atoi(pTmp);
				if (!(pHaConfig->is_preempt == 1 || pHaConfig->is_preempt == 0))
				{
					log_error_fmt("IS_PREEMPT[%d]值无效, 取值为0或者1", pHaConfig->is_preempt);
					ret = -1;
					break;
				}
			}
			else if ((pFind = strcasestr(str, "HEARTBEAT_IFNAME")) != NULL) //心跳口
			{
				pFind += strlen("HEARTBEAT_IFNAME");
				if (strstr(pFind, "\r\n") != NULL)
				{
					pFind[strlen(pFind) - 2] = '\0';
				}
				else if (pFind[strlen(pFind) - 1] == '\r' || pFind[strlen(pFind) - 1] == '\n')
				{
					pFind[strlen(pFind) - 1] = '\0';
				}
				char * pTmp = strchr(pFind, '=');
				if (pTmp == NULL)
				{
					log_error_fmt("HEARTBEAT_IFNAME 不完整");
					return -1;
				}
				pTmp++;
				pTmp = trim(pTmp);
				if (strlen(pTmp) <= 0)
				{
					log_error_fmt("HEARTBEAT_IFNAME 未设置值");
					ret = -1;
					break;
				}
				//检查网口是否存在
				char cmd[1024] = { 0 };
				snprintf(cmd, 1023, "ip a |grep %s | wc -l", pTmp);
				if (getCmdResult(cmd) == 0)
				{
					log_error_fmt("网口[%s]不存在", pTmp);
					ret = -1;
					break;
				}				
				strcpy(pHaConfig->heartbeat_ifname, pTmp);
			}
			else if ((pFind = strcasestr(str, "LISTEN_PORT")) != NULL) //热备口
			{
				pFind += strlen("LISTEN_PORT");
				if (strstr(pFind, "\r\n") != NULL)
				{
					pFind[strlen(pFind) - 2] = '\0';
				}
				else if (pFind[strlen(pFind) - 1] == '\r' || pFind[strlen(pFind) - 1] == '\n')
				{
					pFind[strlen(pFind) - 1] = '\0';
				}
				char * pTmp = strchr(pFind, '=');
				if (pTmp == NULL)
				{
					log_error_fmt("LISTEN_PORT 不完整");
					return -1;
				}
				pTmp++;
				pTmp = trim(pTmp);
				if (strlen(pTmp) <= 0)
				{
					log_error_fmt("LISTEN_PORT 未设置值");
					ret = -1;
					break;
				}
				iflist = atoi(pTmp);
				if (!iflist)
				{
					iflist = 1;
				}
				log_debug_fmt("iflist %u", iflist);
				memset(pHaConfig->ha_ifname, 0, sizeof(pHaConfig->ha_ifname));

				for (i = 0; i < 8; i++) {
					if ((((1 & 0xFFFFFFFF) << i) & iflist) != 0) {
						sprintf(pHaConfig->ha_ifname[0], "eth%u", (i > 0) ? i + 1 : i);
						log_debug_fmt("HA net card :%s ", pHaConfig->ha_ifname[0]);
						break;
					}
				}
			}
			else if ((pFind = strcasestr(str, strVipnum.c_str())) != NULL) //虚拟IP个数
			{
				pFind += strVipnum.length();
				if (strstr(pFind, "\r\n") != NULL)
				{
					pFind[strlen(pFind) - 2] = '\0';
				}
				else if (pFind[strlen(pFind) - 1] == '\r' || pFind[strlen(pFind) - 1] == '\n')
				{
					pFind[strlen(pFind) - 1] = '\0';
				}
				char * pTmp = strchr(pFind, '=');
				if (pTmp == NULL)
				{
					log_error_fmt("%s 不完整", strVipnum.c_str());
					return -1;
				}
				pTmp++;
				pTmp = trim(pTmp);
				if (strlen(pTmp) <= 0)
				{
					log_error_fmt("%s 未设置值", strVipnum.c_str());
					ret = -1;
					break;
				}
				index = atoi(pTmp);
				i = 1;
				snprintf(szVip, 20, "%s%d", strVipHead.c_str(), i);
				snprintf(szVmask, 20, "%s%d", strVmaskHead.c_str(), i);
			}
			else if ((pFind = strcasestr(str, szVip)) != NULL) //虚拟IP
			{
				pFind += strlen(szVip);
				if (strstr(pFind, "\r\n") != NULL)
				{
					pFind[strlen(pFind) - 2] = '\0';
				}
				else if (pFind[strlen(pFind) - 1] == '\r' || pFind[strlen(pFind) - 1] == '\n')
				{
					pFind[strlen(pFind) - 1] = '\0';
				}
				char * pTmp = strchr(pFind, '=');
				if (pTmp == NULL)
				{
					log_error_fmt("%s 不完整", szVip);
					return -1;
				}
				pTmp++;
				pTmp = trim(pTmp);
				if (strlen(pTmp) <= 0)
				{
					log_error_fmt("%s 未设置值", szVip);
					ret = -1;
					break;
				}
				strcpy(v_server_ip, pTmp);
			}
			else if ((pFind = strcasestr(str, szVmask)) != NULL) //虚拟IP掩码
			{
				pFind += strlen(szVmask);
				if (strstr(pFind, "\r\n") != NULL)
				{
					pFind[strlen(pFind) - 2] = '\0';
				}
				else if (pFind[strlen(pFind) - 1] == '\r' || pFind[strlen(pFind) - 1] == '\n')
				{
					pFind[strlen(pFind) - 1] = '\0';
				}
				char * pTmp = strchr(pFind, '=');
				if (pTmp == NULL)
				{
					log_error_fmt("%s 不完整", szVmask);
					return -1;
				}
				pTmp++;
				pTmp = trim(pTmp);
				if (strlen(pTmp) <= 0)
				{
					log_error_fmt("%s 未设置值", szVmask);
					ret = -1;
					break;
				}
				strcpy(v_mask, pTmp);
				virtual_ip virIp;
				strcpy(virIp.v_server_ip, v_server_ip);
				strcpy(virIp.v_mask, v_mask);
				pHaConfig->vectorVirtualIp.push_back(virIp);
				i++;
				if (i > index)
				{
					break;
				}
				memset(v_server_ip, 0, 20);
				memset(v_mask, 0, 20);
				snprintf(szVip, 20, "%s%d", strVipHead.c_str(), i);
				snprintf(szVmask, 20, "%s%d", strVmaskHead.c_str(), i);
			}
		}
	}
	fclose(fd);
	if (!ret) //没有异常情况
	{
		vsrv->vif.ipaddr = ifnameToIp(pHaConfig->heartbeat_ifname);
		vsrv->vrid = pHaConfig->ha_id;
		vsrv->priority = pHaConfig->ha_priority;
		vsrv->preempt = pHaConfig->is_preempt;
		vsrv->no_vmac = pHaConfig->no_virtual_mac;
		vsrv->vif.ifname = pHaConfig->heartbeat_ifname;
		if (pHaConfig->no_virtual_mac == 0)
		{
			vrrp_virtrual_mac[0] = 0x00;
			vrrp_virtrual_mac[1] = 0x00;
			vrrp_virtrual_mac[2] = 0x5E;
			vrrp_virtrual_mac[3] = 0x00;
			vrrp_virtrual_mac[4] = 0x01;
			vrrp_virtrual_mac[5] = vsrv->vrid;
		}
		else {
			log_info_fmt("not use virtual mac");
		}
		if (getIfnameMacToStr(vsrv->vif.ifname, (unsigned char *)vsrv->vif.hwaddr, sizeof(vsrv->vif.hwaddr)))
		{
			log_error_fmt("Can't read the hwaddr on this interface!");
			return  -1;
		}
		for (int i=0; i<pHaConfig->vectorVirtualIp.size(); i++)
		{
			VipAddr vAddr;
			vAddr.addr = getIpFromStr(pHaConfig->vectorVirtualIp[i].v_server_ip);
			vAddr.prefix = getNetworkAddr(pHaConfig->vectorVirtualIp[i].v_server_ip, pHaConfig->vectorVirtualIp[i].v_mask);
			vAddr.deletable = 0;
			vsrv->vecAddr.push_back(vAddr);
		}
	}
	return ret;

	//热备端口
	iflist = getConfigToInt(CONFIG_FIL, "HACONF1", "LISTEM_PORT");
	if (!iflist)
	{
		iflist = 1;
	}
	log_debug_fmt("iflist %u", iflist);
	memset(pHaConfig->ha_ifname, 0, sizeof(pHaConfig->ha_ifname));

	for (i = 0; i < 8; i++) {
		if ((((1 & 0xFFFFFFFF) << i) & iflist) != 0) {
			sprintf(pHaConfig->ha_ifname[0], "eth%u", (i > 0) ? i + 1 : i);
			log_debug_fmt("HA net card :%s ", pHaConfig->ha_ifname[0]);
			break;
		}
	}

// 	ret = get_vip_from_conf(pHaConfig, vsrv, net_flag);
// 	if (ret == -1)
// 	{
// 		log_error_fmt("get_vip_from_conf  error");
// 		return  -1;
// 	}

}

/**********************************************************************
函数名称: getConfInt
函数功能: 从ini配置文件中读取整数配置信息
输入参数：
参数一：	 (I)iniFile, 配置文件
参数二：	 (I)section, 配置文件中哪一区域
参数二：	 (I)key, 配置文件中哪一字段
输出参数:
返    回： 小于0失败
作    者: 赵翌渊
建立时间: 20201023
**********************************************************************/
int getConfInt(const char * iniFile, const char* section, const char* key)
{
	FILE * fd;
	int    ret;
	char str[100];
	char  temp[25];
	memset(str, '\0', sizeof(str));
	memset(temp, '\0', sizeof(temp));
	snprintf(temp, sizeof(temp) - 1, "[%s]", section);	//查找[]
	fd = fopen(iniFile, "r");
	if (!fd)
	{
		log_error_fmt("read config file error..");
		return -1;
	}
	while (fgets(str, sizeof(str), fd) != NULL)
	{
		//printf("str =%s  \n",str);
		if (str[0] == '#' || str[0] == ';')
		{
			//printf("str=%s len=%d\n",str,strlen(str));
			memset(str, '\0', sizeof(str));
			continue;
		}
		if (strstr(str, temp) != NULL)
		{	 // printf("str =%s      temp =%s     \n", str,temp);
			memset(str, '\0', sizeof(str));
			while (fgets(str, sizeof(str), fd) != NULL)
			{
				if (str[0] == '#' || str[0] == ';')
				{
					continue;
				}
				else if (strchr(str, '=') == NULL && strlen(str) > 2)
				{
					// printf("xxxxxxxxx  str=%s\n",str);	
					break;
				}
				else if (strstr(str, key) != NULL)
				{
					fclose(fd);
					// printf("str=%s key =%s\n",str,key); 		 
					if (strstr(str, "\r\n") != NULL)
					{
						str[strlen(str) - 2] = '\0';
					}
					else if (str[strlen(str) - 1] == '\r' || str[strlen(str) - 1] == '\n')
					{
						str[strlen(str) - 1] = '\0';
					}

					//printf("str=%s len=%d\n",str,strlen(str));
					ret = trans_ini_to_int(str, '=');
					return ret;
				}
				memset(str, '\0', sizeof(str));
			}
			//fclose(fd);
		}
	}
	fclose(fd);
	return -2;
}

int readGsiini(const char* iniFile)
{
	char buf[1024], * pz;
	char* key = NULL, * value = NULL;
	FILE* fd;
	if ((fd = fopen(GSI_CFG, "rb")) == NULL)
	{
		log_error_fmt("open %s failed!%s\n", GSI_CFG, strerror(errno));
		return -1;
	}

	string strTasip;
	string strUasip;
	gCommonInfo.nPosition = 0;

	while (fgets(buf, sizeof(buf), fd) != NULL)
	{
		if (buf[0] == '#')
			continue;

		if (strlen(buf) < 3) //长度小于3肯定是非法数据
			continue;

		if ((pz = strchr(buf, 0x0D)) != NULL || (pz = strchr(buf, 0x0A)) != NULL)
			*pz = '\0';

		if (parse_value(buf, &key, &value))
			continue;

		if (!strncmp(key, "gsi.config.tasOrUas", strlen("gsi.config.tasOrUas")))
		{
			if (!strncmp(key, "gsi.config.tasOrUasStr", strlen("gsi.config.tasOrUasStr")))
			{
				continue;
			}
			if (!strncmp(value, "1", 1))
				gCommonInfo.nPosition = GAP_IN;
			else
				gCommonInfo.nPosition = GAP_OUT;
		}
		else if (!strncmp(key, "gsi.config.tas.host", strlen("gsi.config.tas.host")))
		{
			strTasip = value;
		}
		else if (!strncmp(key, "gsi.config.uas.host", strlen("gsi.config.uas.host")))
		{
			strUasip = value;
		}
		else if (!strncmp(key, "datasource.url", strlen("datasource.url")))
		{
			char szUrl[256] = { 0 };
			char szAddr[32] = { 0 };
			char szDbname[100] = { 0 };
			int port = 0;
			sscanf(value, "%*[^/]//%[^?]", szUrl);
			sscanf(szUrl, "%[0-9.]:%d/%s", szAddr, &port, szDbname);
			if (port == 0)
			{
				port = 3306;
				sscanf(szUrl, "%[0-9.]/%s", szAddr, szDbname);
			}
			gstrDBServerIp = szAddr;
			giDBServerPort = port;
			gstrDBServerName = szDbname;
		}
		else if (!strncmp(key, "datasource.username", strlen("datasource.username")))
			gstrDBServerUser = value;
		else if (!strncmp(key, "datasource.password", strlen("datasource.password")))
			gstrDBServerPass = value;
	}
	//g_gap_base_info.position = gap_get_position();
	if (gCommonInfo.nPosition == 0)
	{
		log_error_fmt("readGsiini: gCommonInfo.nPosition = 0");
		return -1;
	}
	gCommonInfo.strSwapDev = SWAP_DEV;
	if (gCommonInfo.nPosition == GAP_IN)
	{
		gCommonInfo.strLocalip = strTasip;
		gCommonInfo.strPeerip = strUasip;
	}
	else
	{
		gCommonInfo.strLocalip = strUasip;
		gCommonInfo.strPeerip = strTasip;
	}

// 	g_gap_base_info.dev_cnt = dev_get_cnt_from_cmd();
	log_debug_fmt("position = %s", (gCommonInfo.nPosition == GAP_IN) ? "IN" : "OUT");
	return 0;
}

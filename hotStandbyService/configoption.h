#ifndef __CONFIGOPTION_H__
#define __CONFIGOPTION_H__

#include "ha_vrrp.h"
#include <string>
using namespace std;

struct CommonInfo
{
	int nPosition;			//当前是内网还时外网
	string strSwapDev;		//交换口名称
	string strLanip;		//LAN交换口地址
	string strWanip;		//WAN交换口地址
	string strLocalip;		//本端交换口地址
	string strPeerip;		//对端网交换口地址
};

extern CommonInfo gCommonInfo;

extern char vrrp_virtrual_mac[6];

/**********************************************************************
函数名称: get_conf_int
函数功能: 从ini文件中读取某个选项的数值
参    数：
第    一：（I）conf_file, ini配置文件
第    二：（I）section, ini的区域
第    三：（I）key, 键
返    回： 0表示空, -1表示出错, -2表示没有选项, 大于0表示成功
作    者: 赵翌渊
建立时间: 20200408
**********************************************************************/
int getConfigToInt(const char * conf_file, const char* section, const char* key);

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
int getConfigToStr(const char * conf_file, char* section, char* key, char* szResult);

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
int readCommonConfigInfo(const char * szCommonConfigFile, char * exchangeIfname, char* exchangeInip, char* exchangeOutip);

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
int readConfigFromIni(HaConfig * pHaConfig, VrrpInfo *vsrv);

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
int getConfInt(const char * iniFile, const char* section, const char* key);

int readGsiini(const char* iniFile);

//网口查找IP
uint32_t ifnameToIp(char* ifname);

//获取网口mac地址
int getIfnameMacToStr(char* ifname, unsigned char* addr, int addrlen);

#endif //__CONFIGOPTION_H__

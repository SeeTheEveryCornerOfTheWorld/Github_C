#ifndef __CONFIGOPTION_H__
#define __CONFIGOPTION_H__

#include "ha_vrrp.h"
#include <string>
using namespace std;

struct CommonInfo
{
	int nPosition;			//��ǰ��������ʱ����
	string strSwapDev;		//����������
	string strLanip;		//LAN�����ڵ�ַ
	string strWanip;		//WAN�����ڵ�ַ
	string strLocalip;		//���˽����ڵ�ַ
	string strPeerip;		//�Զ��������ڵ�ַ
};

extern CommonInfo gCommonInfo;

extern char vrrp_virtrual_mac[6];

/**********************************************************************
��������: get_conf_int
��������: ��ini�ļ��ж�ȡĳ��ѡ�����ֵ
��    ����
��    һ����I��conf_file, ini�����ļ�
��    ������I��section, ini������
��    ������I��key, ��
��    �أ� 0��ʾ��, -1��ʾ����, -2��ʾû��ѡ��, ����0��ʾ�ɹ�
��    ��: ����Ԩ
����ʱ��: 20200408
**********************************************************************/
int getConfigToInt(const char * conf_file, const char* section, const char* key);

/**********************************************************************
��������: getConfigToStr
��������: ��ini�ļ��ж�ȡĳ��ѡ�������
��    ����
��    һ����I��conf_file, ini�����ļ�
��    ������I��section, ini������
��    ������I��key, ��
��    �ģ���O��szResult, �����ַ���
��    �أ� 0��ʾ��, -1��ʾ����, -2��ʾû��ѡ��, ����0��ʾ�ɹ�
��    ��: ����Ԩ
����ʱ��: 20200710
**********************************************************************/
int getConfigToStr(const char * conf_file, char* section, char* key, char* szResult);

/**********************************************************************
��������: readCommonConfigInfo
��������: �ӹ���ini�ļ��ж�ȡ������Ϣ
��    ����
��    һ����I��szCommonConfigFile, ����ini�����ļ�
��    ������O��exchangeIfname, ����������
��    ������O��exchangeInip, ����������IP
��    �ģ���O��exchangeOutip, ����������IP
��    �أ� 0��ʾ�ɹ�, -1��ʾ����
��    ��: ����Ԩ
����ʱ��: 20200713
**********************************************************************/
int readCommonConfigInfo(const char * szCommonConfigFile, char * exchangeIfname, char* exchangeInip, char* exchangeOutip);

/**********************************************************************
��������: readConfigFromIni
��������: ��ini�����ļ��ж�ȡ������Ϣ
��    ����
��    һ����O��pHaConfig, �ȱ�������Ϣ
��    ������O��vsrv, vrrpЭ����Ϣ
��    �أ� 0��ʾ�ɹ�
��    ��: ����Ԩ
����ʱ��: 20200713
**********************************************************************/
int readConfigFromIni(HaConfig * pHaConfig, VrrpInfo *vsrv);

/**********************************************************************
��������: getConfInt
��������: ��ini�����ļ��ж�ȡ����������Ϣ
���������
����һ��	 (I)iniFile, �����ļ�
��������	 (I)section, �����ļ�����һ����
��������	 (I)key, �����ļ�����һ�ֶ�
�������:
��    �أ� С��0ʧ��
��    ��: ����Ԩ
����ʱ��: 20201023
**********************************************************************/
int getConfInt(const char * iniFile, const char* section, const char* key);

int readGsiini(const char* iniFile);

//���ڲ���IP
uint32_t ifnameToIp(char* ifname);

//��ȡ����mac��ַ
int getIfnameMacToStr(char* ifname, unsigned char* addr, int addrlen);

#endif //__CONFIGOPTION_H__

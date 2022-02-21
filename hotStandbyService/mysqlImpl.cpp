// 
#include "mysqlImpl.h"
#include "commonDefine.h"
#include "commonFunc.h"
#include "configoption.h"
#include <string.h>
#include <stdio.h>
#include <mysql.h>

#include <iostream>

// #include "commonHead.h"
// #include "common_impl.h"

#include "log.h"

MYSQL mysql_gConn;    //mysql连接变量

std::string gstrDBServerIp; //数据库IP
int giDBServerPort;			//数据库端口
std::string gstrDBServerUser;		//数据库用户名称
std::string gstrDBServerPass;		//数据库用户密码
std::string gstrDBServerName;		//数据库名

/**********************************************************************
函数名称: connectDb
函数功能: 连接数据库
参    数：
返    回：0表示成功，其他表示失败
作    者: 李高文
建立时间: 20200303
**********************************************************************/
int connectDb()
{
	MYSQL *mysql_ret;
	unsigned int uiTimeOut;
	int iRet;
	int iRlt;
	int opt = 1;

	memset(&mysql_gConn, 0x00, sizeof(mysql_gConn));
	mysql_init(&mysql_gConn);

	uiTimeOut = DB_CONNECT_TIMEOUT;

	//设置连接超时
	iRet = mysql_options(&mysql_gConn, MYSQL_OPT_CONNECT_TIMEOUT, (const char *)&uiTimeOut);
	if (iRet)
	{
		log_error_fmt("数据库连接前设置失败 [%d:%s]", mysql_errno(&mysql_gConn), mysql_error(&mysql_gConn));
		iRlt = -1;
		goto RESULT;
	}

	//连接数据库
	mysql_ret = mysql_real_connect(&mysql_gConn, gstrDBServerIp.c_str(), gstrDBServerUser.c_str(), gstrDBServerPass.c_str(), gstrDBServerName.c_str(), giDBServerPort, NULL, CLIENT_MULTI_STATEMENTS);
	if (mysql_ret == NULL)
	{
		//fprintf(stderr, "连接数据库失败[%d][%s]\n", mysql_errno(&mysql_gConn), mysql_error(&mysql_gConn));
		log_error_fmt("dbip=[%s], user=[%s], pass=[%s], dbname=[%s], port=[%d]", gstrDBServerIp.c_str(), gstrDBServerUser.c_str(), gstrDBServerPass.c_str(), gstrDBServerName.c_str(), giDBServerPort);
		log_error_fmt("连接数据库失败 [%d:%s]", mysql_errno(&mysql_gConn), mysql_error(&mysql_gConn));
		iRlt = -1;
		sleep(3);
		goto RESULT;
	}
	iRet = mysql_set_character_set(&mysql_gConn, "utf8");
	if (iRet)
	{
		log_error_fmt("设置数据库连接字符集失败 [%d:%s]", mysql_errno(&mysql_gConn), mysql_error(&mysql_gConn));
	}
	//设置自动连接开启
	
	iRet = mysql_options(&mysql_gConn, MYSQL_OPT_RECONNECT, &opt);
	
	iRlt = 0;

RESULT:
	return iRlt;
}

/**********************************************************************
函数名称: reConnectDb
函数功能: 重新连接数据库。通常被业务函数调用，在业务函数加锁，这里不用加锁
参    数：
返    回：异常直接退出程序
作    者: 李高文
建立时间: 20200303
**********************************************************************/
int reConnectDb()
{
	MYSQL *mysql_ret;
	unsigned int uiTimeOut;
	int iRet;
	int iRlt;

	//关闭数据库
	mysql_close(&mysql_gConn);

	//开始重连
	memset(&mysql_gConn, 0x00, sizeof(mysql_gConn));
	mysql_init(&mysql_gConn);

	uiTimeOut = DB_CONNECT_TIMEOUT;

	//设置连接超时
	iRet = mysql_options(&mysql_gConn, MYSQL_OPT_CONNECT_TIMEOUT, (const char *)&uiTimeOut);
	if (iRet)
	{
		//fprintf(stderr,"Connection is timeout!\n");
// 		log(LVERR, "Connection is timeout!");
		iRlt = -1;
		goto RESULT;
	}

	//连接数据库
	mysql_ret = mysql_real_connect(&mysql_gConn, gstrDBServerIp.c_str(), gstrDBServerUser.c_str(), gstrDBServerPass.c_str(), gstrDBServerName.c_str(), giDBServerPort, NULL, 0);
	if (mysql_ret == NULL)
	{
		log_error_fmt("连接数据库失败 [%d:%s]", mysql_errno(&mysql_gConn), mysql_error(&mysql_gConn));
		iRlt = -1;
		goto RESULT;
	}
	iRlt = 0;
	mysql_query(&mysql_gConn, "use zkxasde;");
RESULT:
	return iRlt;
}

/**********************************************************************
函数名称: closeDb
函数功能: 关闭数据库
参    数：
返    回：异常直接退出程序
作    者: 李高文
建立时间: 20200303
**********************************************************************/
void closeDb()
{
	mysql_close(&mysql_gConn);
	return;
}

/**********************************************************************
函数名称: getConfigInfo
函数功能: 获取网口配置信息
输入参数：
输出参数
参数一：(O)szNetworkInterface, 网口串,如eth1,eth2...
参数二：(O)status, 启用状态:1启用 2停用 3异常
参数三：(O)logaudit_status, 启用状态:1启用 2停用
返    回：返回0成功
作    者: 赵翌渊
建立时间: 20201224
**********************************************************************/
int getConfigInfo(char * szNetworkInterface, int & status, int & logaudit_status)
{
	int iRet = 0;
	char szSql[1024] = { 0 };
	snprintf(szSql, 1024, "select a.network_card,a.status,b.logaudit_status from %s.t_snort_config a, %s.t_log_config b", gstrDBServerName.c_str(), gstrDBServerName.c_str());
	iRet = mysql_query(&mysql_gConn, szSql);
	if (iRet != 0)
	{
		log_error_fmt("sql=[%s]", szSql);
		log_error_fmt("mysql error [%d:%s]", mysql_errno(&mysql_gConn), mysql_error(&mysql_gConn));
		return iRet;
	}
	MYSQL_RES* result = mysql_store_result(&mysql_gConn);
	if (NULL == result)
	{
		log_error_fmt("mysql error [%d:%s]", mysql_errno(&mysql_gConn), mysql_error(&mysql_gConn));
		return iRet;
	}
	MYSQL_ROW row;
	while (row = mysql_fetch_row(result))
	{
		iRet = 0;
		if (row[0] != NULL || strlen(row[0]) != 0)
		{
			strcpy(szNetworkInterface, row[0]);
		}
		if (row[1] != NULL || strlen(row[1]) != 0)
		{
			status = atoi(row[1]);
		}
		if (row[2] != NULL || strlen(row[2]) != 0)
		{
			logaudit_status = atoi(row[2]);
		}
	}
	mysql_free_result(result);

	return iRet;
}

//获取热备配置信息
int getHotStandbyConfig(HaConfig* pHaConfig, VrrpInfo* vsrv)
{
	pHaConfig->vectorVirtualIp.clear();
	int iRet = 0;
	char szSql[1024] = { 0 };
	if (gCommonInfo.nPosition == GAP_IN)
	{
		snprintf(szSql, 1024, "select model,priority,status,current_type,heartbeat_card,tas_business_card,tas_vip,tas_mask from %s.t_hot_standby_config", gstrDBServerName.c_str());
	}
	else
		snprintf(szSql, 1024, "select model,priority,status,current_type,heartbeat_card,uas_business_card,uas_vip,uas_mask from %s.t_hot_standby_config", gstrDBServerName.c_str());
	iRet = mysql_query(&mysql_gConn, szSql);
	if (iRet != 0)
	{
		log_error_fmt("sql=[%s]", szSql);
		log_error_fmt("mysql error [%d:%s]", mysql_errno(&mysql_gConn), mysql_error(&mysql_gConn));
		return iRet;
	}
	MYSQL_RES* result = mysql_store_result(&mysql_gConn);
	if (NULL == result)
	{
		log_error_fmt("mysql error [%d:%s]", mysql_errno(&mysql_gConn), mysql_error(&mysql_gConn));
		return iRet;
	}
	iRet = -1;
	MYSQL_ROW row;
	while (row = mysql_fetch_row(result))
	{
		iRet = 0;
		pHaConfig->ha_id = VRRP_VRID;
		pHaConfig->no_virtual_mac = 1;
		pHaConfig->is_preempt = atoi(row[0]);
		pHaConfig->ha_priority = atoi(row[1]);
		pHaConfig->action = atoi(row[2]);
// 		vsrv->init_master = atoi(row[3]);
		strcpy(pHaConfig->heartbeat_ifname, row[4]);
		strcpy(pHaConfig->ha_ifname[0], row[5]);
		virtual_ip vip;
		strcpy(vip.v_server_ip, row[6]);
		strcpy(vip.v_mask, row[7]);
		// if (row[8] != NULL && strlen(row[8])>0)
		// {
		// 	strcpy(pHaConfig->gateway3rd_ip, row[8]);
		// }
		log_debug_fmt("vip=[%s], vmask=[%s]", vip.v_server_ip, vip.v_mask);
		if (strlen(vip.v_server_ip) == 0)
		{
			continue;
		}
		vip.net_prefix = getNetworkAddr(vip.v_server_ip, vip.v_mask);
		pHaConfig->vectorVirtualIp.push_back(vip);
	}
	mysql_free_result(result);
	if (1 != pHaConfig->action)
	{
		return 0;
	}

	if (!iRet) //没有异常情况
	{
		vsrv->vif.ipaddr = ifnameToIp(pHaConfig->ha_ifname[0]);
		vsrv->vrid = pHaConfig->ha_id;
		vsrv->priority = pHaConfig->ha_priority;
		vsrv->preempt = pHaConfig->is_preempt;
		vsrv->no_vmac = pHaConfig->no_virtual_mac;
		vsrv->vif.ifname = pHaConfig->ha_ifname[0];
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
		if (getIfnameMacToStr(vsrv->vif.ifname, (unsigned char*)vsrv->vif.hwaddr, sizeof(vsrv->vif.hwaddr)))
		{
			log_error_fmt("Can't read the hwaddr on this interface!");
			return  -1;
		}
		for (int i = 0; i < pHaConfig->vectorVirtualIp.size(); i++)
		{
			VipAddr vAddr;
			vAddr.addr = getIpFromStr(pHaConfig->vectorVirtualIp[i].v_server_ip);
			vAddr.prefix = getNetworkAddr(pHaConfig->vectorVirtualIp[i].v_server_ip, pHaConfig->vectorVirtualIp[i].v_mask);
			vAddr.deletable = 0;
			vsrv->vecAddr.push_back(vAddr);
		}
	}

	return iRet;
}

//更新热备机状态 1主机, 2备机
int updateStatus(int nStatus)
{
	int iRet = 0;
	char szSql[1024] = { 0 };
	snprintf(szSql, 1024, "update %s.t_hot_standby_config set current_type=%d", gstrDBServerName.c_str(), nStatus);
// 	log_debug_fmt("szSql=[%s]", szSql);
	iRet = mysql_query(&mysql_gConn, szSql);
	if (iRet != 0)
	{
		log_error_fmt("mysql error [%d:%s]", mysql_errno(&mysql_gConn), mysql_error(&mysql_gConn));
		return iRet;
	}
	return 0;
}

/**********************************************************************
函数名称: writeLog
函数功能: 写日志
参    数：
第    一：(I)szUsername, 操作的用户
第    二：(I)szLevel, 操作级别
第    三：(I)szClientIp, 操作用户的地址
第    四：(I)szOperation, 是什么操作
第    五：(I)szMessage, 操作描述
第    五：(I)szResult, 操作结果
返    回：0表示成功，-1查询出错
作    者: 赵翌渊
建立时间: 20200811
**********************************************************************/
int writeLog(const char * szUsername, const char * szLevel, const char * szClientIp, const char * szOperation, const char * szMessage, const char * szResult)
{
	int iRet = 0;
	char szSql[2048] = { 0 };
	if (gCommonInfo.nPosition == GAP_OUT)
	{
		snprintf(szSql, 2048, "INSERT INTO %s.t_user_log (username, `level`, ip, message, result) VALUES ('%s','%s',(SELECT ip_addr FROM zkxasde.t_user_info WHERE username='%s'),'%s','%s');",
			gstrDBServerName.c_str(), szUsername, szLevel, szUsername, szMessage, szResult);
	}
	else
	{
		snprintf(szSql, 2048, "insert into %s.t_user_log (username, level, ip, message, result) values ('%s','%s','%s','%s','%s')",
			gstrDBServerName.c_str(), szUsername, szLevel, szClientIp, szMessage, szResult);
	}
	iRet = mysql_query(&mysql_gConn, szSql);
	if (iRet != 0)
	{
		log_error_fmt("mysql error [%d:%s]", mysql_errno(&mysql_gConn), mysql_error(&mysql_gConn));
		return iRet;
	}
	return iRet;
}

/**************************************
** 执行sql语句
**************************************/
int run_sql_statement(const char* szSql)
{
	int iRet = mysql_query(&mysql_gConn, szSql);
	if (iRet != 0)
	{
		log_error_fmt("mysql error [%d:%s]", mysql_errno(&mysql_gConn), mysql_error(&mysql_gConn));
		return iRet;
	}

	return iRet;
}


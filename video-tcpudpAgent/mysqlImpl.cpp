#include "mysqlImpl.h"
#include "commonDefine.h"
#include <string.h>
#include <mysql.h>
#include <string>
#include <iostream>

#include "log.h"
#include "commonHead.h"
#include "commonFunc.h"

MYSQL mysql_gConn;    //mysql连接变量
MYSQL mysqllog_gConn;    //mysql连接变量

std::string gstrDBServerIp; //数据库IP
int giDBServerPort;			//数据库端口
std::string gstrDBUser;		//数据库用户名称
std::string gstrDBPass;		//数据库用户密码
std::string gstrDBName;		//数据库名

extern int gGapSpace;

std::string gstrTime = "2021-04-13 17:00:00"; 

/**********************************************************************
函数名称: connectDb
函数功能: 连接数据库
参    数：
第    一：（I）数据库地址
第    二：（I）数据库端口
第    三：（I）数据库用户名称
第    四：（I）数据库用户密码
第    五：（I）数据库名称
返    回：0表示成功，其他表示失败
作    者: 李高文
建立时间: 20200303
**********************************************************************/
int connectDb(const char *pcaDbServerIp, int iDbServerPort, const char *pcaDbUser, const char *pcaDbPass, const char *pcaDbName)
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
	mysql_ret = mysql_real_connect(&mysql_gConn, pcaDbServerIp, pcaDbUser, pcaDbPass, pcaDbName, iDbServerPort, NULL, CLIENT_MULTI_STATEMENTS);
	if (mysql_ret == NULL)
	{
		//fprintf(stderr, "连接数据库失败[%d][%s]\n", mysql_errno(&mysql_gConn), mysql_error(&mysql_gConn));
		log_error_fmt("连接数据库失败 [%d:%s]", mysql_errno(&mysql_gConn), mysql_error(&mysql_gConn));
		iRlt = -1;
		goto RESULT;
	}
	iRet = mysql_set_character_set(&mysql_gConn, "utf8");
	if (iRet)
	{
		log_error_fmt("设置数据库连接字符集失败 [%d:%s]", mysql_errno(&mysql_gConn), mysql_error(&mysql_gConn));
	}
	//设置自动连接开启
	
	iRet = mysql_options(&mysql_gConn, MYSQL_OPT_RECONNECT, &opt);
	//设置变量，供 reConnectDb() 用
	
// 	if (pcaDbName != NULL)
// 	{
// 		gstrDBName = pcaDbName;
// 	}
	
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
	mysql_ret = mysql_real_connect(&mysql_gConn, gstrDBServerIp.c_str(), gstrDBUser.c_str(), gstrDBPass.c_str(), gstrDBName.c_str(), giDBServerPort, NULL, 0);
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



int getVideoInfo(SvideoInfo *gVideoInfos)
{
	pid_t pid = getpid();
	//log_debug_fmt("mysql ping ok");
	int iRet = -1;
	char szSql[1024] = { 0 };
	int src_id,dst_id;
	int task_counts = 0;
	snprintf(szSql, 1024, "SELECT in_port,in_ip,out_port,out_ip,src_id,dest_id,tas_or_uas,src_port,dest_port,status from %s.t_video", 
		gstrDBName.c_str());
	iRet = mysql_query(&mysql_gConn, szSql);
	MYSQL *mysql_mulconn;
	mysql_mulconn = &mysql_gConn;
	log_debug_fmt("mysql_mulconn = %p   mysql_gConn=%p",mysql_mulconn,&mysql_gConn);
	if (iRet != 0)
	{
		log_error_fmt("mysql error [%d:%s]", mysql_errno(&mysql_gConn), mysql_error(&mysql_gConn));
		return iRet;
	}
	iRet = -2;
	MYSQL_RES* result = mysql_store_result(&mysql_gConn);
	if (NULL == result)
	{
		log_error_fmt("mysql error [%d:%s]", mysql_errno(&mysql_gConn), mysql_error(&mysql_gConn));
		return iRet;
	}
	iRet = 0;
	MYSQL_ROW row;

	while (row = mysql_fetch_row(result))
	{
		gVideoInfos[task_counts].inPort = atoi(row[0]);
		strcpy(gVideoInfos[task_counts].inIp,row[1]);
		gVideoInfos[task_counts].outPort= atoi(row[2]);
		strcpy(gVideoInfos[task_counts].outIp,row[3]);
		gVideoInfos[task_counts].src_id = atoi(row[4]);
		gVideoInfos[task_counts].dst_id = atoi(row[5]);
		gVideoInfos[task_counts].direct = atoi(row[6]);
		gVideoInfos[task_counts].inetMediaPort = atoi(row[7]);
		gVideoInfos[task_counts].onetMediaPort = atoi(row[8]);
		gVideoInfos[task_counts].status = atoi(row[9]);
		task_counts++;
	}
	int i;
	for(i = 0;i < task_counts; i++)
	{
		snprintf(szSql, 1024, "SELECT id,addr from %s.t_video_obj where id='%d' or id='%d'", 
		gstrDBName.c_str(),gVideoInfos[i].src_id,gVideoInfos[i].dst_id);
		iRet = mysql_query(&mysql_gConn, szSql);
		if (iRet != 0)
		{
			log_debug_fmt("mysql error [%d:%s]", mysql_errno(&mysql_gConn), mysql_error(&mysql_gConn));
			return iRet;
		}
		iRet = -2;
		result = mysql_store_result(&mysql_gConn);
		if (NULL == result)
		{
			log_debug_fmt("mysql error [%d:%s]", mysql_errno(&mysql_gConn), mysql_error(&mysql_gConn));
			return iRet;
		}
		iRet = 0;
		while (row = mysql_fetch_row(result))
		{
			if(gVideoInfos[i].src_id == atoi(row[0]))
			{
				strcpy(gVideoInfos[i].inetMediaIp,row[1]);
			}
			else if(gVideoInfos[i].dst_id == atoi(row[0]))
			{
				strcpy(gVideoInfos[i].onetMediaIp,row[1]);
			}
			iRet++;
		}
		// log_debug_fmt("%s  %s  %d   %d",gVideoInfos[i].inetMediaIp,gVideoInfos[i].onetMediaIp,gVideoInfos[i].src_id,gVideoInfos[i].dst_id);
		mysql_free_result(result);
	}
	return task_counts;
}



/**********************************************************************
函数名称: checkUserPass
函数功能: 检查用户密码是否正确
参    数：
第    一：(I)nUserid, 用户id
第    二：(I)szPass, 检查的密码
返    回：0表示密码正确，-1密码错误，-2查询出错
作    者: 赵翌渊
建立时间: 20200730
**********************************************************************/
int checkUserPass(int nUserid, const char * szPass)
{
	mysql_ping(&mysql_gConn);
	int iRet = -1;
	char szSql[1024] = { 0 };
	snprintf(szSql, 1024, "select password from %s.t_user_info where id=%d", gstrDBName.c_str(), nUserid);
	
	iRet = mysql_query(&mysql_gConn, szSql);
	if (iRet != 0)
	{
		log_error_fmt("mysql error [%d:%s]", mysql_errno(&mysql_gConn), mysql_error(&mysql_gConn));
		return iRet;
	}
	iRet = -2;
	MYSQL_RES *result = mysql_store_result(&mysql_gConn);
	if (NULL == result)
	{
		log_error_fmt("mysql error [%d:%s]", mysql_errno(&mysql_gConn), mysql_error(&mysql_gConn));
		return iRet;
	}
	MYSQL_ROW row;
	char szPassMd5[33] = { 0 };
	getMd5OfString(szPass, szPassMd5);
	while (row = mysql_fetch_row(result))
	{
		if (strcmp(szPassMd5, row[0]) == 0)
		{
			iRet = 0;
		}
		break;
	}
	log_debug_fmt("szPassMd5=[%s], row[0]=[%s]", szPassMd5, row[0]);
	mysql_free_result(result);
	return iRet;
}

/**********************************************************************
函数名称: createUserLoginErrorCount
函数功能: 创建用户登录出错计数表
参    数：
返    回：0表示成功，-1查询出错
作    者: 赵翌渊
建立时间: 20200812
**********************************************************************/
int createUserLoginErrorCount()
{
	char szSql[1024] = { 0 };
	snprintf(szSql, 1024, "CREATE TABLE IF NOT EXISTS %s.t_user_login_error (`id` int(11) NOT NULL AUTO_INCREMENT, `user_id` int(11) NOT NULL, `login_error_count` int(11) NOT NULL, PRIMARY KEY (`id`) USING BTREE, UNIQUE KEY `user_id` (`user_id`)) ENGINE=InnoDB;", gstrDBName.c_str());

	int iRet = mysql_query(&mysql_gConn, szSql);
	if (iRet != 0)
	{
		log_debug_fmt("mysql error [%d:%s]", mysql_errno(&mysql_gConn), mysql_error(&mysql_gConn));
		return iRet;
	}
	return iRet;
}

/**********************************************************************
函数名称: countUserLoginError
函数功能: 用户登录出错计数
参 数 一：(I)nUserId, 用户id
参 数 二：(I)szUsername, 用户名
参 数 三：(I)szClientIp, 用户IP
返    回：0表示成功，-1查询出错
作    者: 赵翌渊
建立时间: 20200819
**********************************************************************/
int countUserLoginError(int nUserId, const char * szUsername, const char * szClientIp)
{
	char szSql[1024] = { 0 };
	snprintf(szSql, 1024, "INSERT INTO %s.t_user_login_error(user_id,login_error_count) VALUE(%d,1) ON DUPLICATE KEY UPDATE user_id=%d,login_error_count=login_error_count+1", gstrDBName.c_str(), nUserId, nUserId);
	int iRet = mysql_query(&mysql_gConn, szSql);
	if (iRet != 0)
	{
		log_error_fmt("mysql error [%d:%s]", mysql_errno(&mysql_gConn), mysql_error(&mysql_gConn));
		return iRet;
	}
	snprintf(szSql, 1024, "UPDATE %s.t_user_info SET `status`=1,update_time=NOW() \
		WHERE id = %d AND ((SELECT error_count FROM (SELECT login_error_count AS error_count FROM %s.t_user_login_error WHERE user_id = %d) c) >= (SELECT login_error_count FROM %s.t_user_policy))",
		gstrDBName.c_str(), nUserId, gstrDBName.c_str(), nUserId, gstrDBName.c_str());
	log_debug_fmt("szSql=[%s]", szSql);
	iRet = mysql_query(&mysql_gConn, szSql);
	if (iRet != 0)
	{
		log_error_fmt("mysql error [%d:%s]", mysql_errno(&mysql_gConn), mysql_error(&mysql_gConn));
		return iRet;
	}

	snprintf(szSql, 1024, "select login_error_count from %s.t_user_login_error where user_id=%d", gstrDBName.c_str(), nUserId);
	iRet = mysql_query(&mysql_gConn, szSql);
	if (iRet != 0)
	{
		log_error_fmt("mysql error [%d:%s]", mysql_errno(&mysql_gConn), mysql_error(&mysql_gConn));
		return iRet;
	}
	MYSQL_RES *result = mysql_store_result(&mysql_gConn);
	if (NULL == result)
	{
		log_error_fmt("mysql error [%d:%s]", mysql_errno(&mysql_gConn), mysql_error(&mysql_gConn));
		return iRet;
	}
	MYSQL_ROW row;
	int flag = 0;
	while (row = mysql_fetch_row(result))
	{
		if (strcmp(row[0], "2") == 0)
		{
			flag = 1;
		}
		break;
	}
	mysql_free_result(result);
	if (flag)
	{
		char msg[1024] = { 0 };
		snprintf(msg, 1024, "%s[%s]连续登录失败被锁定", szUsername, szClientIp);
		writeLog(szUsername, "警告", szClientIp, "登录", msg, "失败");
		snprintf(szSql, 1024, "update %s.t_user_login_error set login_error_count=0 where user_id=%d", gstrDBName.c_str(), nUserId);
		mysql_query(&mysql_gConn, szSql);
	}

	return iRet;
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
	mysql_ping(&mysql_gConn);
	int iRet = 0;
	char szSql[2048] = { 0 };
	if (gGapSpace == GAP_OUT)
	{
		snprintf(szSql, 2048, "INSERT INTO %s.t_user_log (username, `level`, ip, message, result) VALUES ('%s','%s',(SELECT ip_addr FROM zkxasde.t_user_info WHERE username='%s'),'%s','%s');",
			gstrDBName.c_str(), szUsername, szLevel, szUsername, szMessage, szResult);
	}
	else
	{
		snprintf(szSql, 2048, "insert into %s.t_user_log (username, level, ip, message, result) values ('%s','%s','%s','%s','%s')",
			gstrDBName.c_str(), szUsername, szLevel, szClientIp, szMessage, szResult);
	}
	iRet = mysql_query(&mysql_gConn, szSql);
	if (iRet != 0)
	{
		log_error_fmt("mysql error [%d:%s]", mysql_errno(&mysql_gConn), mysql_error(&mysql_gConn));
		return iRet;
	}
	return iRet;
}

/**********************************************************************
函数名称: writeLog
函数功能: 写日志
输入参数：
参数一: szUsername, 操作的用户
参数二: nProtocol, 协议，1为TCP, 2为UDP
参数三: szSrcip, 源IP
参数四: nSrcPort, 源端口
参数五: szDstip, 目标IP
参数六: nDstPort, 目标端口
参数七: szOpration, 操作，连接或断开
输出参数: 无
返    回：0表示成功，-1查询出错
作    者: 赵翌渊
建立时间: 20210414
**********************************************************************/
int writeLog(const char* szUsername, int nProtocol, const char* szSrcip, int nSrcPort, const char* szDstip, int nDstPort, const char * szOpration)
{
	mysql_ping(&mysql_gConn);
	int iRet = 0;
	char szSql[2048] = { 0 };

	time_t now;
	struct tm* tm_now;
	char szCreatetime[200] = { 0 };
	time(&now);
	tm_now = localtime(&now);
	strftime(szCreatetime, 200, "%Y-%m-%d %H:%M:%S", tm_now);

	string strProxytype = "tcp";
	if (nProtocol == 2)
	{
		strProxytype = "udp";
	}

	snprintf(szSql, 2048, "INSERT INTO %s.t_proxy_log (username,proxytype,src_ip,src_port,dest_ip,dest_port,operation,create_time) VALUES ('%s','%s','%s',%d,'%s',%d,'%s','%s');",
		gstrDBName.c_str(), szUsername, strProxytype.c_str(), szSrcip, nSrcPort, szDstip, nDstPort, szOpration, szCreatetime, szCreatetime);
	iRet = mysql_query(&mysql_gConn, szSql);
	if (iRet != 0)
	{
		log_error_fmt("mysql error [%d:%s]", mysql_errno(&mysql_gConn), mysql_error(&mysql_gConn));
		return iRet;
	}
	return 0;
}

void getSingleData(const char *line, char *retData, bool getStatus)
{
	int len = strlen(line);
	int i = 0;
	while(i < len)
	{
		if(getStatus == true)
		{
			line = strchr(line,' ') + 1;
			getStatus = false;
			if(isdigit(line[i]) == false);
				return;
		}
		strncat(retData,&line[i],1);	
		if(line[i] == ' ')
		{
			return;
		}
		i++;
	}
}

int writeLog(SvideoInfo gVideoInfo, char *buf, int option, bool is_inet)
{
	//if(!(strstr(buf,"SIP/2.0 200 OK") || strstr(buf,"INVITE sip")))
	//	return 0;
	mysql_ping(&mysql_gConn);
	int iRet = 0;
	char szSql[2048] = { 0 };
	int srcPort = is_inet == true?gVideoInfo.inPort:gVideoInfo.outPort;
	char *srcIp = is_inet == true?gVideoInfo.inIp:gVideoInfo.outIp;
	int mediaPort = is_inet == true?gVideoInfo.inetMediaPort:gVideoInfo.onetMediaPort;
	char *mediaIp = is_inet == true?gVideoInfo.inetMediaIp:gVideoInfo.onetMediaIp;
	unsigned long long callId = 0;

	time_t now;
	struct tm* tm_now;
	char szCreatetime[200] = { 0 };
	time(&now);
	tm_now = localtime(&now);
	strftime(szCreatetime, 200, "%Y-%m-%d %H:%M:%S", tm_now);

	char *pCallId  = strstr(buf,"Call-ID");
	if(pCallId)
	{
		pCallId += strlen("Call-ID") + 2;
		callId = atoll(pCallId);
	}

	char first_line[1024] = {0};
	char *tail = strstr(buf,"\r\n");
	strncpy(first_line,buf,tail-buf);

	//log_debug_fmt("first_line  %s , %d ", first_line,__LINE__);


	if(option == SEND)
	{
		snprintf(szSql, 2048, "INSERT INTO %s.%s (call_id,direct,status,first_line,src_ip,src_port,dest_ip,dest_port,create_time) VALUES ('%llu','%s','%s','%s','%s','%d','%s','%d','%s');",
			gstrDBName.c_str(), is_inet == true?IN_LOG:OUT_LOG,callId,option == SEND?"转出":"转入",option == REJECT?"拒绝":"放行",first_line, srcIp, srcPort, mediaIp, mediaPort, szCreatetime);
	}
	else
	{
		snprintf(szSql, 2048, "INSERT INTO %s.%s (call_id,direct,status,first_line,src_ip,src_port,dest_ip,dest_port,create_time) VALUES ('%llu','%s','%s','%s','%s','%d','%s','%d','%s');",
			gstrDBName.c_str(), is_inet == true?IN_LOG:OUT_LOG,callId,option == SEND?"转出":"转入",option == REJECT?"拒绝":"放行",first_line, mediaIp, mediaPort, srcIp, srcPort, szCreatetime);
	}
	
	iRet = mysql_query(&mysql_gConn, szSql);
	if (iRet != 0)
	{
		log_error_fmt("mysql error [%d:%s]", mysql_errno(&mysql_gConn), mysql_error(&mysql_gConn));
		return iRet;
	}
	return 0;
}

/**********************************************************************
函数名称: updateFlow
函数功能: 更新流量
输入参数：
参数一: ulFlow，流量值
参数二: nProtocl, 协议
参数三: szCreateTime, 创建时间
参数四: szUpdateTime, 更新时间
返    回：0表示成功，-1查询出错
作    者: 赵翌渊
建立时间: 20210414
**********************************************************************/
int updateFlow(unsigned long ulFlow, int nProtocl, const char * szCreateTime, const char* szUpdateTime)
{
	mysql_ping(&mysql_gConn);
// 	return 0;
	char szSql[1024] = { 0 };
	char szProto[] = "TCP";
	int nType = 5;
	int nDirection = 1;
	if (nProtocl == 2)
	{
		nType = 6;
		strcpy(szProto, "UDP");
	}
	if (GAP_OUT == gGapSpace)
	{
		nDirection = 2;
	}

	snprintf(szSql, 1024, "INSERT INTO %s.t_statistics (task_name,type,app_type,correct_flow,total_flow,create_time,update_time) VALUES('%s',%d,%d,%llu,%llu,'%s','%s') ON DUPLICATE KEY UPDATE update_time='%s',correct_flow=correct_flow+%llu,total_flow=total_flow+%llu", 
		gstrDBName.c_str(), szProto, nType, nDirection, ulFlow, ulFlow, szCreateTime, szUpdateTime, szUpdateTime, ulFlow, ulFlow);
// 	log_debug_fmt("szSql=[%s]", szSql);
	int iRet = mysql_query(&mysql_gConn, szSql);
	if (iRet != 0)
	{
		//log_error_fmt("mysql szSql=[%s], error [%d:%s]", szSql, mysql_errno(&mysql_gConn), mysql_error(&mysql_gConn));
		return iRet;
	}
	return 0;
}

/**********************************************************************
函数名称: getUserStatus
函数功能: 获取用户在线状态
输入参数：
参数一: nUserId，用户ID
返    回：1表示在线，2表示离线，-1查询出错, 0未找到用户
作    者: 赵翌渊
建立时间: 20210412
**********************************************************************/
int getUserStatus(u_int64_t ulUserId)
{
	mysql_ping(&mysql_gConn);
	char szSql[1024] = { 0 };
	snprintf(szSql, 1024, "select online from %s.t_security_user where id=%llu", gstrDBName.c_str(), ulUserId);
	int iRet = mysql_query(&mysql_gConn, szSql);
	if (iRet != 0)
	{
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
	iRet = 0;
	while (row = mysql_fetch_row(result))
	{
		if (strcmp(row[0], "1") == 0)
		{
			iRet = 1;
		}
		else if (strcmp(row[0], "2") == 0)
		{
			iRet = 2;
		}
		break;
	}
	mysql_free_result(result);
	return iRet;
}

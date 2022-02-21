#ifndef _MYSQLIMPL_H_
#define _MYSQLIMPL_H_

#include <string>
// #include "commonHead.h"
#include "ha_vrrp.h"

extern std::string gstrDBServerIp; //数据库IP
extern int giDBServerPort;			//数据库端口
extern std::string gstrDBServerUser;		//数据库用户名称
extern std::string gstrDBServerPass;		//数据库用户密码
extern std::string gstrDBServerName;		//数据库名

/**********************************************************************
函数名称: connectDb
函数功能: 连接数据库
参    数：
返    回：0表示成功，其他表示失败
作    者: 赵翌渊
建立时间: 20200303
**********************************************************************/
int connectDb();

/**********************************************************************
函数名称: reConnectDb
函数功能: 重新连接数据库。通常被业务函数调用，在业务函数加锁，这里不用加锁
参    数：
返    回：异常直接退出程序
作    者: 赵翌渊
建立时间: 20200303
**********************************************************************/
int reConnectDb();

/**********************************************************************
函数名称: closeDb
函数功能: 关闭数据库
参    数：
返    回：异常直接退出程序
作    者: 赵翌渊
建立时间: 20200303
**********************************************************************/
void closeDb();

//获取热备配置信息
int getHotStandbyConfig(HaConfig* pHaConfig, VrrpInfo* vsrv);

//更新热备机状态 1主机, 2备机
int updateStatus(int nStatus);

/**************************************
** 执行sql语句
**************************************/
int run_sql_statement(const char* szSql);

#endif


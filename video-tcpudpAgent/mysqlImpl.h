#ifndef _MYSQLIMPL_H_
#define _MYSQLIMPL_H_

#include "commonDefine.h"
#include "commonHead.h"

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
int connectDb(const char *pcaDbServerIp, int iDbServerPort, const char *pcaDbUser, const char *pcaDbPass, const char *pcaDbName);

/**********************************************************************
函数名称: reConnectDb
函数功能: 重新连接数据库。通常被业务函数调用，在业务函数加锁，这里不用加锁
参    数：
返    回：异常直接退出程序
作    者: 李高文
建立时间: 20200303
**********************************************************************/
int reConnectDb();

/**********************************************************************
函数名称: closeDb
函数功能: 关闭数据库
参    数：
返    回：异常直接退出程序
作    者: 李高文
建立时间: 20200303
**********************************************************************/
void closeDb();

/**********************************************************************
函数名称: writeWarning
函数功能: 写报警日志
参    数：
第    一：(I)sender, 邮件发送者
第    二：(I)recver, 邮件接收者
第    三：(I)msg, 警告信息
第    四：(I)emailType, 接收邮件还是发送邮件
返    回：0写成功，其它值则失败
作    者: 赵翌渊
建立时间: 20200511
**********************************************************************/
int writeWarning(const char * sender, const char * recver, const char * msg, const char * emailType);

/**********************************************************************
函数名称: getUserInfo
函数功能: 获取用户信息
参    数：
第    一：(I)szUsername, 用户名
第    二：(I)nClientIp, 用户的地址
第    三：(O)nUserId, 用户id
第    四：(O)nGroupId, 用户组id
第    五：(O)szClientIp, 用户绑定的地址
返    回：0表示没有此用户，-1出错，-2未找到用户，-3登录地址错误，-4用户被锁定
作    者: 赵翌渊
建立时间: 20200811
**********************************************************************/
int getUserInfo(const char * szUsername, uint32_t nClientIp, int &nUserId, int &nGroupId, char * szClientIp);

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
int checkUserPass(int nUserid, const char * szPass);

/**********************************************************************
函数名称: createUserLoginErrorCount
函数功能: 创建用户登录出错计数表
参    数：
返    回：0表示成功，-1查询出错
作    者: 赵翌渊
建立时间: 20200812
**********************************************************************/
int createUserLoginErrorCount();

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
int countUserLoginError(int nUserId, const char * szUsername, const char * szClientIp);

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
int writeLog(const char * szUsername, const char * szLevel, const char * szClientIp, const char * szOperation, const char * szMessage, const char * szResult);

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
int writeLog(const char* szUsername, int nProtocol, const char* szSrcip, int nSrcPort, const char* szDstip, int nDstPort, const char* szOpration);

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
int updateFlow(unsigned long ulFlow, int nProtocl, const char* szCreateTime, const char* szUpdateTime);

/**********************************************************************
函数名称: getUserStatus
函数功能: 获取用户在线状态
输入参数：
参数一: ulUserId，用户ID
返    回：1表示在线，2表示离线，-1查询出错
作    者: 赵翌渊
建立时间: 20210412
**********************************************************************/
int getUserStatus(u_int64_t ulUserId);

int getVideoInfo(SvideoInfo *gVideoInfo);

int writeLog(SvideoInfo gVideoInfo,char *buf, int option, bool is_inet = false);

void getSingleData(const char *line, char *retData, bool getStatus = false);
#endif


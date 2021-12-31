#!/usr/bin/env python
import pymysql
import time
import sys
import os
import json


#数据库表
MYSQL_FLOW_STATISTICS		= "t_statistics" 
MYSQL_TABLE_SHAREFILE_SYNC 	= "t_sharefile_sync_config"
#文件路径配置
filePath=r"C:\Users\lf\Desktop\shareFile.conf"
tmpFilePath=r"C:\Users\lf\Desktop\tmp"
shareDir = r"C:\Users\lf\Desktop"
in_sharedir = "in"
out_sharedir = "out"
fileCounts = 0
fileSize = 0
#log日志配置
logPath=r"C:\Users\lf\Desktop\sharefile-syn.log"
#数据库配置
dbNmae = "zkxasgs"
dbUser = "root"
dbPassWd = "Zkxa~123"
dbServerIp = "192.168.0.199"
#功能初始化
check_destfile = 0
check_virus = 0	
syn_srcdest_file = 0
delete_srcfile	= 0
delete_srcdir = 0
rename_transmission = 0
sync_type = 0       
allow_files = 0
plansync = 0
playtime = 0
run	= 0


#连接数据库
db = pymysql.connect(host=dbServerIp,user=dbUser,password=dbPassWd,database=dbNmae)
cursor = db.cursor()
sqlvalues = "'test','2','5','192.168.0.132','in',administrator,'123456','192.168.0.132','in','administrator','123456','0','1','11'"
sql = "insert into %s (taskname,direct,time_interval,in_ip,in_sharedir,in_user,in_passwd,out_ip,out_sharedir,out_user,out_passwd,syn_srcdest_file,run,log_level) values('test','2','5','192.168.0.132','in','administrator','123456','192.168.0.132','in','administrator','123456','0','1','11')"%(MYSQL_TABLE_SHAREFILE_SYNC)
print(sql)
cursor.execute(sql)
db.close()
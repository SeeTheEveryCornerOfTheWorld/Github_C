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
dbNmae = "zkxagsi"
dbUser = "root"
dbPassWd = "Zkxa~123"
dbServerIp = "192.168.0.95"
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

# if(len(sys.argv) != 4):
# 	print("input error")


#连接数据库
db = pymysql.connect(host=dbServerIp,user=dbUser,password=dbPassWd,database=dbNmae)
cursor = db.cursor()

#流量测试
# localtime = time.strftime("%Y-%m-%d %H:00:00",time.localtime())
# # direct = int(sys.argv[1])
# flow_sql = "SELECT  correct_flow from %s where type='1' and app_type = %d"%(MYSQL_FLOW_STATISTICS,direct)
# cursor.execute(flow_sql)
# flow_result = cursor.fetchall()
# print(flow_result)


#初始化日志
def initLog(logPath):
	return open(logPath,'w')


#写入日志
def printLog(logFd,str):
	logFd.write("%s\n"%(str))


#读取配置文件
def read_baseConf():
	global taskname
	global in_ip
	global out_ip
	global direct
	global fileCounts
	global fileSize
	assert(os.access(filePath,os.F_OK) == True)
	fp = open(filePath,'r') 
	context = json.loads(fp.readline())
	# assert(context.has_key('in_ip'),context.has_key('out_ip'),)
	in_ip = context['in_ip']
	out_ip = context['out_ip']
	taskname = context['taskname']
	direct = int(context['direct'])
	fileCounts = int(context['filecounts'])
	fileSize = int(context['filesize'])
	fp.close()


#创建文件
def createFile(fileCounts=10,fileSize=10):
	global tmpFilePath
	if(os.path.exists(tmpFilePath) == 0):
		os.mkdir(tmpFilePath)
	for i in range(fileCounts):
		tmpfile = "%s\%d.txt"%(tmpFilePath,i)
		tmpFp = open(tmpfile,mode='w')
		tmpFp.truncate(0)
		for byte in range(fileSize):
			tmpFp.write("1")


# 获取前端配置
def get_webConf(dbname,taskname,in_ip,out_ip,direct,db):
	global MYSQL_TABLE_SHAREFILE_SYNC
	global shareDir
	global in_sharedir
	global out_sharedir
	global rename_transmission
	global delete_srcfile
	global check_virus
	global delete_srcdir
	global syn_srcdest_file
	global plansync
	global playtime
	func_sql = "SELECT  in_sharedir,out_sharedir,check_destfile,check_virus,syn_srcdest_file,delete_srcfile,delete_srcdir,rename_transmission,sync_type,allow_files,plansync,playtime,run \
	from %s where taskname='%s' and in_ip='%s' and out_ip='%s' and direct=%d"%(MYSQL_TABLE_SHAREFILE_SYNC,taskname,in_ip,out_ip,direct)
	cursor.execute(func_sql)
	shareFIleConf_result = cursor.fetchall()
	print(shareFIleConf_result)
	for row in shareFIleConf_result:
		in_sharedir = "%s\%s"%(shareDir,row[0])
		out_sharedir = "%s\%s"%(shareDir,row[1])
		check_destfile = row[2]
		check_virus = row[3]	
		syn_srcdest_file = row[4] 	
		delete_srcfile	= row[5] 		
		delete_srcdir = row[6]        
		rename_transmission = row[7]  
		sync_type = row[8]            
		allow_files = row[9]        
		plansync = row[10]		
		playtime = row[11]			
		run	= row[12]	
	db.close()


#将临时文件复制到共享目录的源端
def send_fileDir(tmpFilePath,shareDir,in_sharedir,out_sharedir,direct):
	os.system("xcopy /s %s %s"%(tmpFilePath,in_sharedir if direct == 1 else out_sharedir))


#检查目的端同步的文件是否与源端一致
def check_destDir(fileCounts,fileSize,plansync,direct,in_sharedir,out_sharedir,logFd):
	if(direct == 1):
		destFilePath = in_sharedir
	else:
		destFilePath = out_sharedir
	dstFileDir = os.listdir(destFilePath)
	desFileCounts = len(dstFileDir)
	print(desFileCounts)
	print(dstFileDir)
	size = 0
	for file in dstFileDir:
		count = os.path.getsize(os.path.join(destFilePath,file))
		size += count
	print(size)
	print(fileCounts*fileSize)
	delay_time = size/10000000
	if(delay_time < 3):
		delay_time = 3
	time.sleep(delay_time)
	#检查目的端文件数和大小和源端是否一致
	if(size != fileCounts*fileSize):
		printLog(logFd,"目的端文件数与源端不一致")
		return 
	if(desFileCounts != fileCounts):
		printLog(logFd,"目的端文件总大小与源端不一致")
		return 
	printLog(logFd,"文件从源端到目的端共享同步功能：正常")
	if(plansync != 0):
		printLog(logFd,"计划同步功能：正常")


def check_func_deleteSrc(delete_srcfile,logFd):
	if(direct == 1):
		srcShareDirPath = in_sharedir
	else:
		srcShareDirPath = out_sharedir
	if(delete_srcfile and delete_srcdir):
		time.sleep(10)
		os.mkdir(r"%s\tmpdir"%(srcShareDirPath))
		time.sleep(2)
		srcFileDir = os.listdir(srcShareDirPath)
		srcFileCounts = len(srcFileDir)
		if(srcFileCounts == 0):
			printLog(logFd,"删除源文件源目录功能：正常")
		else:
			print(srcFileCounts)
			printLog(logFd,"删除源文件源目录功能：不正常")
		return
	
	# if(delete_srcdir):
	# 	os.mkdir(r"%s\tmpdir"%(srcShareDirPath))
	# 	time.sleep(2)
	# 	if(os.path.exists(r"%s\tmpdir"%(srcShareDirPath)) == 0):
	# 		printLog(logFd,"删除源目录功能：正常")
	# 	else:
	# 		printLog(logFd,"删除源目录：不正常")
		
def check_func_planTimeSyn(plansync,playtime,direct,in_sharedir,out_sharedir,logFd):
	if (plansync == 0):
		return
	localtime = time.strftime("%H:%M",time.localtime())
	if(direct == 1):
		dstShareDir = out_sharedir
	else:
		dstShareDir = in_sharedir
	while(playtime is not localtime):
		localtime = time.strftime("%H:%M",time.localtime())
		fileCounts = os.listdir(dstShareDir)
		if(fileCounts != 0):
			printLog(logFd,"计划同步功能:不正常")
			return


def check_func_renameTransmission(rename_transmission,logFd):
	if(rename_transmission == 0):
		return
	if(direct == 1):
		destFilePath = out_sharedir
		srcFilepath  = in_sharedir
	else:
		destFilePath = in_sharedir
		srcFilepath  = out_sharedir

	tmpfile = "%s\%s.txt"%(destFilePath,"重命名测试")
	tmp_fp = open(tmpfile,mode='w')
	tmp_fp.write("1")
	tmp_fp.close()
	#等待一秒向源端复制文件
	time.sleep(1)
	os.system("xcopy /s %s %s"%(tmpfile,srcFilepath))
	#等待一秒检测目的端是否重命名成功
	time.sleep(5)
	dstRenameFile = "%s\重命名测试-副本.txt"%(destFilePath)
	print(dstRenameFile)
	if(os.access(dstRenameFile,os.F_OK)):
		printLog(logFd,"重命名测试功能:正常")
		os.remove(dstRenameFile)
	else:
		printLog(logFd,"重命名测试功能:不正常")
	
	os.remove(tmpfile)
	srcFile = "%s\%s.txt"%(srcFilepath,"重命名测试")
	if(os.access(srcFile,os.F_OK)):
		os.remove(srcFile)
	


logFd = initLog(logPath)
read_baseConf()
get_webConf(MYSQL_TABLE_SHAREFILE_SYNC,taskname,in_ip,out_ip,direct,db)
print(fileCounts)
print(fileSize)
createFile(fileCounts,fileSize)
print("%s %s %s %s %d"%(tmpFilePath,shareDir,in_sharedir,out_sharedir,direct))


#检查文件同步
check_func_planTimeSyn(plansync,playtime,direct,in_sharedir,out_sharedir,logFd)
send_fileDir(tmpFilePath,shareDir,in_sharedir,out_sharedir,direct)
check_destDir(fileCounts,fileSize,plansync,direct,in_sharedir,out_sharedir,logFd)
check_func_deleteSrc(delete_srcfile,logFd)

#检查重命名
check_func_renameTransmission(rename_transmission,logFd)


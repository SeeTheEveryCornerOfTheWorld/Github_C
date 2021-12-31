#!/usr/bin/env python
import  os
import subprocess

#rf =open("/mnt/sharefile-sync/00005_40_172.168.0.175_SMB2/File6.txt",mode='r')
rf = open("/root/readspeed.txt",mode = 'r')
command = "date"
command_ret = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE,stderr=subprocess.PIPE).communicate()
size =0
while(1):
	data=rf.read(10240)
	size += len(data)
	print("size = %d"%(size))
	if(len(data) == 0):
		break
	print("reading")
print(command_ret)
os.system("date")

#!/usr/bin/env python 
import sys
import os
import subprocess


commands = "date"
dates = subprocess.Popen(commands, shell=True, stdout=subprocess.PIPE,stderr=subprocess.PIPE).communicate()
os.system("/srv/sharefile-sync/bin/sharefile-sync")

while(1):
    	command = "ls -l /mnt/sharefile-sync/T_share_0_192.168.0.132_in/ | wc -l"
	data = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE,stderr=subprocess.PIPE).communicate()
	if(int(data[0]) > 9999):
		os.system("date")
		break
	print("counts :%s")%(data[0])
print("start :%s")%(dates[0])    


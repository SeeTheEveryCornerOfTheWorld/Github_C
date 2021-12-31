#!/usr/bin/env python
#coding=UTF-8 
import subprocess
import os
import re
ethFilePath = "/etc/sysconfig/network-scripts"

#存放电口，光口和单独的交换口
deviceToMac_1={}
deviceToMac_2={}
deviceToMac_3={}
deviceToMac_4={}


electricals = {}
fibreOpticas = {}
swaps = {}
single_fib = {}



#比较当前mac地址在字典中的排序
def mac_addr_compare(mac,maclist):
    i = 0
    mac_index = mac[15:]
    for k,v in maclist.items():
        mac_value = v[15:]
        if(mac_index > mac_value):
            i += 1
    return i


#删除文件中的指定行
def del_line(line,device_file):
    line = re.findall(r'\d',line[0])
    if(len(line) != 0):
        line = line[0]
        sed_command = "sed  -i '%dd' %s"%(int(line),device_file)
        os.system(sed_command)


#修改网口设备信息
def modify_device_name(device_name,mac,modify_name,ip_addr):
    global ethFilePath
    device_file = "%s/ifcfg-%s"%(ethFilePath,device_name)

    # if(os.access(device_file,os.F_OK) == 0):
    #     print("%s文件不存在")%(device_file)
    #     return

    ethfile  = open("%s/ifcfg-%s"%(ethFilePath,modify_name),mode = 'w')
    ethfile.write("BOOTPROTO=static\n")
    ethfile.write("DEVICE=%s\n"%(modify_name))
    ethfile.write("NAME=%s\n"%(modify_name))
    ethfile.write("NETMASK=255.255.255.0\n")
    ethfile.write("ONBOOT=yes\n")
    ethfile.write("HWADDR=%s\n"%(mac))
    ethfile.write("IPADDR=%s"%(ip_addr))
    ethfile.close()

    # command = "cat -n  %s |grep -i device |awk {'print $1'}"%(device_file)
    # command_ret = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE,stderr=subprocess.PIPE).communicate()
    # del_line(command_ret,device_file)
    
    # command = "cat -n  %s |grep -i IPADDR |awk {'print $1'}"%(device_file)
    # command_ret = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE,stderr=subprocess.PIPE).communicate()
    # del_line(command_ret,device_file)

    # command = "cat -n  %s |grep -i HWADDR |awk {'print $1'}"%(device_file)
    # command_ret = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE,stderr=subprocess.PIPE).communicate()
    # del_line(command_ret,device_file)

    # sed_command = "sed  -i 1a\HWADDR=%s %s"%(mac,device_file)
    # os.system(sed_command)
    # sed_command = "sed  -i 1a\DEVICE=%s %s"%(modify_name,device_file)
    # os.system(sed_command)
    # sed_command = "sed  -i 1a\IPADDR=%s %s"%(ip_addr,device_file)
    # os.system(sed_command)

    # rename_command = "mv %s %s/ifcfg-%s"%(device_file,ethFilePath,modify_name)
    # os.system(rename_command)

#根据ipaddr获取设备信息映射到字典中
def get_device_conf():
    command = "ip addr|awk '/..:..:..:/{if(NR>2)print $2}'"
    data = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE,stderr=subprocess.PIPE).communicate()
    macs = str(data[0])
    macList = macs.split()
    for mac in macList:
        mac_key = mac[0:-3]
        if(macs.count(mac_key) == 6):
            electricals[mac] = mac
        elif(macs.count(mac_key) == 4):
            fibreOpticas[mac] = mac
        elif (macs.count(mac_key) == 2):
            swaps[mac] = mac
        else:
            single_fib[mac] = mac


#电口，光口，交换口信息配置
def netport_conf(is_gap):
    if(is_gap == 6 or is_gap == 2):
        ip = 7
    else:
        ip = 9

    for k,v in electricals.items():
        index = mac_addr_compare(v,electricals)
        modify_name = "eth%d"%(index)
        ip_addr = "1%d2.168.%d.253"%(ip,index)
        modify_device_name(k,v,modify_name,ip_addr)

    for k,v in fibreOpticas.items():
        index = mac_addr_compare(v,fibreOpticas) + 1
        modify_name = "sfp%d"%(index)
        ip_addr = "1%d2.169.%d.253"%(ip,index)
        modify_device_name(k,v,modify_name,ip_addr)

    for k, v in swaps.items():
        index = mac_addr_compare(v, swaps)
        modify_name = "swap%d" % (index)
        ip_addr = "10.0.%d.%d" % (ip, index)
        modify_device_name(k, v, modify_name, ip_addr)

    for k, v in single_fib.items():
        index = mac_addr_compare(v, single_fib)
        modify_name = "sfp%d" % (index)
        ip_addr = "1%d2.169.%d.253" % (ip, index)
        modify_device_name(k, v, modify_name, ip_addr)

#修改字典中的网口配置
def modify_device_list():
    command = "cat -n /etc/bashrc |grep PS1="
    data = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE,stderr=subprocess.PIPE).communicate()
    if("ZK-DES" in data[0]):
        if("ZK-DES-O" in data[0]):
            is_gap = 6
        else:
            is_gap = 5
    if("ZK-SIE" in data[0]):
        if("ZK-SIE-O" in data[0]):
            is_gap = 2
        else:
            is_gap = 1
    if("ZK-USI" in data[0]):
        if("ZK-USI-O" in data[0]):
            is_gap = 2
        else:
            is_gap = 1

    rm_command = "rm -rf /etc/sysconfig/network-scripts/ifcfg-*"
    os.system(rm_command)
    netport_conf(is_gap)




get_device_conf()
modify_device_list()

    

        

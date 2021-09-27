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
def get_device_conf(deviceToMac_1,deviceToMac_2,deviceToMac_3):
    command = "ip addr"
    data = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE,stderr=subprocess.PIPE).communicate()
    ip_addr_data = str(data[0])
    while(len(ip_addr_data)):
        ret = ip_addr_data.find("link/ether")
        strlen =len("link/ether 8c:1c:da:40:cb:74")
        value = ip_addr_data[0:ret+strlen]
        ip_addr_data = ip_addr_data[ret+strlen:]
        if ("link/ether" in value):
            value_len = len(value)
            mac = value[value_len-17:value_len]
            ret = value.rfind("<")
            str1 = value[ret-20:ret-2]
            str1 = str1.split()
            length=len(str1)
            device_name = str1[length-1]
            if(len(deviceToMac_1) ==0):
                deviceToMac_1[device_name] = mac
                mac_compare_1 = mac
            elif(mac[0:-2] in mac_compare_1):
                deviceToMac_1[device_name] = mac
            elif(len(deviceToMac_2) ==0):
                deviceToMac_2[device_name] = mac
                mac_compare_2 = mac
            elif(mac[0:-2] in mac_compare_2):
                deviceToMac_2[device_name] = mac
            else:
                deviceToMac_3[device_name] = mac
        else:
            break


#电口，光口，交换口信息配置
def netport_conf(deviceToMac_electrical ,deviceToMac_fibreOptical,deviceToMac_swap,is_gap):
    if(is_gap == 6 or is_gap == 2):
        ip = 7
    else:
        ip = 9

    if(len(deviceToMac_swap) == 0):
        max_index = 5
    else:
        max_index = 6
        for k,v in deviceToMac_swap.items():
            modify_name = "swap0"
            ip_addr = "10.0.1.%d"%(is_gap)
            modify_device_name(k,v,modify_name,ip_addr)

    for k,v in deviceToMac_electrical.items():
        index = mac_addr_compare(v,deviceToMac_electrical)
        if(index<max_index):
            modify_name = "eth%d"%(index)
            ip_addr = "1%d2.168.%d.253"%(ip,index)
        else:
            modify_name = "swap0"
            ip_addr = "10.0.1.%d"%(is_gap)
        modify_device_name(k,v,modify_name,ip_addr)

    for k,v in deviceToMac_fibreOptical.items():
        index = mac_addr_compare(v,deviceToMac_fibreOptical)
        modify_name = "sfp%d"%(index)
        ip_addr = "1%d2.169.%d.253"%(ip,index)
        modify_device_name(k,v,modify_name,ip_addr)

#修改字典中的网口配置
def modify_device_list(deviceToMac_1,deviceToMac_2,deviceToMac_3):
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

    if(len(deviceToMac_1) <= 1):
        if(len(deviceToMac_2) == 6):
            netport_conf(deviceToMac_2,deviceToMac_3,deviceToMac_1,is_gap)
        else:
            netport_conf(deviceToMac_3,deviceToMac_2,deviceToMac_1,is_gap)

    if(len(deviceToMac_1) == 6):
        if(len(deviceToMac_2) > 1):
            netport_conf(deviceToMac_1,deviceToMac_2,deviceToMac_3,is_gap)
        else:
            netport_conf(deviceToMac_1,deviceToMac_3,deviceToMac_2,is_gap)

    if(len(deviceToMac_1) > 1 and len(deviceToMac_1) < 6):
        if(len(deviceToMac_2) > 1):
            netport_conf(deviceToMac_2,deviceToMac_1,deviceToMac_3,is_gap)
        else:
            netport_conf(deviceToMac_3,deviceToMac_1,deviceToMac_2,is_gap)



get_device_conf(deviceToMac_1,deviceToMac_2,deviceToMac_3)
modify_device_list(deviceToMac_1,deviceToMac_2,deviceToMac_3)

    

        

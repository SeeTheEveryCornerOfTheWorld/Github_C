#!/usr/bin/env python
#coding='utf-8'
import os

from scapy.sendrecv import sniff
from scapy.utils import wrpcap
import requests
import http.cookiejar
from bs4 import BeautifulSoup
import urllib.request as urllib2
import urllib
import json
import importlib
import sys
import re
import  time

dpkt =sniff(count = 100)
wrpcap(r"C:\Users\lf\Desktop\demo.cap",dpkt)

import dpkt
import socket
import datetime

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36'
    # ,'Cookie':'__guid=qsMfbJ6108b1cc2cf958.92325716',
}

if(len(sys.argv)!=2):
    exit(0)

addr = sys.argv[1]
print(addr)
def printPcap(pcap):
    save = open(r'C:\Users\lf\Desktop\save.txt', 'a')
    for timestamp, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf) #获得以太包，即数据链路层包
        if not isinstance(eth.data,dpkt.ip.IP):
            continue
        ip = eth.data
        # print("ip layer:"+eth.data.__class__.__name__) #以太包的数据既是网络层包
        # print("tcp layer:"+eth.data.data.__class__.__name__) #网络层包的数据既是传输层包
        #print("http layer:" + eth.data.data.data.__class__.__name__) #传输层包的数据既是应用层包
        print('Timestamp: ',str(datetime.datetime.utcfromtimestamp(timestamp))) #打印出包的抓取时间

        ip = eth.data
        do_not_fragment =bool(ip.off & dpkt.ip.IP_DF)
        more_fragments =bool(ip.off & dpkt.ip.IP_MF)
        fragment_offset = ip.off & dpkt.ip.IP_OFFMASK
        print('IP: %s -> %s (len=%d ttl=%d DF=%d MF=%d offset=%d)' % (socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst), ip.len, ip.ttl, do_not_fragment, more_fragments,fragment_offset))
        url = "https://www.ip138.com/iplookup.asp?ip=%s&action=2"%(socket.inet_ntoa(ip.dst))
        response = requests.get(url, headers=headers)
        response=response.text.encode("latin1").decode("gbk")
        data = BeautifulSoup(response, "html.parser")

        # #抓取数据
        ip = str(response).find("ip_result")
        end = str(response[ip:]).find("\n")
        ip = response[ip:ip+end]
        print(ip)
        print(addr)
        time.sleep(1)
        if(addr in ip):
            print("找到IP  %s"%(ip))
            save.write(ip)
    save.close()
    print("没有发现")
def main():
    f =open(r'C:\Users\lf\Desktop\demo.pcap','rb')
    pcap = dpkt.pcap.Reader(f)
    printPcap(pcap)

main()
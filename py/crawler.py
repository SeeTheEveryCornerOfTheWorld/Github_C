#!/usr/bin/env python3
#coding=UTF-8
import  requests
import json
import time
from selenium import webdriver
from msedge.selenium_tools import Edge, EdgeOptions
from selenium.webdriver.common.action_chains import ActionChains

udp_video_port = 7603
tcp_video_port = 7605
# 192-publicKey_1   172-publicKey_2
publicKey_1 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAn0Uy6zKA4mlO2IO6dLVV/PMl12Z7sI4Z3/w6XeGnm4AarbR64IoWp1iwbGeYhwSJCrmPyjm5qJ62yzp1GLxcXyc+HW0gtgqwEVQv9eVxfmIHEIOkF8coFfYyMDTzvcPF80G9DOwMdx1Vz2eA97qlLXanMsy1BhaHZXc8Xefkaqevjw3GY8OhccaUntEZ4odivHmR7APsfxy3Ig/qT7mlgEGcUlND8Itm43xgusV4KGyFtRsqSdrbR5ZAGSubt7G+xvGzeEjPIN+yJ1ZEvYi8jytYkZL/6RrGp7mrotEnFgGqx4u/l/1d9fMZJCGAyeP8CSIThaR3zmsyjLwXWEvWrQIDAQAB"
publicKey_2 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAi8uT9PT2U9q57DqoXt7pLRs020sZXVut8MjaywajQrCjNmF/ZwsKG/mQH9hVO/A72F1Emb96f9jPX90eNDVp3pLU/1lq0X/00CDfpFT9WcyBbNVgl0A3FmB3JYLehCLf53+rSijCJ68HUxWsyyYd4K6oCoLac6i7HuhzhCdBfoFRs7OMjoFcmIsZWyaEzW3WWhITv0gwObm+pYbV5Z2lDIXMDNW23e7dee0k90tqA3y6vyeYjcM3BGqaaHpSuxucCnlgcifgGT5Sy/D9oB5/oUWpqt8Ekp/C298nsOsj6oXT0sF78V061gN4fJpNlzAu1AF6DOgrMkjdINcRpHrv1wIDAQAB"
serverCode_1 = "2a78854e-0f3d-45fb-b102-703908341b18"
serverCode_2 = "2f841d82-26dd-4148-acc8-7243c2018873"
# cookie = {"value" :"value","name" : "name"}
# cookies = ""
header = {
	"Host": "192.168.0.82:8001",
	"Connection": "keep-alive",
	"Content-Length": "1465",
	"Accept": "application/json, text/plain, */*",
	"X-Requested-With": "XMLHttpRequest",
	"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36",
	"X-Language-Type": "zh_CN",
	"Content-Type": "application/json;charset=UTF-8",
	"Origin": "http://192.168.0.82:8001",
	"Referer":"http://192.168.0.82:8001/center/status/machines/4B61671A-F62C-4838-A311-0D2DEEE11DC1/components/ncg_5.10.101.20200212195830",
	"Accept-Encoding": "gzip, deflate",
	"Accept-Language": "zh-CN,zh;q=0.9",
	"Cookie": "JSESSIONID=3FBB4EC4E1A31B3AA79602CA25252A37; OPSMGRCASTGC=TGT-105-GDkMboKx0xmTIZnZH0yheUPsIrEA4330m7BpzkhK4VKL1w9HGi-cas",
}

header['Cookie'] = "JSESSIONID=0DD9A82037C9DF48155D632AD945AF68; OPSMGRCASTGC=TGT-138-JgAkIRUW26oQ0XP1htU5rjGsRYxRFP7CMNgL74Nz5iKvqscFCe-cas"
header['Host'] = "172.168.0.82:8001"
header['Origin'] = "http://172.168.0.82:8001"
header['Referer'] = "http://172.168.0.82:8001/center/status/machines/8524E8B7-C402-4F59-A5A3-D98888B33122/components/ncg_5.10.101.20200212195830"


def modify_udp_port(in_or_out,port):	
	datas = {"issue":"true","settings":[{"component":{"category":"","componentId":"ncg","createdAt":"","description":"","enabled":"false","existDbSegment":"false","id":"ncg_5.10.101.20200212195830","lastUpdated":"","latestVersion":"","machine":[],"name":"视频联网网关","size":0,"state":"abnormal","type":"","unsolvedAlerts":0,"version":"5.10.101.20200212195830"},"conflict":{},"hasConflict":"false","instance":{"id":"ncg_5.10.101.20200212195830_cascade_4B61671A-F62C-4838-A311-0D2DEEE11DC1_1","name":"国标联网信令服务-192.168.0.82-#1"},"item":{"addressPort":"false","addressType":"","defaultValue":"7100","description":"上下级之间标准协议sip(udp)通信端口,用于GB/T28181-2016协议通信","imageHeightMax":"","imageHeightMin":"","imageType":"","imageWidthMax":"","imageWidthMin":"","key":"gb2016UdpPort","keyName":"国标2016协议UDP端口","languages":[],"multiLanguage":"false","needRestart":"true","numberMax":"","numberMin":"","portProtocol":"udp","portRange":"false","readonly":"false","stringFormat":"","type":"port","value":"7102"},"lastUpdated":"2021-11-15T03:46:22.073Z","machine":{"createAt":"","id":"4B61671A-F62C-4838-A311-0D2DEEE11DC1","idCenter":"null","ip":"192.168.0.82","name":"Central Management Server","port":"","status":"","type":""},"result":"","service":{"id":"ncg_5.10.101.20200212195830_cascade","name":"国标联网信令服务","type":"service"},"state":"toIssue","portConflict":"false","confilctMsg":"","fontWeight":"true"}]}
	postUrl = "http://192.168.0.82:8001/center/api/settings/services"
	if(in_or_out == "u"):
		datas['settings'][0]['instance']['id'] = "ncg_5.10.101.20200212195830_cascade_8524E8B7-C402-4F59-A5A3-D98888B33122_1"
		datas['settings'][0]['instance']['name'] = "国标联网信令服务-172.168.0.82-#1"
		postUrl = "http://172.168.0.82:8001/center/api/settings/services"
	print(datas['settings'][0]['instance']['id'])
	print(datas['settings'][0]['instance']['name'])
	datas = json.dumps(datas)
	datas = json.loads(datas)
	datas['settings'][0]['item']['value'] = port
	datas = json.dumps(datas)
	responseRes = requests.post(postUrl,data = datas,headers = header)
	# responseRes = requests.get(postUrl)
	print(f"status code :{responseRes.status_code}")
	print(f"text:{responseRes.text}")

def modify_tcp_port(in_or_out,port):
	tcpdatas = {"issue":"true","settings":[{"component":{"category":"","componentId":"ncg","createdAt":"","description":"","enabled":"false","existDbSegment":"false","id":"ncg_5.10.101.20200212195830","lastUpdated":"","latestVersion":"","machine":[],"name":"视频联网网关","size":0,"state":"abnormal","type":"","unsolvedAlerts":0,"version":"5.10.101.20200212195830"},"conflict":{},"hasConflict":"false","instance":{"id":"ncg_5.10.101.20200212195830_cascade_4B61671A-F62C-4838-A311-0D2DEEE11DC1_1","name":"国标联网信令服务-192.168.0.82-#1"},"item":{"addressPort":"false","addressType":"","defaultValue":"7100","description":"上下级之间标准协议sip(tcp)通信端口,用于GB/T28181-2016协议通信","imageHeightMax":"","imageHeightMin":"","imageType":"","imageWidthMax":"","imageWidthMin":"","key":"gb2016TcpPort","keyName":"国标2016协议TCP端口","languages":[],"multiLanguage":"false","needRestart":"true","numberMax":"","numberMin":"","portProtocol":"tcp","portRange":"false","readonly":"false","stringFormat":"","type":"port","value":"7202"},"lastUpdated":"2021-11-15T02:03:49.264Z","machine":{"createAt":"","id":"4B61671A-F62C-4838-A311-0D2DEEE11DC1","idCenter":"null","ip":"192.168.0.82","name":"Central Management Server","port":"","status":"","type":""},"result":"","service":{"id":"ncg_5.10.101.20200212195830_cascade","name":"国标联网信令服务","type":"service"},"state":"toIssue","portConflict":"false","confilctMsg":"","fontWeight":"true"}]}
	postUrl = "http://192.168.0.82:8001/center/api/settings/services"
	if(in_or_out == "u"):
		tcpdatas['settings'][0]['instance']['id'] = "ncg_5.10.101.20200212195830_cascade_8524E8B7-C402-4F59-A5A3-D98888B33122_1"
		tcpdatas['settings'][0]['instance']['name'] = "国标联网信令服务-172.168.0.82-#1"
		postUrl = "http://172.168.0.82:8001/center/api/settings/services"
	tcpdatas = json.dumps(tcpdatas)
	tcpdatas = json.loads(tcpdatas)
	tcpdatas['settings'][0]['item']['value'] = port
	tcpdatas = json.dumps(tcpdatas)
	responseRes = requests.post(postUrl,data = tcpdatas,headers = header)
	print(f"status code :{responseRes.status_code}")
	print(f"text:{responseRes.text}")


def fmt_time():
	now = time.time()
	fmtTime = "%f"%now
	fmtTime = fmtTime[0:10] + fmtTime[11:14]
	return fmtTime

def modify_header(in_or_out):
	if(in_or_out == 1):
		header['Host'] = "192.168.0.82:8080"
		header['origin'] = "http://192.168.0.82:8080"
		header['Referer']  = "http://192.168.0.82:8080/ncg/"
		header['Cookie'] = "JSESSIONID=D073E44759E451CE714DCF4DC58602C0; OPSMGRCASTGC=TGT-107-U7qgeDGxiqUqmH9FlfWefUTL7wCYVCcrubs5BXDcAqoUQYUqCb-cas"
		return

	header['Host'] = "172.168.0.82:8080"
	header['origin'] = "http://172.168.0.82:8080"
	header['Referer']  = "http://172.168.0.82:8080/ncg/"
	header['Cookie'] = "JSESSIONID=CA28DDC986A385DBDBC3EE283BAAD55C; OPSMGRCASTGC=TGT-78-nMGvbxBXcj0yK0X4RhcvDI9v99nQHVviPSoCrmO3dyzuVcaeGc-cas"

def del_invite_rule(in_or_out,deleteAll):
	if(deleteAll == 0):
		return

	url = "http://172.168.0.82:8080"
	if(in_or_out == 't'):
		url = "http://192.168.0.82:8080"

	now_time = fmt_time()
	rule_url = url +"/ncg/netService/v1/gateway/signal/upAndDown?_=" + now_time
	postDatas = {"pageSize":20,"pageNo":1,"sord":"asc","start":0,"type":0,"filterCondition":{"cascadeId":"","name":"","indexCode":"","levelType":"","serverIp":""}}
	modify_header(1)
	postDatas = json.dumps(postDatas)
	getRes = requests.post(rule_url,data = postDatas,headers = header)
	invite_rule = json.loads(getRes.text)
	rule_id = invite_rule['data']['list']
	ids = []
	for id in rule_id:
		ids.append(id['id'])

	now_time = fmt_time()
	delete_id_url = url + "/ncg/netService/v1/gateway/signal/deletion?force=1&_=" + now_time
	code = requests.post(delete_id_url,data = json.dumps(ids),headers = header)
	print(delete_id_url)
	print(code.status_code)
	print(code.text)

def addUpAndDown(in_or_out,up_or_down,name,code,serverIp,serverPort,protocol):
	modify_header(1)
	now_time = fmt_time()
	postDatas = {"name":"下级","indexCode":"44030600002000192169","serverIp":"172.168.0.111","serverPort":"7100","protocol":5,"isAuth":0,"sendIdFrame":1,"publicKey":"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwSvcTq4CWs3SuSnY7vK3RUa1jba2Gg/HJPg6FGIu8lmJb3gr/CM4I5f9dA4OHMti2NMhd9kpgF1sLtrgjOT+bRU4MDS0O6xMSOuHE5M4tVb4tAAUvC0rdmk9wzUgL2Fq9gTWazHnbVY46fEKE8hu8DvCvfwJoZOwU+5ejEnudSqFHW8sd4rYPuqvbKA+DTwOVRG5DOSXLsbS6Z+wVcZoZcsPTBxrN5Gck44KjNMzqft/2pPFWIxJuYxdB1useqE9YpR+s0qwZD/dEunswtD9MQc6W9+O5asu7PsRRAlC5kMj8CC/uFcdzWqUZZWEDb9b7cBVgcMY4nPPDUT8FfezYwIDAQAB","platformType":0,"route":1,"checkRtpSource":0,"serverCode":"2f841d82-26dd-4148-acc8-7243c2018873","transMode":2,"netIp":"172.168.0.82","netId":1,"shareMark":1,"downResRootNode":"0","bautoGenerateUnit":0,"importUnitCode":"","bautoquery":0,"downResRootName":"主控中心","serverName":"cascade","bautosubscribe":0,"subscribestatus":1}
	if(up_or_down == "UP"):
		url += "/ncg/netService/v1/gateway/signal/up?_=" + now_time
		postDatas = {"name":"上级198","indexCode":"44030600002000192169","serverIp":"172.168.0.188","serverPort":"7100","protocol":5,"isAuth":0,"publicKey":"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAi8uT9PT2U9q57DqoXt7pLRs020sZXVut8MjaywajQrCjNmF/ZwsKG/mQH9hVO/A72F1Emb96f9jPX90eNDVp3pLU/1lq0X/00CDfpFT9WcyBbNVgl0A3FmB3JYLehCLf53+rSijCJ68HUxWsyyYd4K6oCoLac6i7HuhzhCdBfoFRs7OMjoFcmIsZWyaEzW3WWhITv0gwObm+pYbV5Z2lDIXMDNW23e7dee0k90tqA3y6vyeYjcM3BGqaaHpSuxucCnlgcifgGT5Sy/D9oB5/oUWpqt8Ekp/C298nsOsj6oXT0sF78V061gN4fJpNlzAu1AF6DOgrMkjdINcRpHrv1wIDAQAB","platformType":0,"rtcpTimeout":1,"sendAudio":1,"serverCode":"2f841d82-26dd-4148-acc8-7243c2018873","sendHead":1,"sipByTCP":1,"netIp":"172.168.0.82","netId":1,"shareMark":0,"serverName":"cascade"}
	
	url = "http://172.168.0.82:8080"
	if(in_or_out == 't'):
		url = "http://192.168.0.82:8080"
		postDatas['publicKey'] = publicKey_1
		postDatas['serverCode'] = serverCode_1
	url += "/ncg/netService/v1/gateway/signal/down?_=" + now_time
	postDatas['name'] = name
	postDatas['indexCode'] = code
	postDatas['serverIp'] = serverIp
	postDatas['serverPort'] = serverPort
	postDatas['protocol'] = protocol
	status_code = requests.post(url,data = json.dumps(postDatas),headers = header)
	print(status_code.status_code)
	# print(status_code.text)

def login():
	
	options = webdriver.ChromeOptions()
	url ="http://172.168.0.82:8001/center/login?service=http%3A%2F%2F192.168.0.82%3A8080%2Fncg%2F#/outDomainConfig"
	Users = "sysadmin"
	password = "Zkxa~1234"
	options.binary_location =r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"
	browser = webdriver.Chrome(options=options, executable_path=r"C:\Users\lf\Desktop\chromedriver.exe")
	browser.get(url)
	time.sleep(2)
	browser.find_element_by_name("userId")
	browser.find_element_by_name("userId").send_keys(Users)
	browser.find_element_by_name("password").click()
	browser.find_element_by_name("password").send_keys(password)
	browser.find_element_by_class_name("login-button").click()
	new_url = "http://172.168.0.82:8001/center/"
	# cookies = "JSESSIONID=" + new_url.cookies[]
	cookie = browser.get_cookies()
	# browser.add_cookie(cookie_dict = cookie)
	time.sleep(3)
	new_url = requests.get(new_url)
	print(new_url.status_code)
	print(cookie)
	time.sleep(202)
	# print(browser.page_source)#browser.page_source是获取网页的全部html
	# browser.close()
	


# modify_tcp_port('u',tcp_video_port)
# del_invite_rule('t',1)
# addUpAndDown('t',"DOWN","test1","44030500002000125461",'192.168.0.199','7400','5')
login()
#modify_udp_port('t', udp_video_port)


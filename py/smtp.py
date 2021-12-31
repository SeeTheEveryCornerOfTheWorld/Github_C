#!/usr/bin/env python
import  os
import smtplib
from email.mime.text import  MIMEText
from email.header import Header
import time
# os.environ['http_proxy'] = 'http://127.0.0.1:1080'
# os.environ['https_proxy'] = 'https://127.0.0.1:1080'


mail_host="smtp.qq.com"
mail_user='940725248'
mail_pass='kxzjwqrsveirbeaa'


send = '940725248@qq.com'
recv = ['940725248@qq.com']

message = MIMEText('a of python 邮件发送测试','plain','utf-8')
message['From'] = Header("a python测试",'utf-8')
message['To'] = Header("测试","utf-8")
subject = 'python subject 邮件测试'
message['Subject'] = Header(subject,'utf-8')

try:
    smtpobj = smtplib.SMTP_SSL(mail_host,465)
    smtpobj.login(mail_user,mail_pass)
    smtpobj.sendmail(send,recv,message.as_string())
    smtpobj.quit()
    print("邮件发送成功")
except smtplib.SMTPException as e:
    print ("Error: 无法发送邮件",e)
    time.sleep(5)


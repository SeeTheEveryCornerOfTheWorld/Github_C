#!/usr/bin/env python
#encoding=UTF-8

import  os
import socket
import  sys
import subprocess

count = len(sys.argv)
print(sys.argv)
if(count>2):
    s_or_c = sys.argv[1]
    host = sys.argv[2]

# host = socket.gethostname()
port = 9999
print(host)

print("%s 端程序"%(s_or_c))
# command =
# command_ret = subprocess.Popen(command,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE).communicate()

def daemon_init():
    pid = os.fork()
    if(pid > 0):
        sys.exit(0)
    os.chdir('/')
    os.umask(0)
    os.setsid()

    _pid = os.fork()
    if(_pid):
        sys.exit(0)

    sys.stdout.flush()
    sys.stderr.flush()


def sock_process():
    if(s_or_c == 's'):
        srvsocket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        srvsocket.bind((host,port))
        srvsocket.listen(1024)

        while(True):
            clisocket,addr = srvsocket.accept()
            print("连接地址: %s"%str(addr))
            msg = "python socket test"
            clisocket.send(msg.encode('utf-8'))
            clisocket.close()
    else:
        Clisocket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        Clisocket.connect((host,port))
        msg = Clisocket.recv(1024)
        print(msg)
        Clisocket.close()

daemon_init()
sock_process()


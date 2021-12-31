#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import sys
import time
import serial
import traceback

reload(sys)
sys.setdefaultencoding('utf-8')

def openDevice(devname):
    return serial.Serial(devname, 9600, timeout=5)
    
def ClearLCD(ser):
    ser.write(chr(0xF4))    
    
def setLight(ser):
    ser.write(chr(0xEF))
    time.sleep(1)
    ser.write(chr(0xE5))    

def WriteLCD(ser,x,y,string):
    ser.write(chr(0xB9))    
    ser.write(chr(x))
    ser.write(chr(y))
    ser.write(string.encode("gb2312"))
    ser.write(chr(0x00))
    ser.read(1)
    
if __name__=='__main__':
    if len(sys.argv) < 2:
        print 'Usage: python <SerialName>'
        sys.exit()
    ser = openDevice(sys.argv[1])
    str = "北京比福特科技发展有限公司"
        setLight(ser)
        ClearLCD(ser)
    WriteLCD(ser, 0x00, 0x00, "")
    WriteLCD(ser, 0x01, 0x00, "")
    WriteLCD(ser, 0x02, 0x00, "")
    WriteLCD(ser, 0x03, 0x00, "")
    WriteLCD(ser, 0x04, 0x00,"中科信安新LED                   ")



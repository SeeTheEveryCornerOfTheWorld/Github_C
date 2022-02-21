#! /bin/bash

CWD=$(pwd)
make clean
make

rm -rf /tmp/zkxaAgent

cd $CWD/Debug
sleep 1
mkdir -p /tmp/zkxaAgent/srv/zkxaAgent/{etc,bin,log,scriptes}
mkdir /tmp/zkxaAgent/srv/bin
#chmod +x tcpproxy_restart.sh udpproxy_restart.sh udpproxy_stop.sh tcpproxy_start.sh tcpproxy_stop.sh udpproxy_start.sh
cp zkxaAgent /tmp/zkxaAgent/srv/zkxaAgent/bin/
cd /srv/bin
chmod +x udpvsi_restart.sh udpvsi_stop.sh  udpvsi_start.sh
cp udpvsi_restart.sh udpvsi_stop.sh  udpvsi_start.sh  /tmp/zkxaAgent/srv/zkxaAgent/scriptes/
cp udpvsi_restart.sh udpvsi_stop.sh  udpvsi_start.sh  /tmp/zkxaAgent/srv/bin
cp /srv/zkxaAgent/etc/zkxaAgent.mlog /tmp/zkxaAgent/srv/zkxaAgent/etc

cd /tmp/zkxaAgent/srv/zkxaAgent/bin/
mv zkxaAgent udpvsi
cd /tmp/zkxaAgent
tar cvjf $CWD/video_udp.tar.bz2 srv

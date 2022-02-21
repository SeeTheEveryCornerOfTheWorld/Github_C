#!/bin/sh
cp ../Debug/hotStandbyService srv/hotStandbyService/bin
rm -f hotStandbyService.tar.bz2
tar cjvf hotStandbyService.tar.bz2 srv

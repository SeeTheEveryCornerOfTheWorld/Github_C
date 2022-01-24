CC	:=g++

INCLUDE_DIRS := /usr/include/libxml2/ /root/rocketmq-client-cpp-2.1.0/include
LIBRARY_DIRS := /root/rocketmq-client-cpp-2.1.0/bin/lib
LIBRARY_NAMES := xml2 mysqlclient rocketmq  pthread jsoncpp boost_atomic boost_system boost_log boost_regex boost_thread boost_filesystem boost_log_setup boost_iostreams boost_chrono boost_serialization event event_pthreads Signature 
CFLAGS := -ggdb -ffunction-sections -O0 -std=c++11
CXXFLAGS := -ggdb -ffunction-sections -O0  -std=c++11  
CXXFLAGS += $(addprefix -I,$(INCLUDE_DIRS))
CXXFLAGS += $(addprefix -L,$(LIBRARY_DIRS))
CXXFLAGS += $(addprefix -l,$(LIBRARY_NAMES))



//CFLAGS	:=-g -Wall -pthread -lmysqlclient
//CFLAGS	:=-Wall -O2 -pthread -lmysqlclient
SRCS	:=$(wildcard *.c)
CPPSRCS = $(wildcard ./*.cpp)

all	:ctest

ctest :$(CPPSRCS)
	$(CC) -fno-strict-aliasing $^ -o $@   $(CXXFLAGS)



.PHONY	:clean all

clean	:
	$(RM) sharefile-sync *.o *.out sharefile-sync.tar.bz2


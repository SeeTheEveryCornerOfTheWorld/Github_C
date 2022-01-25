#include<stdio.h>
#include<string.h>
#include<sys/socket.h>
#include<sys/types.h>
#include<errno.h>
#include<netinet/in.h>
#include<event.h>
#include<time.h>
#include<sys/epoll.h>
#include<ev.h>
int count =0;
void callback(int srv,short int event,void *arg)
{
	char buf[1024]={0};
        struct sockaddr_in cli;
        socklen_t addrlen = sizeof(cli);
	recvfrom(srv,buf,sizeof(buf),0,(struct sockaddr *)&cli,&addrlen);
	printf("data:%s\n",(char *)buf);
	printf("callback  %d\n",count++);	
}

void addSocketToEpoll(int epollFd,int sock)
{
	struct epoll_event ev;
	ev.data.fd = sock;
	ev.events = EPOLLIN |EPOLLET;
	epoll_ctl(epollFd,EPOLL_CTL_ADD,sock,&ev);
	
}

int createTcp()
{
	int sock = socket(AF_INET,SOCK_STREAM,0);
	struct sockaddr_in server,cli;
	server.sin_family = AF_INET;
	server.sin_port = htons(8888);
	server.sin_addr.s_addr = inet_addr("192.168.0.101");
	socklen_t socklen = sizeof(struct sockaddr);
	int opt = SO_REUSEADDR;
	setsockopt(sock,SOL_SOCKET,opt,(char *)&opt,sizeof(opt));
	if(bind(sock,(struct sockaddr*)&server,sizeof(struct sockaddr))<0)
	{
		printf("create tcp error %s\n",strerror(errno));
	}
	if(listen(sock,1024)<0)
	{
		puts("listen error");
	}
//	if(accept(sock,(struct sockaddr *)&cli,&socklen)<0)
//	{
//		puts("accept error");
//	}
	return sock;	
}

int main(void)
{
	//struct event_base *base = event_init();
	struct event ev_call;
	struct timeval tv;
	tv.tv_sec = 1;

/*				
	int srv = socket(AF_INET,SOCK_DGRAM,0);
	struct sockaddr_in server;
	server.sin_family = AF_INET;
	server.sin_port = htons(7777);
	server.sin_addr.s_addr = inet_addr("192.168.0.101");
	
	if(bind(srv,(struct sockaddr*)&server,sizeof(struct sockaddr))<0)
	{
		printf("%s %s %s\n",__FILE__,__LINE__,strerror(errno));
		return -1;
	}
	event_init();
	event_set(&ev_call,srv,EV_READ | EV_PERSIST,callback,NULL);
	event_add(&ev_call,0);
	event_dispatch();
	printf("dispath after\n");
*/

	struct epoll_event ep_ev[1024];
	int tcp_sock = createTcp();
	int epoll_fd = epoll_create(1024);
	addSocketToEpoll(epoll_fd,tcp_sock);
	
	char buf[1024]={0};
	socklen_t socklen = sizeof(struct sockaddr);
	struct sockaddr_in cli;
	while(1)
	{
		int i = 0;
		int ret = epoll_wait(epoll_fd,ep_ev,1024,1);
		for(i = 0;i < ret; i++)
		{
			puts("accept before");
			int fd = ep_ev[i].data.fd;
		        int cli_sock = accept(fd,(struct sockaddr *)&cli,&socklen);
			struct epoll_event tmp;
			tmp.events = EPOLLIN;
			while(1)
			{ 
				if(recv(cli_sock,buf,sizeof(buf),0)<=0)
				{
					if(errno == EAGAIN)
						continue;
			//		 epoll_ctl(epoll_fd, EPOLL_CTL_DEL,fd, &tmp);
		        //                close(cli_sock);
		        //             
		        		puts("guanbi socket");
					break;
				}
			sleep(1);
			printf("TCP  recv %d:[%s]\n",strlen(buf),buf);
			}
			epoll_ctl(epoll_fd, EPOLL_CTL_DEL,fd, &tmp);
			close(cli_sock);
			close(fd);
		}
		puts("accept after");
		sleep(1);
		memset(buf,0,sizeof(buf));
	}



/*	
	struct sockaddr_in cli;
	socklen_t addrlen = sizeof(cli);
	while(1)
	{
		recvfrom(srv,buf,sizeof(buf),0,(struct sockaddr *)&cli,&addrlen);
		if(strlen(buf)<2)
			continue;
		printf("data:%s\n",(char *)buf);
		sleep(2);
	}
*/
	return 0;
	
	
}

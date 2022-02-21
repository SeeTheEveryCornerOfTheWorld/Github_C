#include "ipc.h"

// struct MsgDatas
// {
// 	char local_ip[64];
// 	char exchange_ip[64];
// 	char video_ip[64];
// 	char call_id[64];
	
// 	int  rtp_port;
// 	int  rtcp_port;
// 	int  upper_or_lower;
// 	int  rtp_is_tcp_or_udp;
// }

static int CommShm(int size,int flag)
{
    key_t key = ftok(PATHNAME,PROJ_ID);
    if(key < 0)
    {
        perror("ftok");
        return -2;
    }

    int shmid = 0;
    if((shmid = shmget(key,size,flag))<0)
    {
        perror("shmget");
        return -2;
    }
    return shmid;
}

int DestoryShm(int shmid)
{
    if((shmctl(shmid,IPC_RMID,NULL))<0)
    {
        perror("shmctl");
        return -1;
    }
    return 0;
}

int CreateShm(int size)
{
    return CommShm(size, 0666|IPC_CREAT|IPC_EXCL);
}

int GetShm(int size)
{
    return CommShm(size, IPC_CREAT);
} 


int GetMsg(void)
{
	key_t key = ftok(PATHNAME,PROJ_ID);
	int id = msgget(key,IPC_CREAT | 0666);
	return id;
}



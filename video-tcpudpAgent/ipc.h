#ifndef _IPC_H_
#define _IPC_H_
#include <stdio.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/types.h>
#include <sys/msg.h>

#define PATHNAME "."
#define PROJ_ID 0X666

int CreateShm(int size);
int DestroyShm(int shmid);
int GetShm(int size);
int GetMsg(void);
#endif
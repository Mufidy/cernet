#include <stdio.h>  
#include <string.h>  
#include <errno.h>  
#include <sys/socket.h>  
#include <resolv.h>  
#include <stdlib.h>  
#include <netinet/in.h>  
#include <arpa/inet.h>  
#include <unistd.h>  
#include <time.h>
#include "ds_lib_seu.h"

#define BUFFERT 1024
#define DATABASE_IP "::1"
#define DATABASE_PORT 7838


//0:success; else return errno
int sendData(List * pDfList);

int main()
{
    List dfeatureList;
    InitializeList(&dfeatureList);
    DFEATURE temp1 = {1.1,2.2,3.3,4.4,5.5,6.6,7.7,8.8,9.9,10.10,11.11};
    AddItem(temp1,10101,1,&dfeatureList);
    DFEATURE temp2 = {1.2,2.3,3.3,4.4,5.5,6.6,7.7,8.8,9.9,10.10,11.11};
    AddItem(temp2,10102,1,&dfeatureList);
    sendData(&dfeatureList);
    return 0;
}

//0:success; else return errno
int sendData(List * pDfList)  
{  
    int sockfd;
    struct sockaddr_in6 dest;
    char buffer[BUFFERT];  
    //char recvFileName[128];
      
    /* 创建一个 socket 用于 tcp 通信 */   
    if ((sockfd = socket(AF_INET6, SOCK_STREAM, 0)) < 0) { 
        perror("Socket");  
        return errno;
    }  
    printf("socket created\n");  
  
    /* 初始化服务器端（对方）的地址和端口信息 */  
    bzero(&dest, sizeof(dest));   
    dest.sin6_family = AF_INET6;
    dest.sin6_port = htons(DATABASE_PORT);
    if (inet_pton(AF_INET6, DATABASE_IP, &dest.sin6_addr) < 0 ) {
        perror("DATABASE_IP");  
        return errno;
    }  
    printf("address created\n");  
  
    /* 连接服务器 */  
    if (connect(sockfd, (struct sockaddr *) &dest, sizeof(dest)) != 0) {  
        perror("Connect ");  
        return errno;
    }  
    printf("server connected\n");  

    /*  发送消息，最多发送 BUFFERT 个字节 */
    Node * pnode = *pDfList;
    while(pnode != NULL)
    {
        // 首先发送长度
        int dfLen = 8 * 11 + 4 + 4;  // 11个double类型的特征值 + 1 uint32 时间戳 + type
        bzero(buffer,BUFFERT);
        memcpy(buffer, &dfLen, 4);
        if(send(sockfd, buffer, 4, 0) < 0)
        {
            printf("send sfLen error!!!");
        }
        // 然后发送数据
        bzero(buffer,BUFFERT);
        DFEATURE feature = pnode->item;
        double features[11] = { 
            feature.protocol_type,
            feature.src_bytes,
            feature.dst_bytes,
            feature.flag_count,
            feature.src_ip_count,
            feature.packet_length,
            feature.packet_count,
            feature.tcp_packet_count,
            feature.tcp_src_port_count,
            feature.tcp_dst_port_count,
            feature.tcp_fin_flag_count
        };
        int i = 0;
        for(i=0; i<11; i++)
        {
            memcpy(buffer+i*8, &features[i], 8);
        }
        memcpy(buffer+88,&(pnode->timestamp),4);
        memcpy(buffer+92,&(pnode->ddosType),4);
        if(send(sockfd, buffer, dfLen, 0) < 0)
        {
            printf("send features data error!!!");
        }

        pnode = pnode->next;
    }

    // 最后发送end flag
    int endFlag = -1;  // end flag is -1
    bzero(buffer,BUFFERT);
    memcpy(buffer, &endFlag, 4);
    if(send(sockfd, buffer, 4, 0) < 0)
    {
        printf("send endFlag error!!!");
    }
  
    /* 关闭连接 */  
    close(sockfd);
    return 0;
}  
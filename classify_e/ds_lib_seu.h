#ifndef _DS_LIB_SEU_H
#define _DS_LIB_SEU_H

#include <stdbool.h>

//使用链表存储采集到的报文，实现如下
/* general type definitions */
// DDoS Data Structure
typedef struct dfeature { //以下特征值均为单位时间内的统计。目前单位时间暂定为2秒
    double protocol_type; //单位时间内最多的报文的协议（TCP，UDP，ICMP）
    double src_bytes; //从源主机到目标主机的数据的平均字节数
    double dst_bytes; //从目标主机到源主机的数据的平均字节数
    double flag_count; //SYN,ACK, PSH, URG,RST位置1的报文数量
    double src_ip_count; //不同的源IP数量
    double packet_length; //平均包长度
    double packet_count; //单位时间内报文数量（用于计算速率）
    double tcp_packet_count; //TCP报文数量
    double tcp_src_port_count; //TCP报文中源端口数量
    double tcp_dst_port_count; //TCP报文中目的端口数量
    double tcp_fin_flag_count; //TCP FIN位置1的报文数量
} DFEATURE;


typedef DFEATURE Item;

typedef struct node
{
	Item item;
    unsigned int timestamp;
    int ddosType;
	struct node * next;
} Node;

typedef Node * List;

// function prototypes //
void InitializeList(List * plist);

bool ListIsEmpty(const List *plist); 

bool ListIsFull(const List *plist);

unsigned int ListItemCount(const List *plist);

bool AddItem(Item item, unsigned int timestamp, int ddosType, List * plist);

void Traverse (const List *plist, void (* pfun)(Item item) );

void EmptyTheList(List * plist);


#endif
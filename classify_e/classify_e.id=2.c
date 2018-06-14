/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 4; tab-width: 4 -*-  */
/*
 * classify_e.c
 * 
 */
#include <net/if.h>
#include <time.h>
#include <errno.h>
#include "../include/fast.h"
#include "svm.h"
#include "ds_lib_seu.h"

/*参数设定*/
#define Defense_C_IP "1000:0:200::800"   //30所Defense_C的IP
#define Defense_C_Port 20185  //30所Defense_C的端口号
#define DATABASE_IP "1000:0:200::825"  //DDoS离线流程数据库IP地址
#define DATABASE_PORT 21001
#define EGP_ID 0x02

/* Function declaration */
DFEATURE extract_ddos_features(List * plist);
unsigned int myHash(char *str);
int online_classify(struct svm_model* model, DFEATURE feature);
void sendDdosResult(int ddosType);
void capture_ctl_thrd();
void wait_for_alert_ctl_thrd();
void update_model_server();
unsigned char getEGPID();
int sendData(List * pDfList);

/* ===================================================================
 * main function starts
 * */

struct svm_model* model;
int Capture_Time = 2; //默认采集时间为2秒
int Moniter_Time = 10; ////默认10秒内（5个周期）均未有异常报文过来，则发送至数据库
int isCapturing = 0;
int isThrdRunning = 0;
int isSendingData = 0;
List dfeatureList;
#define MAX_arrLen 102400
#define BUFFERT 1024

/* global variable */
uint32_t pkt_count = 0;
uint32_t tcp_pkt_count = 0;
uint32_t udp_pkt_count = 0;
uint32_t icmp_pkt_count = 0;
uint32_t src_bytes_sum = 0;
uint32_t dst_bytes_sum = 0;
int flag_count = 0;
int flow_array[MAX_arrLen] = {};
int flow_count = 0;
unsigned int src_host_array[MAX_arrLen] = {};
int src_host_count = 0;
//unsigned int dst_host_array[MAX_arrLen] = {};
//int dst_host_count = 0;
uint32_t pkt_len_sum = 0;
unsigned int tcp_src_port_array[MAX_arrLen] = {};
int tcp_src_port_count = 0;
unsigned int tcp_dst_port_array[MAX_arrLen] = {};
int tcp_dst_port_count = 0;
uint32_t tcp_fin_flag_count = 0;
int i = 0;

FILE *fileStoreAbnormal = NULL;

// 使用Hash实现对IP等的统计，实现如下 ====
/* RSHash
unsigned int myHash(char *str)    
{    
	unsigned int b = 378551;    
	unsigned int a = 63689;    
	unsigned int hash = 0;    
	while (*str)    
	{    
		hash = hash * a + (*str++);    
		a *= b;    
	}
	return (hash & 0x7FFFFFFF);    
}*/

//BKDRHash
unsigned int myHash(char* str) 
{
	unsigned int seed = 131; /* 31 131 1313 13131 131313 etc.. */ 
	unsigned int hash = 0; 
	unsigned int i  = 0;

	unsigned int len = strlen(str);

	for(i = 0; i < len; str++, i++) 
	{ 
		hash = (hash * seed) + (*str); 
	} 

	return hash; 
}

//get EGP_ID
unsigned char getEGPID() {
	unsigned char macaddr[6];
	char *device = "obx0";
	int s;
	s = socket(AF_INET, SOCK_DGRAM, 0);
	struct ifreq req;
	strcpy(req.ifr_name, device);
	ioctl(s, SIOCGIFHWADDR, &req);
	close(s);
	memcpy(macaddr, req.ifr_hwaddr.sa_data, 6);
	return macaddr[3];
}

//UA回调函数，功能为计算特征值后送入协议栈
int callback(struct fast_packet *pkt,int pkt_len)
{
	//有报文流入，且控制线程运行中，才会采集
	if(isCapturing && isThrdRunning)
	{
		// 计算流的数量
		int flowID = pkt->um.flowID;
		int isContainByFlowArr = 0;
		for (i=0; i<flow_count; i++)
		{
			if(flowID == flow_array[i])
				isContainByFlowArr = 1;
		}
		if(isContainByFlowArr == 0)
		{
			flow_array[flow_count] = flowID;
			flow_count ++;
		}

		pkt_len_sum += pkt->um.len;

		// 计算报文长度,SYN err等
		if( pkt->um.inport == 0)
		{
			src_bytes_sum += pkt->um.len;
		}
		if( pkt->um.inport == 1)
		{
			dst_bytes_sum += pkt->um.len;
		}
		if( pkt->data[12]==0x08 && pkt->data[13]==0x00 ) //IPv4
		{
			//暂不处理
		}else if (pkt->data[12]==0x86 && pkt->data[13]==0xDD) //IPv6
		{
			// 计算SRC_IP的数量
			char *tmp_src_ip = (char*)malloc(16 * sizeof(char)); 
			memcpy(tmp_src_ip, pkt->data+22,16); // start from data[22]
			unsigned int tmp_src_ip_hash = myHash(tmp_src_ip);
			int isContainBySrcHostArr = 0;
			for (i=0; i<src_host_count; i++)
			{
				if(tmp_src_ip_hash == src_host_array[i])
					isContainBySrcHostArr = 1;
			}
			if (isContainBySrcHostArr == 0)
			{
				src_host_array[src_host_count] = tmp_src_ip_hash;
				src_host_count ++ ;
			}
			free(tmp_src_ip);

			/*
			// 计算DST_IP的数量
			char *tmp_dst_ip = (char*)malloc(16 * sizeof(char)); 
    		memcpy(tmp_dst_ip, pkt->data+38,16); // start from data[30]
			unsigned int tmp_dst_ip_hash = myHash(tmp_dst_ip);
			int isContainByDstHostArr = 0;
			for (i=0; i<dst_host_count; i++)
			{
				if(tmp_dst_ip_hash == dst_host_array[i])
					isContainByDstHostArr = 1;
			}
			if (isContainByDstHostArr == 0)
			{
				dst_host_array[dst_host_count] = tmp_dst_ip_hash;
				dst_host_count ++ ;
			}
			free(tmp_dst_ip);
			*/
			
			if(pkt->data[20] == 6) //TCP
			{
				/*[add] store abnormal data 保存异常报文流至本地文件
				int dataStrLen = 109; //2B:type; 32B:um-metadata; 2B:flag; 74B:14ETH+40IPv6+20TCP;
				char dataStr[dataStrLen];
				dataStr[0] = 0x00;
				memcpy(dataStr+1, &(pkt->um), 32);
				memcpy(dataStr+33, &(pkt->flag), 2);
				memcpy(dataStr+35, &(pkt->data), 74);
				fwrite(dataStr,sizeof(char),dataStrLen,fileStoreAbnormal);//Fixed! 二进制用fwrite函数
				//fprintf(fileStoreAbnormal,"\n");*/

				// 计算tcp_packet_count
				tcp_pkt_count ++;

				int tcpstart = 14 + 40; //tcp header start from data[tcpstart]

				// 计算SYN,ACK, PSH, URG,RST位置1的报文数量
				if(pkt->data[tcpstart+13]&0x3e > 0) 
				{
					flag_count ++;
				}
				
				// 计算tcp_src_port_count
				int tmp_src_port = (pkt->data[tcpstart]<<8) | pkt->data[tcpstart+1];
				int isContainBySrcPortArr = 0;
				for (i=0; i<tcp_src_port_count; i++)
				{
					if(tmp_src_port == tcp_src_port_array[i])
						isContainBySrcPortArr = 1;
				}
				if(isContainBySrcPortArr == 0)
				{
					tcp_src_port_array[tcp_src_port_count] = tmp_src_port;
					tcp_src_port_count ++;
				}

				// 计算tcp_dst_port_count
				int tmp_dst_port = (pkt->data[tcpstart+2]<<8) | pkt->data[tcpstart+3];
				int isContainByDstPortArr = 0;
				for (i=0; i<tcp_dst_port_count; i++)
				{
					if(tmp_src_port == tcp_dst_port_array[i])
						isContainByDstPortArr = 1;
				}
				if(isContainByDstPortArr == 0)
				{
					tcp_dst_port_array[tcp_dst_port_count] = tmp_dst_port;
					tcp_dst_port_count ++;
				}

				// 计算tcp_fin_flag_count
				if(pkt->data[tcpstart+14]&0x01 == 0x01)
				{
					tcp_fin_flag_count++;
				}


			}else if(pkt->data[20] == 17) //UDP
			{
				/*[add] store abnormal data 保存异常报文流至本地文件
				int dataStrLen = 97;  //1B:type; 32B:um-metadata; 2B:flag; 62B:14ETH+40IPv6+8UDP;
				char dataStr[dataStrLen]; 
				dataStr[0] = 0x00;
				memcpy(dataStr+1, &(pkt->um), 32);
				memcpy(dataStr+33, &(pkt->flag), 2);
				memcpy(dataStr+35, &(pkt->data), 62);
				fwrite(dataStr,sizeof(char),dataStrLen,fileStoreAbnormal);//Fixed! 二进制用fwrite函数
				//fprintf(fileStoreAbnormal,"\n");*/

				udp_pkt_count ++;
			}else if(pkt->data[20] == 1) //ICMP
			{
				/*[add] store abnormal data 保存异常报文流至本地文件
				int dataStrLen = 97;  //1B:type; 32B:um-metadata; 2B:flag; 62B:14ETH+40IPv6+8ICMP;
				char dataStr[dataStrLen]; 
				dataStr[0] = 0x00;
				memcpy(dataStr+1, &(pkt->um), 32);
				memcpy(dataStr+33, &(pkt->flag), 2);
				memcpy(dataStr+35, &(pkt->data), 62);
				fwrite(dataStr,sizeof(char),dataStrLen,fileStoreAbnormal);//Fixed! 二进制用fwrite函数
				//fprintf(fileStoreAbnormal,"\n");*/

				icmp_pkt_count ++;
			}else
			{
				//非TCP/UDP/ICMP(IPv6)报文暂不处理
			}
		}else
		{
			//非IP报文暂不处理
		}
		pkt_count ++ ;
	}else{
		if(isThrdRunning)
		{
			// do nothing;
		}else{
			//start thread
			isCapturing = 1;
			isThrdRunning = 1;
			//采集报文,提取特征值并分类的线程
			pthread_t capture_ctl_thrd_t;
			pthread_create(&capture_ctl_thrd_t,NULL,(void*)capture_ctl_thrd,NULL);
		}
	}

//	printf("recv packet, len: %d\n",pkt_len);

	#if 0
	if(pkt->um.inport == 0)
	{
		pkt->um.outport = 1;//指定报文输出端口
		pkt->um.dstmid = 5;//将目的模块id号置为5,直接输出
		pkt->um.pktdst = 0;//将输出方向置为0,即输出到端口
		fast_ua_send(pkt,pkt_len);//发送报文往硬件
	}else
	{
		pkt->um.outport = 0;
		pkt->um.dstmid = 5;
		pkt->um.pktdst = 0;
		fast_ua_send(pkt,pkt_len);
	}
	
	/*
	pkt->um.dstmid = 128;
	fast_ua_send(pkt,pkt_len);
	*/

	#endif
	
	return 0;
}

void ua_init(void)
{
	int ret = 0;
	if((ret=fast_ua_init(131,callback)))//UA模块实例化(输入参数1:接收模块ID号,输入参数2:接收报文的回调处理函数)
	{
		perror("fast_ua_init!\n");
		exit (ret);//如果初始化失败,则需要打印失败信息,并将程序结束退出!
	}
}

void rule_config(void)
{
	int i = 0;
	struct fast_rule rule[8] = {{0},{0},{0},{0},{0},{0},{0},{0}};//初始化八条全空的规则

	//i=0,初始化第0条规则
	//给规则的各字段赋值
//----------写入以太网头部相关字段
	*(u64 *)rule[i].key.dmac = htole64(0x0023CD76631A);//MAC=00:23:CD:76:63:1A
	*(u64 *)rule[i].key.smac = htole64(0x002185C52B8F);//MAC=00:21:85:C5:2B:8F
	rule[i].key.tci = htole16(0x4500);
	rule[i].key.type = htole16(0x0800);
	rule[i].key.tos = 0x32;
	rule[i].key.ttl = 0x35;
	rule[i].key.proto = 0x6;//0x1:ICMP,0x6:TCP,0x11:UDP
//----------写入ipv4协议相关字段，ipv4和ipv6协议不能在同一条规则中生效，会相互覆盖	
//	rule[i].key.ipv4.src = htole32(0xC0A80107);//IP=192.168.1.7
//	rule[i].key.ipv4.dst = htole32(0xC0A80108);//IP=192.168.1.8
//	rule[i].key.ipv4.tp.sport = htole16(0x1388);//Sport = 5000
//	rule[i].key.ipv4.tp.dport = htole16(0x50);//Dport = 80 
//----------写入ipv6协议相关字段，ipv6和ipv4协议不能在同一条规则中生效，会相互覆盖		
//--------------------Src_ipv6_addr = 1000:0:200::142	
	*(u64 *)rule[i].key.ipv6.src.__in6_u.__u6_addr8 =  htole64(0x0000000000000142);
	*(u64 *)(&rule[i].key.ipv6.src.__in6_u.__u6_addr8[8]) =  htole64(0x1000000002000000);

//-------------------Dst_ipv6_addr = 2400:dd01:1034:e00:913f:9bda:7e99:50
//	*(u64 *)rule[i].key.ipv6.dst.__in6_u.__u6_addr8 =  htole64(0x913f9bda7e990050);
//	*(u64 *)(&rule[i].key.ipv6.dst.__in6_u.__u6_addr8[8]) =  htole64(0x2400dd0110340e00);//0x000000000100010b

	rule[i].key.port = 0x0;//写入物理端口号
	rule[i].priority =0xE;//写入第i条规则的优先级，数值越大，优先级越高
	rule[i].action = ACTION_SET_MID<<28|131;//动作字段的涵义请参考fast_type.h，此处位转发往1号端口
	rule[i].md5[0] = i + 1;//写入md5字段，防止规则重复添加，应等于非零值
	//给规则对应字段设置掩码，掩码为1表示使用，为0表示忽略
	//*(u64 *)rule[i].mask.dmac = 0xFFFFFFFFFFFFL;
	//*(u64 *)rule[i].mask.smac = 0xFFFFFFFFFFFFL;
	//rule[i].mask.tag = 0;//0xFFFFFFFF;
	//rule[i].mask.type = 0xFFFF;
	//rule[i].mask.tos = 0xFF;
	//rule[i].mask.ttl = 0xFF;
	//rule[i].mask.proto = 0xFF;//0x1:ICMP,0x6:TCP,0x11:UDP
	//rule[i].mask.ipv4.src = 0xFFFFFFFF;
	//rule[i].mask.ipv4.dst = 0xFFFFFFFF;
    *(u64 *)rule[i].mask.ipv6.src.__in6_u.__u6_addr8 = htole64(0xFFFFFFFFFFFFFFFF);
    *(u64 *)(&rule[i].mask.ipv6.src.__in6_u.__u6_addr8[8]) = htole64(0xFFFFFFFFFFFFFFFF);
    //*(u64 *)rule[i].mask.ipv6.dst.__in6_u.__u6_addr8 = htole64(0xFFFFFFFFFFFFFFFF);
    //*(u64 *)(&rule[i].mask.ipv6.dst.__in6_u.__u6_addr8[8]) = htole64(0xFFFFFFFFFFFFFFFF);
	//rule[i].mask.sport = 0xFFFF;
	//rule[i].mask.dport = 0xFFFF;
	//rule[i].mask.port = 0xF;
	
	fast_add_rule(&rule[i]); //添加硬件规则

	i++;
	//i=1,初始化第1条规则
	//给规则的各字段赋值
//----------写入以太网头部相关字段
	*(u64 *)rule[i].key.dmac = htole64(0x0023CD76631A);//MAC=00:23:CD:76:63:1A
	*(u64 *)rule[i].key.smac = htole64(0x002185C52B8F);//MAC=00:21:85:C5:2B:8F
	rule[i].key.tci = htole16(0x4500);
	rule[i].key.type = htole16(0x0800);
	rule[i].key.tos = 0x32;
	rule[i].key.ttl = 0x35;
	rule[i].key.proto = 0x6;//0x1:ICMP,0x6:TCP,0x11:UDP
//----------写入ipv4协议相关字段，ipv4和ipv6协议不能在同一条规则中生效，会相互覆盖	
//	rule[i].key.ipv4.src = htole32(0xC0A80107);//IP=192.168.1.7
//	rule[i].key.ipv4.dst = htole32(0xC0A80108);//IP=192.168.1.8
//	rule[i].key.ipv4.tp.sport = htole16(0x1388);//Sport = 5000
//	rule[i].key.ipv4.tp.dport = htole16(0x50);//Dport = 80 
//----------写入ipv6协议相关字段，ipv6和ipv4协议不能在同一条规则中生效，会相互覆盖		
//--------------------Src_ipv6_addr = 2001:250:4401:2000:6254:7e81:ed31:1	
//	*(u64 *)rule[i].key.ipv6.src.__in6_u.__u6_addr8 =  htole64(0x62547e81ed310001);
//	*(u64 *)(&rule[i].key.ipv6.src.__in6_u.__u6_addr8[8]) =  htole64(0x2001025044012000);

//-------------------Dst_ipv6_addr = 1000:0:200::142
	*(u64 *)rule[i].key.ipv6.dst.__in6_u.__u6_addr8 =  htole64(0x0000000000000142);
	*(u64 *)(&rule[i].key.ipv6.dst.__in6_u.__u6_addr8[8]) =  htole64(0x1000000002000000);//0x000000000100010b

	rule[i].key.port = 0x0;//写入物理端口号
	rule[i].priority =0xE;//写入第i条规则的优先级，数值越大，优先级越高
	rule[i].action = ACTION_SET_MID<<28|131;//动作字段的涵义请参考fast_type.h，此处位转发往1号端口
	rule[i].md5[0] = i + 1;//写入md5字段，防止规则重复添加，应等于非零值
	//给规则对应字段设置掩码，掩码为1表示使用，为0表示忽略
	//*(u64 *)rule[i].mask.dmac = 0xFFFFFFFFFFFFL;
	//*(u64 *)rule[i].mask.smac = 0xFFFFFFFFFFFFL;
	//rule[i].mask.tag = 0;//0xFFFFFFFF;
	//rule[i].mask.type = 0xFFFF;
	//rule[i].mask.tos = 0xFF;
	//rule[i].mask.ttl = 0xFF;
	//rule[i].mask.proto = 0xFF;//0x1:ICMP,0x6:TCP,0x11:UDP
	//rule[i].mask.ipv4.src = 0xFFFFFFFF;
	//rule[i].mask.ipv4.dst = 0xFFFFFFFF;
    //*(u64 *)rule[i].mask.ipv6.src.__in6_u.__u6_addr8 = htole64(0xFFFFFFFFFFFFFFFF);
    //*(u64 *)(&rule[i].mask.ipv6.src.__in6_u.__u6_addr8[8]) = htole64(0xFFFFFFFFFFFFFFFF);
    *(u64 *)rule[i].mask.ipv6.dst.__in6_u.__u6_addr8 = htole64(0xFFFFFFFFFFFFFFFF);
    *(u64 *)(&rule[i].mask.ipv6.dst.__in6_u.__u6_addr8[8]) = htole64(0xFFFFFFFFFFFFFFFF);
	//rule[i].mask.sport = 0xFFFF;
	//rule[i].mask.dport = 0xFFFF;
	//rule[i].mask.port = 0xF;
	
	fast_add_rule(&rule[i]); //添加硬件规则

	//print_hw_rule(); //打印硬件中的规则

}

//在线分类器分类函数
int online_classify(struct svm_model* model, DFEATURE feature)
{
    double features[11] = { 
		0,//feature.protocol_type,
		0,//feature.src_bytes,
		0,//feature.dst_bytes,
		0,//feature.flag_count,
		0,//feature.src_ip_count,
		0,//feature.packet_length,
		0,//feature.packet_count,
		0,//feature.tcp_packet_count,
		0,//feature.tcp_src_port_count,
		0,//feature.tcp_dst_port_count,
		feature.tcp_fin_flag_count
	};

	/* use svm_light to predict [abandoned now]
    int svfNum = 11;  // 11 features in one support vector
    DOC *doc;        // one predict example
    WORD *words;     // features
    int i = 0;
    double result = 0;
    
    words = (WORD *)my_malloc(sizeof(WORD)*(svfNum));
    for(i = 0; i<svfNum; i++)
    {
        words[i].wnum = i+1;
        words[i].weight = features[i];
    }
    doc = create_example(-1, 0, 0, 0.0, create_svector(words, "ddos_type_predict", 1.0));
    result = classify_example(model, doc);
	*/

	/* use libsvm to predict */
	struct svm_node *x;
	int fNum = 11;  // 11 features in one support vector

	/* ！！！！非常重要！！！！
	 * LibSVM预测时的输入向量的最后一个节点的index必须是-1，否则出错。【调试了好久;
	 * 即: 11个特征值，需要分配12个节点的内存空间;
	 * ！！！！非常重要！！！
	 */
	x = (struct svm_node *) malloc((fNum+1)*sizeof(struct svm_node));
	int i = 0;
	for(i=0;i<fNum;i++)
	{
		x[i].index = i+1;
		x[i].value = features[i];
	}
	x[fNum].index = -1;
	double result = svm_predict(model, x);
	free(x);

    return (int)result;
}

void sendDdosResult(int ddosType)
{
	int mysocket,len;  
    int i=0;  
    struct sockaddr_in6 addr;  
    int addr_len;  
    char msg[7] = {0};  // msg[0-3]:none; msg[4]:报文类型0x12; msg[5]:DDoS攻击类型; msg[6]:EGP_ID
    if((mysocket=socket(AF_INET6,SOCK_DGRAM,0))<0)  
    {  
        perror("error!");  
        return ;
    }

	msg[4] = 0x12;

	/*
	在char变量相应的比特位上置1	
	比特位  DDoS攻击类型
	0	   TCP SYN Flood
	1	   UDP Flood
	2	   ICMP Flood
	3	   Smurf
	4	   Fraggle
	5	   Land
	6	   保留
	7	   保留
	*/
	if(ddosType == 0)
		msg[5] = 0x00;
	else if(ddosType == 1)
		msg[5] = 0x01;
	else if(ddosType == 2)
		msg[5] = 0x02;
	else if(ddosType == 3)
		msg[5] = 0x04;
	else
		msg[5] = 0x00;
	
    //msg[6] = getEGPID();
	msg[6] = EGP_ID;
    addr_len=sizeof(struct sockaddr_in6);  
    bzero(&addr,sizeof(addr));  
    addr.sin6_family=AF_INET6;  
    addr.sin6_port=htons(Defense_C_Port);  
    inet_pton(AF_INET6,Defense_C_IP,&addr.sin6_addr);

	int msgLen = sizeof(msg);
	if(sendto(mysocket,&msgLen,sizeof(msgLen),0,(struct sockaddr *)&addr,addr_len)<0)
    {
        printf("send msgLen error!");
    }
    if(sendto(mysocket,msg,msgLen,0,(struct sockaddr *)&addr,addr_len)<0)
    {
        printf("send msg error!");
    }
    close(mysocket);
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
        perror("DATABASEIP");  
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

/* !!!!Abandoned Now!!!!!
//等待接收Sensor UA告警信息的线程
void wait_for_alert_ctl_thrd()
{
	int sensorSocket = get_server_socket(6665);   //sensor UA发送告警信息的socket
	int alertMsgLen;
	char *msgBuff;
	while(true)
	{
		recv_msg(sensorSocket, &alertMsgLen, 4);
		msgBuff = (char*)malloc(alertMsgLen*sizeof(char));
		recv_msg(sensorSocket, msgBuff, alertMsgLen);

		/* 接收到的msg为以下结构体的string版，第5位是type
		typedef struct AlertPacket {
			long timeStamp;
			unsigned char protocol_type;//0x01
			...
		/
		char protoType = msgBuff[4];
		if(protoType == 0x01) // alert
		{
			alert_flag = true;
		}else if(protoType == 0x11) // alert cancel
		{
			alert_flag = false;
		}
	}
}*/

//采集数据，提取特征值的线程
void capture_ctl_thrd()
{
	//printf("thread start running!\n");
	//thread start
	//采集前复位所有计数器
	pkt_count = 0;
	tcp_pkt_count = 0;
	udp_pkt_count = 0;
	icmp_pkt_count = 0;
	src_bytes_sum = 0;
	dst_bytes_sum = 0;
	flag_count = 0;
	flow_count = 0;
	src_host_count = 0;
	pkt_len_sum = 0;		
	tcp_src_port_count = 0;
	tcp_dst_port_count = 0;
	tcp_fin_flag_count = 0;
	i = 0;

	/*[add] store abnormal data 保存异常报文流至本地文件
	time_t timePrensent = time(NULL);
	char fileNameUseTime[64];
	sprintf(fileNameUseTime,"%s%d.dat","abnormalData/",(uint32_t)timePrensent);
	fileStoreAbnormal = fopen(fileNameUseTime,"w");*/

	sleep(Capture_Time);
	isCapturing = 0; //一个周期采集完成，开始计算；
	printf("captured %d pkts\n",pkt_count);
	if (pkt_count != 0)
	{			
		DFEATURE resultdf = {0,0,0,0,0,0,0,0,0,0,0};
		if(tcp_pkt_count>=udp_pkt_count && tcp_pkt_count>=icmp_pkt_count)
		{
			resultdf.protocol_type = 1;
		}
		if(udp_pkt_count>=tcp_pkt_count && udp_pkt_count>=icmp_pkt_count)
		{
			resultdf.protocol_type = 2;
		}
		if(icmp_pkt_count>=tcp_pkt_count && icmp_pkt_count>=udp_pkt_count)
		{
			resultdf.protocol_type = 3;
		}
		resultdf.src_bytes = src_bytes_sum / pkt_count;
		resultdf.dst_bytes = dst_bytes_sum / pkt_count;
		resultdf.flag_count = flag_count;
		resultdf.src_ip_count = src_host_count;
		resultdf.packet_length = pkt_len_sum / pkt_count;
		resultdf.packet_count = pkt_count;
		resultdf.tcp_packet_count = tcp_pkt_count;
		resultdf.tcp_src_port_count = tcp_src_port_count;
		resultdf.tcp_dst_port_count = tcp_dst_port_count;
		resultdf.tcp_fin_flag_count = tcp_fin_flag_count;
		int ddosType = online_classify(model,resultdf);
		if(pkt_count<20 || tcp_fin_flag_count<20)
			ddosType = 0;
		sendDdosResult(ddosType);
		printf("ddos_type is %d\n",ddosType);
		/*[add 0413] send abnormal data to database 发送异常数据至数据库*/
		unsigned int timePrensent = time(NULL);
		AddItem(resultdf,timePrensent,ddosType,&dfeatureList);
	}
	//thread stop
	isThrdRunning = 0;
	//printf("thread stop running\n");

	/* [Abandoned Now!!!!] For Actual Use Start！ 
	if(alert_flag == true)
	{
		capt_flag = true;
		sleep(Capture_Time);
		capt_flag = false;
		if (pkt_count != 0)
		{			
			DFEATURE resultdf = {0,0,0,0,0,0,0,0,0,0,0};
			if(tcp_pkt_count>=udp_pkt_count && tcp_pkt_count>=icmp_pkt_count)
			{
				resultdf.protocol_type = 1;
			}
			if(udp_pkt_count>=tcp_pkt_count && udp_pkt_count>=icmp_pkt_count)
			{
				resultdf.protocol_type = 2;
			}
			if(icmp_pkt_count>=tcp_pkt_count && icmp_pkt_count>=udp_pkt_count)
			{
				resultdf.protocol_type = 3;
			}
			resultdf.src_bytes = src_bytes_sum / pkt_count;
			resultdf.dst_bytes = dst_bytes_sum / pkt_count;
			resultdf.flag_count = flag_count;
			resultdf.src_ip_count = src_host_count;
			resultdf.packet_length = pkt_len_sum / pkt_count;
			resultdf.packet_count = pkt_count;
			resultdf.tcp_packet_count = tcp_pkt_count;
			resultdf.tcp_src_port_count = tcp_src_port_count;
			resultdf.tcp_dst_port_count = tcp_dst_port_count;
			resultdf.tcp_fin_flag_count = tcp_fin_flag_count;
			int ddosType = online_classify(model,resultdf);
			sendDdosResult(ddosType);
			printf("ddos_type is %d\n",ddosType);
		}
	}else
	{
		sleep(1);
	}
	/* [Abandoned Now!!!!] For Actual Use End! */
}

// 监视异常报文流入并发送至数据库服务端的线程
void moniter_send2DB_ctl_thrd()
{
	while(1)
	{
		//若Moniter_Time秒内均未有异常报文过来，则发送至数据库
		int i = 0;
		for(i=0; i<Moniter_Time; i++)
		{
			if(!isCapturing)
			{
				//当前未采集数据，则1秒后继续查看
				sleep(1);
			}else{
				//当前正在采集数据，重新开始Moniter_Time/2个周期的监测
				i=0;
			}
		}
		int ret = 0;
		if(dfeatureList!=NULL)
		{
			printf("No Abnormal Data in 10s, preparing to send data to DB\n");
			//isSendingData = 1;
			if((ret = sendData(&dfeatureList))!=0)
			{
				printf("Send Data Error! errno is: %d\n",ret);
			}else
			{
				//发送成功才清除特征值列表
				EmptyTheList(&dfeatureList);
				InitializeList(&dfeatureList);
				printf("Send data to DB: OK!\n");
			}
			//isSendingData = 0;
		}
	}

}

// 自动更新模型文件的服务器端
void update_model_server()
{
	struct sockaddr_in6 sock_serv,clt; //IPv6
	int Port = 6789;
    int fd, sfd;
    char buf[BUFFERT];
    off_t count=0, n; // long type
    char filename[256];
    int filesize = 0;
    //int l=sizeof(struct sockaddr_in); //IPv4
    int l=sizeof(struct sockaddr_in6); //IPv6
    
    //sfd = socket(AF_INET,SOCK_DGRAM,0); //IPv4
    sfd = socket(AF_INET6,SOCK_DGRAM,0); //IPv6
    if (sfd == -1)
    {
        perror("socket fail");
        return;
    }
    
    bzero(&sock_serv,l);
    
    //sock_serv.sin_family=AF_INET; //IPv4
    sock_serv.sin6_family=AF_INET6; //IPv6
    //sock_serv.sin_port=htons(port); //IPv4
    sock_serv.sin6_port=htons(Port); //IPv6
    //sock_serv.sin_addr.s_addr=htonl(INADDR_ANY); //IPv4
    sock_serv.sin6_addr=in6addr_any;
    
    if(bind(sfd,(struct sockaddr*)&sock_serv,l)==-1)
    {
        perror("bind fail");
        return;
    }

    bzero(filename,256);
    sprintf(filename,"ddos.features.model");
    //printf("Creating the output file : %s\n",filename);
    
    while (true) // always recv
    {
        //firstly recv file size
        bzero(&buf,BUFFERT);
        n=recvfrom(sfd,&buf,20,0,(struct sockaddr *)&clt,&l);
        filesize = atoi(buf);
        //printf("model file size: %d\n", filesize);

        if((fd=open(filename,O_CREAT|O_WRONLY|O_TRUNC,0600))==-1)
        {
            perror("open fail");
            return;
        }

        count = 0;
        bzero(&buf,BUFFERT);
        n=recvfrom(sfd,&buf,BUFFERT,0,(struct sockaddr *)&clt,&l);
        while(n)
        {
            if(n==-1)
            {
                perror("read fails");
                return;
            }
            count+=n;
            write(fd,buf,n);
            bzero(buf,BUFFERT);
            n=recvfrom(sfd,&buf,BUFFERT,0,(struct sockaddr *)&clt,&l);
        }
        //printf("%ld of data received \n",count);
        close(fd);
	
        bzero(&buf,BUFFERT);
        if(count == filesize)
		{
			printf("%ld of data received... recv success \n",count);
            sprintf(buf, "%d", 0); // 0 is success
			sendto(sfd,buf,1,0,(struct sockaddr*)&clt,l);
        }
		else
		{
            sprintf(buf, "%d", 1); // 1 is fail
			sendto(sfd,buf,1,0,(struct sockaddr*)&clt,l);
         }
    }
    
    close(sfd);
}

int main(int argc,char* argv[])
{
	int ret = 0;
	int i = 0;
	model=svm_load_model("ddos.features.model");

//------------流表部分------------
	fast_init_hw(0,0); //初始化硬件
	//init_rule(ACTION_SET_MID << 28 | 131); //初始化硬件流表空间
	//rule_config(); //写入规则
//----------UA部分-----------
	ua_init();//UA模块初始化

//	test_online_classify();

	InitializeList(&dfeatureList);

	//自动更新,接收model文件的线程
	pthread_t update_model_server_t;
	pthread_create(&update_model_server_t,NULL,(void*)update_model_server,NULL);

	// 监视异常报文流入并发送至数据库服务端的线程
	pthread_t moniter_send2DB_ctl_thrd_t;
	pthread_create(&moniter_send2DB_ctl_thrd_t,NULL,(void*)moniter_send2DB_ctl_thrd,NULL);

	fast_ua_recv();//启动线程接收分派给UA进程的报文
	while(1){sleep(9999);}//主进程进入循环休眠中,数据处理主要在回调函数
	fast_distroy_hw();  //销毁硬件资源
	return (0);
}

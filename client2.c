#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
//#include "criu/include/sk-inet.h"
//#include "criu/sk-inet.c"
//#include "../soccr/soccr.h"
#include "./soccr/soccr.c"
#include <errno.h>
#include <asm/types.h>
#define MAX 80 
#define PORT 8080 
#define SA struct sockaddr 
typedef unsigned int u32;

#define SET_SA_FLAGS	(SOCCR_MEM_EXCL)

int restore_sockaddr(union libsoccr_addr *sa,
		int family, u32 pb_port, u32 *pb_addr, u32 ifindex)
{
	memset(sa, 0, sizeof(*sa));
	if (family == AF_INET) {
		sa->v4.sin_family = AF_INET;
		sa->v4.sin_port = htons(pb_port);
		memcpy(&sa->v4.sin_addr.s_addr, pb_addr, sizeof(sa->v4.sin_addr.s_addr));
		return sizeof(sa->v4);
	}
	return -1;
}
static int libsoccr_set_sk_data_noq_HA(struct libsoccr_sk *sk,
		struct libsoccr_sk_data *data, unsigned data_size)
{

	//if (sk->src_addr->sa.sa_family == AF_INET)
	int	addr_size = sizeof(struct sockaddr_in);

	if (bind(sk->fd, &sk->src_addr->sa, addr_size)) {
		printf("Can't bind inet socket back");
		return -1;
	}
	if (tcp_repair_on(sk->fd))
		return -1;
	if (set_queue_seq(sk, TCP_RECV_QUEUE,data->inq_seq))
		return -2;


	if (set_queue_seq(sk, TCP_SEND_QUEUE,data->outq_seq))
		return -3;

	//if (sk->dst_addr->sa.sa_family == AF_INET)
	addr_size = sizeof(struct sockaddr_in);

	//if (data->state == TCP_SYN_SENT && tcp_repair_off(sk->fd))
	//if (tcp_repair_off(sk->fd))	
		//return -1;

	if (connect(sk->fd, &sk->dst_addr->sa, addr_size) == -1 &&
						errno != EINPROGRESS) {
		printf("Can't connect inet socket back");
		return -1;
	}

	//if (data->state == TCP_SYN_SENT && tcp_repair_on(sk->fd))
	if (tcp_repair_off(sk->fd))
		return -1;

	printf("\tRestoring TCP options\n");


	return 0;
}

int libsoccr_restore_HA(struct libsoccr_sk *sk,
		struct libsoccr_sk_data *data, unsigned data_size)
{

	if (libsoccr_set_sk_data_noq_HA(sk, data, data_size))
		return -1;
	return 0;
}


static int restore_tcp_conn_state_HA(int fd,struct libsoccr_sk *socr,struct libsoccr_sk_data* data)
{
	int aux;

	//struct libsoccr_sk_data data = {};
	union libsoccr_addr sa_src, sa_dst;
	//socr = calloc(1,sizeof(struct libsoccr_sk));
	//socr->fd = fd;

	//data.inq_seq = 2622049721;
	//data.outq_seq = 1381840090;

	printf("start restore inq_seq : %u outq_seq: %u\n", data->inq_seq,data->outq_seq);
	printf("inq_len:%u outq_len:%u\n",data->inq_len,data->outq_len);
	printf("snd_wnd:%u rcv_wnd:%u\n",data->snd_wnd,data->rcv_wnd);
	printf("timestamp:%u\n",data->timestamp);
	struct sockaddr_in clinetaddr,serveraddr;
	serveraddr.sin_addr.s_addr = inet_addr("140.96.29.50");
	clinetaddr.sin_addr.s_addr = inet_addr("192.168.90.95");
	if (restore_sockaddr(&sa_src,
				AF_INET, 2552,
				&clinetaddr.sin_addr.s_addr, 0) < 0)
		goto err;
	if (restore_sockaddr(&sa_dst,
				AF_INET, 8080,
				&serveraddr.sin_addr.s_addr, 0) < 0)
		goto err;

	libsoccr_set_addr(socr, 1, &sa_src, 0);
	libsoccr_set_addr(socr, 0, &sa_dst, 0);


	if (libsoccr_restore_HA(socr, data, sizeof(*data)))
		goto err;

	return 0;

err:
	return -1;
}

int restore_one_tcp_HA(int fd,struct libsoccr_sk_data* data)
{
	struct libsoccr_sk *sk;

	printf("Restoring TCP connection\n");

	/*if (opts.tcp_close &&
		ii->ie->state != TCP_LISTEN && ii->ie->state != TCP_CLOSE) {
		return 0;
	}*/

	sk = libsoccr_pause(fd);
	if (!sk)
		return -1;

	if (restore_tcp_conn_state_HA(fd, sk, data)) {
		libsoccr_release(sk);
		return -1;
	}

	return 0;
}

void func(int sockfd)
{
    int ret = 0;
    char buff[MAX];
    int n;
    for (;;) {
        bzero(buff, sizeof(buff));
        printf("Enter the string : ");
        n = 0;
        while ((buff[n++] = getchar()) != '\n')
            ;
        write(sockfd, buff, sizeof(buff));
        bzero(buff, sizeof(buff));
        /*read(sockfd, buff, sizeof(buff));
        printf("From Server : %s", buff);
        if ((strncmp(buff, "exit", 4)) == 0) {
            printf("Client Exit...\n");
            break;
        }*/

    }
}

void listen_proxy_pri(int sockfd, struct libsoccr_sk_data* data,struct libsoccr_sk_data* tmp)
{
	int ret = 0;
    char buff[MAX];
    int n;
    for (;;) {
        //bzero(buff, sizeof(buff));
		
		
        /*printf("Enter the string : ");
        n = 0;
        while ((buff[n++] = getchar()) != '\n')
            ;
        write(sockfd, buff, sizeof(buff));
        bzero(buff, sizeof(buff));*/
        //while(read(sockfd, buff, sizeof(buff))==0);
		//while(ret = read(sockfd, data, sizeof(*data))==0);
		ret = read(sockfd, data, sizeof(*data));
		printf("ret:%d\n",ret);
		if(ret!=0)
		{
			printf("inq_seq : %u outq_seq: %u\n", data->inq_seq,data->outq_seq);
			memcpy(tmp,data,sizeof(*data));
			bzero(data, sizeof(*data));
		}
		if(ret == 0)
			break;
		

        if ((strncmp(buff, "exit", 4)) == 0) {
            printf("Client Exit...\n");
            break;
        }
		

    }
}

int main()
{
    int sockfd, proxy_fd, proxy_connfd;
    struct sockaddr_in proxy_pri_addr, cli, proxy_backup_addr;

    // socket create and varification 
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
	proxy_fd = socket(AF_INET, SOCK_STREAM, 0);
	
    if (sockfd == -1 || proxy_fd == -1) {
        printf("socket creation failed...\n");
        exit(0);
    }
    else
        printf("Socket successfully created..\n");
	bzero(&proxy_backup_addr, sizeof(proxy_backup_addr));
    proxy_backup_addr.sin_family = AF_INET;
    proxy_backup_addr.sin_addr.s_addr = inet_addr("192.168.90.91");
    proxy_backup_addr.sin_port = htons(PORT);
	bind(proxy_fd, (struct sockaddr*)&proxy_backup_addr, sizeof(proxy_backup_addr));
	// connect the client socket to proxy backup socket 
    if ((listen(proxy_fd, 5)) != 0) { 
        printf("Listen failed...\n"); 
        exit(0); 
    }     
    else
        printf("proxy listening..\n"); 
    int len = sizeof(proxy_pri_addr); 
  
    // Accept the data packet from client and verification 
    proxy_connfd = accept(proxy_fd, (SA*)&proxy_pri_addr, &len); 
    if (proxy_connfd < 0) { 
        printf("proxy acccept failed...\n"); 
        exit(0); 
    } 
    else
        printf("proxy acccept the client...\n"); 


    // connect the backup proxy socket to primary proxy socket 
    /*if (connect(proxy_fd, (SA*)&proxy_pri_addr, sizeof(proxy_pri_addr)) != 0) {
        printf("connection with the server failed...\n");
        exit(0);
    }
    else
        printf("connected to the proxy primary..\n");*/
    // function for chat 
	struct libsoccr_sk_data data;
	struct libsoccr_sk_data tmp;
	struct libsoccr_sk *socr;
    listen_proxy_pri(proxy_connfd,&data,&tmp);
	sleep(1);
	restore_one_tcp_HA(sockfd,&tmp);
    //restore_tcp_conn_state_HA(socr,sockfd,&tmp);
	func(sockfd);
    //printf("inq_seq:%u  outq_seq:%u\n",data->inq_seq,data->outq_seq);
    //printf("errno:%d",errno);
    // close the socket 
    close(sockfd);
}

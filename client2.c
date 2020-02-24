#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "criu_HA.h"

#include <errno.h>
#include <asm/types.h>
#include <pthread.h>
#define MAX 8000
#define PORT 8080 
#define SA struct sockaddr 
#define HEADER_SIZE 84
typedef unsigned int u32;
#define SET_SA_FLAGS	(SOCCR_MEM_EXCL)
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;


int restore_sockaddr(union libsoccr_addr *sa,
		int family, uint16_t pb_port, u32 *pb_addr, u32 ifindex)
{
	memset(sa, 0, sizeof(*sa));
	if (family == AF_INET) {
		sa->v4.sin_family = AF_INET;
		sa->v4.sin_port = pb_port;
		memcpy(&sa->v4.sin_addr.s_addr, pb_addr, sizeof(sa->v4.sin_addr.s_addr));
		return sizeof(sa->v4);
	}
	return -1;
}

static int libsoccr_set_sk_data_noq_HA(struct libsoccr_sk *sk,
			dt_info* data, unsigned data_size)
{

	//if (sk->src_addr->sa.sa_family == AF_INET)
	int	addr_size = sizeof(struct sockaddr_in);

	if (bind(sk->fd, &sk->src_addr->sa, addr_size)) {
		printf("Can't bind inet socket back");
		return -1;
	}
	if (tcp_repair_on(sk->fd))
		return -1;
	if (set_queue_seq(sk, TCP_RECV_QUEUE, data->sk_hd.inq_seq))
		return -2;


	if (set_queue_seq(sk, TCP_SEND_QUEUE, data->sk_hd.outq_seq))
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
		dt_info* data, unsigned data_size)
{
	int mstate = 1 << data->sk_hd.state;

	if (libsoccr_set_sk_data_noq_HA(sk, data, data_size))
		return -1;


	if (libsoccr_restore_queue_HA(sk, data, sizeof(*data), TCP_RECV_QUEUE, data->recv_queue))
		return -1;

	if (libsoccr_restore_queue_HA(sk, data, sizeof(*data), TCP_SEND_QUEUE, data->send_queue))
		return -1;

	if (data->sk_hd.flags & SOCCR_FLAGS_WINDOW) {
		struct tcp_repair_window wopt = {
			.snd_wl1 = data->sk_hd.snd_wl1,
			.snd_wnd = data->sk_hd.snd_wnd,
			.max_window = data->sk_hd.max_window,
			.rcv_wnd = data->sk_hd.rcv_wnd,
			.rcv_wup = data->sk_hd.rcv_wup,
		};

		if (mstate & (RCVQ_FIRST_FIN | RCVQ_SECOND_FIN)) {
			wopt.rcv_wup--;
			wopt.rcv_wnd++;
		}

		if (setsockopt(sk->fd, SOL_TCP, TCP_REPAIR_WINDOW, &wopt, sizeof(wopt))) {
			logerr("Unable to set window parameters");
			return -1;
		}
	}

	/*
	 * To restore a half closed sockets, fin packets has to be restored in
	 * recv and send queues. Here shutdown() is used to restore a fin
	 * packet in the send queue and a fake fin packet is send to restore it
	 * in the recv queue.
	 */
	if (mstate & SNDQ_FIRST_FIN)
		restore_fin_in_snd_queue(sk->fd, mstate & SNDQ_FIN_ACKED);

	/* Send a fin packet to the socket to restore it in a receive queue. */
	if (mstate & (RCVQ_FIRST_FIN | RCVQ_SECOND_FIN))
		if (send_fin_HA(sk, data, data_size, TH_ACK | TH_FIN) < 0)
			return -1;

	if (mstate & SNDQ_SECOND_FIN)
		restore_fin_in_snd_queue(sk->fd, mstate & SNDQ_FIN_ACKED);

	if (mstate & RCVQ_FIN_ACKED)
		data->sk_hd.inq_seq++;

	if (mstate & SNDQ_FIN_ACKED) {
		data->sk_hd.outq_seq++;
		if (send_fin_HA(sk, data, data_size, TH_ACK) < 0)
			return -1;
	}


	return 0;
}

void print_info(dt_info* data)
{
	printf("start restore inq_seq : %u outq_seq: %u\n", data->sk_hd.inq_seq,data->sk_hd.outq_seq);
	printf("inq_len:%u outq_len:%u\n",data->sk_hd.inq_len,data->sk_hd.outq_len);
	printf("snd_wnd:%u rcv_wnd:%u\n",data->sk_hd.snd_wnd,data->sk_hd.rcv_wnd);
	printf("timestamp:%u\n",data->sk_hd.timestamp);
	printf("src_addr:%u\n",data->sk_hd.src_addr);
	printf("dst_addr:%u\n",data->sk_hd.dst_addr);
}

void print_qdata(dt_info data_info)
{
	char out_q[80], in_q[80];
	snprintf(out_q, data_info.sk_hd.outq_len+1, "%s", data_info.send_queue );
	snprintf(in_q, data_info.sk_hd.inq_len+1, "%s", data_info.recv_queue );
	printf("out_q:%s\n", out_q);
	printf("in_q:%s\n", in_q);
}

static int restore_tcp_conn_state_HA(int fd,struct libsoccr_sk *socr,dt_info* data)
{
	int aux;
	union libsoccr_addr sa_src, sa_dst;
	print_info(data);
	struct sockaddr_in clinetaddr,serveraddr;
	//serveraddr.sin_addr.s_addr = inet_addr("140.96.29.50");
	//clinetaddr.sin_addr.s_addr = inet_addr("192.168.90.95");

	if (restore_sockaddr(&sa_src,
				AF_INET, data->sk_hd.src_port,
				&data->sk_hd.src_addr, 0) < 0)
		goto err;
	if (restore_sockaddr(&sa_dst,
				AF_INET, data->sk_hd.dst_port,
				&data->sk_hd.dst_addr, 0) < 0)
		goto err;

	libsoccr_set_addr(socr, 1, &sa_src, 0);
	libsoccr_set_addr(socr, 0, &sa_dst, 0);


	if (libsoccr_restore_HA(socr, data, sizeof(*data)))
		goto err;

	return 0;

err:
	return -1;
}

void get_data(dt_info* data_info, char* tmp, prefix pre)
{
	int len = sizeof(prefix);
	//TODO: for loop to get tcp dump data
	for(int i=0; i < pre.conn_size; i++)
	{
		memcpy(&data_info[i], tmp+len, sizeof(struct sk_hd));	//copy header
		len += sizeof(struct sk_hd);

		data_info[i].send_queue = malloc(data_info[i].sk_hd.outq_len);  
		data_info[i].recv_queue = malloc(data_info[i].sk_hd.inq_len);

		memcpy(data_info[i].send_queue, tmp+len, data_info[i].sk_hd.outq_len);	//copy queue data
		len += data_info[i].sk_hd.outq_len;
		memcpy(data_info[i].recv_queue, tmp+len, data_info[i].sk_hd.inq_len);
		
		print_qdata(data_info[i]);
	}

}

int restore_one_tcp_HA(int fd,dt_info* data)
{
	struct libsoccr_sk *sk;

	printf("Restoring TCP connection\n");

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
    char buff[80];
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

/*hd_info* listen_proxy_pri1(int hd_connfd)
{
	int ret = 0;
	char recv_hd[8];
	char tmp[8];
	hd_info *header_info = calloc(1,sizeof(*header_info));
    char buff[MAX];
    int n;
    for (;;) {
		ret = read(hd_connfd, recv_hd, 8);
		if(ret!=0)
		{
			memcpy(tmp,recv_hd,8);
			//get_header(header_info,tmp);
			bzero(recv_hd, 8);
		}
		if(ret == 0)
		{
			return header_info;
			break;
		}
        if ((strncmp(buff, "exit", 4)) == 0) {
            printf("Client Exit...\n");
            break;
        }
    }
	return header_info;
}*/

dt_info* listen_proxy_pri2(int dt_connfd)
{
	int ret = 0;
	char recv_dt[8000];
	char tmp[8000];
	prefix pre;
	dt_info *data_info;
    char buff[MAX];
    int n;
    for (;;) {
		ret = read(dt_connfd, recv_dt, 8000);
		printf("ret:%d\n", ret);
		if(ret!=0)
		{
			memcpy(tmp, recv_dt, ret);
			memcpy(&pre, tmp, sizeof(prefix));
			data_info = calloc(pre.conn_size, sizeof(*data_info));
			get_data(data_info, tmp, pre);
			bzero(recv_dt, 8000);
		}
		if(ret == 0)
		{
			return data_info;
			break;
		}
        if ((strncmp(buff, "exit", 4)) == 0) {
            printf("Client Exit...\n");
            break;
        }
    }
	return data_info;
}


void *socketThread1(void *arg)
{
  int hd_connfd = *((int *)arg);
  //hd_info* hd_data = listen_proxy_pri1(hd_connfd);
  hd_info* hd_data ;
  pthread_exit((void *) hd_data);
}

void *socketThread2(void *arg)
{
  int dt_connfd = *((int *)arg);
  dt_info* dt_data = listen_proxy_pri2(dt_connfd);
  pthread_exit((void *) dt_data);
}


int main()
{
    int cuju_sockfd, proxy_hd_fd, proxy_dt_fd, hd_connfd, dt_connfd;
    struct sockaddr_in proxy_pri_addr, cli, proxy_backup_addr;

    // socket create and varification 
    cuju_sockfd = socket(AF_INET, SOCK_STREAM, 0);
	proxy_hd_fd = socket(AF_INET, SOCK_STREAM, 0);
	proxy_dt_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (cuju_sockfd == -1 || proxy_hd_fd == -1 || proxy_dt_fd == -1) {
        printf("socket creation failed...\n");
        exit(0);
    }
    else
        printf("Socket successfully created..\n");
	bzero(&proxy_backup_addr, sizeof(proxy_backup_addr));
    proxy_backup_addr.sin_family = AF_INET;
    proxy_backup_addr.sin_addr.s_addr = inet_addr("192.168.90.92");
    proxy_backup_addr.sin_port = htons(PORT);
	bind(proxy_hd_fd, (struct sockaddr*)&proxy_backup_addr, sizeof(proxy_backup_addr));
	// connect the client socket to proxy backup socket 
    if ((listen(proxy_hd_fd, 5)) != 0) { 
        printf("Listen failed 1...\n"); 
        exit(0); 
    }     
    else
        printf("proxy listening 1..\n"); 

    int len = sizeof(proxy_pri_addr); 
  
    // Accept the data packet from client and verification 
    hd_connfd = accept(proxy_hd_fd, (SA*)&proxy_pri_addr, &len); 	//no use
    if (hd_connfd < 0) { 
        printf("proxy acccept failed 1...\n"); 
        exit(0); 
    } 
    else
        printf("proxy acccept the client 1...\n"); 

	dt_connfd = accept(proxy_hd_fd, (SA*)&cli, &len); 
    if (dt_connfd < 0) { 
        printf("proxy acccept failed 2...\n"); 
        exit(0); 
    } 
    else
        printf("proxy acccept the client 2...\n"); 
	pthread_t tid[2];
	int i = 0;
    void *ret1;
	void *ret2;
	
	//Only thread2 work (receive TCP dump data from HA proxy1)
    if( pthread_create(&tid[0], NULL, socketThread1, &hd_connfd) != 0 )		//no use
        printf("Failed to create thread1\n");
	if( pthread_create(&tid[1], NULL, socketThread2, &dt_connfd) != 0 )
        printf("Failed to create thread1\n");


    pthread_join(tid[0], &ret1);
    pthread_join(tid[1], &ret2);

    hd_info* header = (hd_info*)ret1;
    dt_info* data = (dt_info*)ret2;

	printf("final:\n");
	printf("data->inq_seq:%u\n", data->sk_hd.inq_seq);
	printf("data->outq_seq:%u\n", data->sk_hd.outq_seq);

	sleep(2);
	restore_one_tcp_HA(cuju_sockfd, data);
	func(cuju_sockfd);

    //printf("errno:%d",errno);
    // close the socket 
    close(cuju_sockfd);
}

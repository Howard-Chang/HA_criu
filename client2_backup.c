#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "soccr/soccr.h"
#include <errno.h>
#include <asm/types.h>
#define MAX 80 
#define PORT 8080 
#define SA struct sockaddr 
typedef unsigned int u32;
struct libsoccr_sk {
	int fd;
	unsigned flags;
	char *recv_queue;
	char *send_queue;
	union libsoccr_addr *src_addr;
	union libsoccr_addr *dst_addr;
};
struct soccr_tcp_info {
	__u8	tcpi_state;
	__u8	tcpi_ca_state;
	__u8	tcpi_retransmits;
	__u8	tcpi_probes;
	__u8	tcpi_backoff;
	__u8	tcpi_options;
	__u8	tcpi_snd_wscale : 4, tcpi_rcv_wscale : 4;
};
static int tcp_repair_on(int fd)
{
	int ret, aux = 1;

	ret = setsockopt(fd, SOL_TCP, TCP_REPAIR, &aux, sizeof(aux));
	if (ret < 0)
		printf("Can't turn TCP repair mode ON");

	return ret;
}
static int tcp_repair_off(int fd)
{
	int aux = 0, ret;

	ret = setsockopt(fd, SOL_TCP, TCP_REPAIR, &aux, sizeof(aux));
	if (ret < 0)
		printf("Failed to turn off repair mode on socket");

	return ret;
}
static int get_queue(int sk, int queue_id,
		__u32 *seq, __u32 len)
{
	int ret, aux;
	socklen_t auxl;
	char *buf;

	aux = queue_id;
	auxl = sizeof(aux);
	ret = setsockopt(sk, SOL_TCP, TCP_REPAIR_QUEUE, &aux, auxl);
	if (ret < 0)
		goto err_sopt;

	auxl = sizeof(*seq);
	ret = getsockopt(sk, SOL_TCP, TCP_QUEUE_SEQ, seq, &auxl);
	if (ret < 0)
		goto err_sopt;

	return 0;

err_sopt:
	printf("\tsockopt failed");
err_buf:
	return -1;

err_recv:
	printf("\trecv failed (%d, want %d)", ret, len);
	free(buf);
	goto err_buf;
}
#define SET_SA_FLAGS	(SOCCR_MEM_EXCL)
int libsoccr_set_addr(struct libsoccr_sk *sk, int self, union libsoccr_addr *addr, unsigned flags)
{
	if (flags & ~SET_SA_FLAGS)
		return -1;

	if (self) {
		sk->src_addr = addr;
		/*if (flags & SOCCR_MEM_EXCL)
			sk->flags |= SK_FLAG_FREE_SA;*/
	} else {
		sk->dst_addr = addr;
		/*if (flags & SOCCR_MEM_EXCL)
			sk->flags |= SK_FLAG_FREE_DA;*/
	}

	return 0;
}

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

static int set_queue_seq(struct libsoccr_sk *sk, int queue, __u32 seq)
{
	printf("\tSetting %d queue seq to %u\n", queue, seq);

	if (setsockopt(sk->fd, SOL_TCP, TCP_REPAIR_QUEUE, &queue, sizeof(queue)) < 0) {
		printf("Can't set repair queue");
		return -1;
	}

	if (setsockopt(sk->fd, SOL_TCP, TCP_QUEUE_SEQ, &seq, sizeof(seq)) < 0) {
		printf("Can't set queue seq");
		return -1;
	}

	return 0;
}

static int libsoccr_set_sk_data_noq(struct libsoccr_sk *sk,
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

int libsoccr_restore(struct libsoccr_sk *sk,
		struct libsoccr_sk_data *data, unsigned data_size)
{

	if (libsoccr_set_sk_data_noq(sk, data, data_size))
		return -1;
	return 0;
}

static int restore_tcp_conn_state(struct libsoccr_sk *socr,int fd)
{
	int aux;

	struct libsoccr_sk_data data = {};
	union libsoccr_addr sa_src, sa_dst;
	socr = calloc(1,sizeof(struct libsoccr_sk));
	socr->fd = fd;

	data.inq_seq = 3394533156;
	data.outq_seq = 3205869059;

	struct sockaddr_in clinetaddr,serveraddr;
	serveraddr.sin_addr.s_addr = inet_addr("140.96.29.50");
	clinetaddr.sin_addr.s_addr = inet_addr("192.168.90.95");
	if (restore_sockaddr(&sa_src,
				AF_INET, 2552,
				&clinetaddr.sin_addr.s_addr, 0) < 0)
		goto err_c;
	if (restore_sockaddr(&sa_dst,
				AF_INET, 8080,
				&serveraddr.sin_addr.s_addr, 0) < 0)
		goto err_c;

	libsoccr_set_addr(socr, 1, &sa_src, 0);
	libsoccr_set_addr(socr, 0, &sa_dst, 0);


	if (libsoccr_restore(socr, &data, sizeof(data)))
		goto err_c;

	return 0;

err_c:
	/*tcp_stream_entry__free_unpacked(tse, NULL);
	close_image(img);*/
err:
	return -1;
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
int main()
{
    int sockfd, connfd;
    struct sockaddr_in servaddr, cli;

    // socket create and varification 
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        printf("socket creation failed...\n");
        exit(0);
    }
    else
        printf("Socket successfully created..\n");
    /*bzero(&servaddr, sizeof(servaddr));

    // assign IP, PORT 
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr("140.96.29.50");
    servaddr.sin_port = htons(PORT);*/

    // connect the client socket to server socket 
    /*if (connect(sockfd, (SA*)&servaddr, sizeof(servaddr)) != 0) {
        printf("connection with the server failed...\n");
        exit(0);
    }
    else
        printf("connected to the server..\n");*/
    // function for chat 
    
    struct libsoccr_sk_data* data = calloc(1,sizeof(struct libsoccr_sk_data));
    //memset(data, 0, sizeof(data));
	struct libsoccr_sk *socr;
    restore_tcp_conn_state(socr,sockfd);
	func(sockfd);
    //printf("inq_seq:%u  outq_seq:%u\n",data->inq_seq,data->outq_seq);
    //printf("errno:%d",errno);
    // close the socket 
    close(sockfd);
}

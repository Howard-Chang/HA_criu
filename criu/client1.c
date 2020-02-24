#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "../soccr/soccr.h"
#include "../soccr/soccr.c"
#include "./include/sk-inet.h"
#include <errno.h>
#include <asm/types.h>
#define MAX 80 
#define PORT 8080 
#define SA struct sockaddr 
/*struct libsoccr_sk {
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

static int refresh_sk(int fd,
			struct libsoccr_sk_data *data, struct soccr_tcp_info *ti)
{
	int size;
	socklen_t olen = sizeof(*ti);

	if (getsockopt(fd, SOL_TCP, TCP_INFO, ti, &olen) || olen != sizeof(*ti)) {
		printf("Failed to obtain TCP_INFO");
		return -1;
	}

	switch (ti->tcpi_state) {
	case TCP_ESTABLISHED:
	case TCP_FIN_WAIT1:
	case TCP_FIN_WAIT2:
	case TCP_LAST_ACK:
	case TCP_CLOSE_WAIT:
	case TCP_CLOSING:
	case TCP_CLOSE:
	case TCP_SYN_SENT:
		break;
	default:
		printf("Unknown state %d\n", ti->tcpi_state);
		return -1;
	}

	if (data->state == TCP_CLOSE) {
		data->unsq_len = 0;
		data->outq_len = 0;
	}

	return 0;
}
*/
/*static int get_queue(int sk, int queue_id,
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
}*/
/*
int libsoccr_save(struct libsoccr_sk *sk, struct libsoccr_sk_data *data, unsigned data_size)
{
	struct soccr_tcp_info ti;

	if (!data || data_size < SOCR_DATA_MIN_SIZE) {
		loge("Invalid input parameters\n");
		return -1;
	}

	memset(data, 0, data_size);

	if (refresh_sk(sk, data, &ti))
		return -2;

	if (get_stream_options(sk, data, &ti))
		return -3;

	if (get_window(sk, data))
		return -4;

	sk->flags |= SK_FLAG_FREE_SQ | SK_FLAG_FREE_RQ;

	if (get_queue(sk->fd, TCP_RECV_QUEUE, &data->inq_seq, data->inq_len, &sk->recv_queue))
		return -5;

	if (get_queue(sk->fd, TCP_SEND_QUEUE, &data->outq_seq, data->outq_len, &sk->send_queue))
		return -6;

	return sizeof(struct libsoccr_sk_data);
}
*/
static int dump_tcp_conn_state_HA(int fd,struct libsoccr_sk_data* data)
{
	struct libsoccr_sk *socr = calloc(1,sizeof(struct libsoccr_sk));
    if (tcp_repair_on(fd) < 0) {
		return -1;
	}
	socr->fd = fd;
    int ret;
	ret = libsoccr_save(socr, data, sizeof(*data));
	if (ret < 0) {
		printf("libsoccr_save() failed with %d\n", ret);
		return ret;
	}
	if (ret != sizeof(*data)) {
		printf("This libsocr is not supported (%d vs %d)\n",
				ret, (int)sizeof(*data));
		return ret;
	}
	if (tcp_repair_off(fd) < 0) {
		return -1;
	}
	return ret;
}

void func(int sockfd,struct libsoccr_sk_data* data)
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
		if ((strncmp(buff, "exit", 4)) == 0) {
			read(sockfd, buff, sizeof(buff));
			printf("sent from server:%s\n",buff);
            printf("Client Exit...\n");
            break;
        }
        bzero(buff, sizeof(buff));
		dump_tcp_conn_state_HA(sockfd,data);
        /*read(sockfd, buff, sizeof(buff));
        printf("From Server : %s", buff);
        if ((strncmp(buff, "exit", 4)) == 0) {
            printf("Client Exit...\n");
            break;
        }*/
        /*struct libsoccr_sk_data* data = calloc(1,sizeof(struct libsoccr_sk_data));
        memset(data, 0, sizeof(data));
        dump_tcp_conn_state(sockfd,data);
        printf("inq_seq:%u  outq_seq:%u\n",data->inq_seq,data->outq_seq);
        printf("errno:%d",errno);*/
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
    bzero(&servaddr, sizeof(servaddr));

    // assign IP, PORT 
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr("140.96.29.50");
    servaddr.sin_port = htons(PORT);
	struct sockaddr_in cli_addr;
	memset(&cli_addr, 0, sizeof(cli_addr));  
	cli_addr.sin_family = AF_INET;  
	cli_addr.sin_addr.s_addr = inet_addr("192.168.90.95");  
	cli_addr.sin_port = htons(2552);  
	bind(sockfd, (struct sockaddr*)&cli_addr, sizeof(cli_addr));

    // connect the client socket to server socket 
    if (connect(sockfd, (SA*)&servaddr, sizeof(servaddr)) != 0) {
        printf("connection with the server failed...\n");
        exit(0);
    }
    else
        printf("connected to the server..\n");
    
	struct libsoccr_sk_data* data = calloc(1,sizeof(struct libsoccr_sk_data));
    
    func(sockfd,data);
    dump_tcp_conn_state_HA(sockfd,data); 
    printf("inq_seq:%u  outq_seq:%u\n",data->inq_seq,data->outq_seq);
    printf("errno:%d",errno);
    // close the socket 
    close(sockfd);
}

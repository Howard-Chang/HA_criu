#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#include <asm/types.h>
#include "criu_HA.h"
#define MAX 65535 
#define PORT 8080 
#define HEADER_SIZE 84
#define SA struct sockaddr 
typedef unsigned int u32;

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

void free_buf(dt_info* buf)
{
    free(buf->recv_queue);
    free(buf->send_queue);
    free(buf);
}

void final_save_data(char *send_data, dt_info *buf,int hd_idx, int q_idx)
{
    memcpy(send_data+hd_idx, &buf->sk_hd, sizeof(struct sk_hd));
    memcpy(send_data+q_idx, buf->send_queue, buf->sk_hd.outq_len);
    memcpy(send_data+q_idx+buf->sk_hd.outq_len, buf->recv_queue, buf->sk_hd.inq_len);
}

void print_info(struct libsoccr_sk_data* data, struct libsoccr_sk* socr)
{
    printf("src_addr:%u\n", socr->src_addr->v4.sin_addr.s_addr);
    printf("dst_addr:%u\n", socr->dst_addr->v4.sin_addr.s_addr);
    printf("src_port:%u\n", socr->dst_addr->v4.sin_port);
    printf("dst_port:%u\n", socr->src_addr->v4.sin_port);
    printf("buf->timestamp:%u\n", data->timestamp);
    printf("outq_len:%d inq_len:%d\n", data->outq_len,data->inq_len);
    printf("unsq_len:%u", data->unsq_len);
}

void save_sk_header(prefix* pre, uint16_t conn_size)
{
    pre->version = 1;
    pre->type = 1;
    pre->conn_size = conn_size;
}

void save_sk_data(struct libsoccr_sk_data* data, struct libsoccr_sk* socr, dt_info* buf)
{
    buf->sk_hd.src_addr = socr->src_addr->v4.sin_addr.s_addr;
    buf->sk_hd.dst_addr = socr->dst_addr->v4.sin_addr.s_addr;
    buf->sk_hd.src_port = socr->src_addr->v4.sin_port;
    buf->sk_hd.dst_port = socr->dst_addr->v4.sin_port;

    memcpy(&buf->sk_hd.state, data, sizeof(*data));

    buf->send_queue = malloc(buf->sk_hd.outq_len);
    memcpy(buf->send_queue, socr->send_queue, data->outq_len);

    buf->recv_queue = malloc(buf->sk_hd.inq_len);
    memcpy(buf->recv_queue,socr->recv_queue,data->inq_len);

    //print_info(data,socr);
}

void set_addr_port(struct libsoccr_sk *socr)
{
    union libsoccr_addr sa_src, sa_dst;
    struct sockaddr_in clinetaddr,serveraddr;
	serveraddr.sin_addr.s_addr = inet_addr("140.96.29.50");
	clinetaddr.sin_addr.s_addr = inet_addr("192.168.90.95");
	if (restore_sockaddr(&sa_src,
				AF_INET, 2552,
				&clinetaddr.sin_addr.s_addr, 0) < 0)
		return;
	if (restore_sockaddr(&sa_dst,
				AF_INET, 8080,
				&serveraddr.sin_addr.s_addr, 0) < 0)
		return;

	libsoccr_set_addr(socr, 1, &sa_src, 0);
	libsoccr_set_addr(socr, 0, &sa_dst, 0);
}

static int dump_tcp_conn_state_HA(int fd, struct libsoccr_sk_data* data, prefix* hd, dt_info* buf)
{
    int ret;
	struct libsoccr_sk *socr = calloc(1, sizeof(struct libsoccr_sk));
    socr->fd = fd;

    set_addr_port(socr);
    uint32_t src_addr = socr->src_addr->v4.sin_addr.s_addr;
    uint16_t src_port = socr->src_addr->v4.sin_port;                                                                               

	ret = libsoccr_save(socr, data, sizeof(*data));
    socr->src_addr->v4.sin_addr.s_addr = src_addr;
    socr->src_addr->v4.sin_port = src_port;

	if (ret < 0) {
		printf("libsoccr_save() failed with %d\n", ret);
		return ret;
	}
	if (ret != sizeof(*data)) {
		printf("This libsocr is not supported (%d vs %d)\n",
				ret, (int)sizeof(*data));
		return ret;
	}
    
    save_sk_data(data, socr, buf);

	return ret;
}

void dump_send(int sockfd, int proxy_dt_fd, struct libsoccr_sk_data* data, prefix* pre, dt_info* buf)
{
    int hd_idx, len;
    buf = calloc(pre->conn_size, sizeof(*buf));

    if (tcp_repair_on(sockfd) < 0) {
        printf("tcp_repair_on fail.\n");
        return;
    }

    for(int i=0; i < pre->conn_size; i++)        // for loop to collect each socket data.
    {
		dump_tcp_conn_state_HA(sockfd, data, pre, &buf[i]);
    }
    
    hd_idx = sizeof(prefix);
    len = sizeof(prefix)+pre->conn_size*sizeof(struct sk_hd);
    char *send_data = malloc(len);

    memcpy(send_data, pre, sizeof(prefix));

    for(int i=0; i < pre->conn_size; i++)        //for loop to store send out buf
    {
        send_data = realloc(send_data, len + buf[i].sk_hd.outq_len + buf[i].sk_hd.inq_len);
        final_save_data(send_data, &buf[i], hd_idx, len);
        len += buf[i].sk_hd.inq_len + buf[i].sk_hd.outq_len;
        hd_idx += sizeof(struct sk_hd);
    }

    if (tcp_repair_off(sockfd) < 0) {
        printf("tcp_repair_off fail.\n");
        return ;
	}

    write(proxy_dt_fd, send_data, len);
    free(send_data);
    free_buf(buf);
}

void func(int sockfd, int proxy_dt_fd, struct libsoccr_sk_data* data, prefix* pre, dt_info* buf)
{
    int ret = 0, len = 0, hd_idx = 0;
    char Buff[80];
    int n;
    for (;;) {
        bzero(Buff, sizeof(Buff));
        printf("Enter the string : ");
        n = 0;  
        len = 0;
        while ((Buff[n++] = getchar()) != '\n')
            ;
        n--;
        write(sockfd, Buff, n);

		if ((strncmp(Buff, "exit", 4)) == 0) {
			read(sockfd, Buff, sizeof(Buff));
			printf("sent from server:%s\n",Buff);
            printf("Client Exit...\n");
            break;
        }
        bzero(Buff, sizeof(Buff));
        save_sk_header(pre, 1);
        dump_send(sockfd,proxy_dt_fd,data,pre,buf);
    }
}
int main()
{
    int sockfd, proxy_hd_fd, proxy_dt_fd;
    struct libsoccr_sk_data* data = calloc(1, sizeof(struct libsoccr_sk_data));
    struct sockaddr_in servaddr, cli_addr, proxy_backup_addr;
    prefix *pre;
    dt_info *buf;
    
    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (sockfd == -1) {
        printf("socket creation failed...\n");
        exit(0);
    }
    else
        printf("Socket successfully created..\n");
    
    proxy_hd_fd = socket(AF_INET, SOCK_STREAM, 0);      //no use
    if (proxy_hd_fd == -1) {
        printf("proxy_hd_fd creation failed...\n");
        exit(0);
    }
    else
        printf("proxy_hd_fd successfully created..\n");
    
    proxy_dt_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (proxy_dt_fd == -1) {
        printf("proxy_dt_fd creation failed...\n");
        exit(0);
    }
    else
        printf("proxy_dt_fd successfully created..\n");
        
    // assign proxy backup IP, PORT
    bzero(&proxy_backup_addr, sizeof(proxy_backup_addr));
    proxy_backup_addr.sin_family = AF_INET;
    proxy_backup_addr.sin_addr.s_addr = inet_addr("192.168.90.92");
    proxy_backup_addr.sin_port = htons(PORT);
    // assign Server IP, PORT 
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr("140.96.29.50");
    servaddr.sin_port = htons(PORT);
    // assign host IP, PORT
	bzero(&cli_addr, sizeof(cli_addr));  
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

    if (connect(proxy_hd_fd, (SA*)&proxy_backup_addr, sizeof(proxy_backup_addr)) != 0) {    //no use
        printf("connection with the proxy failed 1...\n");
        exit(0);
    }
    else
        printf("connected to the proxy 1..\n");
    
    if (connect(proxy_dt_fd, (SA*)&proxy_backup_addr, sizeof(proxy_backup_addr)) != 0) {
        printf("connection with the proxy failed 2...\n");
        exit(0);
    }
    else
        printf("connected to the proxy 2..\n");
    

    pre = calloc(1, sizeof(*pre));

    func(sockfd, proxy_dt_fd, data, pre, buf);
    dump_send(sockfd,proxy_dt_fd,data,pre,buf);

	tcp_repair_on(sockfd);

    system("sudo /etc/init.d/keepalived restart"); //transfer VIP to backup

    // close the socket 
    //close(sockfd);
}

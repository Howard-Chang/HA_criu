#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "./soccr/soccr.c"
#include <errno.h>
#include <asm/types.h>
#define MAX 65535 
#define PORT 8080 
#define HEADER_SIZE 84
#define SA struct sockaddr 
typedef unsigned int u32;
static uint32_t id = 0; 
typedef struct sk_buf_packet
{
    int header_idx;
    int header_size;
    int queue_size;
    char *sk_header_data;
    char *sk_queue_data;
}sk_buf;

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

void put_byte_4(unsigned char* buf,uint32_t v,int index)
{
    buf[index]   = v >> 24;
    buf[index+1] = v >> 16;
    buf[index+2] = v >> 8;
    buf[index+3] = v;	
}

void put_byte_6(unsigned char* buf,uint64_t v,int index)
{
    buf[index]   = v >> 40;
    buf[index+1] = v >> 32;
    buf[index+2] = v >> 24;
    buf[index+3] = v >> 16;
    buf[index+4] = v >> 8;
    buf[index+5] = v;

}

uint32_t get_be32(char* buf,int index)
{
	return (buf[index] <<  24) | (buf[index+1] << 16) | (buf[index+2] << 8) | buf[index+3];	
}

void save_sk_header(char *sk_header)
{
    uint16_t conn_size = 5;
    memcpy(sk_header,(char*)&id,sizeof(id));
    sk_header[4] = 1;
    sk_header[5] = 0;
    memcpy(sk_header+6,(char*)&conn_size,sizeof(conn_size));
    
}

void sk_buf_packet_init(sk_buf* buf,int conn_size)
{
    buf->header_size = HEADER_SIZE*conn_size;
    buf->sk_header_data = realloc(buf->sk_header_data,sizeof(buf->header_size));
    buf->sk_queue_data = realloc(buf->sk_queue_data,1);
}

char* final_save_data(sk_buf *buf)
{
    char *send_data = malloc(buf->header_size+buf->queue_size);
    memcpy(send_data,buf->sk_header_data,buf->header_size);
    memcpy(send_data+buf->header_size,buf->sk_queue_data,buf->queue_size);
    printf("buf->queue_size:%d\n",buf->queue_size);
    //buf->sk_queue_data[buf->queue_size]=0;
    //printf("buf->sk_queue_data:%s\n",buf->sk_queue_data);
    //free(buf->sk_header_data);
    //free(buf->sk_queue_data);
    //free(buf);
    return send_data;
}

void save_sk_data(struct libsoccr_sk_data* data,struct libsoccr_sk* socr,sk_buf* buf)
{

    memcpy(buf->sk_header_data+buf->header_idx,(char*)&id,sizeof(id));
    memcpy(buf->sk_header_data+buf->header_idx+4,(char*)&socr->src_addr->v4.sin_addr.s_addr,4);
    printf("src_addr:%u\n",socr->src_addr->v4.sin_addr.s_addr);
    memcpy(buf->sk_header_data+buf->header_idx+8,(char*)&socr->dst_addr->v4.sin_addr.s_addr,4);
    printf("dst_addr:%u\n",socr->dst_addr->v4.sin_addr.s_addr);
    memcpy(buf->sk_header_data+buf->header_idx+12,(char*)&socr->src_addr->v4.sin_port,2);
    printf("src_port:%u\n",socr->dst_addr->v4.sin_port);
    memcpy(buf->sk_header_data+buf->header_idx+14,(char*)&socr->dst_addr->v4.sin_port,2);
    printf("dst_port:%u\n",socr->src_addr->v4.sin_port);
    
    memcpy(buf->sk_header_data+buf->header_idx+16,(char*)data,sizeof(*data));
    //buf->header_idx += HEADER_SIZE;
    //printf("+++++++++buf->queue_size:%d",buf->queue_size);
    buf->sk_queue_data = realloc(buf->sk_queue_data,buf->queue_size+data->outq_len);
    memcpy(buf->sk_queue_data+buf->queue_size,socr->send_queue,data->outq_len);
    buf->queue_size += data->outq_len;
    printf("outq_len:%d inq_len:%d\n",data->outq_len,data->inq_len);
    
    buf->sk_queue_data = realloc(buf->sk_queue_data,buf->queue_size+data->inq_len);
    if(data->inq_len)
    memcpy(buf->sk_queue_data+buf->queue_size,socr->recv_queue,data->inq_len);
    buf->queue_size += data->inq_len;
    
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

static int dump_tcp_conn_state_HA(int fd, int proxy_hd_fd, int proxy_dt_fd, struct libsoccr_sk_data* data,sk_buf* buf)
{
    char sk_header[8];

	struct libsoccr_sk *socr = calloc(1,sizeof(struct libsoccr_sk));
    if (tcp_repair_on(fd) < 0) {
        printf("tcp_repair_on fail.\n");
		return -1;
	}
	socr->fd = fd;
    set_addr_port(socr);
    uint32_t src_addr = socr->src_addr->v4.sin_addr.s_addr;
    uint16_t src_port = socr->src_addr->v4.sin_port;                                                                               
    int ret;
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
    
	if (tcp_repair_off(fd) < 0) {
        printf("tcp_repair_off fail.\n");
		return -1;
	}
    save_sk_header(sk_header);
    write(proxy_hd_fd, sk_header, sizeof(sk_header));
    
    //if 連線數量達預期..開始存sk queue data.
    save_sk_data(data,socr,buf);
    int len = buf->header_size+buf->queue_size;

    char *send_data = final_save_data(buf);
    write(proxy_dt_fd, send_data, len);
	free(send_data);
	return ret;
}

void func(int sockfd, int proxy_hd_fd, int proxy_dt_fd, struct libsoccr_sk_data* data,sk_buf* buf)
{
    int ret = 0;
    char Buff[70];
    int n;
    for (;;) {
        bzero(Buff, sizeof(Buff));
        printf("Enter the string : ");
        n = 0;
        id++;
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
        //sk_buf_packet_init(buf,1);
        buf->header_size = HEADER_SIZE*1;
        //buf->sk_header_data = malloc(buf->sk_header_data,buf->header_size);
        //buf->sk_queue_data = malloc(buf->sk_queue_data,1);
        buf->sk_header_data = malloc(100);
        buf->sk_queue_data = malloc(100);
        buf->queue_size = 0;
        
		dump_tcp_conn_state_HA(sockfd,proxy_hd_fd,proxy_dt_fd,data,buf);
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
    int sockfd, proxy_hd_fd, proxy_dt_fd;
    struct sockaddr_in servaddr, cli_addr, proxy_backup_addr;
    sk_buf *buf;
    //sk_buf_packet_init(buf,1);
 
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        printf("socket creation failed...\n");
        exit(0);
    }
    else
        printf("Socket successfully created..\n");
    
    proxy_hd_fd = socket(AF_INET, SOCK_STREAM, 0);
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
    proxy_backup_addr.sin_addr.s_addr = inet_addr("192.168.90.91");
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

    if (connect(proxy_hd_fd, (SA*)&proxy_backup_addr, sizeof(proxy_backup_addr)) != 0) {
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
    
	struct libsoccr_sk_data* data = calloc(1,sizeof(struct libsoccr_sk_data));
    buf = calloc(1,sizeof(*buf));
    func(sockfd,proxy_hd_fd,proxy_dt_fd,data,buf);
    dump_tcp_conn_state_HA(sockfd,proxy_hd_fd,proxy_dt_fd,data,buf); 
	tcp_repair_on(sockfd);

    system("sudo /etc/init.d/keepalived restart"); //transfer VIP to backup

    // close the socket 
    //close(sockfd);
}

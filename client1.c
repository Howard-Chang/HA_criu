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
#define MAX 80 
#define PORT 8080 
#define SA struct sockaddr 
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

static int dump_tcp_conn_state_HA(int fd, int proxy_fd, struct libsoccr_sk_data* data)
{
    
    char buff[MAX];
	struct libsoccr_sk *socr = calloc(1,sizeof(struct libsoccr_sk));
    if (tcp_repair_on(fd) < 0) {
        printf("tcp_repair_on fail.\n");
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
        printf("tcp_repair_off fail.\n");
		return -1;
	}
    //save_sk_header(fd,data,socr);
    write(proxy_fd, data, sizeof(*data));
		
	return ret;
}

void func(int sockfd, int proxy_fd, struct libsoccr_sk_data* data)
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
		dump_tcp_conn_state_HA(sockfd,proxy_fd,data);
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
    int sockfd, proxy_fd;
    struct sockaddr_in servaddr, cli_addr, proxy_backup_addr;
    
    // socket create and varification 
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        printf("socket creation failed...\n");
        exit(0);
    }
    else
        printf("Socket successfully created..\n");
    proxy_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (proxy_fd == -1) {
        printf("proxy_fd creation failed...\n");
        exit(0);
    }
    else
        printf("proxy_fd successfully created..\n");
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
    if (connect(proxy_fd, (SA*)&proxy_backup_addr, sizeof(proxy_backup_addr)) != 0) {
        printf("connection with the proxy failed...\n");
        exit(0);
    }
    else
        printf("connected to the proxy..\n");
    
	struct libsoccr_sk_data* data = calloc(1,sizeof(struct libsoccr_sk_data));
    
    func(sockfd,proxy_fd,data);
    dump_tcp_conn_state_HA(sockfd,proxy_fd,data); 
	tcp_repair_on(sockfd);
    //sleep(3);
    system("sudo /etc/init.d/keepalived restart"); //transfer VIP to backup

    // close the socket 
    //close(sockfd);
}

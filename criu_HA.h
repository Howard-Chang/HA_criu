#include "./soccr/soccr.c"
#include "./soccr/soccr.h"
typedef unsigned int u32;
/*typedef struct sk_data_info
{
    uint8_t version;
	uint8_t type;
	uint16_t conn_size; 
    uint32_t src_addr;
    uint32_t dst_addr;
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t state;
	uint32_t inq_len;
	uint32_t inq_seq;
	uint32_t outq_len;
	uint32_t outq_seq;
	uint32_t unsq_len;
	uint32_t opt_mask;
	uint32_t mss_clamp;
	uint32_t snd_wscale;
	uint32_t rcv_wscale;
	uint32_t timestamp;

	uint32_t flags; // SOCCR_FLAGS_... below 
	uint32_t snd_wl1;
	uint32_t snd_wnd;
	uint32_t max_window;
	uint32_t rcv_wnd;
	uint32_t rcv_wup;
    char* send_queue;
    char* recv_queue;
}dt_info;*/

typedef struct sk_data_info
{
    struct sk_hd{
        uint32_t src_addr;
        uint32_t dst_addr;
        uint16_t src_port;
        uint16_t dst_port;
        uint32_t state;
        uint32_t inq_len;
        uint32_t inq_seq;
        uint32_t outq_len;
        uint32_t outq_seq;
        uint32_t unsq_len;
        uint32_t opt_mask;
        uint32_t mss_clamp;
        uint32_t snd_wscale;
        uint32_t rcv_wscale;
        uint32_t timestamp;

        uint32_t flags; /* SOCCR_FLAGS_... below */
        uint32_t snd_wl1;
        uint32_t snd_wnd;
        uint32_t max_window;
        uint32_t rcv_wnd;
        uint32_t rcv_wup;

    }sk_hd;
    char* send_queue;
    char* recv_queue;
}dt_info;

typedef struct sk_prefix_info 
{
    uint8_t version;
    uint8_t type;
    uint16_t conn_size;
}prefix;

typedef struct sk_header_info 
{
    uint32_t id;
    uint8_t version;
    uint8_t type;
    uint8_t conn_size;
}hd_info;

static int libsoccr_restore_queue_HA(struct libsoccr_sk *sk, dt_info *data, unsigned data_size,
		int queue, char *buf)
{
	if (!buf)
		return 0;

	if (!data || data_size < SOCR_DATA_MIN_SIZE)
		return -1;

	if (queue == TCP_RECV_QUEUE) {
		if (!data->sk_hd.inq_len)
			return 0;
		return send_queue(sk, TCP_RECV_QUEUE, buf, data->sk_hd.inq_len);
	}

	if (queue == TCP_SEND_QUEUE) {
		__u32 len, ulen;

		/*
		 * All data in a write buffer can be divided on two parts sent
		 * but not yet acknowledged data and unsent data.
		 * The TCP stack must know which data have been sent, because
		 * acknowledgment can be received for them. These data must be
		 * restored in repair mode.
		 */
		ulen = data->sk_hd.unsq_len;
		len = data->sk_hd.outq_len - ulen;
		if (len && send_queue(sk, TCP_SEND_QUEUE, buf, len))
			return -2;

		if (ulen) {
			/*
			 * The second part of data have never been sent to outside, so
			 * they can be restored without any tricks.
			 */
			tcp_repair_off(sk->fd);
			if (__send_queue(sk, TCP_SEND_QUEUE, buf + len, ulen))
				return -3;
			if (tcp_repair_on(sk->fd))
				return -4;
		}

		return 0;
	}

	return -5;
}
static int send_fin_HA(struct libsoccr_sk *sk, dt_info *data,
		unsigned data_size, uint8_t flags)
{
	uint32_t src_v4 = sk->src_addr->v4.sin_addr.s_addr;
	uint32_t dst_v4 = sk->dst_addr->v4.sin_addr.s_addr;
	int ret, exit_code = -1, family;
	char errbuf[LIBNET_ERRBUF_SIZE];
	int mark = SOCCR_MARK;
	int libnet_type;
	libnet_t *l;

	family = sk->dst_addr->sa.sa_family;

	if (family == AF_INET6 && ipv6_addr_mapped(sk->dst_addr)) {
		/* TCP over IPv4 */
		family = AF_INET;
		dst_v4 = sk->dst_addr->v6.sin6_addr.s6_addr32[3];
		src_v4 = sk->src_addr->v6.sin6_addr.s6_addr32[3];
	}

	if (family == AF_INET6)
		libnet_type = LIBNET_RAW6;
	else
		libnet_type = LIBNET_RAW4;

	l = libnet_init(
		libnet_type,		/* injection type */
		NULL,			/* network interface */
		errbuf);		/* errbuf */
	if (l == NULL) {
		loge("libnet_init failed (%s)\n", errbuf);
		return -1;
	}

	if (setsockopt(l->fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark))) {
		logerr("Can't set SO_MARK (%d) for socket\n", mark);
		goto err;
	}

	ret = libnet_build_tcp(
		ntohs(sk->dst_addr->v4.sin_port),		/* source port */
		ntohs(sk->src_addr->v4.sin_port),		/* destination port */
		data->sk_hd.inq_seq,			/* sequence number */
		data->sk_hd.outq_seq - data->sk_hd.outq_len,	/* acknowledgement num */
		flags,				/* control flags */
		data->sk_hd.rcv_wnd,			/* window size */
		0,				/* checksum */
		10,				/* urgent pointer */
		LIBNET_TCP_H + 20,		/* TCP packet size */
		NULL,				/* payload */
		0,				/* payload size */
		l,				/* libnet handle */
		0);				/* libnet id */
	if (ret == -1) {
		loge("Can't build TCP header: %s\n", libnet_geterror(l));
		goto err;
	}

	if (family == AF_INET6) {
		struct libnet_in6_addr src, dst;

		memcpy(&dst, &sk->dst_addr->v6.sin6_addr, sizeof(dst));
		memcpy(&src, &sk->src_addr->v6.sin6_addr, sizeof(src));

		ret = libnet_build_ipv6(
			0, 0,
			LIBNET_TCP_H,	/* length */
			IPPROTO_TCP,	/* protocol */
			64,		/* hop limit */
			dst,		/* source IP */
			src,		/* destination IP */
			NULL,		/* payload */
			0,		/* payload size */
			l,		/* libnet handle */
			0);		/* libnet id */
	} else if (family == AF_INET)
		ret = libnet_build_ipv4(
			LIBNET_IPV4_H + LIBNET_TCP_H + 20,	/* length */
			0,			/* TOS */
			242,			/* IP ID */
			0,			/* IP Frag */
			64,			/* TTL */
			IPPROTO_TCP,		/* protocol */
			0,			/* checksum */
			dst_v4,			/* source IP */
			src_v4,			/* destination IP */
			NULL,			/* payload */
			0,			/* payload size */
			l,			/* libnet handle */
			0);			/* libnet id */
	else {
		loge("Unknown socket family\n");
		goto err;
	}
	if (ret == -1) {
		loge("Can't build IP header: %s\n", libnet_geterror(l));
		goto err;
	}

	ret = libnet_write(l);
	if (ret == -1) {
		loge("Unable to send a fin packet: %s\n", libnet_geterror(l));
		goto err;
	}

	exit_code = 0;
err:
	libnet_destroy(l);
	return exit_code;
}


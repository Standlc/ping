#include "ft_ping.h"

// char hostname[1024];
// gethostname(hostname, sizeof(hostname));
// printf("%s\n", hostname);

// struct hostent *address = gethostbyname("Macbook-Air-4.local");
// struct in_addr **addr_list = (struct in_addr **)address->h_addr_list;
// for (int i = 0; addr_list[i] != NULL; i++) {
//     printf("%s \n", inet_ntoa(*addr_list[i]));
// }
// return 0;

#define PING_INTERVAL_US 1000 * 1000
#define READ_BUFF_SIZE 1024
#define IS_VERBOSE 0x0001

int stop = 0;
int options = 0;

void print_usage() {
    printf("usage: ./ping [-v] <host>\n");
}

char *parse_options(int argc, char **argv) {
    int c;

    while ((c = getopt(argc, argv, "v")) != -1) {
        switch (c) {
            case 'v':
                options |= IS_VERBOSE;
                break;
            default:
                print_usage();
                return NULL;
        }
    }

    if (argc - optind != 1) {
        print_usage();
        return NULL;
    }

    return argv[optind];
}

uint16_t in_cksum(uint16_t *addr, int len) {
    int nleft = len;
    uint32_t sum = 0;
    uint16_t *w = addr;
    uint16_t answer = 0;

    /*
     * Our algorithm is simple, using a 32 bit accumulator (sum), we add
     * sequential 16 bit words to it, and at the end, fold back all the
     * carry bits from the top 16 bits into the lower 16 bits.
     */
    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    /* 4mop up an odd byte, if necessary */
    if (nleft == 1) {
        *(unsigned char *)(&answer) = *(unsigned char *)w;
        sum += answer;
    }

    /* 4add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
    sum += (sum >> 16);                 /* add carry */
    answer = ~sum;                      /* truncate to 16 bits */
    return (answer);
}

void handle_sigint(int signo) {
    (void)signo;
    stop = 1;
}

int send_echo_request(int socket, int pid, struct addrinfo *ai, struct timeval *send_time) {
    static int sequence_no = 0;
    char send_buff[1024];
    bzero(send_buff, sizeof(send_buff));

    struct icmp *icmp = (void *)send_buff;
    icmp->icmp_type = ICMP_ECHO;
    icmp->icmp_code = 0;
    icmp->icmp_id = pid;
    icmp->icmp_seq = sequence_no;
    // memset(icmp->icmp_data, 0xa5, ICMP_DATA_LEN); /* fill with pattern */
    gettimeofday((struct timeval *)icmp->icmp_data, NULL);
    memcpy(send_time, icmp->icmp_data, sizeof(struct timeval));
    icmp->icmp_cksum = in_cksum((u_short *)icmp, 8 + ICMP_DATA_LEN);

    int sent_bytes = sendto(socket, send_buff, 8 + ICMP_DATA_LEN, 0, ai->ai_addr, ai->ai_addrlen);
    if (sent_bytes != 8 + ICMP_DATA_LEN) {
        warn("sendto");
    }
    return sequence_no++;
}

int get_address_infos(char *hostname, struct addrinfo **ai) {
    struct addrinfo hints;
    bzero(&hints, sizeof(struct addrinfo));
    hints.ai_flags = AI_CANONNAME;
    hints.ai_family = AF_INET;

    int ret = 0;
    if ((ret = getaddrinfo(hostname, NULL, &hints, ai)) != 0) {
        dprintf(2, "getaddrinfo: %s\n", gai_strerror(ret));
        return 1;
    }

    return 0;
}

char *get_ip_address(struct addrinfo *ai) {
    static char ip_address[INET_ADDRSTRLEN];
    struct sockaddr_in *sin = (struct sockaddr_in *)ai->ai_addr;
    inet_ntop(AF_INET, &sin->sin_addr, ip_address, INET_ADDRSTRLEN);
    return ip_address;
}

int create_raw_socket() {
    int socket_type = getuid() ? SOCK_DGRAM : SOCK_RAW;
    int socketfd = socket(AF_INET, socket_type, IPPROTO_ICMP);
    if (socketfd == -1) {
        warn("socket");
        return -1;
    }

    int on = 1;
    if (setsockopt(socketfd, SOL_SOCKET, SO_TIMESTAMP, &on, sizeof(on)) < 0) {
        warn("setsockopt");
        return -1;
    }

    return socketfd;
}

struct ping_stats {
    long req_count;
    long replies_count;
    double rtt_ms_sum;
    double rtt_ms_sumq;
    double min_rtt_ms;
    double max_rtt_ms;
};

ssize_t read_echo_reply(int socket_fd, struct msghdr *msg) {
    struct iovec iov;
    struct sockaddr_in from;
    bzero(msg, sizeof(*msg));
    bzero(&iov, sizeof(iov));

    msg->msg_iov = &iov;
    msg->msg_iovlen = 1;
    msg->msg_name = (void *)&from;
    msg->msg_namelen = sizeof(from);

    char control_buff[1024];
    bzero(control_buff, sizeof(control_buff));
    msg->msg_control = control_buff;
    msg->msg_controllen = sizeof(control_buff);

    char recv_buff[1024];
    bzero(recv_buff, sizeof(recv_buff));
    iov.iov_base = recv_buff;
    iov.iov_len = sizeof(recv_buff);

    ssize_t read_bytes = recvmsg(socket_fd, msg, 0);
    if (read_bytes == -1) {
        warn("recvmsg");
        return -1;
    }
    return read_bytes;
}

struct timeval get_reply_timestamps(struct msghdr *msg) {
    struct timeval recv_time;
    struct cmsghdr *cmsg = NULL;

    for (cmsg = CMSG_FIRSTHDR(msg); cmsg != NULL; cmsg = CMSG_NXTHDR(msg, cmsg)) {
        if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_TIMESTAMP && cmsg->cmsg_len == CMSG_LEN(sizeof(recv_time))) {
            memcpy(&recv_time, CMSG_DATA(cmsg), sizeof(recv_time));
            return recv_time;
        }
    }

    gettimeofday(&recv_time, NULL);
    return recv_time;
}

void print_icmp_type(struct icmp *icp) {
    switch (icp->icmp_type) {
        case ICMP_ECHOREPLY:
            printf("Echo Reply\n");
            break;
        case ICMP_UNREACH:
            switch (icp->icmp_code) {
                case ICMP_UNREACH_NET:
                    printf("Destination Net Unreachable\n");
                    break;
                case ICMP_UNREACH_HOST:
                    printf("Destination Host Unreachable\n");
                    break;
                case ICMP_UNREACH_PROTOCOL:
                    printf("Destination Protocol Unreachable\n");
                    break;
                case ICMP_UNREACH_PORT:
                    printf("Destination Port Unreachable\n");
                    break;
                case ICMP_UNREACH_NEEDFRAG:
                    printf("frag needed and DF set (MTU %d)\n", ntohs(icp->icmp_nextmtu));
                    break;
                case ICMP_UNREACH_SRCFAIL:
                    printf("Source Route Failed\n");
                    break;
                case ICMP_UNREACH_FILTER_PROHIB:
                    printf("Communication prohibited by filter\n");
                    break;
                default:
                    printf("Dest Unreachable, Bad Code: %d\n", icp->icmp_code);
                    break;
            }
            break;
        case ICMP_SOURCEQUENCH:
            printf("Source Quench\n");
            break;
        case ICMP_REDIRECT:
            switch (icp->icmp_code) {
                case ICMP_REDIRECT_NET:
                    printf("Redirect Network");
                    break;
                case ICMP_REDIRECT_HOST:
                    printf("Redirect Host");
                    break;
                case ICMP_REDIRECT_TOSNET:
                    printf("Redirect Type of Service and Network");
                    break;
                case ICMP_REDIRECT_TOSHOST:
                    printf("Redirect Type of Service and Host");
                    break;
                default:
                    printf("Redirect, Bad Code: %d", icp->icmp_code);
                    break;
            }
            printf("(New addr: %s)\n", inet_ntoa(icp->icmp_gwaddr));
            break;
        case ICMP_ECHO:
            printf("Echo Request\n");
            break;
        case ICMP_TIMXCEED:
            switch (icp->icmp_code) {
                case ICMP_TIMXCEED_INTRANS:
                    printf("Time to live exceeded\n");
                    break;
                case ICMP_TIMXCEED_REASS:
                    printf("Frag reassembly time exceeded\n");
                    break;
                default:
                    printf("Time exceeded, Bad Code: %d\n",
                           icp->icmp_code);
                    break;
            }
            break;
        case ICMP_PARAMPROB:
            printf("Parameter problem: pointer = 0x%02x\n", icp->icmp_hun.ih_pptr);
            break;
        case ICMP_TSTAMP:
            printf("Timestamp\n");
            break;
        case ICMP_TSTAMPREPLY:
            printf("Timestamp Reply\n");
            break;
        case ICMP_IREQ:
            printf("Information Request\n");
            break;
        case ICMP_IREQREPLY:
            printf("Information Reply\n");
            break;
        case ICMP_MASKREQ:
            printf("Address Mask Request\n");
            break;
        case ICMP_MASKREPLY:
            printf("Address Mask Reply\n");
            break;
        case ICMP_ROUTERADVERT:
            printf("Router Advertisement\n");
            break;
        case ICMP_ROUTERSOLICIT:
            printf("Router Solicitation\n");
            break;
        default:
            printf("Bad ICMP type: %d\n", icp->icmp_type);
    }
}

int process_echo_reply(int echo_id, struct msghdr *msg, int msg_size, struct ping_stats *stats) {
    struct ip *ipheader = (void *)msg->msg_iov->iov_base;
    int ip_header_len = ipheader->ip_hl * 4;

    if (ipheader->ip_p != IPPROTO_ICMP) {
        if (options & IS_VERBOSE)
            dprintf(2, "packet not ICMP message (%d bytes) from %s\n", msg_size - ip_header_len, inet_ntoa(ipheader->ip_src));
        return 1;
    }
    if (msg_size < ip_header_len + ICMP_MINLEN) {
        if (options & IS_VERBOSE)
            dprintf(2, "packet too short (%d bytes) from %s\n", msg_size - ip_header_len, inet_ntoa(ipheader->ip_src));
        return 1;
    }

    struct icmp *echo_reply = (void *)msg->msg_iov->iov_base + ip_header_len;
    if (echo_reply->icmp_type != ICMP_ECHOREPLY) {
        if (options & IS_VERBOSE) {
            dprintf(2, "%d bytes from %s: ", msg_size - ip_header_len, inet_ntoa(ipheader->ip_src));
            print_icmp_type(echo_reply);
        }
        return 1;
    }
    if (echo_reply->icmp_id != echo_id) {
        if (options & IS_VERBOSE)
            dprintf(2, "packet not for us (%d bytes) from %s\n", msg_size - ip_header_len, inet_ntoa(ipheader->ip_src));
        return 1;
    }

    struct timeval *msg_tval = (void *)echo_reply->icmp_data;
    struct timeval recv_time = get_reply_timestamps(msg);
    double rtt_usec = (recv_time.tv_sec - msg_tval->tv_sec) * 1000 * 1000 + (recv_time.tv_usec - msg_tval->tv_usec);
    printf("%d bytes from %s: icmp_seq=%d ttl=%d time=%.3f ms\n", msg_size - ip_header_len, inet_ntoa(ipheader->ip_src), echo_reply->icmp_seq, ipheader->ip_ttl, rtt_usec / 1000);

    stats->replies_count++;
    double rtt_ms = rtt_usec / 1000;
    stats->rtt_ms_sum += rtt_ms;
    stats->rtt_ms_sumq += rtt_ms * rtt_ms;
    stats->min_rtt_ms = rtt_ms < stats->min_rtt_ms ? rtt_ms : stats->min_rtt_ms;
    stats->max_rtt_ms = rtt_ms > stats->max_rtt_ms ? rtt_ms : stats->max_rtt_ms;
    return 0;
}

struct timeval readjust_timeout(struct timeval *send_time) {
    struct timeval timeout;
    struct timeval now;

    gettimeofday(&now, NULL);
    long time_elapsed_us = (now.tv_sec - send_time->tv_sec) * 1000 * 1000 + (now.tv_usec - send_time->tv_usec);
    long time_left_us = (PING_INTERVAL_US - time_elapsed_us < 0) ? 0 : PING_INTERVAL_US - time_elapsed_us;
    timeout.tv_sec = time_left_us / (1000 * 1000);
    timeout.tv_usec = time_left_us % (1000 * 1000);

    return timeout;
}

void ping_loop(int socket_fd, struct addrinfo *ai, struct ping_stats *stats) {
    fd_set master_fd_set;
    FD_ZERO(&master_fd_set);
    FD_SET(socket_fd, &master_fd_set);

    int got_echo_response_flag = 0;
    struct timeval timeout = {PING_INTERVAL_US / (1000 * 1000), 0};
    struct timeval send_time;

    int echo_id = getpid() & 0xFFFF;  // icmp id is 2 bytes
    stats->req_count = send_echo_request(socket_fd, echo_id, ai, &send_time) + 1;

    while (!stop) {
        fd_set read_set = master_fd_set;

        int is_readable = select(socket_fd + 1, &read_set, NULL, NULL, &timeout);

        timeout = readjust_timeout(&send_time);

        if (is_readable < 0) {
            return;
        }

        if (is_readable == 1) {
            struct msghdr msg;

            int msg_size = read_echo_reply(socket_fd, &msg);
            if (msg_size == -1) {
                continue;
            }

            if (!process_echo_reply(echo_id, &msg, msg_size, stats)) {
                got_echo_response_flag = 1;
            }
        } else {
            stats->req_count = send_echo_request(socket_fd, echo_id, ai, &send_time) + 1;

            if (!got_echo_response_flag) {
                printf("Request timeout for icmp_seq %ld\n", stats->req_count - 2);
            }

            got_echo_response_flag = 0;
            timeout = (struct timeval){PING_INTERVAL_US / (1000 * 1000), 0};
        }
    }
}

int main(int argc, char **argv) {
    char *hostname = NULL;

    if ((hostname = parse_options(argc, argv)) == NULL) {
        exit(1);
    }

    if (handle_signal(SIGINT, handle_sigint) || handle_signal(SIGQUIT, handle_sigint)) {
        exit(1);
    }

    struct addrinfo *address_info;
    if (get_address_infos(hostname, &address_info)) {
        exit(1);
    }

    char *ip_address = get_ip_address(address_info);
    printf("PING %s (%s): %d data bytes\n", address_info->ai_canonname != NULL ? address_info->ai_canonname : ip_address, ip_address, 56);

    int socket_fd = create_raw_socket();
    if (socket_fd == -1) {
        freeaddrinfo(address_info);
        exit(1);
    }

    struct ping_stats stats;
    bzero(&stats, sizeof(struct ping_stats));
    stats.min_rtt_ms = INFINITY;

    ping_loop(socket_fd, address_info, &stats);

    printf("\n--- %s ping statistics ---", address_info->ai_canonname != NULL ? address_info->ai_canonname : ip_address);
    printf("\n%ld packets transmitted, %ld packets received, %.1f%% packet loss", stats.req_count, stats.replies_count, (1 - (stats.replies_count / (double)stats.req_count)) * 100);

    if (options & IS_VERBOSE && stats.req_count - stats.replies_count > 0) {
        printf(", %ld packets out of wait time", stats.req_count - stats.replies_count);
    }

    if (stats.replies_count > 0) {
        double rtt_avg_ms = stats.rtt_ms_sum / stats.replies_count;
        double rtt_stddev_ms = sqrt(stats.rtt_ms_sumq / stats.replies_count - rtt_avg_ms * rtt_avg_ms);
        printf("\nround-trip min/avg/max/stddev = %.3f/%.3f/%.3f/%.3f ms", stats.min_rtt_ms, rtt_avg_ms, stats.max_rtt_ms, rtt_stddev_ms);
    }

    printf("\n");

    freeaddrinfo(address_info);
    exit(0);
}

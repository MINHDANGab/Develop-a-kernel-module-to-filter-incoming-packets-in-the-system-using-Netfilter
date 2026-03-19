// fw_cli.c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/netlink.h>

#define NETLINK_FW NETLINK_USERSOCK
#define MAX_PAYLOAD 2048

enum fw_cmd {
    FW_CMD_BLOCK_ADD = 1,
    FW_CMD_BLOCK_DEL,
    FW_CMD_RL_ADD,
    FW_CMD_RL_DEL,
    FW_CMD_SHOW,
};

struct fw_msg {
    uint32_t cmd;
    uint32_t ipv4_be;
    uint32_t bytes_per_sec;
};

static void die(const char *m) { perror(m); exit(1); }

static uint32_t parse_ipv4_be(const char *s)
{
    struct in_addr a;
    if (inet_pton(AF_INET, s, &a) != 1) {
        fprintf(stderr, "Invalid IPv4: %s\n", s);
        exit(1);
    }
    return a.s_addr;
}

static void send_cmd_and_print(int sock_fd, const struct fw_msg *m)
{
    struct sockaddr_nl dst = {0};
    struct nlmsghdr *nlh;
    struct iovec iov;
    struct msghdr msg = {0};

    dst.nl_family = AF_NETLINK;
    dst.nl_pid = 0;
    dst.nl_groups = 0;

    nlh = (struct nlmsghdr*)malloc(NLMSG_SPACE(MAX_PAYLOAD));
    if (!nlh) die("malloc");
    memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));

    /* send request */
    nlh->nlmsg_len = NLMSG_SPACE(sizeof(*m));
    nlh->nlmsg_pid = getpid();
    memcpy(NLMSG_DATA(nlh), m, sizeof(*m));

    iov.iov_base = (void*)nlh;
    iov.iov_len  = nlh->nlmsg_len;

    msg.msg_name = (void*)&dst;
    msg.msg_namelen = sizeof(dst);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    if (sendmsg(sock_fd, &msg, 0) < 0) die("sendmsg");

    /* receive reply (buffer must be large) */
    memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
    iov.iov_base = (void*)nlh;
    iov.iov_len  = NLMSG_SPACE(MAX_PAYLOAD);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    if (recvmsg(sock_fd, &msg, 0) < 0) die("recvmsg");

    printf("%s\n", (char*)NLMSG_DATA(nlh));
    free(nlh);
}

int main(int argc, char **argv)
{
    int sock_fd;
    struct sockaddr_nl src = {0};
    struct fw_msg m = {0};

    if (argc < 2) {
        fprintf(stderr,
            "Usage:\n"
            "  %s show\n"
            "  %s block add <ip>\n"
            "  %s block del <ip>\n"
            "  %s ratelimit add <ip> <bytes_per_sec>\n"
            "  %s ratelimit del <ip>\n",
            argv[0], argv[0], argv[0], argv[0], argv[0]);
        return 1;
    }

    sock_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_FW);
    if (sock_fd < 0) die("socket");

    src.nl_family = AF_NETLINK;
    src.nl_pid = getpid();
    if (bind(sock_fd, (struct sockaddr*)&src, sizeof(src)) < 0) die("bind");

    if (!strcmp(argv[1], "show")) {
        m.cmd = FW_CMD_SHOW;
    } else if (!strcmp(argv[1], "block")) {
        if (argc != 4) { fprintf(stderr, "Need: block add|del <ip>\n"); return 1; }
        if (!strcmp(argv[2], "add")) {
            m.cmd = FW_CMD_BLOCK_ADD;
            m.ipv4_be = parse_ipv4_be(argv[3]);
        } else if (!strcmp(argv[2], "del")) {
            m.cmd = FW_CMD_BLOCK_DEL;
            m.ipv4_be = parse_ipv4_be(argv[3]);
        } else { fprintf(stderr, "Unknown: %s\n", argv[2]); return 1; }
    } else if (!strcmp(argv[1], "ratelimit")) {
        if (!strcmp(argv[2], "add")) {
            if (argc != 5) { fprintf(stderr, "Need: ratelimit add <ip> <bytes_per_sec>\n"); return 1; }
            m.cmd = FW_CMD_RL_ADD;
            m.ipv4_be = parse_ipv4_be(argv[3]);
            m.bytes_per_sec = (uint32_t)strtoul(argv[4], NULL, 10);
        } else if (!strcmp(argv[2], "del")) {
            if (argc != 4) { fprintf(stderr, "Need: ratelimit del <ip>\n"); return 1; }
            m.cmd = FW_CMD_RL_DEL;
            m.ipv4_be = parse_ipv4_be(argv[3]);
        } else { fprintf(stderr, "Unknown: %s\n", argv[2]); return 1; }
    } else {
        fprintf(stderr, "Unknown command\n");
        return 1;
    }

    send_cmd_and_print(sock_fd, &m);
    close(sock_fd);
    return 0;
}

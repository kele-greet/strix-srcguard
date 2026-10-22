/* Minimal DNS allowlist guard for SRCGuard.
 *
 * UDP-only. It does not recurse; it forwards allowed queries to an upstream
 * resolver and returns NXDOMAIN for names outside the allowlist. The intent is
 * scope enforcement for the sandbox's resolver, not a general-purpose DNS
 * server. Build static: gcc -O2 -static -o bin/srcguard-dnsguard ...
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define MAX_PACKET 4096
#define MAX_ALLOW 2048
#define MAX_NAME 256

static char allow_patterns[MAX_ALLOW][MAX_NAME];
static int allow_count = 0;
static char log_path[1024] = "";

static void lower(char *s) {
    for (; *s; s++) *s = (char)tolower((unsigned char)*s);
}

static int load_allow(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char line[MAX_NAME];
    while (fgets(line, sizeof(line), f) && allow_count < MAX_ALLOW) {
        char *p = line;
        while (*p && isspace((unsigned char)*p)) p++;
        char *end = p + strlen(p);
        while (end > p && isspace((unsigned char)end[-1])) *--end = '\0';
        if (!*p || *p == '#') continue;
        lower(p);
        snprintf(allow_patterns[allow_count], MAX_NAME, "%s", p);
        allow_count++;
    }
    fclose(f);
    return 0;
}

static int allowed(const char *qname) {
    if (!strcmp(qname, "localhost") || !strcmp(qname, "host.docker.internal")) return 1;
    for (int i = 0; i < allow_count; i++) {
        const char *p = allow_patterns[i];
        if (!strcmp(p, qname)) return 1;
        if (p[0] == '*' && p[1] == '.') {
            const char *suffix = p + 1; /* ".example.com" */
            size_t ql = strlen(qname), sl = strlen(suffix);
            if (ql > sl && !strcmp(qname + ql - sl, suffix)) return 1;
        }
    }
    return 0;
}

static int parse_qname(const unsigned char *buf, int len, char *out, int outlen, int *qend) {
    if (len < 12) return -1;
    int off = 12;
    int written = 0;
    while (off < len) {
        unsigned int l = buf[off++];
        if (l == 0) {
            if (written > 0 && out[written - 1] == '.') written--;
            if (written == 0) out[written++] = '.';
            out[written] = '\0';
            *qend = off + 4; /* qtype + qclass */
            return (*qend <= len) ? 0 : -1;
        }
        if (l > 63 || off + (int)l > len || written + (int)l + 2 >= outlen) return -1;
        for (unsigned int i = 0; i < l; i++) out[written++] = (char)tolower(buf[off + i]);
        out[written++] = '.';
        off += (int)l;
    }
    return -1;
}

static void write_log(const char *client, const char *qname, int ok, int rcode) {
    if (!log_path[0]) return;
    int fd = open(log_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) return;
    char row[1024];
    int n = snprintf(row, sizeof(row),
                     "{\"client\":\"%s\",\"qname\":\"%s\",\"allowed\":%s,\"rcode\":%d,\"ts\":%ld}\n",
                     client, qname, ok ? "true" : "false", rcode, (long)time(NULL));
    if (n > 0) {
        ssize_t ignored = write(fd, row, (size_t)n);
        (void)ignored;
    }
    close(fd);
}

static int nxdomain(const unsigned char *query, int qlen, unsigned char *resp) {
    if (qlen < 12) return -1;
    memcpy(resp, query, (size_t)qlen < 12 ? (size_t)qlen : 12);
    resp[2] = (unsigned char)((resp[2] & 0x01) | 0x80); /* QR, keep RD */
    resp[3] = (unsigned char)((resp[3] & 0xf0) | 0x03); /* NXDOMAIN */
    resp[4] = 0; resp[5] = 1; /* QDCOUNT */
    resp[6] = 0; resp[7] = 0; resp[8] = 0; resp[9] = 0; resp[10] = 0; resp[11] = 0;
    char name[MAX_NAME];
    int qend = 0;
    if (parse_qname(query, qlen, name, sizeof(name), &qend) != 0) return -1;
    if (qend > qlen || qend > MAX_PACKET) return -1;
    memcpy(resp + 12, query + 12, (size_t)(qend - 12));
    return qend;
}

int main(int argc, char **argv) {
    char listen_addr[64] = "172.17.0.1";
    int listen_port = 53;
    char upstream_addr[64] = "10.255.255.254";
    int upstream_port = 53;
    char allow_file[1024] = "";

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-listen") && i + 1 < argc) {
            char *v = argv[++i];
            char *colon = strrchr(v, ':');
            if (colon) { *colon = '\0'; listen_port = atoi(colon + 1); }
            snprintf(listen_addr, sizeof(listen_addr), "%s", v);
        } else if (!strcmp(argv[i], "-upstream") && i + 1 < argc) {
            char *v = argv[++i];
            char *colon = strrchr(v, ':');
            if (colon) { *colon = '\0'; upstream_port = atoi(colon + 1); }
            snprintf(upstream_addr, sizeof(upstream_addr), "%s", v);
        } else if (!strcmp(argv[i], "-allow") && i + 1 < argc) {
            snprintf(allow_file, sizeof(allow_file), "%s", argv[++i]);
        } else if (!strcmp(argv[i], "-log") && i + 1 < argc) {
            snprintf(log_path, sizeof(log_path), "%s", argv[++i]);
        } else {
            fprintf(stderr, "unknown argument: %s\n", argv[i]);
            return 2;
        }
    }
    if (!allow_file[0]) {
        fprintf(stderr, "missing -allow\n");
        return 2;
    }
    /* Fail closed: no allowlist means do not start rather than allow all. */
    if (load_allow(allow_file) != 0) {
        fprintf(stderr, "cannot read allowlist %s: %s\n", allow_file, strerror(errno));
        return 2;
    }

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) { perror("socket"); return 2; }
    struct sockaddr_in bindaddr;
    memset(&bindaddr, 0, sizeof(bindaddr));
    bindaddr.sin_family = AF_INET;
    bindaddr.sin_port = htons((uint16_t)listen_port);
    if (inet_pton(AF_INET, listen_addr, &bindaddr.sin_addr) != 1) {
        fprintf(stderr, "bad listen address %s\n", listen_addr);
        return 2;
    }
    if (bind(sock, (struct sockaddr *)&bindaddr, sizeof(bindaddr)) != 0) {
        perror("bind"); return 2;
    }
    struct sockaddr_in upstream;
    memset(&upstream, 0, sizeof(upstream));
    upstream.sin_family = AF_INET;
    upstream.sin_port = htons((uint16_t)upstream_port);
    if (inet_pton(AF_INET, upstream_addr, &upstream.sin_addr) != 1) {
        fprintf(stderr, "bad upstream %s\n", upstream_addr);
        return 2;
    }

    fprintf(stderr, "dnsguard listening on %s:%d -> %s:%d, %d allow patterns\n",
            listen_addr, listen_port, upstream_addr, upstream_port, allow_count);

    for (;;) {
        unsigned char query[MAX_PACKET], resp[MAX_PACKET], answer[MAX_PACKET];
        struct sockaddr_in client;
        socklen_t clen = sizeof(client);
        ssize_t n = recvfrom(sock, query, sizeof(query), 0, (struct sockaddr *)&client, &clen);
        if (n <= 0) continue;
        char qname[MAX_NAME] = "";
        int qend = 0;
        if (parse_qname(query, (int)n, qname, sizeof(qname), &qend) != 0) {
            qend = -1;
        }
        char client_ip[64];
        inet_ntop(AF_INET, &client.sin_addr, client_ip, sizeof(client_ip));
        int ok = (qend > 0) && allowed(qname);
        if (!ok) {
            int r = nxdomain(query, (int)n, resp);
            if (r > 0) sendto(sock, resp, (size_t)r, 0, (struct sockaddr *)&client, clen);
            write_log(client_ip, qname[0] ? qname : "?", 0, 3);
            continue;
        }
        int up = socket(AF_INET, SOCK_DGRAM, 0);
        if (up < 0) continue;
        struct timeval tv = {.tv_sec = 3, .tv_usec = 0};
        setsockopt(up, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        if (sendto(up, query, (size_t)n, 0, (struct sockaddr *)&upstream, sizeof(upstream)) < 0) {
            close(up);
            write_log(client_ip, qname, 0, 2);
            continue;
        }
        ssize_t an = recv(up, answer, sizeof(answer), 0);
        close(up);
        if (an > 0) {
            sendto(sock, answer, (size_t)an, 0, (struct sockaddr *)&client, clen);
            write_log(client_ip, qname, 1, answer[3] & 0x0f);
        } else {
            write_log(client_ip, qname, 1, 2);
        }
    }
    return 0;
}

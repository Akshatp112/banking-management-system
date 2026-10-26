/* net.c - socket helpers */
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "net.h"

int net_listen(int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return -1; }

    int yes = 1;   /* let us restart quickly without "address already in use" */
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port        = htons((unsigned short)port);

    if (bind(fd, (struct sockaddr *)&addr, sizeof addr) < 0) { perror("bind"); close(fd); return -1; }
    if (listen(fd, 16) < 0)                                  { perror("listen"); close(fd); return -1; }
    return fd;
}

void net_reader_init(LineReader *r, int fd)
{
    r->fd = fd;
    r->start = r->end = 0;
    r->discarding = 0;
}

int net_read_line(LineReader *r, char *out, size_t out_size)
{
    for (;;) {
        /* 1. Is a complete line already in the buffer? */
        char *base = r->buf + r->start;
        char *nl   = memchr(base, '\n', r->end - r->start);
        if (nl) {
            size_t len = (size_t)(nl - base);
            r->start += len + 1;
            if (r->discarding) { r->discarding = 0; continue; }   /* tail of an oversized line */
            if (len > 0 && base[len - 1] == '\r') len--;
            if (len >= out_size) return NET_TOO_LONG;
            memcpy(out, base, len);
            out[len] = '\0';
            return (int)len;
        }

        /* 2. No newline yet. Guard against a client that never sends one. */
        if (r->discarding) {
            r->start = r->end = 0;                    /* throw away and keep reading */
        } else if (r->end - r->start >= NET_BUF_SIZE) {
            r->start = r->end = 0;
            r->discarding = 1;
            return NET_TOO_LONG;
        }

        /* 3. Make room, then read more bytes from the socket. */
        if (r->start > 0) {
            memmove(r->buf, r->buf + r->start, r->end - r->start);
            r->end  -= r->start;
            r->start = 0;
        }
        ssize_t n = read(r->fd, r->buf + r->end, NET_BUF_SIZE - r->end);   /* system call */
        if (n > 0)  { r->end += (size_t)n; continue; }
        if (n == 0) return NET_EOF;
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) return NET_TIMEOUT;   /* SO_RCVTIMEO fired */
        return NET_ERR;
    }
}

int net_send_line(int fd, const char *fmt, ...)
{
    char buf[NET_BUF_SIZE];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof buf - 1, fmt, ap);
    va_end(ap);
    if (n < 0) return -1;
    if ((size_t)n > sizeof buf - 2) n = sizeof buf - 2;     /* truncated: still send a valid line */
    buf[n++] = '\n';

    /* write() may send fewer bytes than asked; loop until everything is out. */
    int off = 0;
    while (off < n) {
        ssize_t w = write(fd, buf + off, (size_t)(n - off));  /* system call */
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;                                        /* e.g. EPIPE: client is gone */
        }
        off += (int)w;
    }
    return 0;
}

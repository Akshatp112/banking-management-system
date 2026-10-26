/* net.h - socket helpers built on raw system calls (socket/bind/listen/read/write) */
#ifndef NET_H
#define NET_H

#include <stddef.h>

#define NET_BUF_SIZE 1024

/* return codes of net_read_line (a successful read returns the line length >= 0) */
#define NET_EOF       -1   /* client closed the connection */
#define NET_ERR       -2   /* socket error */
#define NET_TIMEOUT   -3   /* nothing received within the idle timeout */
#define NET_TOO_LONG  -4   /* line exceeded the limit; it has been discarded */

/* TCP is a BYTE STREAM, not a message stream: one read() may return half a
 * request, or three requests glued together. LineReader keeps the leftover
 * bytes between calls so every request is handled as exactly one line. */
typedef struct {
    int    fd;
    char   buf[NET_BUF_SIZE];
    size_t start, end;     /* unread bytes are buf[start .. end) */
    int    discarding;     /* inside an oversized line: dropping until '\n' */
} LineReader;

int net_listen(int port);                      /* returns listening fd, or -1 */
void net_reader_init(LineReader *r, int fd);
int net_read_line(LineReader *r, char *out, size_t out_size);   /* '\n' / "\r\n" stripped */
int net_send_line(int fd, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

#endif

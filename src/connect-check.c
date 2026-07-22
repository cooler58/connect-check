/*
 * connect-check.c — диагностика доступа в интернет (ПК, TV, IoT, телефоны).
 *
 * Windows:  make -f Makefile.diagnose win
 * Unix:     make -f Makefile.diagnose
 */

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>

#include "version.h"

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <iphlpapi.h>
#  include <wininet.h>
#  include <shellapi.h>
#  include <io.h>
#  pragma comment(lib, "ws2_32.lib")
#  pragma comment(lib, "iphlpapi.lib")
#  pragma comment(lib, "wininet.lib")
#  pragma comment(lib, "shell32.lib")
#else
#  include <unistd.h>
#  include <sys/types.h>
#  include <sys/socket.h>
#  include <sys/time.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <netdb.h>
#  include <fcntl.h>
#  include <termios.h>
#  include <signal.h>

/*
 * macOS: системный curl/LibreSSL ломает TLS к части госсайтов (gosuslugi и др.).
 * SecureTransport ведёт себя как Safari/браузер.
 */
#  ifdef __APPLE__
#    define CURL_SSL_ENV "CURL_SSL_BACKEND=secure-transport "
#  else
#    define CURL_SSL_ENV ""
#  endif
#endif

#define MAX_CHECKS   1024
#define MAX_FINDINGS 160
#define MAX_DNS      8
#define MAX_DOMAINS  10000
#define STR          512
#define LONGSTR      1024

typedef struct {
    char category[96];
    char name[128];
    char status[12];
    char detail[STR];
    char hint[STR];
    char resolved_ip[64];
    char diag_url[256];
    int spoiler; /* 1 = fold long category / diag under <details> */
} Check;

typedef struct {
    char level[16];
    char title[256];
    char text[LONGSTR];
} Finding;

typedef struct {
    int ok;
    int code;
    int ms;
    char redirect[STR];
    char error[STR];
    char body[256];
} HttpResult;

static Check checks[MAX_CHECKS];
static int nchecks;
static Finding findings[MAX_FINDINGS];
static int nfindings;
static int ok_n, warn_n, fail_n;

static char local_ip[64];
static char external_ip[64];
static char gateway[64];
static char dns_list[MAX_DNS][64];
static int ndns;
static char wifi_ssid[128];
static int wifi_channel = -1;
static int wifi_signal = -1;
static char wifi_radio[64];
static int no_open;
static int opt_yes;           /* -y: без интерактивных пропусков */
static int opt_skip_dns_bulk;
static int opt_force_dns_bulk; /* --dns-bulk: запустить даже при -y / без Enter */
static int opt_skip_speed;
static int opt_skip_video;
static int opt_dns_limit = 1000; /* полный прогон: --dns-limit 10000 */
static int g_sys_dns_broken; /* getaddrinfo не резолвит известные имена — remote-этапы бессмысленны */
static char domains_path[STR];
static char resources_path[STR]; /* --resources FILE; иначе resources.conf рядом */
static char output_dir[STR];
static char report_path[STR];
static char stamp[32];
static char generated[64];
static char exe_dir[STR];
static int g_resources_from_file; /* 1 = resources.conf (или --resources) */

/* прогресс этапа (в т.ч. подшаги UA) */
static char g_prog_item[48];
static int g_prog_cur;
static int g_prog_total;
static void stage_progress(const char *msg, int cur, int total);

/* ---------- utils ---------- */

static long long now_ms(void) {
#ifdef _WIN32
    return (long long)GetTickCount64();
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (long long)tv.tv_sec * 1000 + tv.tv_usec / 1000;
#endif
}

static void str_trim(char *s) {
    char *p = s;
    size_t n;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    if (p != s) memmove(s, p, strlen(p) + 1);
    n = strlen(s);
    while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t' || s[n - 1] == '\r' || s[n - 1] == '\n'))
        s[--n] = 0;
}

static int starts_with(const char *s, const char *p) {
    return strncmp(s, p, strlen(p)) == 0;
}

static void html_esc(FILE *f, const char *s) {
    if (!s) return;
    for (; *s; s++) {
        switch (*s) {
        case '&': fputs("&amp;", f); break;
        case '<': fputs("&lt;", f); break;
        case '>': fputs("&gt;", f); break;
        case '"': fputs("&quot;", f); break;
        default: fputc(*s, f); break;
        }
    }
}

static void add_check_ex(const char *cat, const char *name, const char *st,
                         const char *detail, const char *hint,
                         const char *ip, const char *url, int spoiler) {
    Check *c;
    if (nchecks >= MAX_CHECKS) return;
    c = &checks[nchecks++];
    memset(c, 0, sizeof *c);
    snprintf(c->category, sizeof c->category, "%s", cat);
    snprintf(c->name, sizeof c->name, "%s", name);
    snprintf(c->status, sizeof c->status, "%s", st);
    snprintf(c->detail, sizeof c->detail, "%s", detail ? detail : "");
    snprintf(c->hint, sizeof c->hint, "%s", hint ? hint : "");
    if (ip && ip[0]) snprintf(c->resolved_ip, sizeof c->resolved_ip, "%s", ip);
    if (url && url[0]) snprintf(c->diag_url, sizeof c->diag_url, "%s", url);
    c->spoiler = spoiler;
    if (strcmp(st, "ok") == 0) ok_n++;
    else if (strcmp(st, "warn") == 0) warn_n++;
    else if (strcmp(st, "fail") == 0) fail_n++;
}

static void add_check(const char *cat, const char *name, const char *st,
                      const char *detail, const char *hint) {
    add_check_ex(cat, name, st, detail, hint, NULL, NULL, 0);
}

static void add_finding(const char *level, const char *title, const char *text) {
    Finding *f;
    if (nfindings >= MAX_FINDINGS) return;
    f = &findings[nfindings++];
    snprintf(f->level, sizeof f->level, "%s", level);
    snprintf(f->title, sizeof f->title, "%s", title);
    snprintf(f->text, sizeof f->text, "%s", text);
}

static int run_capture(const char *cmd, char *buf, size_t buflen) {
    FILE *fp;
    size_t n = 0;
    buf[0] = 0;
#ifdef _WIN32
    fp = _popen(cmd, "r");
#else
    fp = popen(cmd, "r");
#endif
    if (!fp) return -1;
    while (n + 1 < buflen) {
        size_t r = fread(buf + n, 1, buflen - 1 - n, fp);
        if (r == 0) break;
        n += r;
    }
    buf[n] = 0;
#ifdef _WIN32
    _pclose(fp);
#else
    pclose(fp);
#endif
    return 0;
}

/* ---------- TCP ---------- */

static int tcp_open(const char *host, int port, int timeout_ms) {
#ifdef _WIN32
    SOCKET s;
    struct addrinfo hints, *res = NULL, *ai;
    char portstr[16];
    int ok = 0;
    u_long nb = 1;
    fd_set wset;
    struct timeval tv;
    int err = 0;
    int errlen = sizeof err;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(portstr, sizeof portstr, "%d", port);
    if (getaddrinfo(host, portstr, &hints, &res) != 0) return 0;

    for (ai = res; ai; ai = ai->ai_next) {
        s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s == INVALID_SOCKET) continue;
        ioctlsocket(s, FIONBIO, &nb);
        if (connect(s, ai->ai_addr, (int)ai->ai_addrlen) == 0) {
            ok = 1;
            closesocket(s);
            break;
        }
        if (WSAGetLastError() == WSAEWOULDBLOCK) {
            FD_ZERO(&wset);
            FD_SET(s, &wset);
            tv.tv_sec = timeout_ms / 1000;
            tv.tv_usec = (timeout_ms % 1000) * 1000;
            if (select(0, NULL, &wset, NULL, &tv) > 0) {
                getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&err, &errlen);
                if (err == 0) ok = 1;
            }
        }
        closesocket(s);
        if (ok) break;
    }
    freeaddrinfo(res);
    return ok;
#else
    struct addrinfo hints, *res = NULL, *ai;
    char portstr[16];
    int s, ok = 0, flags, err;
    socklen_t errlen;
    fd_set wset;
    struct timeval tv;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(portstr, sizeof portstr, "%d", port);
    if (getaddrinfo(host, portstr, &hints, &res) != 0) return 0;

    for (ai = res; ai; ai = ai->ai_next) {
        s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s < 0) continue;
        flags = fcntl(s, F_GETFL, 0);
        fcntl(s, F_SETFL, flags | O_NONBLOCK);
        if (connect(s, ai->ai_addr, ai->ai_addrlen) == 0) {
            ok = 1;
            close(s);
            break;
        }
        if (errno == EINPROGRESS) {
            FD_ZERO(&wset);
            FD_SET(s, &wset);
            tv.tv_sec = timeout_ms / 1000;
            tv.tv_usec = (timeout_ms % 1000) * 1000;
            if (select(s + 1, NULL, &wset, NULL, &tv) > 0) {
                err = 0;
                errlen = sizeof err;
                getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &errlen);
                if (err == 0) ok = 1;
            }
        }
        close(s);
        if (ok) break;
    }
    freeaddrinfo(res);
    return ok;
#endif
}

#ifdef _WIN32
typedef SOCKET net_sock;
#  define NET_SOCK_BAD INVALID_SOCKET
#  define net_sock_close closesocket
#else
typedef int net_sock;
#  define NET_SOCK_BAD (-1)
#  define net_sock_close close
#endif

static int net_wait_recv(net_sock s, unsigned char *buf, int buflen, int timeout_ms) {
    fd_set rset;
    struct timeval tv;
    int n;
    FD_ZERO(&rset);
    FD_SET(s, &rset);
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
#ifdef _WIN32
    if (select(0, &rset, NULL, NULL, &tv) <= 0) return 0;
#else
    if (select((int)s + 1, &rset, NULL, NULL, &tv) <= 0) return 0;
#endif
    n = recv(s, (char *)buf, buflen, 0);
    return n > 0 ? n : 0;
}

/* TCP connect, возвращает сокет или NET_SOCK_BAD. */
static net_sock tcp_connect_sock(const char *host, int port, int timeout_ms) {
#ifdef _WIN32
    SOCKET s = INVALID_SOCKET;
    struct addrinfo hints, *res = NULL, *ai;
    char portstr[16];
    u_long nb = 1;
    fd_set wset;
    struct timeval tv;
    int err = 0, errlen = sizeof err;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(portstr, sizeof portstr, "%d", port);
    if (getaddrinfo(host, portstr, &hints, &res) != 0) return INVALID_SOCKET;

    for (ai = res; ai; ai = ai->ai_next) {
        s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s == INVALID_SOCKET) continue;
        ioctlsocket(s, FIONBIO, &nb);
        if (connect(s, ai->ai_addr, (int)ai->ai_addrlen) == 0) {
            nb = 0; ioctlsocket(s, FIONBIO, &nb);
            freeaddrinfo(res);
            return s;
        }
        if (WSAGetLastError() == WSAEWOULDBLOCK) {
            FD_ZERO(&wset);
            FD_SET(s, &wset);
            tv.tv_sec = timeout_ms / 1000;
            tv.tv_usec = (timeout_ms % 1000) * 1000;
            if (select(0, NULL, &wset, NULL, &tv) > 0) {
                getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&err, &errlen);
                if (err == 0) {
                    nb = 0; ioctlsocket(s, FIONBIO, &nb);
                    freeaddrinfo(res);
                    return s;
                }
            }
        }
        closesocket(s);
        s = INVALID_SOCKET;
    }
    freeaddrinfo(res);
    return INVALID_SOCKET;
#else
    struct addrinfo hints, *res = NULL, *ai;
    char portstr[16];
    int s = -1, flags, err;
    socklen_t errlen;
    fd_set wset;
    struct timeval tv;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(portstr, sizeof portstr, "%d", port);
    if (getaddrinfo(host, portstr, &hints, &res) != 0) return -1;

    for (ai = res; ai; ai = ai->ai_next) {
        s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s < 0) continue;
        flags = fcntl(s, F_GETFL, 0);
        fcntl(s, F_SETFL, flags | O_NONBLOCK);
        if (connect(s, ai->ai_addr, ai->ai_addrlen) == 0) {
            fcntl(s, F_SETFL, flags);
            freeaddrinfo(res);
            return s;
        }
        if (errno == EINPROGRESS) {
            FD_ZERO(&wset);
            FD_SET(s, &wset);
            tv.tv_sec = timeout_ms / 1000;
            tv.tv_usec = (timeout_ms % 1000) * 1000;
            if (select(s + 1, NULL, &wset, NULL, &tv) > 0) {
                err = 0;
                errlen = sizeof err;
                getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &errlen);
                if (err == 0) {
                    fcntl(s, F_SETFL, flags);
                    freeaddrinfo(res);
                    return s;
                }
            }
        }
        close(s);
        s = -1;
    }
    freeaddrinfo(res);
    return -1;
#endif
}

/* Минимальный TLS ClientHello + SNI; ждём ServerHello/Alert (как в probe-mqtt). */
static int tls_clienthello_sni(net_sock s, const char *sni, int timeout_ms) {
    unsigned char pkt[512];
    unsigned char *p = pkt;
    size_t sni_len = strlen(sni);
    size_t ext_len, hello_len, rec_len;
    unsigned char resp[1500];
    int n;

    if (!sni || sni_len == 0 || sni_len > 200) return 0;
    p += 5;
    *p++ = 0x01;
    p += 3;
    *p++ = 0x03; *p++ = 0x03;
    memset(p, 0x22, 32); p += 32;
    *p++ = 0;
    *p++ = 0x00; *p++ = 0x02;
    *p++ = 0x00; *p++ = 0x2f;
    *p++ = 0x01; *p++ = 0x00;
    {
        unsigned char *ext_start = p;
        p += 2;
        *p++ = 0x00; *p++ = 0x00;
        *p++ = 0x00; *p++ = (unsigned char)(sni_len + 5);
        *p++ = 0x00; *p++ = (unsigned char)(sni_len + 3);
        *p++ = 0x00;
        *p++ = 0x00; *p++ = (unsigned char)sni_len;
        memcpy(p, sni, sni_len); p += sni_len;
        ext_len = (size_t)(p - ext_start - 2);
        ext_start[0] = (unsigned char)((ext_len >> 8) & 0xff);
        ext_start[1] = (unsigned char)(ext_len & 0xff);
    }
    hello_len = (size_t)(p - pkt - 9);
    pkt[6] = (unsigned char)((hello_len >> 16) & 0xff);
    pkt[7] = (unsigned char)((hello_len >> 8) & 0xff);
    pkt[8] = (unsigned char)(hello_len & 0xff);
    rec_len = (size_t)(p - pkt - 5);
    pkt[0] = 0x16;
    pkt[1] = 0x03; pkt[2] = 0x01;
    pkt[3] = (unsigned char)((rec_len >> 8) & 0xff);
    pkt[4] = (unsigned char)(rec_len & 0xff);

    if (send(s, (const char *)pkt, (int)(p - pkt), 0) <= 0) return 0;
    n = net_wait_recv(s, resp, sizeof resp, timeout_ms);
    return n > 0 && (resp[0] == 0x16 || resp[0] == 0x15 || resp[0] == 0x14);
}

/* SNI для DoT: у IP-адресов резолверов имя из сертификата. */
static const char *dot_sni_for(const char *host) {
    if (!host || !host[0]) return "dns.google";
    if (strcmp(host, "1.1.1.1") == 0 || strcmp(host, "1.0.0.1") == 0)
        return "cloudflare-dns.com";
    if (strcmp(host, "8.8.8.8") == 0 || strcmp(host, "8.8.4.4") == 0)
        return "dns.google";
    if (strcmp(host, "9.9.9.9") == 0 || strcmp(host, "149.112.112.112") == 0)
        return "dns.quad9.net";
    return host;
}

/*
 * DoT probe: TCP/853 + TLS ClientHello с SNI.
 * Возврат: 2 = TLS OK, 1 = TCP открыт без TLS, 0 = закрыт/таймаут.
 */
static int dot_probe(const char *host, int timeout_ms, int *ms_out) {
    const char *sni = dot_sni_for(host);
    net_sock s;
    long long t0 = now_ms();
    int rc = 0;

    if (ms_out) *ms_out = 0;
    s = tcp_connect_sock(host, 853, timeout_ms);
    if (s == NET_SOCK_BAD) {
        if (ms_out) *ms_out = (int)(now_ms() - t0);
        return 0;
    }
    if (tls_clienthello_sni(s, sni, timeout_ms))
        rc = 2;
    else
        rc = 1;
    net_sock_close(s);
    if (ms_out) *ms_out = (int)(now_ms() - t0);
    return rc;
}

/* Resolve A/AAAA; returns 1 on success. Optionally fills first IP into ip_out. */
static int dns_resolve(const char *host, char *ip_out, size_t ip_len) {
    struct addrinfo hints, *res = NULL;
    int rc;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    rc = getaddrinfo(host, NULL, &hints, &res);
    if (rc != 0 || !res) return 0;
    if (ip_out && ip_len) {
        ip_out[0] = 0;
        if (res->ai_family == AF_INET) {
            struct sockaddr_in *sa = (struct sockaddr_in *)res->ai_addr;
            inet_ntop(AF_INET, &sa->sin_addr, ip_out, (socklen_t)ip_len);
        }
#ifdef AF_INET6
        else if (res->ai_family == AF_INET6) {
            struct sockaddr_in6 *sa = (struct sockaddr_in6 *)res->ai_addr;
            inet_ntop(AF_INET6, &sa->sin6_addr, ip_out, (socklen_t)ip_len);
        }
#endif
    }
    freeaddrinfo(res);
    return 1;
}

/* Имя не резолвится системным DNS — не путать с «ресурс недоступен». */
static int host_unresolved(const char *host, const char *ip) {
    return host && host[0] && (!ip || !ip[0]);
}

/* 1 if host has at least one A (IPv4) record */
static int dns_has_ipv4(const char *host) {
    struct addrinfo hints, *res = NULL;
    int ok;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    ok = (getaddrinfo(host, NULL, &hints, &res) == 0 && res != NULL);
    if (res) freeaddrinfo(res);
    return ok;
}

/*
 * Connect to host:port, keep idle for hold_ms, detect RST/close.
 * Returns: 1 = alive after hold, 0 = connect fail, -1 = dropped during hold.
 */
static int tcp_hold(const char *host, int port, int connect_ms, int hold_ms) {
#ifdef _WIN32
    SOCKET s = INVALID_SOCKET;
    struct addrinfo hints, *res = NULL, *ai;
    char portstr[16];
    u_long nb = 1;
    fd_set rset, wset;
    struct timeval tv;
    int err = 0, errlen = sizeof err;
    int connected = 0;
    char junk[8];
    int n;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(portstr, sizeof portstr, "%d", port);
    if (getaddrinfo(host, portstr, &hints, &res) != 0) return 0;

    for (ai = res; ai; ai = ai->ai_next) {
        s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s == INVALID_SOCKET) continue;
        ioctlsocket(s, FIONBIO, &nb);
        if (connect(s, ai->ai_addr, (int)ai->ai_addrlen) == 0) {
            connected = 1;
            break;
        }
        if (WSAGetLastError() == WSAEWOULDBLOCK) {
            FD_ZERO(&wset);
            FD_SET(s, &wset);
            tv.tv_sec = connect_ms / 1000;
            tv.tv_usec = (connect_ms % 1000) * 1000;
            if (select(0, NULL, &wset, NULL, &tv) > 0) {
                getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&err, &errlen);
                if (err == 0) { connected = 1; break; }
            }
        }
        closesocket(s);
        s = INVALID_SOCKET;
    }
    freeaddrinfo(res);
    if (!connected || s == INVALID_SOCKET) {
        if (s != INVALID_SOCKET) closesocket(s);
        return 0;
    }

    {
        long long t_end = now_ms() + hold_ms;
        int hold_sec = (hold_ms + 999) / 1000;
        int tick = 0;
        while (now_ms() < t_end) {
            long long left = t_end - now_ms();
            int slice = left > 1000 ? 1000 : (int)left;
            if (slice < 1) break;
            tick++;
            stage_progress(g_prog_item[0] ? g_prog_item : "MQTT hold",
                           tick > hold_sec ? hold_sec : tick, hold_sec);
            FD_ZERO(&rset);
            FD_SET(s, &rset);
            tv.tv_sec = slice / 1000;
            tv.tv_usec = (slice % 1000) * 1000;
            n = select(0, &rset, NULL, NULL, &tv);
            if (n > 0 && FD_ISSET(s, &rset)) {
                n = recv(s, junk, sizeof junk, 0);
                closesocket(s);
                return -1;
            }
            if (n < 0) break;
        }
    }
    err = 0;
    errlen = sizeof err;
    getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&err, &errlen);
    closesocket(s);
    return err == 0 ? 1 : -1;
#else
    struct addrinfo hints, *res = NULL, *ai;
    char portstr[16];
    int s = -1, flags, err, connected = 0, n;
    socklen_t errlen;
    fd_set rset, wset;
    struct timeval tv;
    char junk[8];

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(portstr, sizeof portstr, "%d", port);
    if (getaddrinfo(host, portstr, &hints, &res) != 0) return 0;

    for (ai = res; ai; ai = ai->ai_next) {
        s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s < 0) continue;
        flags = fcntl(s, F_GETFL, 0);
        fcntl(s, F_SETFL, flags | O_NONBLOCK);
        if (connect(s, ai->ai_addr, ai->ai_addrlen) == 0) {
            connected = 1;
            break;
        }
        if (errno == EINPROGRESS) {
            FD_ZERO(&wset);
            FD_SET(s, &wset);
            tv.tv_sec = connect_ms / 1000;
            tv.tv_usec = (connect_ms % 1000) * 1000;
            if (select(s + 1, NULL, &wset, NULL, &tv) > 0) {
                err = 0;
                errlen = sizeof err;
                getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &errlen);
                if (err == 0) { connected = 1; break; }
            }
        }
        close(s);
        s = -1;
    }
    freeaddrinfo(res);
    if (!connected || s < 0) {
        if (s >= 0) close(s);
        return 0;
    }

    {
        long long t_end = now_ms() + hold_ms;
        int hold_sec = (hold_ms + 999) / 1000;
        int tick = 0;
        while (now_ms() < t_end) {
            long long left = t_end - now_ms();
            int slice = left > 1000 ? 1000 : (int)left;
            if (slice < 1) break;
            tick++;
            stage_progress(g_prog_item[0] ? g_prog_item : "MQTT hold",
                           tick > hold_sec ? hold_sec : tick, hold_sec);
            FD_ZERO(&rset);
            FD_SET(s, &rset);
            tv.tv_sec = slice / 1000;
            tv.tv_usec = (slice % 1000) * 1000;
            n = select(s + 1, &rset, NULL, NULL, &tv);
            if (n > 0 && FD_ISSET(s, &rset)) {
                n = (int)recv(s, junk, sizeof junk, 0);
                close(s);
                return -1;
            }
            if (n < 0) break;
        }
    }
    err = 0;
    errlen = sizeof err;
    getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &errlen);
    close(s);
    return err == 0 ? 1 : -1;
#endif
}

/* Minimal NTP client (UDP/123). Returns 1 if response received. */
static int ntp_probe(const char *host, int timeout_ms) {
#ifdef _WIN32
    SOCKET s;
#else
    int s;
#endif
    struct addrinfo hints, *res = NULL, *ai;
    unsigned char req[48], resp[48];
    fd_set rset;
    struct timeval tv;
    int ok = 0;
    long long t0;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    if (getaddrinfo(host, "123", &hints, &res) != 0) return 0;

    memset(req, 0, sizeof req);
    req[0] = 0x1b; /* LI=0, VN=3, Mode=3 (client) */

    for (ai = res; ai && !ok; ai = ai->ai_next) {
#ifdef _WIN32
        s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s == INVALID_SOCKET) continue;
#else
        s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s < 0) continue;
#endif
        t0 = now_ms();
        if (sendto(s, (const char *)req, sizeof req, 0, ai->ai_addr, (int)ai->ai_addrlen) == (int)sizeof req) {
            FD_ZERO(&rset);
#ifdef _WIN32
            FD_SET(s, &rset);
            tv.tv_sec = timeout_ms / 1000;
            tv.tv_usec = (timeout_ms % 1000) * 1000;
            if (select(0, &rset, NULL, NULL, &tv) > 0) {
                if (recvfrom(s, (char *)resp, sizeof resp, 0, NULL, NULL) >= 48)
                    ok = 1;
            }
#else
            FD_SET(s, &rset);
            tv.tv_sec = timeout_ms / 1000;
            tv.tv_usec = (timeout_ms % 1000) * 1000;
            if (select(s + 1, &rset, NULL, NULL, &tv) > 0) {
                if (recvfrom(s, resp, sizeof resp, 0, NULL, NULL) >= 48)
                    ok = 1;
            }
#endif
        }
        (void)t0;
#ifdef _WIN32
        closesocket(s);
#else
        close(s);
#endif
    }
    freeaddrinfo(res);
    return ok;
}

static void check_tcp_ep(const char *cat, const char *name, const char *host,
                         int port, int timeout_ms, int critical, int spoiler,
                         int *fail_n, char fail_names[][64], int fail_cap) {
    char detail[STR], hint[STR], ip[64], url[256];
    long long t0;
    int open;

    snprintf(url, sizeof url, "https://%s/", host);
    if (!dns_resolve(host, ip, sizeof ip)) {
        snprintf(detail, sizeof detail, "DNS не резолвит %s", host);
        add_check_ex(cat, name, "warn", detail,
                     "Имя не резолвится — это сбой DNS, а не доказательство недоступности сервиса. "
                     "Проверьте системный DNS / фильтр / Private DNS.",
                     NULL, url, spoiler);
        /* не считаем критическим fail ресурса */
        return;
    }
    t0 = now_ms();
    open = tcp_open(host, port, timeout_ms);
    if (open) {
        snprintf(detail, sizeof detail, "%s:%d открыт, %lld ms",
                 host, port, (long long)(now_ms() - t0));
        add_check_ex(cat, name, "ok", detail, "", ip, url, spoiler);
        return;
    }
    snprintf(detail, sizeof detail, "%s:%d закрыт/фильтр", host, port);
    snprintf(hint, sizeof hint,
             "Типичный симптом DPI/firewall: TCP connect не проходит. "
             "Для IoT нужны allowlist хостов и портов (часто 443/8883).");
    add_check_ex(cat, name, "fail", detail, hint, ip, url, spoiler);
    if (critical && fail_n && *fail_n < fail_cap)
        snprintf(fail_names[(*fail_n)++], 64, "%s", name);
}

/*
 * Steam CM: старые cm2-1.steampowered.com — NXDOMAIN.
 * Берём IP:port из GetCMList WebAPI и пробуем TCP (как клиент Steam).
 */
static void check_steam_cm(int *fail_n, char fail_names[][64], int fail_cap) {
    char out[16384], detail[STR], ip[64];
    const char *p;
    int tried = 0, ok = 0, port = 0;
    long long t0;
#ifdef _WIN32
    const char *cmd =
        "curl.exe -sS --max-time 12 "
        "\"https://api.steampowered.com/ISteamDirectory/GetCMList/v1/?cellid=0\" 2>nul";
#else
    const char *cmd =
        CURL_SSL_ENV
        "curl -sS --max-time 12 "
        "'https://api.steampowered.com/ISteamDirectory/GetCMList/v1/?cellid=0' 2>/dev/null";
#endif

    out[0] = 0;
    if (run_capture(cmd, out, sizeof out) != 0 || !out[0]) {
        add_check_ex("Игры", "Steam CM (GetCMList)", "fail",
                     "не удалось получить список CM",
                     "Нужен HTTPS к api.steampowered.com (ISteamDirectory/GetCMList).",
                     NULL,
                     "https://api.steampowered.com/ISteamDirectory/GetCMList/v1/?cellid=0",
                     0);
        if (fail_n && *fail_n < fail_cap)
            snprintf(fail_names[(*fail_n)++], 64, "%s", "Steam CM");
        return;
    }

    p = out;
    ip[0] = 0;
    while (tried < 10 && !ok) {
        int a, b, c, d, po, n = 0;
        while (*p && (*p < '0' || *p > '9')) p++;
        if (!*p) break;
        if (sscanf(p, "%d.%d.%d.%d:%d%n", &a, &b, &c, &d, &po, &n) == 5 &&
            a >= 0 && a < 256 && b >= 0 && b < 256 &&
            c >= 0 && c < 256 && d >= 0 && d < 256 &&
            po > 0 && po < 65536 && n > 0) {
            snprintf(ip, sizeof ip, "%d.%d.%d.%d", a, b, c, d);
            port = po;
            p += n;
            tried++;
            t0 = now_ms();
            if (tcp_open(ip, port, 3500)) {
                ok = 1;
                snprintf(detail, sizeof detail, "CM %s:%d открыт, %lld ms (из GetCMList, попытка %d)",
                         ip, port, (long long)(now_ms() - t0), tried);
                add_check_ex("Игры", "Steam CM TCP", "ok", detail, "",
                             ip,
                             "https://api.steampowered.com/ISteamDirectory/GetCMList/v1/?cellid=0",
                             0);
                break;
            }
        } else {
            p++;
        }
    }

    if (!ok) {
        snprintf(detail, sizeof detail,
                 "GetCMList ok, TCP к CM не открылся (%d попыток)", tried);
        add_check_ex("Игры", "Steam CM TCP", "fail", detail,
                     "Список CM получен, но порты 27017+ фильтруются/недоступны.",
                     tried ? ip : NULL,
                     "https://api.steampowered.com/ISteamDirectory/GetCMList/v1/?cellid=0",
                     0);
        if (fail_n && *fail_n < fail_cap)
            snprintf(fail_names[(*fail_n)++], 64, "%s", "Steam CM");
    }
}

/* ---------- HTTP ---------- */

typedef struct {
    const char *id; /* short label in report */
    const char *ua;
} UaProfile;

/* Desktop Win / non-Win, mobile, Smart TV / embed */
static const UaProfile UA_PROFILES[] = {
    {"win",
     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
     "Chrome/131.0.0.0 Safari/537.36"},
    {"mac",
     "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7) AppleWebKit/537.36 (KHTML, like Gecko) "
     "Chrome/131.0.0.0 Safari/537.36"},
    {"android",
     "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) "
     "Chrome/131.0.0.0 Mobile Safari/537.36"},
    {"tv",
     "Mozilla/5.0 (SMART-TV; Linux; Tizen 7.0) AppleWebKit/537.36 (KHTML, like Gecko) "
     "Chrome/94.0.4606.65 TV Safari/537.36"},
    {"embed",
     "Mozilla/5.0 (X11; Linux armv7l) AppleWebKit/537.36 (KHTML, like Gecko) "
     "Chrome/91.0.4472.114 Safari/537.36 CrKey/1.54.248666"},
};
#define N_UA_PROFILES ((int)(sizeof UA_PROFILES / sizeof UA_PROFILES[0]))

static const char *ua_default(void) {
    return UA_PROFILES[0].ua; /* Windows desktop */
}

#ifdef _WIN32
static HttpResult http_probe_ua(const char *url, int timeout_sec, int insecure, const char *ua, int follow) {
    HttpResult r;
    HINTERNET hNet = NULL, hUrl = NULL;
    DWORD flags, code = 0, code_len = sizeof code, read;
    char buf[4096];
    char redir[STR];
    char final_url[STR];
    DWORD redir_len = sizeof redir;
    DWORD final_len = sizeof final_url;
    long long t0;
    DWORD to = (DWORD)timeout_sec * 1000;

    memset(&r, 0, sizeof r);
    (void)insecure;
    t0 = now_ms();

    hNet = InternetOpenA(ua && ua[0] ? ua : ua_default(),
                         INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!hNet) {
        snprintf(r.error, sizeof r.error, "InternetOpen failed");
        r.ms = (int)(now_ms() - t0);
        return r;
    }
    InternetSetOptionA(hNet, INTERNET_OPTION_CONNECT_TIMEOUT, &to, sizeof to);
    InternetSetOptionA(hNet, INTERNET_OPTION_RECEIVE_TIMEOUT, &to, sizeof to);
    InternetSetOptionA(hNet, INTERNET_OPTION_SEND_TIMEOUT, &to, sizeof to);

    flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE;
    if (!follow)
        flags |= INTERNET_FLAG_NO_AUTO_REDIRECT;
    if (starts_with(url, "https://"))
        flags |= INTERNET_FLAG_SECURE | INTERNET_FLAG_IGNORE_CERT_CN_INVALID |
                 INTERNET_FLAG_IGNORE_CERT_DATE_INVALID;

    hUrl = InternetOpenUrlA(hNet, url, NULL, 0, flags, 0);
    if (!hUrl) {
        DWORD err = GetLastError();
        snprintf(r.error, sizeof r.error, "ошибка WinINet %lu", (unsigned long)err);
        r.ms = (int)(now_ms() - t0);
        InternetCloseHandle(hNet);
        return r;
    }

    if (HttpQueryInfoA(hUrl, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &code, &code_len, NULL))
        r.code = (int)code;

    redir[0] = 0;
    redir_len = sizeof redir;
    if (!follow) {
        if (HttpQueryInfoA(hUrl, HTTP_QUERY_LOCATION, redir, &redir_len, NULL) && redir[0])
            snprintf(r.redirect, sizeof r.redirect, "%s", redir);
    } else {
        final_url[0] = 0;
        final_len = sizeof final_url;
        if (InternetQueryOptionA(hUrl, INTERNET_OPTION_URL, final_url, &final_len) && final_url[0]) {
            if (strcmp(final_url, url) != 0)
                snprintf(r.redirect, sizeof r.redirect, "%s", final_url);
        }
        /* если follow, но всё ещё 3xx — цепочка оборвалась */
        if (r.code >= 300 && r.code < 400) {
            redir_len = sizeof redir;
            if (HttpQueryInfoA(hUrl, HTTP_QUERY_LOCATION, redir, &redir_len, NULL) && redir[0])
                snprintf(r.redirect, sizeof r.redirect, "%s", redir);
        }
    }

    if (InternetReadFile(hUrl, buf, sizeof buf - 1, &read) && read > 0) {
        if (read > sizeof r.body - 1) read = (DWORD)(sizeof r.body - 1);
        memcpy(r.body, buf, read);
        r.body[read] = 0;
        str_trim(r.body);
    }

    r.ms = (int)(now_ms() - t0);
    if (follow)
        r.ok = (r.code >= 200 && r.code < 400);
    else
        r.ok = (r.code >= 200 && r.code < 400 && r.redirect[0] == 0);
    InternetCloseHandle(hUrl);
    InternetCloseHandle(hNet);
    return r;
}
#else
static HttpResult http_probe_ua(const char *url, int timeout_sec, int insecure, const char *ua, int follow) {
    HttpResult r;
    char cmd[LONGSTR];
    char out[STR];
    char *p, *q;
    long long t0 = now_ms();
    const char *agent = ua && ua[0] ? ua : ua_default();
    int nredir = 0;
    memset(&r, 0, sizeof r);
    /* follow: идём по 301/302/… и смотрим финальный код + url_effective
     * nofollow: как для captive — редирект сам по себе сигнал.
     * Не форсируем --http1.1: госсайты/CDN часто лучше на HTTP/2 + TLS1.3. */
    snprintf(cmd, sizeof cmd,
             CURL_SSL_ENV
             "curl -sS -o /tmp/netdiag_body.$$ -w "
             "'%%{http_code}\\t%%{time_total}\\t%%{url_effective}\\t%%{num_redirects}\\t%%{redirect_url}' "
             "--max-time %d --connect-timeout %d "
             "-A '%s' "
             "%s --max-redirs %d %s '%s' 2>/dev/null",
             timeout_sec, timeout_sec > 2 ? timeout_sec - 1 : timeout_sec, agent,
             follow ? "-L" : "",
             follow ? 8 : 0,
             insecure ? "-k" : "", url);
    if (run_capture(cmd, out, sizeof out) != 0 || !out[0]) {
        snprintf(r.error, sizeof r.error, "curl failed");
        r.ms = (int)(now_ms() - t0);
        return r;
    }
    p = out;
    r.code = atoi(p);
    q = strchr(p, '\t');
    if (q) {
        double sec = atof(q + 1);
        r.ms = (int)(sec * 1000 + 0.5);
        /* url_effective */
        q = strchr(q + 1, '\t');
        if (q) {
            char effective[STR];
            char *q2 = strchr(q + 1, '\t');
            size_t elen;
            if (q2) {
                elen = (size_t)(q2 - (q + 1));
                if (elen >= sizeof effective) elen = sizeof effective - 1;
                memcpy(effective, q + 1, elen);
                effective[elen] = 0;
                str_trim(effective);
                nredir = atoi(q2 + 1);
                /* redirect_url (nofollow Location) */
                {
                    char *q3 = strchr(q2 + 1, '\t');
                    if (!follow && q3 && q3[1] && strcmp(q3 + 1, "0") != 0) {
                        snprintf(r.redirect, sizeof r.redirect, "%s", q3 + 1);
                        str_trim(r.redirect);
                    }
                }
            } else {
                snprintf(effective, sizeof effective, "%s", q + 1);
                str_trim(effective);
            }
            if (follow) {
                if (nredir > 0 && effective[0] && strcmp(effective, url) != 0)
                    snprintf(r.redirect, sizeof r.redirect, "%s", effective);
                /* финальный 3xx = цепочка не завершилась успешно */
                if (r.code >= 300 && r.code < 400 && !r.redirect[0] && effective[0])
                    snprintf(r.redirect, sizeof r.redirect, "%s", effective);
            }
        }
    } else {
        r.ms = (int)(now_ms() - t0);
    }
    if (follow)
        r.ok = (r.code >= 200 && r.code < 400);
    else
        r.ok = (r.code >= 200 && r.code < 400 && r.redirect[0] == 0);
    return r;
}
#endif

/* Обычные ресурсы: ходим по 301/302 и проверяем финальный ответ */
static HttpResult http_probe(const char *url, int timeout_sec, int insecure) {
    return http_probe_ua(url, timeout_sec, insecure, ua_default(), 1);
}

/* Captive / generate_204: редирект = портал, follow не нужен */
static HttpResult http_probe_nofollow(const char *url, int timeout_sec, int insecure) {
    return http_probe_ua(url, timeout_sec, insecure, ua_default(), 0);
}

/* DoH: DNS over HTTPS с Accept: application/dns-json (Cloudflare иначе даёт 400). */
static HttpResult doh_probe(const char *url, int timeout_sec) {
    HttpResult r;
    char cmd[LONGSTR], out[STR];
    char *p, *q;
    long long t0 = now_ms();
    double sec = 0;

    memset(&r, 0, sizeof r);
#ifdef _WIN32
    snprintf(cmd, sizeof cmd,
             "curl.exe -sS -o NUL -w \"%%{http_code}\\t%%{time_total}\" "
             "--max-time %d --connect-timeout %d "
             "-H \"Accept: application/dns-json\" --http1.1 -k \"%s\" 2>NUL",
             timeout_sec, timeout_sec, url);
#else
    snprintf(cmd, sizeof cmd,
             CURL_SSL_ENV
             "curl -sS -o /dev/null -w '%%{http_code}\\t%%{time_total}' "
             "--max-time %d --connect-timeout %d "
             "-H 'Accept: application/dns-json' -k '%s' 2>/dev/null",
             timeout_sec, timeout_sec, url);
#endif
    if (run_capture(cmd, out, sizeof out) != 0 || !out[0]) {
        snprintf(r.error, sizeof r.error, "curl failed");
        r.ms = (int)(now_ms() - t0);
        return r;
    }
    p = out;
    r.code = atoi(p);
    q = strchr(p, '\t');
    if (q) {
        sec = atof(q + 1);
        r.ms = (int)(sec * 1000.0 + 0.5);
    } else {
        r.ms = (int)(now_ms() - t0);
    }
    r.ok = (r.code == 200);
    if (!r.ok && r.code <= 0)
        snprintf(r.error, sizeof r.error, "таймаут/нет ответа");
    return r;
}

/*
 * Прогон несколькими UA. Возвращает «лучший» ответ (есть HTTP-код предпочтительнее).
 * ua_summary: "win=200 mac=200 android=403 …" или "все=200".
 * ua_mismatch: 1 если коды/доступность разошлись между агентами.
 */
static HttpResult http_probe_agents(const char *url, int timeout_sec, int insecure,
                                    char *ua_summary, size_t ua_summary_len, int *ua_mismatch) {
    HttpResult best;
    int codes[16];
    int n = N_UA_PROFILES;
    int i, all_same = 1, any_ok = 0, sum_ms = 0, n_done = 0;
    size_t used = 0;

    memset(&best, 0, sizeof best);
    if (ua_mismatch) *ua_mismatch = 0;
    if (ua_summary && ua_summary_len) ua_summary[0] = 0;
    if (n > 16) n = 16;

    for (i = 0; i < n; i++) {
        HttpResult r;
        if (g_prog_item[0]) {
            char label[64];
            int steps = n;
            int cur = (g_prog_cur > 0 ? (g_prog_cur - 1) * steps : 0) + i + 1;
            int tot = g_prog_total > 0 ? g_prog_total * steps : steps;
            snprintf(label, sizeof label, "%s · %s", g_prog_item, UA_PROFILES[i].id);
            stage_progress(label, cur, tot);
        }
        r = http_probe_ua(url, timeout_sec, insecure, UA_PROFILES[i].ua, 1);
        codes[i] = r.code > 0 ? r.code : 0;
        if (r.code > 0 || r.error[0]) {
            sum_ms += r.ms;
            n_done++;
        }
        if (r.code >= 200 && r.code < 500) any_ok = 1;
        if (i == 0) best = r;
        else if ((!best.code && r.code) ||
                 (r.code >= 200 && r.code < 400 && !(best.code >= 200 && best.code < 400)) ||
                 (r.code > 0 && best.code > 0 && r.ms < best.ms &&
                  (r.code >= 200 && r.code < 400) == (best.code >= 200 && best.code < 400)))
            best = r;
        if (i > 0 && codes[i] != codes[0]) all_same = 0;
    }

    if (n_done > 0)
        best.ms = sum_ms / n_done;

    if (ua_summary && ua_summary_len > 8) {
        if (all_same && codes[0] > 0) {
            snprintf(ua_summary, ua_summary_len, "все=%d", codes[0]);
        } else if (all_same && codes[0] == 0) {
            snprintf(ua_summary, ua_summary_len, "все=нет ответа");
        } else {
            for (i = 0; i < n; i++) {
                char piece[48];
                int left;
                if (codes[i] > 0)
                    snprintf(piece, sizeof piece, "%s=%d", UA_PROFILES[i].id, codes[i]);
                else
                    snprintf(piece, sizeof piece, "%s=—", UA_PROFILES[i].id);
                left = (int)ua_summary_len - (int)used - 1;
                if (left <= 0) break;
                if (used > 0 && left > 1) {
                    ua_summary[used++] = ' ';
                    ua_summary[used] = 0;
                    left--;
                }
                snprintf(ua_summary + used, (size_t)left + 1, "%s", piece);
                used = strlen(ua_summary);
            }
        }
    }

    if (ua_mismatch) *ua_mismatch = !all_same;
    (void)any_ok;
    return best;
}

/* ---------- network identity ---------- */

#ifdef _WIN32
static void detect_network(void) {
    ULONG buflen = 15000;
    IP_ADAPTER_ADDRESSES *addrs = NULL, *a;
    ULONG ret;
    int i;

    addrs = (IP_ADAPTER_ADDRESSES *)malloc(buflen);
    if (!addrs) return;
    ret = GetAdaptersAddresses(AF_UNSPEC,
                               GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_INCLUDE_PREFIX,
                               NULL, addrs, &buflen);
    if (ret == ERROR_BUFFER_OVERFLOW) {
        free(addrs);
        addrs = (IP_ADAPTER_ADDRESSES *)malloc(buflen);
        if (!addrs) return;
        ret = GetAdaptersAddresses(AF_UNSPEC,
                                   GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_INCLUDE_PREFIX,
                                   NULL, addrs, &buflen);
    }
    if (ret != NO_ERROR) {
        free(addrs);
        return;
    }

    for (a = addrs; a; a = a->Next) {
        IP_ADAPTER_UNICAST_ADDRESS *u;
        IP_ADAPTER_GATEWAY_ADDRESS *g;
        IP_ADAPTER_DNS_SERVER_ADDRESS *d;
        if (a->OperStatus != IfOperStatusUp) continue;
        if (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;

        for (u = a->FirstUnicastAddress; u; u = u->Next) {
            if (u->Address.lpSockaddr->sa_family == AF_INET) {
                struct sockaddr_in *sa = (struct sockaddr_in *)u->Address.lpSockaddr;
                inet_ntop(AF_INET, &sa->sin_addr, local_ip, sizeof local_ip);
                break;
            }
        }
        for (g = a->FirstGatewayAddress; g; g = g->Next) {
            if (g->Address.lpSockaddr->sa_family == AF_INET) {
                struct sockaddr_in *sa = (struct sockaddr_in *)g->Address.lpSockaddr;
                inet_ntop(AF_INET, &sa->sin_addr, gateway, sizeof gateway);
                break;
            }
        }
        for (d = a->FirstDnsServerAddress; d && ndns < MAX_DNS; d = d->Next) {
            if (d->Address.lpSockaddr->sa_family == AF_INET) {
                struct sockaddr_in *sa = (struct sockaddr_in *)d->Address.lpSockaddr;
                inet_ntop(AF_INET, &sa->sin_addr, dns_list[ndns], sizeof dns_list[0]);
                /* skip duplicates */
                for (i = 0; i < ndns; i++)
                    if (strcmp(dns_list[i], dns_list[ndns]) == 0) break;
                if (i == ndns) ndns++;
            }
        }
        if (local_ip[0] && gateway[0]) break;
    }
    free(addrs);
}

static void detect_wifi(void) {
    char out[8192];
    char *line, *ctx = NULL;
    if (run_capture("netsh wlan show interfaces", out, sizeof out) != 0) return;
    for (line = strtok_s(out, "\r\n", &ctx); line; line = strtok_s(NULL, "\r\n", &ctx)) {
        char *p = strstr(line, ":");
        if (!p) continue;
        *p++ = 0;
        while (*p == ' ' || *p == '\t') p++;
        str_trim(line);
        str_trim(p);
        /* English + Russian netsh labels */
        if (_stricmp(line, "SSID") == 0 || strstr(line, "SSID")) {
            if (strstr(line, "BSSID")) continue;
            snprintf(wifi_ssid, sizeof wifi_ssid, "%s", p);
        } else if (_stricmp(line, "Signal") == 0 || strstr(line, "Сигнал") || strstr(line, "ignal")) {
            wifi_signal = atoi(p);
        } else if (_stricmp(line, "Channel") == 0 || strstr(line, "Канал") || strstr(line, "hannel")) {
            wifi_channel = atoi(p);
        } else if (_stricmp(line, "Radio type") == 0 || strstr(line, "Тип радио") || strstr(line, "adio")) {
            snprintf(wifi_radio, sizeof wifi_radio, "%s", p);
        }
    }
}
#else
static void detect_network(void) {
    char out[4096];
    if (run_capture("route -n get default 2>/dev/null", out, sizeof out) == 0) {
        char *p = strstr(out, "gateway:");
        char *q = strstr(out, "interface:");
        if (p) {
            sscanf(p + 8, "%63s", gateway);
        }
        if (q) {
            char iface[64];
            char cmd[256];
            sscanf(q + 10, "%63s", iface);
            snprintf(cmd, sizeof cmd, "ipconfig getifaddr %s 2>/dev/null", iface);
            run_capture(cmd, local_ip, sizeof local_ip);
            str_trim(local_ip);
        }
    }
    if (run_capture("scutil --dns 2>/dev/null | awk '/nameserver\\[/{print $3}' | awk '!s[$0]++' | head -6",
                    out, sizeof out) == 0) {
        char *line, *ctx = NULL;
        for (line = strtok_r(out, "\n", &ctx); line && ndns < MAX_DNS; line = strtok_r(NULL, "\n", &ctx)) {
            str_trim(line);
            if (line[0]) snprintf(dns_list[ndns++], sizeof dns_list[0], "%s", line);
        }
    }
}

static void detect_wifi(void) {
    char out[8192];
    if (run_capture("system_profiler SPAirPortDataType 2>/dev/null", out, sizeof out) != 0) return;
    /* best-effort parse */
    {
        char *p = strstr(out, "Channel:");
        if (p) wifi_channel = atoi(p + 8);
        p = strstr(out, "Signal / Noise:");
        if (p) wifi_signal = atoi(p + 15); /* dBm negative */
    }
}
#endif

/* ---------- ping via system ---------- */

static int ping_summary(const char *target, int count, int *loss, double *avg) {
    char cmd[256], out[4096];
    *loss = 100;
    *avg = 0;
#ifdef _WIN32
    snprintf(cmd, sizeof cmd, "ping -n %d -w 1000 %s", count, target);
#else
    snprintf(cmd, sizeof cmd, "ping -c %d -W 1000 %s 2>&1", count, target);
#endif
    if (run_capture(cmd, out, sizeof out) != 0) return -1;
#ifdef _WIN32
    {
        char *p = strstr(out, "(");
        char *lost = strstr(out, "Lost =");
        char *avgp = strstr(out, "Average =");
        if (!avgp) avgp = strstr(out, "Average=");
        if (!lost) lost = strstr(out, "потеряно =");
        if (!lost) lost = strstr(out, "Lost=");
        if (lost) {
            int nloss = 0;
            if (sscanf(lost, "Lost = %d", &nloss) == 1 ||
                sscanf(lost, "Lost=%d", &nloss) == 1 ||
                sscanf(strstr(out, "потеряно") ? strstr(out, "потеряно") : "потеряно = 0",
                       "потеряно = %d", &nloss) == 1) {
                *loss = (nloss * 100) / (count ? count : 1);
            }
            /* also parse "Lost = x (y% loss)" */
            p = strstr(out, "% loss");
            if (!p) p = strstr(out, "% потерь");
            if (p) {
                char *q = p;
                while (q > out && *q != '(') q--;
                if (*q == '(') *loss = atoi(q + 1);
            }
        }
        if (avgp) {
            avgp = strchr(avgp, '=');
            if (avgp) *avg = atof(avgp + 1);
        }
    }
#else
    {
        char *p = strstr(out, "packet loss");
        char *r = strstr(out, "round-trip");
        if (!r) r = strstr(out, "rtt");
        if (p) {
            /* "x.x% packet loss" — find % before */
            char *pct = p;
            while (pct > out && *pct != ',') pct--;
            while (pct > out && !isdigit((unsigned char)*pct) && *pct != '.') pct--;
            while (pct > out && (isdigit((unsigned char)pct[-1]) || pct[-1] == '.')) pct--;
            *loss = (int)atof(pct);
        }
        if (r) {
            /* min/avg/max */
            char *sl = strchr(r, '=');
            if (sl) {
                double mn, av, mx;
                if (sscanf(sl + 1, " %lf/%lf/%lf", &mn, &av, &mx) >= 2) *avg = av;
            }
        }
    }
#endif
    return 0;
}

/* ---------- DNS latency ---------- */

static int dns_ms_nslookup(const char *server, int *ms_out) {
    char cmd[256], out[2048];
    long long t0, t1;
    *ms_out = 0;
#ifdef _WIN32
    snprintf(cmd, sizeof cmd, "nslookup connectivitycheck.gstatic.com %s", server);
#else
    snprintf(cmd, sizeof cmd, "dig @%s +time=1 +tries=1 +stats connectivitycheck.gstatic.com A 2>&1", server);
#endif
    t0 = now_ms();
    if (run_capture(cmd, out, sizeof out) != 0) return 0;
    t1 = now_ms();
    *ms_out = (int)(t1 - t0);
#ifdef _WIN32
    if (strstr(out, "Address:") || strstr(out, "Addresses:")) return 1;
    return 0;
#else
    if (strstr(out, "Query time:")) {
        char *p = strstr(out, "Query time:");
        *ms_out = atoi(p + 11);
        return 1;
    }
    return 0;
#endif
}

/* ---------- progress / skip (raw TTY: Enter / Space, no echo) ---------- */

enum { KEY_NONE = 0, KEY_ENTER = 1, KEY_SPACE = 2, KEY_OTHER = 3 };

#ifdef _WIN32
static DWORD g_con_mode_saved;
static int g_con_raw;
#else
static struct termios g_term_saved;
static int g_term_raw;
#endif

static void term_restore(void) {
#ifdef _WIN32
    if (g_con_raw) {
        SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), g_con_mode_saved);
        g_con_raw = 0;
    }
#else
    if (g_term_raw) {
        tcsetattr(STDIN_FILENO, TCSANOW, &g_term_saved);
        g_term_raw = 0;
    }
#endif
}

static void term_raw_on(void) {
#ifdef _WIN32
    HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    if (h == INVALID_HANDLE_VALUE || !_isatty(_fileno(stdin))) return;
    if (!GetConsoleMode(h, &mode)) return;
    g_con_mode_saved = mode;
    /* disable line/echo; keep processed input for KEY_EVENT records */
    mode &= ~(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT);
    mode |= ENABLE_WINDOW_INPUT;
    SetConsoleMode(h, mode);
    FlushConsoleInputBuffer(h);
    g_con_raw = 1;
#else
    struct termios t;
    if (!isatty(STDIN_FILENO) || g_term_raw) return;
    if (tcgetattr(STDIN_FILENO, &g_term_saved) != 0) return;
    t = g_term_saved;
    t.c_lflag &= (tcflag_t)~(ICANON | ECHO | ECHOE | ECHOK | ECHONL);
    t.c_cc[VMIN] = 0;
    t.c_cc[VTIME] = 0;
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &t) != 0) return;
    g_term_raw = 1;
#endif
}

/* Drain stdin noise (arrows ^[[A etc.) without echoing / scrolling. */
static void stdin_drain(void) {
#ifdef _WIN32
    HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
    INPUT_RECORD rec;
    DWORD n = 0;
    if (h == INVALID_HANDLE_VALUE) return;
    while (PeekConsoleInputA(h, &rec, 1, &n) && n > 0)
        ReadConsoleInputA(h, &rec, 1, &n);
#else
    unsigned char buf[64];
    int fl = fcntl(STDIN_FILENO, F_GETFL, 0);
    if (fl < 0) return;
    fcntl(STDIN_FILENO, F_SETFL, fl | O_NONBLOCK);
    while (read(STDIN_FILENO, buf, sizeof buf) > 0) { /* discard */ }
    fcntl(STDIN_FILENO, F_SETFL, fl);
#endif
}

/*
 * Read one logical key within timeout_ms.
 * Consumes Escape sequences (arrows) so the terminal does not scroll/move.
 */
static int read_key(int timeout_ms) {
    long long deadline = now_ms() + timeout_ms;
#ifdef _WIN32
    HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
    if (h == INVALID_HANDLE_VALUE) return KEY_NONE;
    while (now_ms() < deadline) {
        DWORD wait = (DWORD)(deadline - now_ms());
        if (wait < 1) wait = 1;
        if (wait > 50) wait = 50;
        if (WaitForSingleObject(h, wait) != WAIT_OBJECT_0) continue;
        INPUT_RECORD rec;
        DWORD n = 0;
        if (!ReadConsoleInputA(h, &rec, 1, &n) || n == 0) continue;
        if (rec.EventType != KEY_EVENT || !rec.Event.KeyEvent.bKeyDown) continue;
        {
            WORD vk = rec.Event.KeyEvent.wVirtualKeyCode;
            char ch = rec.Event.KeyEvent.uChar.AsciiChar;
            if (vk == VK_RETURN) return KEY_ENTER;
            if (ch == ' ' || vk == VK_SPACE) return KEY_SPACE;
            /* swallow arrows / page / etc. — do not let console scroll */
            if (vk == VK_LEFT || vk == VK_RIGHT || vk == VK_UP || vk == VK_DOWN ||
                vk == VK_PRIOR || vk == VK_NEXT || vk == VK_HOME || vk == VK_END)
                continue;
            if (ch == 0 || ch == 27) continue;
            return KEY_OTHER;
        }
    }
    return KEY_NONE;
#else
    while (now_ms() < deadline) {
        fd_set fds;
        struct timeval tv;
        long long left = deadline - now_ms();
        int n;
        unsigned char c;
        if (left < 1) left = 1;
        FD_ZERO(&fds);
        FD_SET(STDIN_FILENO, &fds);
        tv.tv_sec = (int)(left / 1000);
        tv.tv_usec = (int)((left % 1000) * 1000);
        if (tv.tv_sec > 0 || tv.tv_usec > 50000) {
            tv.tv_sec = 0;
            tv.tv_usec = 50000;
        }
        n = select(STDIN_FILENO + 1, &fds, NULL, NULL, &tv);
        if (n <= 0) continue;
        if (read(STDIN_FILENO, &c, 1) != 1) continue;
        if (c == '\r' || c == '\n') return KEY_ENTER;
        if (c == ' ') return KEY_SPACE;
        if (c == 0x1b) {
            /* CSI / SS3 escape — drain the rest of the sequence */
            unsigned char rest[8];
            fd_set f2;
            struct timeval t2;
            int i, m;
            for (i = 0; i < 8; i++) {
                FD_ZERO(&f2);
                FD_SET(STDIN_FILENO, &f2);
                t2.tv_sec = 0;
                t2.tv_usec = 30000;
                m = select(STDIN_FILENO + 1, &f2, NULL, NULL, &t2);
                if (m <= 0) break;
                if (read(STDIN_FILENO, &rest[i], 1) != 1) break;
                /* CSI ends with 0x40–0x7E */
                if (rest[i] >= 0x40 && rest[i] <= 0x7e) break;
            }
            continue; /* ignore arrows etc. */
        }
        return KEY_OTHER;
    }
    return KEY_NONE;
#endif
}

/*
 * default_run:
 *   1 — обычный этап: таймаут/Enter = выполнить, Space = пропустить
 *   0 — opt-in (DNS): таймаут/Space = пропустить, Enter = выполнить
 * Returns 1 = run, 0 = skip.
 */
static int stage_begin_ex(const char *title, const char *desc, int default_run) {
    int key = KEY_NONE;
    int run = default_run;
    int interactive = 0;
    long long until;

    if (g_sys_dns_broken && default_run) {
        printf("\n▶ %s\n  ⏭ пропущено: системный DNS не резолвит имена\n", title);
        fflush(stdout);
        add_check(title, "Этап", "info",
                  "пропущен — DNS не резолвит имена",
                  "Без резолва проверки по hostname дают ложные сбои недоступности.");
        return 0;
    }

    printf("\n▶ %s\n  %s\n", title, desc ? desc : "");
    fflush(stdout);

    if (opt_yes) return default_run ? 1 : 0;

#ifdef _WIN32
    interactive = _isatty(_fileno(stdin));
#else
    interactive = isatty(STDIN_FILENO);
#endif
    if (!interactive) return default_run ? 1 : 0;

    term_raw_on();
    stdin_drain();
    if (default_run)
        printf("  Enter — далее · Space — пропустить  (4 с → далее)\n");
    else
        printf("  Enter — запустить · Space — пропустить  (4 с → пропустить)\n");
    fflush(stdout);

    until = now_ms() + 4000;
    while (now_ms() < until) {
        int left = (int)(until - now_ms());
        if (left < 1) break;
        key = read_key(left);
        if (key == KEY_ENTER) { run = 1; break; }
        if (key == KEY_SPACE) { run = 0; break; }
        if (key == KEY_NONE) { run = default_run; break; }
        /* KEY_OTHER / стрелки уже проглочены — продолжаем ждать */
    }

    if (!run) {
        printf("  ⏭ пропущено\n");
        fflush(stdout);
    }
    stdin_drain();
    term_restore();
    return run;
}

static int stage_begin(const char *title, const char *desc) {
    return stage_begin_ex(title, desc, 1);
}

/* Текущий пункт этапа — для подпрогресса UA / hold */
static void stage_progress(const char *msg, int cur, int total) {
    char name[52];
    char line[112];
    size_t i, n;
    snprintf(name, sizeof name, "%s", msg ? msg : "");
    n = strlen(name);
    if (n > 44) {
        name[41] = '.'; name[42] = '.'; name[43] = '.'; name[44] = 0;
        n = 44;
    }
    for (i = n; i < 44; i++) name[i] = ' ';
    name[44] = 0;
    if (total > 0)
        snprintf(line, sizeof line, "  … %s [%d/%d]", name, cur, total);
    else
        snprintf(line, sizeof line, "  … %s", name);
#ifdef _WIN32
    printf("\r%s          ", line);
#else
    printf("\r\033[K%s", line);
#endif
    fflush(stdout);
}

static void stage_item(const char *msg, int cur, int total) {
    snprintf(g_prog_item, sizeof g_prog_item, "%s", msg ? msg : "");
    g_prog_cur = cur;
    g_prog_total = total;
    stage_progress(msg, cur, total);
}

static void stage_item_clear(void) {
    g_prog_item[0] = 0;
    g_prog_cur = 0;
    g_prog_total = 0;
}

static void stage_done(void) {
    stage_item_clear();
#ifdef _WIN32
    printf("\r                                                                              \r");
#else
    printf("\r\033[K");
#endif
    fflush(stdout);
}

/* ---------- raw DNS A query to a specific resolver ---------- */
/* Returns: 1 = got reply (NOERROR/NXDOMAIN/…), 0 = timeout/error. Sets rcode. */

static int dns_encode_name(unsigned char *out, size_t outlen, const char *name, size_t *written) {
    size_t o = 0;
    const char *p = name;
    while (*p) {
        const char *dot = strchr(p, '.');
        size_t lab = dot ? (size_t)(dot - p) : strlen(p);
        if (lab == 0 || lab > 63 || o + 1 + lab + 1 >= outlen) return 0;
        out[o++] = (unsigned char)lab;
        memcpy(out + o, p, lab);
        o += lab;
        if (!dot) break;
        p = dot + 1;
    }
    out[o++] = 0;
    *written = o;
    return 1;
}

static int dns_query_udp(const char *server, const char *name, int timeout_ms,
                         int *rcode_out, int *ms_out) {
#ifdef _WIN32
    SOCKET s;
#else
    int s;
#endif
    struct addrinfo hints, *res = NULL;
    unsigned char req[512], resp[512];
    size_t namelen = 0;
    unsigned short id;
    fd_set rset;
    struct timeval tv;
    long long t0;
    int n;

    if (rcode_out) *rcode_out = -1;
    if (ms_out) *ms_out = 0;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    if (getaddrinfo(server, "53", &hints, &res) != 0 || !res) return 0;

    memset(req, 0, sizeof req);
    id = (unsigned short)(now_ms() & 0xffff);
    req[0] = (unsigned char)(id >> 8);
    req[1] = (unsigned char)(id & 0xff);
    req[2] = 0x01; /* RD */
    req[5] = 1;    /* QDCOUNT = 1 */
    if (!dns_encode_name(req + 12, sizeof req - 12, name, &namelen)) {
        freeaddrinfo(res);
        return 0;
    }
    req[12 + namelen] = 0;
    req[12 + namelen + 1] = 1; /* A */
    req[12 + namelen + 2] = 0;
    req[12 + namelen + 3] = 1; /* IN */

#ifdef _WIN32
    s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s == INVALID_SOCKET) { freeaddrinfo(res); return 0; }
#else
    s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s < 0) { freeaddrinfo(res); return 0; }
#endif

    t0 = now_ms();
    if (sendto(s, (const char *)req, (int)(12 + namelen + 4), 0,
               res->ai_addr, (int)res->ai_addrlen) < 0) {
#ifdef _WIN32
        closesocket(s);
#else
        close(s);
#endif
        freeaddrinfo(res);
        return 0;
    }

    FD_ZERO(&rset);
#ifdef _WIN32
    FD_SET(s, &rset);
#else
    FD_SET(s, &rset);
#endif
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
#ifdef _WIN32
    n = select(0, &rset, NULL, NULL, &tv);
#else
    n = select(s + 1, &rset, NULL, NULL, &tv);
#endif
    if (n <= 0) {
#ifdef _WIN32
        closesocket(s);
#else
        close(s);
#endif
        freeaddrinfo(res);
        return 0;
    }
#ifdef _WIN32
    n = recvfrom(s, (char *)resp, sizeof resp, 0, NULL, NULL);
    closesocket(s);
#else
    n = (int)recvfrom(s, resp, sizeof resp, 0, NULL, NULL);
    close(s);
#endif
    freeaddrinfo(res);
    if (ms_out) *ms_out = (int)(now_ms() - t0);
    if (n < 12) return 0;
    if (rcode_out) *rcode_out = resp[3] & 0x0f;
    return 1;
}

/*
 * Системный getaddrinfo vs прямой UDP к публичным резолверам.
 * Если имена не резолвятся ОС — дальнейшие hostname-проверки дают ложные FAIL.
 */
static void assess_system_dns(void) {
    const char *names[] = {"ya.ru", "dns.google", "cloudflare.com", "microsoft.com"};
    const char *pub[] = {"8.8.8.8", "1.1.1.1", "77.88.8.8"};
    int n = (int)(sizeof names / sizeof names[0]);
    int sys_ok = 0, pub_ok = 0, i, j;
    char ip[64], detail[STR], samples[256];
    int rcode, ms;

    samples[0] = 0;
    for (i = 0; i < n; i++) {
        ip[0] = 0;
        if (dns_resolve(names[i], ip, sizeof ip)) {
            sys_ok++;
            if (samples[0]) {
                size_t L = strlen(samples);
                if (L + 2 < sizeof samples) {
                    samples[L] = ','; samples[L + 1] = ' ';
                    samples[L + 2] = 0;
                }
            }
            {
                size_t L = strlen(samples);
                snprintf(samples + L, sizeof samples - L, "%s→%s", names[i], ip);
            }
        }
        for (j = 0; j < (int)(sizeof pub / sizeof pub[0]); j++) {
            if (dns_query_udp(pub[j], names[i], 2000, &rcode, &ms) && rcode == 0) {
                pub_ok++;
                break;
            }
        }
    }

    snprintf(detail, sizeof detail,
             "система %d/%d, публичный DNS %d/%d%s%s",
             sys_ok, n, pub_ok, n,
             samples[0] ? " · " : "",
             samples[0] ? samples : "");

    if (sys_ok == 0) {
        g_sys_dns_broken = 1;
        if (pub_ok >= 2) {
            add_check("DNS", "Резолв имён (система)", "fail", detail,
                      "Сеть/публичный DNS живы, сломан системный резолвер. "
                      "Проверки по именам пропущены — иначе ложные «ресурсы недоступны».");
            add_finding("critical", "Системный DNS не резолвит имена",
                        "getaddrinfo не решает известные домены, при этом 8.8.8.8 / 1.1.1.1 / "
                        "77.88.8.8 отвечают. Почините DNS на роутере/ОС (или отключите Private DNS). "
                        "Дальнейшие проверки сайтов/IoT/captive по hostname пропущены.");
        } else {
            add_check("DNS", "Резолв имён (система)", "fail", detail,
                      "Имена не резолвятся. Hostname-проверки бессмысленны и пропущены.");
            add_finding("critical", "DNS не резолвит имена",
                        "Системный и публичный DNS не отдают A-записи для известных доменов. "
                        "Отчёт не будет помечать ресурсы как недоступные — сначала восстановите DNS.");
        }
        printf("⚠ Системный DNS не резолвит имена — remote-этапы по hostname пропускаются.\n");
    } else if (sys_ok < n) {
        add_check("DNS", "Резолв имён (система)", "warn", detail,
                  "Часть имён не резолвится — смотрите отдельные DNS-строки, не как «сайт упал».");
    } else {
        add_check("DNS", "Резолв имён (система)", "ok", detail, "");
    }
}

/* ---------- QUIC / UDP:443 probe (Initial-like datagram) ---------- */

static int quic_probe(const char *host, int timeout_ms, int *ms_out) {
#ifdef _WIN32
    SOCKET s;
#else
    int s;
#endif
    struct addrinfo hints, *res = NULL, *ai;
    unsigned char pkt[1252];
    fd_set rset;
    struct timeval tv;
    long long t0;
    int ok = 0;

    if (ms_out) *ms_out = 0;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    if (getaddrinfo(host, "443", &hints, &res) != 0) return 0;

    /* QUIC path probe: unknown version → Version Negotiation (RFC 9000).
     * Битый Initial v1 Google/CF часто дропают молча — false negative. */
    memset(pkt, 0, sizeof pkt);
    pkt[0] = 0xc0; /* long header */
    pkt[1] = 0x1a; pkt[2] = 0x1a; pkt[3] = 0x1a; pkt[4] = 0x1a; /* unknown version */
    pkt[5] = 8; /* DCID len */
    pkt[6] = 0xde; pkt[7] = 0xad; pkt[8] = 0xbe; pkt[9] = 0xef;
    pkt[10] = 0x01; pkt[11] = 0x02; pkt[12] = 0x03; pkt[13] = 0x04;
    pkt[14] = 0; /* SCID len */
    pkt[15] = 0; /* token length varint 0 */
    pkt[16] = 0x40; pkt[17] = 0; /* length placeholder */

    for (ai = res; ai && !ok; ai = ai->ai_next) {
#ifdef _WIN32
        s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s == INVALID_SOCKET) continue;
#else
        s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s < 0) continue;
#endif
        t0 = now_ms();
        if (sendto(s, (const char *)pkt, 1200, 0, ai->ai_addr, (int)ai->ai_addrlen) > 0) {
            FD_ZERO(&rset);
#ifdef _WIN32
            FD_SET(s, &rset);
            tv.tv_sec = timeout_ms / 1000;
            tv.tv_usec = (timeout_ms % 1000) * 1000;
            if (select(0, &rset, NULL, NULL, &tv) > 0) {
                char buf[1500];
                if (recvfrom(s, buf, sizeof buf, 0, NULL, NULL) > 0) ok = 1;
            }
#else
            FD_SET(s, &rset);
            tv.tv_sec = timeout_ms / 1000;
            tv.tv_usec = (timeout_ms % 1000) * 1000;
            if (select(s + 1, &rset, NULL, NULL, &tv) > 0) {
                char buf[1500];
                if (recvfrom(s, buf, sizeof buf, 0, NULL, NULL) > 0) ok = 1;
            }
#endif
            if (ms_out) *ms_out = (int)(now_ms() - t0);
        }
#ifdef _WIN32
        closesocket(s);
#else
        close(s);
#endif
    }
    freeaddrinfo(res);
    return ok;
}

/* ---------- speed: download sample via HTTPS ---------- */

static int http_download_bytes(const char *url, int timeout_sec, long *bytes_out, int *ms_out) {
    long long t0 = now_ms();
    long bytes = 0;
    if (bytes_out) *bytes_out = 0;
    if (ms_out) *ms_out = 0;
#ifdef _WIN32
    {
        HINTERNET hNet, hUrl;
        DWORD flags, read;
        char buf[8192];
        DWORD to = (DWORD)timeout_sec * 1000;
        hNet = InternetOpenA("NetDiagnose/1.0", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
        if (!hNet) return 0;
        InternetSetOptionA(hNet, INTERNET_OPTION_RECEIVE_TIMEOUT, &to, sizeof to);
        InternetSetOptionA(hNet, INTERNET_OPTION_CONNECT_TIMEOUT, &to, sizeof to);
        flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_SECURE |
                INTERNET_FLAG_IGNORE_CERT_CN_INVALID | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID;
        hUrl = InternetOpenUrlA(hNet, url, NULL, 0, flags, 0);
        if (!hUrl) { InternetCloseHandle(hNet); return 0; }
        while (InternetReadFile(hUrl, buf, sizeof buf, &read) && read > 0) {
            bytes += read;
            if (bytes > 12 * 1024 * 1024) break; /* хватит для пробы ~10 МБ */
        }
        InternetCloseHandle(hUrl);
        InternetCloseHandle(hNet);
    }
#else
    {
        char cmd[STR], out[64];
        /* curl: write body to /dev/null, print size downloaded */
        snprintf(cmd, sizeof cmd,
                 "curl -k -sS -L --max-time %d -o /dev/null -w '%%{size_download}' '%s' 2>/dev/null",
                 timeout_sec, url);
        if (run_capture(cmd, out, sizeof out) != 0) return 0;
        str_trim(out);
        bytes = atol(out);
    }
#endif
    if (ms_out) *ms_out = (int)(now_ms() - t0);
    if (bytes_out) *bytes_out = bytes;
    return bytes > 0;
}

/* Скачать тело ответа (до buflen-1). cookie — опционально ("a=b; c=d"). Возвращает HTTP-код или 0. */
static int http_fetch_text_ex(const char *url, char *buf, size_t buflen, int timeout_sec,
                              int *ms_out, const char *cookie) {
    long long t0 = now_ms();
    int code = 0;
    if (buf && buflen) buf[0] = 0;
    if (ms_out) *ms_out = 0;
#ifdef _WIN32
    {
        HINTERNET hNet, hUrl;
        DWORD flags, read, total = 0, scode = 0, slen = sizeof scode;
        DWORD to = (DWORD)timeout_sec * 1000;
        char tmp[4096];
        char hdrs[STR];
        hNet = InternetOpenA(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
        if (!hNet) return 0;
        InternetSetOptionA(hNet, INTERNET_OPTION_RECEIVE_TIMEOUT, &to, sizeof to);
        InternetSetOptionA(hNet, INTERNET_OPTION_CONNECT_TIMEOUT, &to, sizeof to);
        flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE |
                INTERNET_FLAG_SECURE | INTERNET_FLAG_IGNORE_CERT_CN_INVALID |
                INTERNET_FLAG_IGNORE_CERT_DATE_INVALID;
        hdrs[0] = 0;
        if (cookie && cookie[0])
            snprintf(hdrs, sizeof hdrs,
                     "Cookie: %s\r\nAccept-Language: ru-RU,ru;q=0.9,en;q=0.8\r\n",
                     cookie);
        hUrl = InternetOpenUrlA(hNet, url, hdrs[0] ? hdrs : NULL,
                                hdrs[0] ? (DWORD)strlen(hdrs) : 0, flags, 0);
        if (!hUrl) { InternetCloseHandle(hNet); return 0; }
        HttpQueryInfoA(hUrl, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &scode, &slen, NULL);
        code = (int)scode;
        if (buf && buflen > 1) {
            while (total + 1 < buflen &&
                   InternetReadFile(hUrl, tmp, sizeof tmp, &read) && read > 0) {
                size_t chunk = read;
                if (total + chunk > buflen - 1) chunk = buflen - 1 - total;
                memcpy(buf + total, tmp, chunk);
                total += (DWORD)chunk;
                if (chunk < read) break;
            }
            buf[total] = 0;
            str_trim(buf);
        }
        InternetCloseHandle(hUrl);
        InternetCloseHandle(hNet);
    }
#else
    {
        char cmd[STR * 2], meta[64];
        char tmp[] = "/tmp/netdiag_fetch_XXXXXX";
        FILE *f;
        size_t n;
        int fd;
        fd = mkstemp(tmp);
        if (fd < 0) return 0;
        close(fd);
        if (cookie && cookie[0]) {
            snprintf(cmd, sizeof cmd,
                     CURL_SSL_ENV
                     "curl -sS -L --max-time %d --connect-timeout %d "
                     "-A 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                     "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36' "
                     "-H 'Accept-Language: ru-RU,ru;q=0.9,en;q=0.8' "
                     "-H 'Cookie: %s' "
                     "-o '%s' -w '%%{http_code}' '%s' 2>/dev/null",
                     timeout_sec, timeout_sec, cookie, tmp, url);
        } else {
            snprintf(cmd, sizeof cmd,
                     CURL_SSL_ENV
                     "curl -sS -L --max-time %d --connect-timeout %d "
                     "-A 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                     "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36' "
                     "-o '%s' -w '%%{http_code}' '%s' 2>/dev/null",
                     timeout_sec, timeout_sec, tmp, url);
        }
        if (run_capture(cmd, meta, sizeof meta) != 0) {
            unlink(tmp);
            return 0;
        }
        code = atoi(meta);
        f = fopen(tmp, "rb");
        if (f && buf && buflen > 1) {
            n = fread(buf, 1, buflen - 1, f);
            buf[n] = 0;
            str_trim(buf);
            fclose(f);
        } else if (f) fclose(f);
        unlink(tmp);
    }
#endif
    if (ms_out) *ms_out = (int)(now_ms() - t0);
    return code;
}

static int http_fetch_text(const char *url, char *buf, size_t buflen, int timeout_sec, int *ms_out) {
    return http_fetch_text_ex(url, buf, buflen, timeout_sec, ms_out, NULL);
}

/* Минимальный base64 → out; возвращает длину или -1. */
static int b64_decode(const char *in, unsigned char *out, size_t outmax) {
    size_t n = 0;
    unsigned val = 0;
    int bits = 0;
    if (!in || !out) return -1;
    for (; *in; in++) {
        int v = -1;
        char ch = *in;
        if (ch >= 'A' && ch <= 'Z') v = ch - 'A';
        else if (ch >= 'a' && ch <= 'z') v = ch - 'a' + 26;
        else if (ch >= '0' && ch <= '9') v = ch - '0' + 52;
        else if (ch == '+') v = 62;
        else if (ch == '/') v = 63;
        else if (ch == '=') break;
        else continue;
        val = (val << 6) | (unsigned)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (n >= outmax) return -1;
            out[n++] = (unsigned char)((val >> bits) & 0xFF);
        }
    }
    return (int)n;
}

/* 2ip.ru JS-challenge: atob(...) → cookie 2ip_js_challenge / salt. */
static int parse_2ip_challenge(const char *html, char *answer, size_t an,
                               char *salt, size_t sn) {
    const char *p, *q;
    char b64[2048];
    unsigned char js[2048];
    int jn, i;
    const char *ap, *sp;
    if (answer) answer[0] = 0;
    if (salt) salt[0] = 0;
    if (!html) return 0;
    p = strstr(html, "atob(\"");
    if (!p) p = strstr(html, "atob('");
    if (!p) return 0;
    p += 6;
    q = strchr(p, p[-1] == '"' ? '"' : '\'');
    if (!q || (size_t)(q - p) >= sizeof b64) return 0;
    memcpy(b64, p, (size_t)(q - p));
    b64[q - p] = 0;
    jn = b64_decode(b64, js, sizeof js - 1);
    if (jn <= 0) return 0;
    js[jn] = 0;
    ap = strstr((char *)js, "answer");
    sp = strstr((char *)js, "salt");
    if (!ap || !sp) return 0;
    /* answer = "..." */
    ap = strchr(ap, '"');
    if (!ap) return 0;
    ap++;
    for (i = 0; ap[i] && ap[i] != '"' && (size_t)i + 1 < an; i++)
        answer[i] = ap[i];
    answer[i] = 0;
    sp = strchr(sp, '"');
    if (!sp) return 0;
    sp++;
    for (i = 0; sp[i] && sp[i] != '"' && (size_t)i + 1 < sn; i++)
        salt[i] = sp[i];
    salt[i] = 0;
    return answer[0] && salt[0];
}

/* IP со страницы 2ip после challenge (не хватает Chrome 131.0.0.0 из UA). */
static int extract_2ip_page_ip(const char *s, char *ip, size_t iplen) {
    const char *p;
    int a, b, c, d, n;
    if (!s || !ip || iplen < 8) return 0;
    ip[0] = 0;
    p = strstr(s, "return '");
    while (p) {
        if (sscanf(p + 8, "%d.%d.%d.%d'%n", &a, &b, &c, &d, &n) == 4 &&
            a >= 1 && a <= 255 && n > 0) {
            snprintf(ip, iplen, "%d.%d.%d.%d", a, b, c, d);
            return 1;
        }
        p = strstr(p + 8, "return '");
    }
    p = strstr(s, "data-ip=\"");
    if (p && sscanf(p + 9, "%d.%d.%d.%d", &a, &b, &c, &d) == 4 && a >= 1) {
        snprintf(ip, iplen, "%d.%d.%d.%d", a, b, c, d);
        return 1;
    }
    /* fallback: первая «серьёзная» IPv4 (не *.0.0) */
    for (p = s; *p; p++) {
        if (*p < '0' || *p > '9') continue;
        if (sscanf(p, "%d.%d.%d.%d%n", &a, &b, &c, &d, &n) == 4 &&
            a >= 1 && a <= 255 && b <= 255 && c <= 255 && d <= 255 && n > 0) {
            if (c == 0 && d == 0) { p += n - 1; continue; }
            snprintf(ip, iplen, "%d.%d.%d.%d", a, b, c, d);
            return 1;
        }
    }
    return 0;
}

/*
 * 2ip.ru: 503 + JS challenge → cookies → повтор.
 * Пишет внешний IPv4 в ip_out. Возвращает HTTP-код финального ответа.
 */
static int http_fetch_2ip(char *ip_out, size_t ip_n, int timeout_sec, int *ms_out) {
    char answer[96], salt[96], cookie[256];
    char *big;
    size_t big_n = 256 * 1024;
    int code, ms1 = 0;
    long long t0 = now_ms();

    if (ip_out && ip_n) ip_out[0] = 0;
    big = (char *)malloc(big_n);
    if (!big) {
        char small[8192];
        code = http_fetch_text_ex("https://2ip.ru/", small, sizeof small, timeout_sec, ms_out, NULL);
        if (code > 0) extract_2ip_page_ip(small, ip_out, ip_n);
        return code;
    }

    code = http_fetch_text_ex("https://2ip.ru/", big, big_n, timeout_sec, &ms1, NULL);
    if (code != 200 || !extract_2ip_page_ip(big, ip_out, ip_n)) {
        if ((code == 503 || code == 0 || strstr(big, "2ip loading") || strstr(big, "atob(")) &&
            parse_2ip_challenge(big, answer, sizeof answer, salt, sizeof salt)) {
            snprintf(cookie, sizeof cookie,
                     "2ip_js_challenge_salt=%s; 2ip_js_challenge=%s", salt, answer);
            code = http_fetch_text_ex("https://2ip.ru/", big, big_n, timeout_sec, NULL, cookie);
            extract_2ip_page_ip(big, ip_out, ip_n);
        }
    }
    free(big);
    if (ms_out) *ms_out = (int)(now_ms() - t0);
    return code;
}

/* Первая IPv4 в тексте (JSON "x.x.x.x", HTML, plain). */
static int extract_ipv4(const char *s, char *ip, size_t iplen) {
    const char *p;
    if (!s || !ip || iplen < 8) return 0;
    ip[0] = 0;
    for (p = s; *p; p++) {
        int a, b, c, d, n = 0;
        if (*p < '0' || *p > '9') continue;
        if (sscanf(p, "%d.%d.%d.%d%n", &a, &b, &c, &d, &n) == 4 &&
            a >= 0 && a <= 255 && b >= 0 && b <= 255 &&
            c >= 0 && c <= 255 && d >= 0 && d <= 255 && n > 0) {
            /* отсечь очевидный мусор вроде версий 1.2.3.4 в CSS редко, но OK */
            if (a == 0 && b == 0) { p += n - 1; continue; }
            snprintf(ip, iplen, "%d.%d.%d.%d", a, b, c, d);
            return 1;
        }
    }
    return 0;
}

/* URL probe 100kb из get-probes Интернетометра. */
static int yandex_speed_probe_url(char *url_out, size_t url_n) {
    char body[8192];
    const char *p, *start;
    size_t i;
    int code;
    url_out[0] = 0;
    code = http_fetch_text("https://yandex.ru/internet/api/v0/get-probes",
                           body, sizeof body, 10, NULL);
    if (code != 200 || !body[0]) return 0;
    p = strstr(body, "probes/100kb");
    if (!p) return 0;
    start = p;
    while (start > body && !(start[0] == 'h' && start[1] == 't' && start[2] == 't' && start[3] == 'p'))
        start--;
    if (strncmp(start, "http", 4) != 0) return 0;
    for (i = 0; start[i] && start[i] != '"' && i + 1 < url_n; i++)
        url_out[i] = start[i];
    url_out[i] = 0;
    return url_out[0] != 0;
}

#include "top_domains_embed.h"

/* Заполняет domains из файла. Возвращает число доменов или 0. */
static int load_domains_file(const char *path, char domains[][128], int maxn) {
    FILE *f;
    char line[256];
    int n = 0;
    if (!path || !path[0]) return 0;
    f = fopen(path, "r");
    if (!f) return 0;
    while (n < maxn && fgets(line, sizeof line, f)) {
        str_trim(line);
        if (!line[0] || line[0] == '#') continue;
        if (strlen(line) >= 128) continue;
        snprintf(domains[n++], 128, "%s", line);
    }
    fclose(f);
    return n;
}

/* Встроенный список (собирается из wordlists/top_domains.txt). */
static int load_domains_embedded(char domains[][128], int maxn) {
    const char *p = EMBEDDED_DOMAINS_BLOB;
    int n = 0;
    while (*p && n < maxn) {
        char line[128];
        int i = 0;
        while (*p && *p != '\n' && i < (int)sizeof(line) - 1)
            line[i++] = *p++;
        if (*p == '\n') p++;
        line[i] = '\0';
        str_trim(line);
        if (!line[0] || line[0] == '#') continue;
        snprintf(domains[n++], 128, "%s", line);
    }
    return n;
}

/*
 * Порядок:
 *  1) --domains FILE (только файл; без fallback)
 *  2) wordlists/top_domains.txt рядом с exe / cwd
 *  3) встроенный список
 * used_embed: 1 если взяли встроенный.
 */
static int load_domains(char domains[][128], int maxn, int *used_embed) {
    char try1[STR];
    int n;

    if (used_embed) *used_embed = 0;

    if (domains_path[0])
        return load_domains_file(domains_path, domains, maxn);

    if (exe_dir[0]) {
        snprintf(try1, sizeof try1, "%s/wordlists/top_domains.txt", exe_dir);
        n = load_domains_file(try1, domains, maxn);
        if (n > 0) return n;
#ifdef _WIN32
        {
            char try2[STR];
            snprintf(try2, sizeof try2, "%s\\wordlists\\top_domains.txt", exe_dir);
            n = load_domains_file(try2, domains, maxn);
            if (n > 0) return n;
        }
#endif
    }
    n = load_domains_file("wordlists/top_domains.txt", domains, maxn);
    if (n > 0) return n;

    n = load_domains_embedded(domains, maxn);
    if (used_embed && n > 0) *used_embed = 1;
    return n;
}

/* ---------- resources.conf (группы URL/endpoints) ---------- */

#define MAX_RES      96
#define RES_NAME     128
#define RES_URL      256
#define RES_NOTE     256
#define RES_HOST     160
#define RES_CAT      64

typedef struct {
    char name[RES_NAME];
    char url[RES_URL];
    char note[RES_NOTE];
    int expected_block;
} ResSig;

typedef struct {
    char name[RES_NAME];
    char host[RES_HOST];
    int port;
    int crit;
} ResTcp;

typedef struct {
    char name[RES_NAME];
    char url[RES_URL];
} ResHttp;

typedef struct {
    char name[RES_NAME];
    char url[RES_URL];
    int crit;
} ResHttpCrit;

typedef struct {
    char name[RES_NAME];
    char home[RES_URL];
    char video[RES_URL];
} ResVideo;

typedef struct {
    char cat[RES_CAT];
    char name[RES_NAME];
    char url[RES_URL];
} ResBank;

static ResSig g_sig[MAX_RES];
static int g_nsig;
static ResTcp g_game_tcp[MAX_RES];
static int g_ngame_tcp;
static ResTcp g_infra_tcp[MAX_RES];
static int g_ninfra_tcp;
static ResHttp g_infra_https[MAX_RES];
static int g_ninfra_https;
static ResHttp g_game_https[MAX_RES];
static int g_ngame_https;
static ResHttpCrit g_ai[MAX_RES];
static int g_nai;
static ResVideo g_video[MAX_RES];
static int g_nvideo;
static ResBank g_banks[MAX_RES];
static int g_nbanks;

/* Разбивает line по | в поля fields[0..nf-1], до maxf полей. Возвращает число полей. */
static int split_pipe(char *line, char **fields, int maxf) {
    int n = 0;
    char *p = line;
    if (!line) return 0;
    while (n < maxf) {
        fields[n++] = p;
        p = strchr(p, '|');
        if (!p) break;
        *p++ = 0;
    }
    {
        int i;
        for (i = 0; i < n; i++)
            str_trim(fields[i]);
    }
    return n;
}

static void resources_load_defaults(void) {
    static const struct { const char *name, *url, *note; int eb; } sig[] = {
        /* РФ: топ из «белого списка» Минцифры */
        {"Госуслуги", "https://www.gosuslugi.ru/", "белый список Минцифры", 0},
        {"Президент РФ", "https://www.kremlin.ru/", "белый список Минцифры", 0},
        {"Правительство РФ", "https://government.ru/", "белый список Минцифры", 0},
        {"Госдума", "https://duma.gov.ru/", "белый список Минцифры", 0},
        {"ЦБ РФ", "https://www.cbr.ru/", "белый список Минцифры", 0},
        {"Почта России", "https://www.pochta.ru/", "белый список Минцифры", 0},
        {"Честный знак", "https://crpt.ru/", "белый список Минцифры (ЦРПТ)", 0},
        {"Платёжная система Мир", "https://vamprivet.ru/", "белый список Минцифры (НСПК/Мир)", 0},
        {"Яндекс (yandex.ru)", "https://yandex.ru/", "белый список Минцифры", 0},
        {"Яндекс (ya.ru)", "https://ya.ru/", "белый список Минцифры", 0},
        {"Яндекс Карты", "https://yandex.ru/maps/", "белый список Минцифры", 0},
        {"Яндекс Маркет", "https://market.yandex.ru/", "белый список Минцифры", 0},
        {"VK (vk.com)", "https://vk.com/", "белый список Минцифры", 0},
        {"VK (vk.ru)", "https://vk.ru/", "белый список Минцифры", 0},
        {"OK.ru", "https://ok.ru/", "белый список Минцифры", 0},
        {"Mail.ru", "https://mail.ru/", "белый список Минцифры", 0},
        {"MAX", "https://max.ru/", "белый список Минцифры", 0},
        {"Дзен", "https://dzen.ru/", "белый список Минцифры", 0},
        {"Rutube", "https://rutube.ru/", "белый список Минцифры", 0},
        {"IVI", "https://www.ivi.ru/", "белый список Минцифры", 0},
        {"Okko", "https://okko.tv/", "белый список Минцифры", 0},
        {"Premier", "https://premier.one/", "белый список Минцифры", 0},
        {"Кинопоиск", "https://www.kinopoisk.ru/", "белый список Минцифры", 0},
        {"РИА Новости", "https://ria.ru/", "белый список Минцифры", 0},
        {"ТАСС", "https://tass.ru/", "белый список Минцифры", 0},
        {"РБК", "https://www.rbc.ru/", "белый список Минцифры", 0},
        {"Лента.ру", "https://lenta.ru/", "белый список Минцифры", 0},
        {"Рувики", "https://ru.ruwiki.ru/", "белый список Минцифры", 0},
        {"Ozon", "https://www.ozon.ru/", "белый список Минцифры", 0},
        {"Wildberries", "https://www.wildberries.ru/", "белый список Минцифры", 0},
        {"Мегамаркет", "https://megamarket.ru/", "белый список Минцифры", 0},
        {"Avito", "https://www.avito.ru/", "белый список Минцифры", 0},
        {"Домклик", "https://domclick.ru/", "белый список Минцифры", 0},
        {"2ГИС", "https://2gis.ru/", "белый список Минцифры", 0},
        {"HH.ru", "https://hh.ru/", "белый список Минцифры", 0},
        {"РЖД", "https://www.rzd.ru/", "белый список Минцифры", 0},
        {"Туту.ру", "https://www.tutu.ru/", "белый список Минцифры", 0},
        {"Gismeteo", "https://www.gismeteo.ru/", "белый список Минцифры", 0},
        {"Сбербанк", "https://www.sberbank.ru/", "белый список Минцифры", 0},
        /* контроль: зарубежные (часть — ожидаемый блок в РФ) */
        {"Google", "https://www.google.com/", "", 0},
        {"Gmail", "https://mail.google.com/", "", 0},
        {"Microsoft", "https://www.microsoft.com/", "", 0},
        {"Microsoft Teams", "https://teams.microsoft.com/", "", 0},
        {"YouTube", "https://www.youtube.com/",
         "Ожидаемо: ограничен/блокируется в РФ — не проблема сети.", 1},
        {"Instagram", "https://www.instagram.com/",
         "Ожидаемо: запрещённая в РФ организация — не проблема сети.", 1},
        {"Facebook", "https://www.facebook.com/",
         "Ожидаемо: запрещённая в РФ организация — не проблема сети.", 1},
        {"X / Twitter", "https://x.com/",
         "Ожидаемо: ограничен в РФ — не проблема сети.", 1},
        {"Discord", "https://discord.com/",
         "Ожидаемо: часто режется в РФ — не проблема сети.", 1},
        {"Telegram", "https://web.telegram.org/",
         "Ожидаемо: ограничен/нестабилен в РФ — не проблема сети.", 1},
        {"Telegram.org", "https://telegram.org/",
         "Ожидаемо: ограничен в РФ — не проблема сети.", 1},
        {"WhatsApp", "https://web.whatsapp.com/",
         "Ожидаемо: Meta, часто ограничен в РФ — не проблема сети.", 1},
        {"Wikipedia", "https://ru.wikipedia.org/", "", 0},
        {"Cloudflare", "https://www.cloudflare.com/", "", 0},
    };
    static const struct { const char *name, *host; int port, crit; } gtcp[] = {
        {"Battle.net HTTPS", "battle.net", 443, 1},
        {"Blizzard.com HTTPS", "www.blizzard.com", 443, 1},
        {"Battle.net account", "account.battle.net", 443, 1},
        {"Battle.net OAuth", "oauth.battle.net", 443, 1},
        {"Battle.net EU", "eu.battle.net", 443, 1},
        {"Battle.net US", "us.battle.net", 443, 0},
        {"BNET version EU", "eu.version.battle.net", 443, 1},
        {"BNET download", "download.battle.net", 443, 0},
        {"BNET CDN Akamai", "blzddist1-a.akamaihd.net", 443, 0},
        {"BNET login :1119 EU", "eu.actual.battle.net", 1119, 1},
        {"BNET login :1119 US", "us.actual.battle.net", 1119, 0},
        {"BNET login :1119 KR", "kr.actual.battle.net", 1119, 0},
        {"Steam store :443", "store.steampowered.com", 443, 1},
        {"Steam API :443", "api.steampowered.com", 443, 1},
        {"Steam community :443", "steamcommunity.com", 443, 1},
        {"Steam CDN :443", "cdn.cloudflare.steamstatic.com", 443, 0},
        {"Steam media CDN", "media.steampowered.com", 443, 0},
        {"Epic Games :443", "www.epicgames.com", 443, 0},
        {"Epic launcher API", "launcher-public-service-prod06.ol.epicgames.com", 443, 0},
        {"Riot clientconfig", "clientconfig.rpg.riotgames.com", 443, 0},
        {"Riot auth", "auth.riotgames.com", 443, 0},
        {"Xbox Live", "xboxlive.com", 443, 0},
        {"PlayStation", "www.playstation.com", 443, 0},
        {"EA / Origin", "www.ea.com", 443, 0},
        {"Ubisoft Connect", "www.ubisoft.com", 443, 0},
        {"GOG", "www.gog.com", 443, 0},
        {"Faceit", "api.faceit.com", 443, 0},
    };
    /* Selectel: ru-1 ≈ СПб (Дубровка), ru-7 ≈ Москва (Берзарина). SFTP :22 — публично у SPB. */
    static const struct { const char *name, *host; int port, crit; } itcp[] = {
        {"Selectel SPb SFTP :22", "ftp.ru-1.storage.selcloud.ru", 22, 0},
        {"Selectel SPb S3 :80", "s3.ru-1.storage.selcloud.ru", 80, 0},
        {"Selectel SPb S3 :443", "s3.ru-1.storage.selcloud.ru", 443, 0},
        {"Selectel Мск S3 :80", "s3.ru-7.storage.selcloud.ru", 80, 0},
        {"Selectel Мск S3 :443", "s3.ru-7.storage.selcloud.ru", 443, 0},
        {"Selectel Мск API :443", "api.ru-7.storage.selcloud.ru", 443, 0},
        /* AWS TCP — региональные (глобальный s3.amazonaws.com из РФ часто рвёт TLS) */
        {"AWS S3 EU-Central :443", "s3.eu-central-1.amazonaws.com", 443, 0},
        {"AWS S3 EU-North :443", "s3.eu-north-1.amazonaws.com", 443, 0},
        {"AWS EC2 EU-Central :443", "ec2.eu-central-1.amazonaws.com", 443, 0},
        /* Azure */
        {"Azure portal :443", "portal.azure.com", 443, 0},
        {"Azure management :443", "management.azure.com", 443, 0},
        {"Azure login :443", "login.microsoftonline.com", 443, 0},
        {"Azure Blob East US :443", "eastus.blob.core.windows.net", 443, 0},
    };
    /* HTTPS-проверки облаков: 200/301/403 XML от S3 = сервис отвечает */
    static const struct { const char *name, *url; } ihttps[] = {
        {"AWS Health", "https://health.aws.amazon.com/health/status"},
        {"AWS Status", "https://status.aws.amazon.com/"},
        {"AWS S3 (landsat-pds)", "https://landsat-pds.s3.amazonaws.com/"},
        {"AWS S3 CDN (amazonlinux)", "https://cdn.amazonlinux.com/"},
    };
    static const struct { const char *name, *url; } ghttps[] = {
        {"Battle.net", "https://battle.net/"},
        {"Blizzard", "https://www.blizzard.com/"},
        {"Battle.net login", "https://account.battle.net/login/"},
        {"Battle.net support", "https://eu.battle.net/support/"},
        {"Steam Store", "https://store.steampowered.com/"},
        {"Steam Community", "https://steamcommunity.com/"},
        {"Steam API", "https://api.steampowered.com/ISteamWebAPIUtil/GetServerInfo/v1/"},
        {"Steam Help", "https://help.steampowered.com/"},
        {"Epic Games Store", "https://store.epicgames.com/"},
        {"Epic launcher", "https://launcher.store.epicgames.com/"},
        {"Riot Games", "https://www.riotgames.com/"},
        {"Xbox", "https://www.xbox.com/"},
        {"PlayStation Network", "https://www.playstation.com/"},
        {"EA App", "https://www.ea.com/ea-app"},
        {"Ubisoft Connect", "https://www.ubisoft.com/"},
        {"GOG Galaxy", "https://www.gog.com/"},
        {"Nintendo", "https://www.nintendo.com/"},
        {"Roblox", "https://www.roblox.com/"},
        {"Minecraft / Mojang", "https://www.minecraft.net/"},
        {"VK Play", "https://vkplay.ru/"},
        {"Lesta / Mir Tankov", "https://tanki.su/"},
    };
    static const struct { const char *name, *url; int crit; } ai[] = {
        {"Cursor", "https://www.cursor.com/", 1},
        {"Cursor API", "https://api2.cursor.sh/", 1},
        {"OpenAI", "https://openai.com/", 1},
        {"ChatGPT", "https://chatgpt.com/", 1},
        {"OpenAI API", "https://api.openai.com/", 1},
        {"Claude / Anthropic", "https://claude.ai/", 1},
        {"Anthropic API", "https://api.anthropic.com/", 1},
        {"Anthropic console", "https://console.anthropic.com/", 0},
        {"Grok / xAI", "https://grok.x.ai/", 1},
        {"xAI", "https://x.ai/", 0},
        {"xAI API", "https://api.x.ai/", 0},
        {"Gemini", "https://gemini.google.com/", 1},
        {"Google AI Studio", "https://aistudio.google.com/", 0},
        {"Google AI / Generative", "https://generativelanguage.googleapis.com/", 0},
        {"Microsoft Copilot", "https://copilot.microsoft.com/", 0},
        {"GitHub Copilot", "https://github.com/features/copilot", 0},
        {"Perplexity", "https://www.perplexity.ai/", 0},
        {"DeepSeek", "https://www.deepseek.com/", 0},
        {"DeepSeek Chat", "https://chat.deepseek.com/", 0},
        {"Mistral", "https://mistral.ai/", 0},
        {"Mistral Chat", "https://chat.mistral.ai/", 0},
        {"Hugging Face", "https://huggingface.co/", 0},
        {"Groq", "https://groq.com/", 0},
        {"Together AI", "https://www.together.ai/", 0},
        {"Poe", "https://poe.com/", 0},
        {"Notion AI", "https://www.notion.so/", 0},
        {"YandexGPT / Alice AI", "https://alice.yandex.ru/", 0},
        {"GigaChat", "https://giga.chat/", 0},
    };
    static const struct { const char *name, *home, *video; } vids[] = {
        {"Яндекс Видео", "https://ya.ru/video/", "https://ya.ru/video/search?text=news"},
        {"VK Видео", "https://vkvideo.ru/", "https://vkvideo.ru/sitemaps/sitemap-video-1.xml"},
        {"IVI", "https://www.ivi.ru/", "https://www.ivi.ru/watch/masha_i_medved"},
        {"Okko", "https://okko.tv/", "https://okko.tv/movie/avatar"},
        {"Rutube", "https://rutube.ru/", "https://rutube.ru/"},
    };
    static const struct { const char *cat, *name, *url; } banks[] = {
        {"Банки РФ", "Сбербанк", "https://www.sberbank.ru/"},
        {"Банки РФ", "СберБанк Онлайн", "https://online.sberbank.ru/"},
        {"Банки РФ", "Т-Банк", "https://www.tbank.ru/"},
        {"Банки РФ", "Т-Банк (tinkoff.ru)", "https://www.tinkoff.ru/"},
        {"Банки РФ", "ВТБ", "https://www.vtb.ru/"},
        {"Банки РФ", "Альфа-Банк", "https://alfabank.ru/"},
        {"Банки РФ", "Газпромбанк", "https://www.gazprombank.ru/"},
        {"Банки РФ", "Россельхозбанк", "https://rshb.ru/"},
        {"Банки РФ", "Совкомбанк", "https://sovcombank.ru/"},
        {"Банки РФ", "МТС Банк", "https://www.mtsbank.ru/"},
        {"Банки РФ", "Райффайзен", "https://www.raiffeisen.ru/"},
        {"Банки РФ", "ПСБ", "https://www.psbank.ru/"},
        {"Банки РФ", "Росбанк", "https://www.rosbank.ru/"},
        {"Сервисы РФ", "Mail.ru", "https://mail.ru/"},
        {"Сервисы РФ", "2ГИС", "https://2gis.ru/"},
        {"Сервисы РФ", "Wildberries", "https://www.wildberries.ru/"},
        {"Сервисы РФ", "Ozon", "https://www.ozon.ru/"},
        {"Сервисы РФ", "Avito", "https://www.avito.ru/"},
        {"Сервисы РФ", "HH.ru", "https://hh.ru/"},
        {"Сервисы РФ", "DNS Shop", "https://www.dns-shop.ru/"},
        {"Сервисы РФ", "ЦИАН", "https://www.cian.ru/"},
    };
    int i, n;

    n = (int)(sizeof sig / sizeof sig[0]);
    if (n > MAX_RES) n = MAX_RES;
    g_nsig = n;
    for (i = 0; i < n; i++) {
        snprintf(g_sig[i].name, sizeof g_sig[i].name, "%s", sig[i].name);
        snprintf(g_sig[i].url, sizeof g_sig[i].url, "%s", sig[i].url);
        snprintf(g_sig[i].note, sizeof g_sig[i].note, "%s", sig[i].note);
        g_sig[i].expected_block = sig[i].eb;
    }

    n = (int)(sizeof gtcp / sizeof gtcp[0]);
    if (n > MAX_RES) n = MAX_RES;
    g_ngame_tcp = n;
    for (i = 0; i < n; i++) {
        snprintf(g_game_tcp[i].name, sizeof g_game_tcp[i].name, "%s", gtcp[i].name);
        snprintf(g_game_tcp[i].host, sizeof g_game_tcp[i].host, "%s", gtcp[i].host);
        g_game_tcp[i].port = gtcp[i].port;
        g_game_tcp[i].crit = gtcp[i].crit;
    }

    n = (int)(sizeof itcp / sizeof itcp[0]);
    if (n > MAX_RES) n = MAX_RES;
    g_ninfra_tcp = n;
    for (i = 0; i < n; i++) {
        snprintf(g_infra_tcp[i].name, sizeof g_infra_tcp[i].name, "%s", itcp[i].name);
        snprintf(g_infra_tcp[i].host, sizeof g_infra_tcp[i].host, "%s", itcp[i].host);
        g_infra_tcp[i].port = itcp[i].port;
        g_infra_tcp[i].crit = itcp[i].crit;
    }

    n = (int)(sizeof ihttps / sizeof ihttps[0]);
    if (n > MAX_RES) n = MAX_RES;
    g_ninfra_https = n;
    for (i = 0; i < n; i++) {
        snprintf(g_infra_https[i].name, sizeof g_infra_https[i].name, "%s", ihttps[i].name);
        snprintf(g_infra_https[i].url, sizeof g_infra_https[i].url, "%s", ihttps[i].url);
    }

    n = (int)(sizeof ghttps / sizeof ghttps[0]);
    if (n > MAX_RES) n = MAX_RES;
    g_ngame_https = n;
    for (i = 0; i < n; i++) {
        snprintf(g_game_https[i].name, sizeof g_game_https[i].name, "%s", ghttps[i].name);
        snprintf(g_game_https[i].url, sizeof g_game_https[i].url, "%s", ghttps[i].url);
    }

    n = (int)(sizeof ai / sizeof ai[0]);
    if (n > MAX_RES) n = MAX_RES;
    g_nai = n;
    for (i = 0; i < n; i++) {
        snprintf(g_ai[i].name, sizeof g_ai[i].name, "%s", ai[i].name);
        snprintf(g_ai[i].url, sizeof g_ai[i].url, "%s", ai[i].url);
        g_ai[i].crit = ai[i].crit;
    }

    n = (int)(sizeof vids / sizeof vids[0]);
    if (n > MAX_RES) n = MAX_RES;
    g_nvideo = n;
    for (i = 0; i < n; i++) {
        snprintf(g_video[i].name, sizeof g_video[i].name, "%s", vids[i].name);
        snprintf(g_video[i].home, sizeof g_video[i].home, "%s", vids[i].home);
        snprintf(g_video[i].video, sizeof g_video[i].video, "%s", vids[i].video);
    }

    n = (int)(sizeof banks / sizeof banks[0]);
    if (n > MAX_RES) n = MAX_RES;
    g_nbanks = n;
    for (i = 0; i < n; i++) {
        snprintf(g_banks[i].cat, sizeof g_banks[i].cat, "%s", banks[i].cat);
        snprintf(g_banks[i].name, sizeof g_banks[i].name, "%s", banks[i].name);
        snprintf(g_banks[i].url, sizeof g_banks[i].url, "%s", banks[i].url);
    }
}

/*
 * Читает resources.conf. Непустые секции заменяют соответствующую группу.
 * Возвращает 1 если файл открылся, 0 если нет.
 */
static int resources_load_file(const char *path) {
    FILE *f;
    char line[1024];
    char section[64] = "";
    int got_sig = 0, got_gtcp = 0, got_itcp = 0, got_ihttps = 0, got_ghttps = 0, got_ai = 0, got_vid = 0, got_bank = 0;
    int nsig = 0, ngtcp = 0, nitcp = 0, nihttps = 0, nghttps = 0, nai = 0, nvid = 0, nbank = 0;
    ResSig sig[MAX_RES];
    ResTcp gtcp[MAX_RES];
    ResTcp itcp[MAX_RES];
    ResHttp ihttps[MAX_RES];
    ResHttp ghttps[MAX_RES];
    ResHttpCrit ai[MAX_RES];
    ResVideo vids[MAX_RES];
    ResBank banks[MAX_RES];

    if (!path || !path[0]) return 0;
    f = fopen(path, "r");
    if (!f) return 0;

    while (fgets(line, sizeof line, f)) {
        char *fields[8];
        int nf;
        str_trim(line);
        if (!line[0] || line[0] == '#') continue;
        if (line[0] == '[' && line[strlen(line) - 1] == ']') {
            size_t n = strlen(line) - 2;
            if (n >= sizeof section) n = sizeof section - 1;
            memcpy(section, line + 1, n);
            section[n] = 0;
            str_trim(section);
            continue;
        }
        nf = split_pipe(line, fields, 8);
        if (!section[0] || nf < 2) continue;

        if (strcmp(section, "significant") == 0 && nsig < MAX_RES) {
            snprintf(sig[nsig].name, sizeof sig[nsig].name, "%s", fields[0]);
            snprintf(sig[nsig].url, sizeof sig[nsig].url, "%s", fields[1]);
            snprintf(sig[nsig].note, sizeof sig[nsig].note, "%s", nf > 2 ? fields[2] : "");
            sig[nsig].expected_block = (nf > 3 && fields[3][0] == '1') ? 1 : 0;
            nsig++;
            got_sig = 1;
        } else if (strcmp(section, "games_tcp") == 0 && ngtcp < MAX_RES && nf >= 3) {
            snprintf(gtcp[ngtcp].name, sizeof gtcp[ngtcp].name, "%s", fields[0]);
            snprintf(gtcp[ngtcp].host, sizeof gtcp[ngtcp].host, "%s", fields[1]);
            gtcp[ngtcp].port = atoi(fields[2]);
            gtcp[ngtcp].crit = (nf > 3 && fields[3][0] == '1') ? 1 : 0;
            ngtcp++;
            got_gtcp = 1;
        } else if (strcmp(section, "infra_tcp") == 0 && nitcp < MAX_RES && nf >= 3) {
            snprintf(itcp[nitcp].name, sizeof itcp[nitcp].name, "%s", fields[0]);
            snprintf(itcp[nitcp].host, sizeof itcp[nitcp].host, "%s", fields[1]);
            itcp[nitcp].port = atoi(fields[2]);
            itcp[nitcp].crit = (nf > 3 && fields[3][0] == '1') ? 1 : 0;
            nitcp++;
            got_itcp = 1;
        } else if (strcmp(section, "infra_https") == 0 && nihttps < MAX_RES) {
            snprintf(ihttps[nihttps].name, sizeof ihttps[nihttps].name, "%s", fields[0]);
            snprintf(ihttps[nihttps].url, sizeof ihttps[nihttps].url, "%s", fields[1]);
            nihttps++;
            got_ihttps = 1;
        } else if (strcmp(section, "games_https") == 0 && nghttps < MAX_RES) {
            snprintf(ghttps[nghttps].name, sizeof ghttps[nghttps].name, "%s", fields[0]);
            snprintf(ghttps[nghttps].url, sizeof ghttps[nghttps].url, "%s", fields[1]);
            nghttps++;
            got_ghttps = 1;
        } else if (strcmp(section, "ai") == 0 && nai < MAX_RES) {
            snprintf(ai[nai].name, sizeof ai[nai].name, "%s", fields[0]);
            snprintf(ai[nai].url, sizeof ai[nai].url, "%s", fields[1]);
            ai[nai].crit = (nf > 2 && fields[2][0] == '1') ? 1 : 0;
            nai++;
            got_ai = 1;
        } else if (strcmp(section, "video") == 0 && nvid < MAX_RES && nf >= 3) {
            snprintf(vids[nvid].name, sizeof vids[nvid].name, "%s", fields[0]);
            snprintf(vids[nvid].home, sizeof vids[nvid].home, "%s", fields[1]);
            snprintf(vids[nvid].video, sizeof vids[nvid].video, "%s", fields[2]);
            nvid++;
            got_vid = 1;
        } else if (strcmp(section, "banks") == 0 && nbank < MAX_RES && nf >= 3) {
            snprintf(banks[nbank].cat, sizeof banks[nbank].cat, "%s", fields[0]);
            snprintf(banks[nbank].name, sizeof banks[nbank].name, "%s", fields[1]);
            snprintf(banks[nbank].url, sizeof banks[nbank].url, "%s", fields[2]);
            nbank++;
            got_bank = 1;
        }
    }
    fclose(f);

    if (got_sig) {
        memcpy(g_sig, sig, (size_t)nsig * sizeof sig[0]);
        g_nsig = nsig;
    }
    if (got_gtcp) {
        memcpy(g_game_tcp, gtcp, (size_t)ngtcp * sizeof gtcp[0]);
        g_ngame_tcp = ngtcp;
    }
    if (got_itcp) {
        memcpy(g_infra_tcp, itcp, (size_t)nitcp * sizeof itcp[0]);
        g_ninfra_tcp = nitcp;
    }
    if (got_ihttps) {
        memcpy(g_infra_https, ihttps, (size_t)nihttps * sizeof ihttps[0]);
        g_ninfra_https = nihttps;
    }
    if (got_ghttps) {
        memcpy(g_game_https, ghttps, (size_t)nghttps * sizeof ghttps[0]);
        g_ngame_https = nghttps;
    }
    if (got_ai) {
        memcpy(g_ai, ai, (size_t)nai * sizeof ai[0]);
        g_nai = nai;
    }
    if (got_vid) {
        memcpy(g_video, vids, (size_t)nvid * sizeof vids[0]);
        g_nvideo = nvid;
    }
    if (got_bank) {
        memcpy(g_banks, banks, (size_t)nbank * sizeof banks[0]);
        g_nbanks = nbank;
    }
    return 1;
}

/*
 * Порядок:
 *  1) --resources FILE
 *  2) resources.conf рядом с exe
 *  3) resources.conf в cwd
 *  иначе — встроенные списки
 */
static void resources_init(void) {
    char try1[STR];

    resources_load_defaults();
    g_resources_from_file = 0;

    if (resources_path[0]) {
        if (resources_load_file(resources_path))
            g_resources_from_file = 1;
        return;
    }

    if (exe_dir[0]) {
        snprintf(try1, sizeof try1, "%s/resources.conf", exe_dir);
        if (resources_load_file(try1)) {
            g_resources_from_file = 1;
            return;
        }
#ifdef _WIN32
        snprintf(try1, sizeof try1, "%s\\resources.conf", exe_dir);
        if (resources_load_file(try1)) {
            g_resources_from_file = 1;
            return;
        }
#endif
    }
    if (resources_load_file("resources.conf"))
        g_resources_from_file = 1;
}

/* ---------- HTML ---------- */

static const char *status_label(const char *st) {
    if (strcmp(st, "ok") == 0) return "OK";
    if (strcmp(st, "warn") == 0) return "Внимание";
    if (strcmp(st, "fail") == 0) return "Сбой";
    return "Инфо";
}

static void write_html(void) {
    FILE *f;
    int i;
    const char *prev_cat = "";
    char wifi_line[256];
    char dns_line[256];
    int di;

    f = fopen(report_path, "wb");
    if (!f) {
        fprintf(stderr, "Не удалось записать %s\n", report_path);
        return;
    }
    /* UTF-8 BOM for Windows Notepad */
    fputs("\xEF\xBB\xBF", f);

    if (wifi_ssid[0] || wifi_channel >= 0)
        snprintf(wifi_line, sizeof wifi_line, "%s · ch=%d · signal=%d%%",
                 wifi_ssid[0] ? wifi_ssid : "?", wifi_channel, wifi_signal);
    else
        snprintf(wifi_line, sizeof wifi_line, "не Wi-Fi / нет данных");

    dns_line[0] = 0;
    for (di = 0; di < ndns; di++) {
        if (di) strncat(dns_line, ", ", sizeof dns_line - strlen(dns_line) - 1);
        strncat(dns_line, dns_list[di], sizeof dns_line - strlen(dns_line) - 1);
    }

    fprintf(f,
        "<!DOCTYPE html>\n<html lang=\"ru\"><head><meta charset=\"utf-8\"/>"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"/>"
        "<meta name=\"generator\" content=\"connect-check %s\"/>"
        "<title>Диагностика интернета — connect-check %s — %s</title>\n"
        "<style>\n"
        ":root{--bg:#0f1419;--panel:#1a222c;--text:#e7ecf1;--muted:#8b9aab;"
        "--ok:#3dd68c;--warn:#f5a524;--fail:#f31260;--info:#66b3ff;--line:#2a3542}\n"
        "*{box-sizing:border-box}body{margin:0;font-family:\"Segoe UI\",system-ui,sans-serif;"
        "background:radial-gradient(1200px 600px at 10%% -10%%,#1a2a3a 0%%,var(--bg) 55%%);"
        "color:var(--text);line-height:1.45;padding:24px}\n"
        "h1{font-size:1.5rem;margin:0 0 4px;font-weight:650}.sub{color:var(--muted);margin-bottom:20px}\n"
        ".cards{display:flex;flex-wrap:wrap;gap:12px;margin-bottom:20px}\n"
        ".card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px 16px;min-width:120px}\n"
        ".card .n{font-size:1.6rem;font-weight:700}.card .l{color:var(--muted);font-size:.85rem}\n"
        ".card.ok .n{color:var(--ok)}.card.warn .n{color:var(--warn)}.card.fail .n{color:var(--fail)}\n"
        ".finding{border-radius:12px;padding:14px 16px;margin-bottom:10px;border:1px solid var(--line);background:var(--panel)}\n"
        ".finding.critical{border-left:4px solid var(--fail)}.finding.warning{border-left:4px solid var(--warn)}"
        ".finding.info{border-left:4px solid var(--info)}.finding p{margin:6px 0 0;color:var(--muted)}\n"
        ".problems{margin-bottom:18px}.prob{display:flex;flex-wrap:wrap;gap:8px 12px;align-items:baseline;"
        "border-radius:12px;padding:12px 14px;margin-bottom:8px;border:1px solid var(--line);background:var(--panel)}\n"
        ".prob.fail{border-left:4px solid var(--fail)}.prob.warn{border-left:4px solid var(--warn)}\n"
        ".prob .meta{color:var(--muted);font-size:.85rem;flex:1 1 180px}.prob .det{color:var(--muted);font-size:.9rem;"
        "flex:2 1 240px;min-width:0;word-break:break-word}\n"
        "a.jumplink{color:var(--info);text-decoration:none;font-weight:650;white-space:nowrap}"
        "a.jumplink:hover{text-decoration:underline}\n"
        "tr.target-hl>td{background:#2a2418!important;box-shadow:inset 0 0 0 2px var(--warn)}\n"
        "table{width:100%%;border-collapse:collapse;background:var(--panel);border-radius:12px;overflow:hidden;border:1px solid var(--line)}\n"
        "th,td{text-align:left;padding:10px 12px;vertical-align:top;border-bottom:1px solid var(--line)}\n"
        "th{color:var(--muted);font-size:.8rem;font-weight:600;text-transform:uppercase;letter-spacing:.04em}\n"
        "tr.cat td{background:#121820;color:var(--info);font-weight:600}\n"
        ".badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:.75rem;font-weight:650;background:#243040}\n"
        "tr.ok .badge{color:var(--ok)}tr.warn .badge{color:var(--warn)}tr.fail .badge{color:var(--fail)}tr.info .badge{color:var(--info)}\n"
        ".hint{margin-top:6px;color:var(--warn);font-size:.88rem}.hintcol{color:var(--muted);font-size:.85rem;max-width:320px}\n"
        "@media(max-width:800px){.hintcol{display:none}}\n"
        "details.spoiler{margin:8px 0;border:1px solid var(--line);border-radius:10px;background:#121820;padding:8px 12px}\n"
        "details.spoiler>summary{cursor:pointer;color:var(--info);font-weight:600;user-select:none}\n"
        "details.diag{margin-top:6px;font-size:.85rem;color:var(--muted)}\n"
        "details.diag summary{cursor:pointer;color:var(--muted)}\n"
        ".copyrow{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-top:4px}\n"
        ".copyrow code{background:#0c1015;padding:2px 8px;border-radius:4px;word-break:break-all}\n"
        "button.copy{background:#243040;border:1px solid var(--line);color:var(--text);border-radius:6px;"
        "padding:2px 8px;font-size:.75rem;cursor:pointer}\n"
        "button.copy:hover{border-color:var(--info)}\n"
        ".howto{margin-top:22px;padding:16px;border-radius:12px;background:var(--panel);border:1px solid var(--line);color:var(--muted)}\n"
        ".howto h2{color:var(--text);font-size:1.1rem;margin:0 0 8px}code{background:#0c1015;padding:1px 6px;border-radius:4px}\n"
        "</style>\n"
        "<script>\n"
        "async function copyText(t,btn){try{await navigator.clipboard.writeText(t);"
        "if(btn){const o=btn.textContent;btn.textContent='Скопировано';setTimeout(()=>btn.textContent=o,1200)}}"
        "catch(e){prompt('Скопируйте:',t)}}\n"
        "function revealTarget(){const id=location.hash.slice(1);if(!id)return;"
        "const el=document.getElementById(id);if(!el)return;"
        "let p=el.parentElement;while(p){if(p.tagName==='DETAILS')p.open=true;p=p.parentElement}"
        "document.querySelectorAll('tr.target-hl').forEach(r=>r.classList.remove('target-hl'));"
        "el.classList.add('target-hl');"
        "setTimeout(()=>el.scrollIntoView({behavior:'smooth',block:'center'}),30)}\n"
        "window.addEventListener('hashchange',revealTarget);"
        "window.addEventListener('DOMContentLoaded',revealTarget);\n"
        "</script></head><body>\n",
        CONNECT_CHECK_VERSION, CONNECT_CHECK_VERSION, stamp);

    fputs("<h1>Диагностика интернета</h1>\n<div class=\"sub\">Сгенерировано версией connect-check ", f);
    html_esc(f, CONNECT_CHECK_VERSION);
    fputs(" · ", f);
    html_esc(f, generated);
    fputs(" · локальный IP: ", f); html_esc(f, local_ip[0] ? local_ip : "—");
    fputs(" · внешний IP: ", f); html_esc(f, external_ip[0] ? external_ip : "—");
    fputs(" · шлюз: ", f); html_esc(f, gateway);
    fputs(" · Wi‑Fi: ", f); html_esc(f, wifi_line);
    fputs(" · DNS: ", f); html_esc(f, dns_line);
    fputs("</div>\n", f);

    fprintf(f,
        "<div class=\"cards\">"
        "<div class=\"card ok\"><div class=\"n\">%d</div><div class=\"l\">OK</div></div>"
        "<div class=\"card warn\"><div class=\"n\">%d</div><div class=\"l\">Внимание</div></div>"
        "<div class=\"card fail\"><div class=\"n\">%d</div><div class=\"l\">Сбои</div></div>"
        "</div>\n", ok_n, warn_n, fail_n);

    /* Проблемы сверху — все fail/warn со ссылкой на строку проверки */
    {
        int nprob = 0;
        fputs("<div class=\"problems\"><h2 style=\"font-size:1.15rem;margin:0 0 10px\">Проблемы</h2>\n", f);
        for (i = 0; i < nchecks; i++) {
            Check *c = &checks[i];
            const char *cls;
            if (strcmp(c->status, "fail") != 0 && strcmp(c->status, "warn") != 0)
                continue;
            nprob++;
            cls = strcmp(c->status, "fail") == 0 ? "fail" : "warn";
            fprintf(f, "<div class=\"prob %s\"><span class=\"badge\">%s</span>"
                       "<span class=\"meta\">", cls, status_label(c->status));
            html_esc(f, c->category);
            fputs(" · ", f);
            html_esc(f, c->name);
            fputs("</span><span class=\"det\">", f);
            html_esc(f, c->detail[0] ? c->detail : (c->hint[0] ? c->hint : "—"));
            fprintf(f, "</span><a class=\"jumplink\" href=\"#c%d\">к проверке →</a></div>\n", i);
        }
        if (nprob == 0)
            fputs("<div class=\"finding info\"><strong>Проблем не найдено</strong>"
                  "<p>Сбои и предупреждения отсутствуют (ожидаемые блокировки в РФ не считаются).</p></div>\n", f);
        fputs("</div>\n", f);
    }

    fputs("<h2 style=\"font-size:1.1rem;margin:0 0 10px\">Выводы</h2>\n", f);
    for (i = 0; i < nfindings; i++) {
        fprintf(f, "<div class=\"finding %s\"><strong>", findings[i].level);
        html_esc(f, findings[i].title);
        fputs("</strong><p>", f);
        html_esc(f, findings[i].text);
        fputs("</p></div>\n", f);
    }

    fputs("<h2 id=\"checks\" style=\"font-size:1.1rem;margin:18px 0 10px\">Проверки</h2>\n"
          "<table><thead><tr><th>Проверка</th><th>Статус</th><th>Детали</th><th>Что делать</th></tr></thead><tbody>\n", f);

    {
        int in_spoiler = 0;
        int spoiler_count = 0;
        for (i = 0; i < nchecks; i++) {
            Check *c = &checks[i];
            int cat_spoiler = 0;
            int j, cat_n = 0;
            if (strcmp(c->category, prev_cat) != 0) {
                if (in_spoiler) {
                    fputs("</tbody></table></details>\n", f);
                    in_spoiler = 0;
                }
                for (j = i; j < nchecks && strcmp(checks[j].category, c->category) == 0; j++) {
                    cat_n++;
                    if (checks[j].spoiler) cat_spoiler = 1;
                }
                /* long IoT / popular lists → fold */
                if (cat_spoiler || cat_n >= 12 ||
                    strcmp(c->category, "Умный дом / IoT") == 0 ||
                    strcmp(c->category, "Значимые ресурсы") == 0) {
                    fputs("<tr class=\"cat\"><td colspan=\"4\">", f);
                    html_esc(f, c->category);
                    fprintf(f, " <span style=\"color:var(--muted);font-weight:400\">(%d)</span></td></tr>\n", cat_n);
                    fputs("<tr><td colspan=\"4\">", f);
                    fputs("<details class=\"spoiler\"><summary>Показать все проверки раздела</summary>\n"
                          "<table style=\"width:100%;border:0;background:transparent\"><tbody>\n", f);
                    in_spoiler = 1;
                    spoiler_count++;
                } else {
                    fputs("<tr class=\"cat\"><td colspan=\"4\">", f);
                    html_esc(f, c->category);
                    fputs("</td></tr>\n", f);
                }
                prev_cat = c->category;
            }
            fprintf(f, "<tr id=\"c%d\" class=\"%s\"><td>", i, c->status);
            html_esc(f, c->name);
            fprintf(f, "</td><td><span class=\"badge\">%s</span></td><td>", status_label(c->status));
            html_esc(f, c->detail);
            if (c->hint[0]) {
                fputs("<div class=\"hint\">", f);
                html_esc(f, c->hint);
                fputs("</div>", f);
            }
            if (c->resolved_ip[0] || c->diag_url[0]) {
                int captive_row = (strcmp(c->category, "Captive / OS") == 0);
                fprintf(f, "<details class=\"diag\"%s><summary>SNI / IP / URL</summary><div class=\"copyrow\">",
                        captive_row ? " open" : "");
                if (c->diag_url[0]) {
                    char hostbuf[128];
                    const char *p = c->diag_url;
                    hostbuf[0] = 0;
                    if (starts_with(p, "https://")) p += 8;
                    else if (starts_with(p, "http://")) p += 7;
                    {
                        size_t hi = 0;
                        while (p[hi] && p[hi] != '/' && p[hi] != ':' && p[hi] != '?' && hi + 1 < sizeof hostbuf) {
                            hostbuf[hi] = p[hi];
                            hi++;
                        }
                        hostbuf[hi] = 0;
                    }
                    if (hostbuf[0]) {
                        fputs("<span>SNI: <code>", f);
                        html_esc(f, hostbuf);
                        fputs("</code> <button type=\"button\" class=\"copy\" onclick=\"copyText('", f);
                        html_esc(f, hostbuf);
                        fputs("',this)\">копировать</button></span>", f);
                    }
                }
                if (c->resolved_ip[0]) {
                    fputs("<span>IP: <code>", f);
                    html_esc(f, c->resolved_ip);
                    fputs("</code> <button type=\"button\" class=\"copy\" onclick=\"copyText('", f);
                    html_esc(f, c->resolved_ip);
                    fputs("',this)\">копировать</button></span>", f);
                }
                if (c->diag_url[0]) {
                    fputs("<span>URL: <code>", f);
                    html_esc(f, c->diag_url);
                    fputs("</code> <button type=\"button\" class=\"copy\" onclick=\"copyText('", f);
                    html_esc(f, c->diag_url);
                    fputs("',this)\">копировать</button></span>", f);
                }
                fputs("</div></details>", f);
            }
            fputs("</td><td class=\"hintcol\">", f);
            html_esc(f, c->hint);
            fputs("</td></tr>\n", f);
        }
        if (in_spoiler) fputs("</tbody></table></details></td></tr>\n", f);
        (void)spoiler_count;
    }

    fputs(
        "</tbody></table>\n"
        "<div class=\"howto\"><h2>Как читать отчёт</h2><ul>"
        "<li><strong>Выводы сверху</strong> — сначала смотрите блоки finding (critical / warning / info), "
        "потом таблицы по разделам.</li>"
        "<li><strong>Captive / OS</strong> — URL, по которым телефон/ПК решают «есть ли интернет». "
        "Для Android важен HTTP <code>204</code> без редиректа на gstatic/OEM.</li>"
        "<li><strong>Private DNS / DoT / DoH</strong> — DoT это DNS поверх TLS на TCP/<code>853</code>; "
        "DoH — тот же DNS, но через HTTPS (обычно <code>443</code>). "
        "Сети часто режут одно и оставляют другое: если DoH падает, а DoT открыт — на клиентах "
        "ставьте Private DNS с именем хоста (DoT), а не DoH-приложения; наоборот — выключите "
        "Private DNS «Автоматически», обычный DNS роутера и при необходимости DoH в браузере.</li>"
        "<li><strong>Умный дом / IoT</strong> — облака и MQTT (:443 / :8883); браузер может жить, а Tuya/Алиса — нет.</li>"
        "<li><strong>Игры / AI / Видео</strong> — отдельные контуры (Battle.net, LLM API, видеохостинги РФ).</li>"
        "<li><strong>DPI</strong> — служебные порты, DoH, SNI, QUIC. Живой HTTPS к ya.ru не значит, что MQTT/QUIC/DoH тоже живы.</li>"
        "<li><strong>DNS-прогон</strong> — массовый резолв через DNS РФ и публичные резолверы.</li>"
        "<li><strong>NTP</strong> — кривое время ломает TLS на IoT и TV.</li>"
        "<li><strong>DFS</strong> — Wi‑Fi каналы 52–64 и 100–144 дают краткие обрывы; стабильнее 36/40/44/48.</li>"
        "<li>Запускайте с той же Wi‑Fi/VLAN, что и проблемные клиенты.</li>"
        "</ul>"
        "<p style=\"margin:14px 0 0\">Отчёт сгенерирован <code>connect-check</code> "
        "(connect-check ", f);
    html_esc(f, CONNECT_CHECK_VERSION);
    fputs(").</p></div></body></html>\n", f);
    fclose(f);
}

/* ---------- main diagnostics ---------- */

static void host_from_url(const char *url, char *host, size_t hostlen) {
    const char *p = url;
    host[0] = 0;
    if (starts_with(p, "https://")) p += 8;
    else if (starts_with(p, "http://")) p += 7;
    snprintf(host, hostlen, "%s", p);
    {
        char *slash = strchr(host, '/');
        if (slash) *slash = 0;
        slash = strchr(host, ':');
        if (slash) *slash = 0;
        slash = strchr(host, '?');
        if (slash) *slash = 0;
    }
}

static void check_captive(const char *name, const char *url, int expect, int critical) {
    /* Captive: НЕ follow — 301/302 = портал/подмена */
    HttpResult r = http_probe_nofollow(url, 5, 0);
    char detail[STR], hint[STR], host[128], ip[64];
    const char *st;

    host_from_url(url, host, sizeof host);
    ip[0] = 0;
    if (host[0]) dns_resolve(host, ip, sizeof ip);

    /* Без резолва HTTP-ошибка — не «captive/нет интернета», а DNS */
    if (host_unresolved(host, ip) && r.code != expect && !r.redirect[0]) {
        snprintf(detail, sizeof detail, "SNI %s · DNS не резолвит имя", host);
        add_check_ex("Captive / OS", name, "warn", detail,
                     "Имя не резолвится — это не доказательство captive portal / «нет интернета».",
                     NULL, url, 0);
        return;
    }

    if (r.redirect[0]) {
        snprintf(detail, sizeof detail, "SNI %s · редирект → %s (HTTP %d)",
                 host[0] ? host : "?", r.redirect, r.code);
        add_check_ex("Captive / OS", name, "fail", detail,
                     "Captive portal или подмена HTTP.", ip, url, 0);
        if (critical) {
            char t[256], tx[LONGSTR];
            snprintf(t, sizeof t, "Подмена %s", name);
            snprintf(tx, sizeof tx, "Запрос к %s уходит на редирект. Проверьте Hotspot/Web-proxy на MikroTik.", url);
            add_finding("critical", t, tx);
        }
        return;
    }
    if (r.code == expect) {
        st = (r.ms > 1500) ? "warn" : "ok";
        snprintf(detail, sizeof detail, "SNI %s · HTTP %d, %d ms",
                 host[0] ? host : "?", r.code, r.ms);
        hint[0] = 0;
        if (r.ms > 1500)
            snprintf(hint, sizeof hint, "Медленный ответ — ОС может решить, что интернета нет");
        add_check_ex("Captive / OS", name, st, detail, hint, ip, url, 0);
        return;
    }
    /* ipv6.msftconnecttest.com — только AAAA: на IPv4-only это не сбой сети */
    if (host[0] && !dns_has_ipv4(host) && r.code != expect) {
        snprintf(detail, sizeof detail, "SNI %s · %s (хост без A-записи)",
                 host, r.error[0] ? r.error : "нет ответа");
        add_check_ex("Captive / OS", name, "info", detail,
                     "Проверка только по IPv6. На сети без IPv6 ожидаемо недоступна — не проблема.",
                     ip, url, 0);
        return;
    }
    if (r.error[0])
        snprintf(detail, sizeof detail, "SNI %s · %s", host[0] ? host : "?", r.error);
    else
        snprintf(detail, sizeof detail, "SNI %s · HTTP %d, %d ms",
                 host[0] ? host : "?", r.code, r.ms);
    add_check_ex("Captive / OS", name, "fail", detail,
                 "URL проверки связности ОС/устройства.", ip, url, 0);
    if (critical) {
        char t[256], tx[LONGSTR];
        snprintf(t, sizeof t, "Не проходит %s", name);
        snprintf(tx, sizeof tx, "%s — %s", url, detail);
        add_finding("critical", t, tx);
    }
}

static void check_ru(const char *cat, const char *name, const char *url,
                     const char *note, int spoiler, int multi_ua,
                     char fail_names[][64], int *nfail,
                     char slow_names[][80], int *nslow) {
    char ua_sum[256];
    int ua_mismatch = 0;
    HttpResult r;
    char detail[STR], hint[STR], host[128], ip[64];
    const char *st;

    /*
     * Значимые/банки: один UA и больший таймаут.
     * Раньше 5 UA × 3 с на LibreSSL давали ложные FAIL на госуслугах и др.
     */
    if (multi_ua)
        r = http_probe_agents(url, 8, 1, ua_sum, sizeof ua_sum, &ua_mismatch);
    else {
        r = http_probe_ua(url, 12, 1, ua_default(), 1);
        if (r.code > 0)
            snprintf(ua_sum, sizeof ua_sum, "chrome=%d", r.code);
        else
            snprintf(ua_sum, sizeof ua_sum, "chrome=нет ответа");
        ua_mismatch = 0;
    }

    host_from_url(url, host, sizeof host);
    ip[0] = 0;
    if (host[0]) dns_resolve(host, ip, sizeof ip);

    if (r.code <= 0 && host_unresolved(host, ip)) {
        snprintf(detail, sizeof detail, "DNS не резолвит %s", host);
        add_check_ex(cat, name, "warn", detail,
                     "Имя не резолвится — это сбой DNS, а не недоступность ресурса.",
                     NULL, url, spoiler);
        return;
    }

    if (r.code <= 0) {
        snprintf(detail, sizeof detail, "%s [%s]",
                 r.error[0] ? r.error : "таймаут/нет ответа", ua_sum[0] ? ua_sum : "—");
        snprintf(hint, sizeof hint, "%s%sНедоступен по HTTPS-пробе (браузер может работать при другом маршруте/QUIC).",
                 note && note[0] ? note : "", note && note[0] ? " " : "");
        add_check_ex(cat, name, "fail", detail, hint, ip, url, spoiler);
        if (*nfail < 40) snprintf(fail_names[(*nfail)++], 64, "%s", name);
        return;
    }
    if (r.redirect[0])
        snprintf(detail, sizeof detail, "HTTP %d (финал ← %s), %d ms [%s]",
                 r.code, r.redirect, r.ms, ua_sum);
    else
        snprintf(detail, sizeof detail, "HTTP %d, %d ms [%s]", r.code, r.ms, ua_sum);

    /* 3xx — сервер ответил редиректом, это не «ресурс недоступен» */
    if (r.code >= 300 && r.code < 400) {
        add_check_ex(cat, name, "ok", detail,
                     "HTTP-редирект (301/302/…): хост отвечает. Не считаем сбоем доступности.",
                     ip, url, spoiler);
        return;
    }
    if (r.code >= 500) {
        add_check_ex(cat, name, "fail", detail,
                     "Сервер отвечает 5xx.", ip, url, spoiler);
        if (*nfail < 40) snprintf(fail_names[(*nfail)++], 64, "%s", name);
        return;
    }
    st = "ok";
    hint[0] = 0;
    if (note && note[0]) snprintf(hint, sizeof hint, "%s", note);
    if (ua_mismatch) {
        st = "warn";
        snprintf(hint, sizeof hint,
                 "%s%sОтвет зависит от User-Agent (win/mac/android/tv/embed).",
                 note && note[0] ? note : "", note && note[0] ? " " : "");
    }
    if (r.ms > 3000) {
        st = "warn";
        snprintf(hint, sizeof hint, "%s%sМедленный ответ (>3000 ms).",
                 note && note[0] ? note : "", note && note[0] ? " " : "");
        if (*nslow < 40) snprintf(slow_names[(*nslow)++], 80, "%s %dms", name, r.ms);
    }
    add_check_ex(cat, name, st, detail, hint, ip, url, spoiler);
}

static void usage(const char *argv0) {
    fprintf(stderr,
        "Usage: %s [options]\n"
        "  --version, -V          версия (connect-check %s)\n"
        "  --no-open              не открывать HTML\n"
        "  -o DIR                 каталог отчёта\n"
        "  -y, --yes              без вопросов (DNS-прогон по умолчанию пропускается)\n"
        "  --dns-bulk             принудительно запустить DNS-прогон (в т.ч. с -y)\n"
        "  --skip-dns-bulk        не предлагать DNS-прогон\n"
        "  --skip-speed           пропустить замер скорости\n"
        "  --skip-video           пропустить скрытую проверку видео\n"
        "  --dns-limit N          доменов на резолвер (по умолчанию 1000, макс. 10000)\n"
        "  --domains FILE         свой список доменов (иначе файл или встроенный)\n"
        "  --resources FILE       списки ресурсов по группам (иначе resources.conf рядом)\n"
        "Клавиши на этапах: Enter — далее/запустить, Space — пропустить (без эха).\n",
        argv0, CONNECT_CHECK_VERSION);
}

int main(int argc, char **argv) {
    int i;
    time_t now;
    struct tm *tm;
    char dns_extra[][16] = {"1.1.1.1", "8.8.8.8", "9.9.9.9"};
    char fail_names[40][64];
    char slow_names[40][80];
    int nfail = 0, nslow = 0;
    int any_dot_closed = 0;
    int loss;
    double avg;
    char detail[STR];
    const char *st;
    char mt[256];
    int mt_n = 0;
    int flaky_ok = 0, flaky_fail = 0, flaky_sum = 0;

    setvbuf(stdout, NULL, _IONBF, 0);

#ifdef _WIN32
    WSADATA wsa;
    SetConsoleOutputCP(65001);
    SetConsoleCP(65001);
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }
#endif
    atexit(term_restore);

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--no-open") == 0) no_open = 1;
        else if (strcmp(argv[i], "-V") == 0 || strcmp(argv[i], "--version") == 0) {
            printf("connect-check %s\n", CONNECT_CHECK_VERSION);
            return 0;
        }
        else if (strcmp(argv[i], "-y") == 0 || strcmp(argv[i], "--yes") == 0) opt_yes = 1;
        else if (strcmp(argv[i], "--dns-bulk") == 0) opt_force_dns_bulk = 1;
        else if (strcmp(argv[i], "--skip-dns-bulk") == 0) opt_skip_dns_bulk = 1;
        else if (strcmp(argv[i], "--skip-speed") == 0) opt_skip_speed = 1;
        else if (strcmp(argv[i], "--skip-video") == 0) opt_skip_video = 1;
        else if ((strcmp(argv[i], "--dns-limit") == 0) && i + 1 < argc) {
            opt_dns_limit = atoi(argv[++i]);
            if (opt_dns_limit < 1) opt_dns_limit = 1;
            if (opt_dns_limit > MAX_DOMAINS) opt_dns_limit = MAX_DOMAINS;
        } else if ((strcmp(argv[i], "--domains") == 0) && i + 1 < argc)
            snprintf(domains_path, sizeof domains_path, "%s", argv[++i]);
        else if ((strcmp(argv[i], "--resources") == 0) && i + 1 < argc)
            snprintf(resources_path, sizeof resources_path, "%s", argv[++i]);
        else if ((strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--output-dir") == 0) && i + 1 < argc)
            snprintf(output_dir, sizeof output_dir, "%s", argv[++i]);
        else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "Unknown arg: %s\n", argv[i]);
            usage(argv[0]);
            return 2;
        }
    }

#ifdef _WIN32
    {
        char exe[MAX_PATH];
        char *slash;
        GetModuleFileNameA(NULL, exe, MAX_PATH);
        slash = strrchr(exe, '\\');
        if (slash) *slash = 0;
        snprintf(exe_dir, sizeof exe_dir, "%s", exe);
        if (!output_dir[0])
            snprintf(output_dir, sizeof output_dir, "%s\\reports", exe);
    }
#else
    {
        char *slash = strrchr(argv[0], '/');
        if (slash) {
            size_t n = (size_t)(slash - argv[0]);
            if (n >= sizeof exe_dir) n = sizeof exe_dir - 1;
            memcpy(exe_dir, argv[0], n);
            exe_dir[n] = 0;
        } else {
            snprintf(exe_dir, sizeof exe_dir, ".");
        }
        if (!output_dir[0])
            snprintf(output_dir, sizeof output_dir, "reports");
    }
#endif

    resources_init();

#ifdef _WIN32
    CreateDirectoryA(output_dir, NULL);
#else
    {
        char cmd[STR];
        snprintf(cmd, sizeof cmd, "mkdir -p '%s'", output_dir);
        system(cmd);
    }
#endif

    now = time(NULL);
    tm = localtime(&now);
    strftime(stamp, sizeof stamp, "%Y%m%d_%H%M%S", tm);
    strftime(generated, sizeof generated, "%Y-%m-%d %H:%M:%S", tm);
#ifdef _WIN32
    snprintf(report_path, sizeof report_path, "%s\\net_diag_%s.html", output_dir, stamp);
#else
    snprintf(report_path, sizeof report_path, "%s/net_diag_%s.html", output_dir, stamp);
#endif

    printf("Диагностика интернета (connect-check %s) — сбор данных...\n", CONNECT_CHECK_VERSION);
    printf("Клавиши: Enter — далее, Space — пропустить (DNS: Enter — запустить, иначе пропуск).\n");
    if (opt_yes) printf("Режим -y: без вопросов; DNS-прогон пропускается (нужен --dns-bulk).\n");

    printf("\n▶ Сеть и Wi‑Fi\n");
    stage_progress("локальная сеть", 1, 6);
    detect_network();
    stage_progress("Wi‑Fi", 2, 6);
    detect_wifi();

    add_check("Сеть", "Локальный IPv4", local_ip[0] ? "ok" : "fail",
              local_ip[0] ? local_ip : "не найден", "");
    add_check("Сеть", "Шлюз", gateway[0] ? "ok" : "fail",
              gateway[0] ? gateway : "не найден", "");
    {
        char dnsbuf[256] = "";
        for (i = 0; i < ndns; i++) {
            if (i) strcat(dnsbuf, ", ");
            strcat(dnsbuf, dns_list[i]);
        }
        add_check("Сеть", "DNS", ndns ? "info" : "warn", ndns ? dnsbuf : "пусто", "");
    }

    if (wifi_ssid[0]) {
        add_check("Wi‑Fi", "SSID", "info", wifi_ssid, "");
        if (wifi_signal >= 0) {
            st = wifi_signal >= 70 ? "ok" : (wifi_signal >= 50 ? "warn" : "fail");
            snprintf(detail, sizeof detail, "%d%%", wifi_signal);
            add_check("Wi‑Fi", "Уровень сигнала", st, detail,
                      strcmp(st, "ok") ? "Слабый сигнал — обрывы и ложные сбои связности" : "");
        }
        if (wifi_radio[0]) add_check("Wi‑Fi", "Radio", "info", wifi_radio, "");
        if (wifi_channel >= 0) {
            int is_dfs = (wifi_channel >= 52 && wifi_channel <= 64) ||
                         (wifi_channel >= 100 && wifi_channel <= 144);
            snprintf(detail, sizeof detail, "канал %d%s%s", wifi_channel,
                     wifi_channel <= 14 ? " (2.4 GHz)" : " (5 GHz)",
                     is_dfs ? " — DFS" : "");
            if (is_dfs) {
                add_check("Wi‑Fi", "Канал", "warn", detail,
                          "DFS: при «радаре» AP замолкает. Смените на 36/40/44/48.");
                snprintf(detail, sizeof detail, "Wi‑Fi на DFS-канале %d", wifi_channel);
                add_finding("critical", detail,
                            "Точка на DFS-канале. AP может кратковременно отключать Wi‑Fi. "
                            "Смените канал на 36, 40, 44 или 48.");
            } else {
                add_check("Wi‑Fi", "Канал", "ok", detail, "");
            }
        }
    } else {
        add_check("Wi‑Fi", "Статус", "info",
                  "Нет данных Wi‑Fi. Запускайте с той же сети, что и проблемные устройства.", "");
    }

    if (gateway[0]) {
        stage_progress("ping шлюза", 3, 6);
        ping_summary(gateway, 10, &loss, &avg);
        st = loss == 0 ? "ok" : (loss < 20 ? "warn" : "fail");
        snprintf(detail, sizeof detail, "loss=%d%%, avg=%.1f ms", loss, avg);
        add_check("Связность", "Ping шлюза", st, detail,
                  strcmp(st, "ok") ? "Потери до шлюза = проблема Wi‑Fi/кабеля/AP" : "");
        if (loss >= 10) {
            snprintf(detail, sizeof detail, "Loss %d%% до %s — клиенты на Wi‑Fi теряют связность.",
                     loss, gateway);
            add_finding("warning", "Потери до шлюза", detail);
        }
    }
    {
        const char *hosts[] = {"1.1.1.1", "8.8.8.8", "9.9.9.9"};
        char name[64];
        for (i = 0; i < 3; i++) {
            snprintf(name, sizeof name, "Ping %s", hosts[i]);
            stage_progress(name, 4, 6);
            ping_summary(hosts[i], 5, &loss, &avg);
            st = (loss == 0) ? "ok" : (loss < 20 ? "warn" : "fail");
            snprintf(detail, sizeof detail, "loss=%d%%, avg=%.1f ms", loss, avg);
            add_check("Связность", name, st, detail, "");
        }
    }

    /* DNS targets */
    {
        char targets[12][64];
        int nt = 0, j, k;
        for (i = 0; i < ndns && nt < 12; i++) {
            snprintf(targets[nt++], 64, "%s", dns_list[i]);
        }
        for (i = 0; i < 3 && nt < 12; i++) {
            for (j = 0; j < nt; j++)
                if (strcmp(targets[j], dns_extra[i]) == 0) break;
            if (j == nt) snprintf(targets[nt++], 64, "%s", dns_extra[i]);
        }
        if (nt > 6) nt = 6;
        for (i = 0; i < nt; i++) {
            int okc = 0, failc = 0, sum = 0, ms;
            char name[80];
            snprintf(name, sizeof name, "DNS %s", targets[i]);
            stage_progress(name, 5, 6);
            for (k = 0; k < 3; k++) {
                if (dns_ms_nslookup(targets[i], &ms)) {
                    okc++;
                    sum += ms;
                } else failc++;
            }
            snprintf(name, sizeof name, "Резолвер %s", targets[i]);
            if (okc == 0) {
                add_check("DNS", name, "fail", "не отвечает",
                          "DNS не отвечает — проверки связности клиентов падают");
                snprintf(detail, sizeof detail, "DNS %s недоступен", targets[i]);
                add_finding("critical", detail, "Устройства с этим DNS будут считать сеть без интернета.");
            } else {
                int a = sum / okc;
                st = (failc > 0 || a > 200) ? "warn" : "ok";
                snprintf(detail, sizeof detail, "avg=%d ms, fails=%d/3", a, failc);
                add_check("DNS", name, st, detail,
                          a > 200 ? "Медленный DNS — таймауты проверок связности" : "");
            }
        }
    }

    {
        const char *dots[] = {"dns.google", "1.1.1.1", "8.8.8.8", "9.9.9.9"};
        char name[80];
        int any_dot_tls = 0;
        for (i = 0; i < 4; i++) {
            int rc, ms = 0;
            const char *sni = dot_sni_for(dots[i]);
            snprintf(name, sizeof name, "DoT %s", dots[i]);
            stage_progress(name, 6, 6);
            rc = dot_probe(dots[i], 3000, &ms);
            snprintf(name, sizeof name, "DoT %s:853", dots[i]);
            if (rc == 2) {
                snprintf(detail, sizeof detail, "TLS+SNI OK (%s) %d ms", sni, ms);
                add_check("Private DNS", name, "ok", detail, "");
                any_dot_tls = 1;
            } else if (rc == 1) {
                any_dot_closed = 1;
                snprintf(detail, sizeof detail, "TCP открыт, TLS нет (%s) %d ms", sni, ms);
                add_check("Private DNS", name, "warn", detail,
                          "Порт 853 отвечает, но DoT-handshake не проходит — Private DNS не заработает.");
            } else {
                any_dot_closed = 1;
                add_check("Private DNS", name, "warn", "закрыт/фильтр",
                          "Если Private DNS=Автоматически — поставьте «Выкл.»");
            }
        }
        (void)any_dot_tls;
        if (any_dot_closed)
            add_finding("warning", "DoT (TCP/853 + TLS) фильтруется или неполный",
                        "Android Private DNS «Автоматически» и часть OEM ищут DoT (TCP/853 + TLS). "
                        "Если порт закрыт или TLS не отвечает, клиент может решить, что сети нет. "
                        "Настройки → Сеть → Частный DNS → Выкл. "
                        "Если в разделе DPI DoH ещё отвечает — шифрованный DNS можно оставить только в браузере (DoH).");
    }

    stage_progress("резолв имён", 6, 6);
    assess_system_dns();
    stage_done();

    if (g_sys_dns_broken) {
        printf("\n▶ Captive / OS — пропущено (DNS)\n");
        add_check("Captive / OS", "Этап", "info",
                  "пропущен — DNS не резолвит имена",
                  "Без резолва captive-проверки дают ложный «нет интернета».");
    } else {
    printf("\n▶ Captive / OS (мобильные + ПК)\n");
    {
        /* Mobile OEMs + desktop OS connectivity probes — «нет интернета» без HTTP сюда */
        struct { const char *name, *url; int expect; int critical; } caps[] = {
            /* Android / Google */
            {"[Mobile] Google gstatic", "http://connectivitycheck.gstatic.com/generate_204", 204, 1},
            {"[Mobile] Google android", "http://connectivitycheck.android.com/generate_204", 204, 1},
            {"[Mobile] Google www", "http://www.google.com/generate_204", 204, 1},
            {"[Mobile] Google clients3", "http://clients3.google.com/generate_204", 204, 1},
            {"[Mobile] Google clients1", "http://clients1.google.com/generate_204", 204, 0},
            /* Android OEMs */
            {"[Mobile] Xiaomi MIUI", "http://connect.rom.miui.com/generate_204", 204, 1},
            {"[Mobile] Huawei HiCloud", "http://connectivitycheck.platform.hicloud.com/generate_204", 204, 1},
            {"[Mobile] Samsung", "http://connectivitycheck.gstatic.com/generate_204", 204, 0},
            {"[Mobile] Vivo", "http://wifi.vivo.com.cn/generate_204", 204, 0},
            {"[Mobile] OPPO ColorOS", "http://conn1.oppomobile.com/generate_204", 204, 0},
            {"[Mobile] OPPO conn2", "http://conn2.oppomobile.com/generate_204", 204, 0},
            /* Realme/OnePlus — ColorOS/OxygenOS: тот же captive, что OPPO (отдельные
             * connectivitycheck.realme.com / .oneplus.com — NXDOMAIN). */
            {"[Mobile] Realme (OPPO)", "http://conn1.oppomobile.com/generate_204", 204, 0},
            {"[Mobile] OnePlus (OPPO)", "http://conn1.oppomobile.com/generate_204", 204, 0},
            {"[Mobile] Honor", "http://connectivitycheck.platform.hicloud.com/generate_204", 204, 0},
            /* Apple iPhone / iPad / Mac */
            {"[Mobile] Apple captive", "http://captive.apple.com/hotspot-detect.html", 200, 1},
            {"[Mobile] Apple success", "http://www.apple.com/library/test/success.html", 200, 0},
            {"[Mobile] Apple www", "http://www.appleiphonecell.com/", 200, 0},
            {"[PC] Apple captive (Mac)", "http://captive.apple.com/hotspot-detect.html", 200, 0},
            /* Windows PC — ipv6.msftconnecttest.com только AAAA: на IPv4-only = info, не fail */
            {"[PC] Microsoft NCSI", "http://www.msftconnecttest.com/connecttest.txt", 200, 1},
            {"[PC] Microsoft msftncsi", "http://www.msftncsi.com/ncsi.txt", 200, 1},
            {"[PC] Microsoft ipv6", "http://ipv6.msftconnecttest.com/connecttest.txt", 200, 0},
            /* Desktop browsers / Linux */
            {"[PC] Firefox detect", "http://detectportal.firefox.com/success.txt", 200, 0},
            {"[PC] Ubuntu NM", "http://connectivity-check.ubuntu.com/", 204, 0},
            {"[PC] Debian NM", "http://network-test.debian.org/nm", 200, 0},
            {"[PC] Fedora NM", "http://static.redhat.com/test/rhel-networkmanager.txt", 200, 0},
            {"[PC] Elementary", "http://connectivitycheck.gstatic.com/generate_204", 204, 0},
            /* Kindle: spectrum.s3… живой; captive.amazon.com — NXDOMAIN, убран */
            {"[Device] Amazon Kindle", "http://spectrum.s3.amazonaws.com/kindle-wifi/wifistub.html", 200, 0},
        };
        int nc = (int)(sizeof caps / sizeof caps[0]);
        for (i = 0; i < nc; i++) {
            stage_progress(caps[i].name, i + 1, nc + 8);
            check_captive(caps[i].name, caps[i].url, caps[i].expect, caps[i].critical);
        }
        for (i = 0; i < 8; i++) {
            HttpResult r;
            stage_progress("gstatic ×8", nc + i + 1, nc + 8);
            r = http_probe_nofollow("http://connectivitycheck.gstatic.com/generate_204", 3, 0);
            if (r.code == 204 && !r.redirect[0]) {
                flaky_ok++;
                flaky_sum += r.ms;
            } else flaky_fail++;
        }
    }
    {
        int a = flaky_ok ? flaky_sum / flaky_ok : 0;
        st = flaky_fail == 0 ? "ok" : (flaky_fail <= 2 ? "warn" : "fail");
        snprintf(detail, sizeof detail, "ok=%d fail=%d avg=%dms", flaky_ok, flaky_fail, a);
        add_check("Стабильность", "gstatic ×8", st, detail,
                  flaky_fail ? "Нестабильный generate_204 = DFS/помехи/перегруз AP" : "");
        if (flaky_fail) {
            snprintf(detail, sizeof detail, "%d из 8 запросов generate_204 не прошли.", flaky_fail);
            add_finding("warning", "Нестабильная проверка Google", detail);
        }
    }
    stage_done();
    } /* !g_sys_dns_broken captive */

#ifdef _WIN32
    add_check("IPv6", "Глобальный адрес", "info",
              "проверьте ipconfig — сломанный глобальный IPv6 даёт ложный «нет интернета»", "");
#else
    {
        char out[1024];
        run_capture("ifconfig 2>/dev/null | awk '/inet6 /{print $2}' | grep -v fe80 | grep -v '::1' | head -3",
                    out, sizeof out);
        str_trim(out);
        if (out[0])
            add_check("IPv6", "Глобальный адрес", "warn", out,
                      "Если IPv6 сломан, клиенты могут показывать «нет интернета».");
        else
            add_check("IPv6", "Глобальный адрес", "ok",
                      "нет (только link-local)", "");
    }
#endif

    if (gateway[0]) {
        stage_progress("шлюз MikroTik", 1, 3);
        mt[0] = 0;
        if (tcp_open(gateway, 8291, 1500)) { strcat(mt, "8291/Winbox"); mt_n++; }
        if (tcp_open(gateway, 8728, 1500)) { if (mt_n) strcat(mt, ", "); strcat(mt, "8728/API"); mt_n++; }
        if (tcp_open(gateway, 2000, 1500)) { if (mt_n) strcat(mt, ", "); strcat(mt, "2000/BW-test"); mt_n++; }
        if (tcp_open(gateway, 1723, 1500)) { if (mt_n) strcat(mt, ", "); strcat(mt, "1723/PPTP"); mt_n++; }
        if (mt_n) add_check("Шлюз", "Признаки MikroTik", "info", mt, "");
    }

    if (g_sys_dns_broken) {
        add_check("Интернет", "Внешний IP", "info",
                  "пропущен — DNS не резолвит имена",
                  "Нужен резолв hostname API (Яндекс / 2ip / ifconfig.me).");
    } else {
    stage_progress("внешний IP", 2, 3);
    {
        char body[4096], ip[64];
        int ms = 0, code;
        char best_ip[64] = "";

        /* 1) Яндекс Интернетометр API (как на internet.yandex.ru) */
        code = http_fetch_text("https://ipv4-internet.yandex.net/api/v0/ip",
                               body, sizeof body, 8, &ms);
        if (code == 200 && extract_ipv4(body, ip, sizeof ip)) {
            snprintf(best_ip, sizeof best_ip, "%s", ip);
            snprintf(detail, sizeof detail, "%s (%d ms)", ip, ms);
            add_check_ex("Интернет", "Внешний IP (Яндекс)", "ok", detail, "",
                         ip, "https://ipv4-internet.yandex.net/api/v0/ip", 0);
        } else {
            snprintf(detail, sizeof detail, "HTTP %d / нет IP", code);
            add_check_ex("Интернет", "Внешний IP (Яндекс)", "warn", detail,
                         "API Интернетометра недоступен.",
                         NULL, "https://ipv4-internet.yandex.net/api/v0/ip", 0);
        }

        /* 2) 2ip.ru — JS-challenge (cookies) + IP со страницы */
        {
            char ip2[64];
            code = http_fetch_2ip(ip2, sizeof ip2, 12, &ms);
            if (code == 200 && ip2[0]) {
                snprintf(ip, sizeof ip, "%s", ip2);
                if (!best_ip[0]) snprintf(best_ip, sizeof best_ip, "%s", ip);
                snprintf(detail, sizeof detail, "%s (%d ms, challenge OK)", ip, ms);
                add_check_ex("Интернет", "2ip.ru", "ok", detail, "",
                             ip, "https://2ip.ru/", 0);
            } else if (code == 503) {
                snprintf(detail, sizeof detail, "HTTP 503, anti-bot не обойдён (%d ms)", ms);
                add_check_ex("Интернет", "2ip.ru", "warn", detail,
                             "JS-challenge 2ip.ru не разобран — смотрите Яндекс / ifconfig.me.",
                             NULL, "https://2ip.ru/", 0);
            } else if (code > 0) {
                snprintf(detail, sizeof detail, "HTTP %d, нет IP в ответе (%d ms)", code, ms);
                add_check_ex("Интернет", "2ip.ru", "warn", detail,
                             "2ip.ru ответил без IP в HTML.",
                             NULL, "https://2ip.ru/", 0);
            } else {
                add_check_ex("Интернет", "2ip.ru", "fail", "нет ответа",
                             "HTTPS к 2ip.ru не проходит.", NULL, "https://2ip.ru/", 0);
            }
        }

        /* 3) запасной ifconfig.me */
        code = http_fetch_text("https://ifconfig.me/ip", body, sizeof body, 8, &ms);
        if (code == 200 && extract_ipv4(body, ip, sizeof ip)) {
            if (!best_ip[0]) snprintf(best_ip, sizeof best_ip, "%s", ip);
            snprintf(detail, sizeof detail, "%s (%d ms)", ip, ms);
            add_check_ex("Интернет", "Внешний IP (ifconfig.me)", "ok", detail, "",
                         ip, "https://ifconfig.me/ip", 0);
        } else {
            add_check("Интернет", "Внешний IP (ifconfig.me)", "warn",
                      code > 0 ? "ответ без IP" : "не получен", "");
        }

        if (best_ip[0]) {
            snprintf(external_ip, sizeof external_ip, "%s", best_ip);
            add_check("Интернет", "Внешний IP", "ok", best_ip, "");
        } else
            add_check("Интернет", "Внешний IP", "warn", "не получен ни с одного источника", "");
    }
    } /* !g_sys_dns_broken external IP */

    /* NTP — IoT TLS depends on correct clock */
    if (g_sys_dns_broken) {
        printf("\n▶ NTP — пропущено (DNS)\n");
        add_check("NTP / время", "Этап", "info",
                  "пропущен — DNS не резолвит имена",
                  "Без резолва NTP-хостов нельзя отличить фильтр UDP/123 от DNS.");
    } else {
        const char *ntp_hosts[] = {
            "time.google.com", "time.cloudflare.com", "pool.ntp.org"
        };
        int ntp_ok = 0;
        int ntp_n = (int)(sizeof ntp_hosts / sizeof ntp_hosts[0]);
        printf("\n▶ NTP\n");
        for (i = 0; i < ntp_n; i++) {
            char name[80];
            int ok;
            snprintf(name, sizeof name, "NTP %s", ntp_hosts[i]);
            stage_progress(name, i + 1, ntp_n);
            ok = ntp_probe(ntp_hosts[i], 2500);
            if (ok) {
                ntp_ok++;
                add_check("NTP / время", name, "ok", "UDP/123 ответ получен", "");
            } else {
                add_check("NTP / время", name, "warn", "нет ответа UDP/123",
                          "Без NTP часы на IoT сбиваются → TLS handshake fail → туннель не поднимается.");
            }
        }
        stage_done();
        if (ntp_ok == 0)
            add_finding("critical", "NTP полностью недоступен",
                        "Умные устройства не смогут проверить TLS-сертификаты облака. "
                        "Разрешите UDP/123 к pool.ntp.org / time.google.com / time.cloudflare.com "
                        "(или свой NTP на роутере).");
        else if (ntp_ok < ntp_n)
            add_finding("warning", "NTP частично фильтруется",
                        "Часть NTP-серверов не отвечает. IoT иногда «теряет» облако после перезагрузки.");
    }

    /* Smart home / IoT clouds */
    if (stage_begin("Умный дом / IoT", "Точки входа облаков умного дома (Tuya, Алиса, Xiaomi, Sber…)")) {
        char iot_fail[48][64];
        int niot = 0;
        struct { const char *name, *host; int port; int crit; } eps[] = {
            {"Tuya MQTT EU mb", "mq.mb.tuyaeu.com", 8883, 1},
            /* mq.eu.tuyaeu.com — NXDOMAIN; актуальные EU: mb / gw */
            {"Tuya MQTT GW EU", "mq.gw.tuyaeu.com", 8883, 1},
            {"Tuya MQTT US", "mq.mb.tuyaus.com", 8883, 0},
            {"Tuya MQTT CN", "mq.mb.tuyacn.com", 8883, 0},
            {"Tuya API a1 EU", "a1.tuyaeu.com", 443, 1},
            {"Tuya API a3 EU", "a3.tuyaeu.com", 443, 1},
            {"Tuya m1 EU", "m1.tuyaeu.com", 443, 0},
            {"Tuya openapi", "openapi.tuyaeu.com", 443, 0},
            {"Яндекс IoT API", "api.iot.yandex.net", 443, 1},
            {"Алиса uniproxy", "uniproxy.alice.yandex.net", 443, 1},
            {"Алиса quasar", "quasar.yandex.net", 443, 0},
            {"Алиса quasar.ru", "quasar.yandex.ru", 443, 0},
            {"Xiaomi Mi IoT", "api.io.mi.com", 443, 0},
            {"Xiaomi home", "home.mi.com", 443, 0},
            {"Xiaomi account", "account.xiaomi.com", 443, 0},
            {"SmartThings API", "api.smartthings.com", 443, 0},
            {"Google mtalk :5228", "mtalk.google.com", 5228, 0},
            {"Google mtalk :5229", "mtalk.google.com", 5229, 0},
            {"Google Home", "home.google.com", 443, 0},
            {"Sber Salute", "salute.ru", 443, 0},
            {"SberDevices", "devices.sberbank.ru", 443, 0},
            {"Sber Salute portal", "salute.sber.ru", 443, 0},
            {"VK Marusya", "marusia.mail.ru", 443, 0},
            {"Nabu Casa account", "account.nabucasa.com", 443, 0},
            {"Nabu Casa API", "api.nabucasa.com", 443, 0},
            {"Philips Hue", "api.meethue.com", 443, 0},
            {"TP-Link Tapo", "n-wap-gw.tplinkcloud.com", 443, 0},
            {"TP-Link Kasa", "use1-api.tplinkra.com", 443, 0},
            {"eWeLink / Sonoff", "eu-apia.coolkit.cc", 443, 0},
            /* Aqara MQTT :8883 снаружи часто закрыт; :443 отвечает */
            {"Aqara MQTT host", "aiot-mqtt-eu.aiot.aqara.com", 443, 0},
            {"Yeelight", "api.yeelight.com", 443, 0},
            {"Roborock", "api-eu.roborock.com", 443, 0},
            {"Broadlink", "www.ibroadlink.com", 443, 0},
            {"Broadlink tx", "tx.ibroadlink.com", 443, 0},
            {"Amazon Alexa", "api.amazon.com", 443, 0},
            {"Apple Home / iCloud", "p62-ckdatabase.icloud.com", 443, 0},
            {"Mosquitto test :8883", "test.mosquitto.org", 8883, 0},
            {"Mosquitto test :1883", "test.mosquitto.org", 1883, 0},
        };
        int n = (int)(sizeof eps / sizeof eps[0]);
        for (i = 0; i < n; i++) {
            stage_item(eps[i].name, i + 1, n);
            check_tcp_ep("Умный дом / IoT", eps[i].name, eps[i].host, eps[i].port,
                         4000, eps[i].crit, 1, &niot, iot_fail, 48);
        }

        {
            struct { const char *name, *url; } https[] = {
                {"Tuya EU portal", "https://eu.iot.tuya.com/"},
                {"Tuya IoT platform", "https://iot.tuya.com/"},
                {"Яндекс IoT API HTTPS", "https://api.iot.yandex.net/"},
                {"Алиса HTTPS", "https://alice.yandex.ru/"},
                {"Xiaomi Home HTTPS", "https://home.mi.com/"},
                {"Sber Salute HTTPS", "https://salute.sber.ru/"},
                {"Home Assistant", "https://www.home-assistant.io/"},
                {"Philips Hue", "https://www.philips-hue.com/"},
                {"Tapo", "https://www.tapo.com/"},
            };
            int nh = (int)(sizeof https / sizeof https[0]);
            char host[128], ip[64], ua_sum[256];
            int ua_mismatch;
            for (i = 0; i < nh; i++) {
                HttpResult r;
                stage_item(https[i].name, i + 1, nh);
                r = http_probe_agents(https[i].url, 3, 1, ua_sum, sizeof ua_sum, &ua_mismatch);
                host_from_url(https[i].url, host, sizeof host);
                ip[0] = 0;
                if (host[0]) dns_resolve(host, ip, sizeof ip);
                if (r.code > 0) {
                    if (r.code >= 300 && r.code < 400) {
                        snprintf(detail, sizeof detail, "HTTP %d (редирект → %s), %d ms [%s]",
                                 r.code, r.redirect[0] ? r.redirect : "?", r.ms, ua_sum);
                        add_check_ex("Умный дом / IoT", https[i].name, "ok", detail,
                                     "HTTP-редирект: облако отвечает. Не сбой доступности.",
                                     ip, https[i].url, 1);
                    } else {
                    st = (r.ms > 3000 || ua_mismatch) ? "warn" : "ok";
                    if (r.redirect[0])
                        snprintf(detail, sizeof detail, "HTTP %d (финал ← %s), %d ms [%s]",
                                 r.code, r.redirect, r.ms, ua_sum);
                    else
                        snprintf(detail, sizeof detail, "HTTP %d, %d ms [%s]", r.code, r.ms, ua_sum);
                    add_check_ex("Умный дом / IoT", https[i].name, st, detail,
                                 ua_mismatch ? "Ответ зависит от User-Agent."
                                 : (r.ms > 3000 ? "Медленный ответ облака IoT" : ""),
                                 ip, https[i].url, 1);
                    }
                } else if (host_unresolved(host, ip)) {
                    snprintf(detail, sizeof detail, "DNS не резолвит %s", host);
                    add_check_ex("Умный дом / IoT", https[i].name, "warn", detail,
                                 "Имя не резолвится — это сбой DNS, а не недоступность облака.",
                                 NULL, https[i].url, 1);
                } else {
                    snprintf(detail, sizeof detail, "%s [%s]",
                             r.error[0] ? r.error : "таймаут", ua_sum[0] ? ua_sum : "—");
                    add_check_ex("Умный дом / IoT", https[i].name, "fail", detail,
                                 "HTTPS к облаку IoT недоступен.",
                                 ip, https[i].url, 1);
                    if (niot < 48) snprintf(iot_fail[niot++], 64, "%s", https[i].name);
                }
            }
        }

        {
            int hold;
            stage_item("Tuya MQTT hold 15s", 1, 1);
            hold = tcp_hold("mq.mb.tuyaeu.com", 8883, 4000, 15000);
            if (hold == 1) {
                add_check("Умный дом / IoT", "Tuya MQTT hold 15s", "ok",
                          "mq.mb.tuyaeu.com:8883 удержан idle 15 с", "");
            } else if (hold == 0) {
                add_check("Умный дом / IoT", "Tuya MQTT hold 15s", "fail",
                          "не удалось подключиться для hold-теста",
                          "Сначала почините TCP :8883 — без него hold не имеет смысла.");
            } else {
                add_check("Умный дом / IoT", "Tuya MQTT hold 15s", "fail",
                          "соединение сброшено за 15 с idle",
                          "Классика DPI/NAT timeout: устройство поднимает MQTT, через десятки секунд "
                          "туннель рвётся → Алиса теряет Tuya. Увеличьте TCP timeout / сделайте "
                          "bypass для mq.*.tuya*.com:8883.");
                add_finding("critical", "Tuya MQTT туннель не держится",
                            "TCP :8883 к mq.mb.tuyaeu.com устанавливается, но idle-сессия рвётся "
                            "за ~15 с. Это объясняет падение интеграций Алисы при «живом» интернете. "
                            "В политике фильтрации: allowlist Tuya MQTT + отключить idle/DPI reset "
                            "для этих сессий; на MikroTik — увеличить connection-tracking timeout "
                            "для TCP к *.tuyaeu.com.");
            }
        }

        if (niot > 0) {
            char names[LONGSTR] = "", tx[LONGSTR];
            for (i = 0; i < niot; i++) {
                if (i) strcat(names, ", ");
                strcat(names, iot_fail[i]);
            }
            snprintf(detail, sizeof detail, "Недоступны точки умного дома (%d)", niot);
            snprintf(tx, sizeof tx,
                     "Не отвечают: %s. Браузер может работать, а Tuya/Алиса — нет. "
                     "Проверьте DNS и allowlist хостов/портов 443 и 8883.", names);
            add_finding("critical", detail, tx);
        }
        stage_done();
    } else if (!g_sys_dns_broken) {
        add_check("Умный дом / IoT", "Этап", "info", "пропущен пользователем", "");
    }

    /* DPI */
    if (stage_begin("DPI", "Служебные порты, DoH, SNI, QUIC")) {
        char dpi_fail[40][64];
        int ndpi = 0;
        struct { const char *name, *host; int port; int expect_open; } dpi[] = {
            {"HTTPS 1.1.1.1:443", "1.1.1.1", 443, 1},
            {"HTTPS ya.ru:443", "ya.ru", 443, 1},
            {"DoT dns.google:853", "dns.google", 853, 0},
            {"DoT 1.1.1.1:853", "1.1.1.1", 853, 0},
            {"MQTT test.mosquitto.org:8883", "test.mosquitto.org", 8883, 1},
            {"MQTT test.mosquitto.org:1883", "test.mosquitto.org", 1883, 1},
            {"Google mtalk:5228", "mtalk.google.com", 5228, 1},
            {"Apple push:5223", "1-courier.push.apple.com", 5223, 1},
            {"XMPP xmpp.org:5222", "xmpp.org", 5222, 0},
        };
        int n = (int)(sizeof dpi / sizeof dpi[0]);
        int dpi_total = n + 2 + 4 + 6; /* ports + DoH×2 + SNI×4 + QUIC×6 */
        int step = 0;
        int dot_open = 0;
        for (i = 0; i < n; i++) {
            char ip[64], url[256];
            int open;
            stage_progress(dpi[i].name, ++step, dpi_total);
            snprintf(url, sizeof url, "https://%s/", dpi[i].host);
            if (!dns_resolve(dpi[i].host, ip, sizeof ip)) {
                snprintf(detail, sizeof detail, "DNS fail %s", dpi[i].host);
                add_check_ex("DPI", dpi[i].name, "warn", detail, "", NULL, url, 0);
                continue;
            }
            if (strncmp(dpi[i].name, "DoT ", 4) == 0) {
                int ms = 0, rc = dot_probe(dpi[i].host, 3000, &ms);
                const char *sni = dot_sni_for(dpi[i].host);
                if (rc == 2) {
                    snprintf(detail, sizeof detail, "DoT TLS+SNI OK (%s) %d ms", sni, ms);
                    add_check_ex("DPI", dpi[i].name, "ok", detail, "", ip, url, 0);
                    dot_open++;
                } else if (rc == 1) {
                    snprintf(detail, sizeof detail, "TCP :853 есть, TLS нет (%s) %d ms", sni, ms);
                    add_check_ex("DPI", dpi[i].name, "warn", detail,
                                 "Порт открыт, но DoT-handshake не проходит.",
                                 ip, url, 0);
                } else {
                    add_check_ex("DPI", dpi[i].name, "warn",
                                 "TCP :853 закрыт (может быть нормой)",
                                 "Не критично само по себе; смотрите DoH и Private DNS.",
                                 ip, url, 0);
                }
                continue;
            }
            open = tcp_open(dpi[i].host, dpi[i].port, 3000);
            if (open) {
                add_check_ex("DPI", dpi[i].name, "ok", "TCP открыт", "", ip, url, 0);
            } else if (dpi[i].expect_open) {
                add_check_ex("DPI", dpi[i].name, "fail",
                             "TCP закрыт/фильтр",
                             "Порт часто режется DPI. IoT и push могут страдать при живом HTTPS.",
                             ip, url, 0);
                if (ndpi < 40) snprintf(dpi_fail[ndpi++], 64, "%s", dpi[i].name);
            } else {
                add_check_ex("DPI", dpi[i].name, "warn",
                             "TCP закрыт (может быть нормой)",
                             "Не критично само по себе; смотрите в связке с IoT/VPN.",
                             ip, url, 0);
            }
        }

        {
            HttpResult r;
            int doh_ok = 0, doh_fail = 0;
            stage_progress("DoH Cloudflare", ++step, dpi_total);
            r = doh_probe(
                "https://cloudflare-dns.com/dns-query?name=example.com&type=A", 5);
            if (r.code == 200) {
                snprintf(detail, sizeof detail, "HTTP %d, %d ms (dns-json)", r.code, r.ms);
                add_check("DPI", "DoH Cloudflare", "ok", detail, "");
                doh_ok++;
            } else if (r.code > 0) {
                snprintf(detail, sizeof detail, "HTTP %d, %d ms", r.code, r.ms);
                add_check("DPI", "DoH Cloudflare", "warn", detail,
                          "Ожидали 200 с Accept: application/dns-json — возможна подмена/фильтр DoH.");
            } else {
                add_check("DPI", "DoH Cloudflare", "fail",
                          r.error[0] ? r.error : "таймаут",
                          "DoH часто режет DPI. Private DNS/DoH может ломать связность на клиентах.");
                if (ndpi < 40) snprintf(dpi_fail[ndpi++], 64, "%s", "DoH Cloudflare");
                doh_fail++;
            }
            stage_progress("DoH Google", ++step, dpi_total);
            r = doh_probe("https://dns.google/resolve?name=example.com&type=A", 5);
            if (r.code == 200) {
                snprintf(detail, sizeof detail, "HTTP %d, %d ms (dns-json)", r.code, r.ms);
                add_check("DPI", "DoH Google JSON", "ok", detail, "");
                doh_ok++;
            } else if (r.code > 0) {
                snprintf(detail, sizeof detail, "HTTP %d, %d ms", r.code, r.ms);
                add_check("DPI", "DoH Google JSON", "warn", detail, "");
            } else {
                add_check("DPI", "DoH Google JSON", "fail",
                          r.error[0] ? r.error : "таймаут",
                          "Фильтр DoH Google — частый признак DPI.");
                if (ndpi < 40) snprintf(dpi_fail[ndpi++], 64, "%s", "DoH Google");
                doh_fail++;
            }
            if (doh_fail > 0 && dot_open > 0) {
                add_finding("info", "DoH режется, DoT (TCP/853 + TLS) доступен",
                            "Включайте шифрованный DNS как DoT / Private DNS (хост dns.google или 1dot1dot1dot1.cloudflare-dns.com), "
                            "а не DoH-клиенты и не «DNS over HTTPS» в браузере: HTTPS к DoH-эндпоинтам на пути режется, "
                            "DoT TLS на :853 при этом жив. Android: Сеть → Частный DNS → «Имя хоста» (не «Автоматически»).");
            } else if (doh_ok > 0 && dot_open == 0) {
                add_finding("info", "DoT (TCP/853 + TLS) недоступен, DoH работает",
                            "Private DNS «Автоматически» на Android/некоторых OEM ищет DoT и при мёртвом :853/TLS "
                            "может показывать «нет интернета». Выключите Private DNS или задайте обычный DNS роутера. "
                            "Шифрование через DoH (браузер / приложение) на этой сети ещё живо.");
            } else if (doh_fail > 0 && dot_open == 0) {
                add_finding("warning", "И DoH, и DoT недоступны",
                            "Шифрованный DNS с публичных резолверов режется. Оставьте DNS роутера/провайдера "
                            "или свой резолвер во внутренней сети; клиентский Private DNS / DoH лучше выключить.");
            }
        }

        {
            /* youtube/discord/telegram в РФ часто режутся — не считаем признаком DPI */
            struct { const char *name, *url; int expected_ru; } sni[] = {
                {"SNI youtube", "https://www.youtube.com/", 1},
                {"SNI discord", "https://discord.com/", 1},
                {"SNI telegram", "https://telegram.org/", 1},
                {"SNI cloudflare", "https://www.cloudflare.com/", 0},
            };
            int nsni = (int)(sizeof sni / sizeof sni[0]);
            int sni_fail = 0;
            for (i = 0; i < nsni; i++) {
                HttpResult r;
                char host[128], ip[64];
                stage_progress(sni[i].name, ++step, dpi_total);
                r = http_probe(sni[i].url, 6, 1);
                host_from_url(sni[i].url, host, sizeof host);
                ip[0] = 0;
                if (host[0]) dns_resolve(host, ip, sizeof ip);
                if (r.code > 0 && r.code < 500) {
                    snprintf(detail, sizeof detail, "HTTP %d, %d ms", r.code, r.ms);
                    add_check_ex("DPI", sni[i].name, "ok", detail, "", ip, sni[i].url, 0);
                } else if (sni[i].expected_ru) {
                    add_check_ex("DPI", sni[i].name, "info",
                                 r.error[0] ? r.error : "таймаут/блок",
                                 "Ожидаемо в РФ — не считается проблемой сети / DPI.",
                                 ip, sni[i].url, 0);
                } else if (host_unresolved(host, ip)) {
                    add_check_ex("DPI", sni[i].name, "warn",
                                 "DNS не резолвит имя",
                                 "Сбой DNS, не SNI/DPI.",
                                 NULL, sni[i].url, 0);
                } else {
                    add_check_ex("DPI", sni[i].name, "fail",
                                 r.error[0] ? r.error : "таймаут/блок",
                                 "SNI/DPI-фильтр: сайт режется по имени, не по «интернету вообще».",
                                 ip, sni[i].url, 0);
                    sni_fail++;
                }
            }
            if (sni_fail >= 1)
                add_finding("warning", "Похоже на SNI/DPI фильтрацию",
                            "Неожиданно недоступны «обычные» зарубежные HTTPS (не YouTube/Telegram/Discord). "
                            "IoT-облака за рубежом (Tuya EU) могут попадать под те же правила.");
        }

        /* QUIC / HTTP3 path */
        {
            struct { const char *name, *host; int expected_ru; } qh[] = {
                /* Контроль: Яндекс. youtube/discord в РФ часто без QUIC — не проблема. */
                {"QUIC ya.ru:443/udp", "ya.ru", 0},
                {"QUIC yandex.ru:443/udp", "www.yandex.ru", 0},
                {"QUIC google.com:443/udp", "www.google.com", 0},
                {"QUIC youtube.com:443/udp", "www.youtube.com", 1},
                {"QUIC cloudflare.com:443/udp", "cloudflare.com", 0},
                {"QUIC discord.com:443/udp", "discord.com", 1},
            };
            int qok = 0;
            int nq = (int)(sizeof qh / sizeof qh[0]);
            for (i = 0; i < nq; i++) {
                int ms = 0;
                char ip[64], url[256];
                stage_progress(qh[i].name, ++step, dpi_total);
                ip[0] = 0;
                dns_resolve(qh[i].host, ip, sizeof ip);
                snprintf(url, sizeof url, "https://%s/", qh[i].host);
                if (quic_probe(qh[i].host, 2500, &ms)) {
                    qok++;
                    snprintf(detail, sizeof detail, "QUIC VN (UDP/443) за %d ms", ms);
                    add_check_ex("DPI", qh[i].name, "ok", detail, "", ip, url, 0);
                } else if (qh[i].expected_ru) {
                    add_check_ex("DPI", qh[i].name, "info", "нет UDP-ответа на :443",
                                 "Ожидаемо в РФ для этого хоста — не считается проблемой.",
                                 ip, url, 0);
                } else {
                    add_check_ex("DPI", qh[i].name, "warn", "нет UDP-ответа на :443",
                                 "QUIC/HTTP3 может резаться DPI при живом TCP/443. "
                                 "Браузеры откатятся на TCP; часть CDN/видео — нет.",
                                 ip, url, 0);
                }
            }
            if (qok == 0)
                add_finding("warning", "QUIC недоступен",
                            "Ни один контрольный хост (кроме ожидаемо ограниченных в РФ) "
                            "не ответил на UDP/443. Возможна фильтрация QUIC на пути.");
        }

        if (ndpi >= 2) {
            char names[LONGSTR] = "", tx[LONGSTR];
            for (i = 0; i < ndpi; i++) {
                if (i) strcat(names, ", ");
                strcat(names, dpi_fail[i]);
            }
            snprintf(detail, sizeof detail, "DPI режет служебные порты (%d)", ndpi);
            snprintf(tx, sizeof tx,
                     "Закрыто/падает: %s. Для умного дома критичны MQTT :8883 и стабильный TLS; "
                     "добавьте исключения в политику фильтрации.", names);
            add_finding("warning", detail, tx);
        }
        stage_done();
    } else if (!g_sys_dns_broken) {
        add_check("DPI", "Этап", "info", "пропущен пользователем", "");
    }

    /* Significant resources — блок РФ (YouTube/Telegram/…) не считаем проблемой сети */
    if (stage_begin("Значимые ресурсы",
                    "Топ белого списка Минцифры + контроль зарубежных (блок РФ ≠ сбой сети)")) {
        char sig_fail[40][64];
        char sig_slow[40][80];
        int nsig_fail = 0, nsig_slow = 0;
        int n = g_nsig;
        int before_fail, before_checks;
        if (g_resources_from_file)
            add_check("Значимые ресурсы", "Список", "info",
                      "из resources.conf", "");
        for (i = 0; i < n; i++) {
            stage_item(g_sig[i].name, i + 1, n);
            before_fail = nsig_fail;
            before_checks = nchecks;
            check_ru("Значимые ресурсы", g_sig[i].name, g_sig[i].url, g_sig[i].note, 1, 0,
                     sig_fail, &nsig_fail, sig_slow, &nsig_slow);
            if (g_sig[i].expected_block && nsig_fail > before_fail) {
                /* ожидаемый блок РФ: не FAIL/WARN сети */
                Check *c = &checks[before_checks];
                if (strcmp(c->status, "fail") == 0) {
                    snprintf(c->status, sizeof c->status, "info");
                    fail_n--;
                } else if (strcmp(c->status, "warn") == 0) {
                    snprintf(c->status, sizeof c->status, "info");
                    warn_n--;
                }
                if (g_sig[i].note[0])
                    snprintf(c->hint, sizeof c->hint, "%s", g_sig[i].note);
                nsig_fail = before_fail;
            }
        }
        stage_done();
        if (nsig_fail > 0) {
            char names[LONGSTR] = "", tx[LONGSTR];
            for (i = 0; i < nsig_fail; i++) {
                if (i) strcat(names, ", ");
                strcat(names, sig_fail[i]);
            }
            snprintf(detail, sizeof detail, "Недоступны значимые ресурсы (%d)", nsig_fail);
            snprintf(tx, sizeof tx,
                     "Не отвечают (кроме ожидаемо ограниченных в РФ): %s.", names);
            add_finding("warning", detail, tx);
        }
    }

    /* Облака: Selectel / AWS / Azure — TCP + рабочие HTTPS (AWS/S3) */
    if ((g_ninfra_tcp > 0 || g_ninfra_https > 0) &&
        stage_begin("Облако", "Selectel, AWS/S3, Azure — TCP и HTTPS")) {
        char fail[64][64];
        int nfail = 0;
        int n = g_ninfra_tcp;
        int nh = g_ninfra_https;
        for (i = 0; i < n; i++) {
            stage_item(g_infra_tcp[i].name, i + 1, n + nh);
            check_tcp_ep("Облако", g_infra_tcp[i].name, g_infra_tcp[i].host, g_infra_tcp[i].port,
                         4000, g_infra_tcp[i].crit, 0, &nfail, fail, 64);
        }
        for (i = 0; i < nh; i++) {
            HttpResult r;
            char host[128], ip[64], ua_sum[256];
            int ua_mismatch;
            stage_item(g_infra_https[i].name, n + i + 1, n + nh);
            r = http_probe_agents(g_infra_https[i].url, 8, 1, ua_sum, sizeof ua_sum, &ua_mismatch);
            host_from_url(g_infra_https[i].url, host, sizeof host);
            ip[0] = 0;
            if (host[0]) dns_resolve(host, ip, sizeof ip);
            if (r.code > 0) {
                /* 403 AccessDenied от S3/CDN = endpoint жив (аноним без ключа — норма) */
                if (r.code >= 300 && r.code < 400) {
                    snprintf(detail, sizeof detail, "HTTP %d (редирект → %s), %d ms [%s]",
                             r.code, r.redirect[0] ? r.redirect : "?", r.ms, ua_sum);
                    add_check_ex("Облако", g_infra_https[i].name, "ok", detail,
                                 "Облако отвечает редиректом.", ip, g_infra_https[i].url, 0);
                } else {
                    st = (r.ms > 4000 || ua_mismatch) ? "warn" : "ok";
                    snprintf(detail, sizeof detail, "HTTP %d, %d ms [%s]", r.code, r.ms, ua_sum);
                    add_check_ex("Облако", g_infra_https[i].name, st, detail,
                                 (r.code == 403)
                                     ? "403 от S3/CDN без ключа — сервис доступен (ожидаемо)."
                                     : (r.ms > 4000 ? "Медленный ответ облака" : ""),
                                 ip, g_infra_https[i].url, 0);
                }
            } else if (host_unresolved(host, ip)) {
                snprintf(detail, sizeof detail, "DNS не резолвит %s", host);
                add_check_ex("Облако", g_infra_https[i].name, "warn", detail,
                             "Имя не резолвится — сбой DNS, не обязательно блок AWS.",
                             NULL, g_infra_https[i].url, 0);
            } else {
                snprintf(detail, sizeof detail, "%s [%s]",
                         r.error[0] ? r.error : "таймаут", ua_sum[0] ? ua_sum : "—");
                add_check_ex("Облако", g_infra_https[i].name, "fail", detail,
                             "HTTPS к AWS/S3 недоступен (DPI/фильтр/маршрут).",
                             ip, g_infra_https[i].url, 0);
                if (nfail < 64) snprintf(fail[nfail++], 64, "%s", g_infra_https[i].name);
            }
        }
        if (nfail > 0) {
            char names[LONGSTR] = "", tx[LONGSTR];
            for (i = 0; i < nfail; i++) {
                if (i) strcat(names, ", ");
                strcat(names, fail[i]);
            }
            snprintf(detail, sizeof detail, "Облако: сбои HTTPS (%d)", nfail);
            snprintf(tx, sizeof tx, "Не отвечают: %s.", names);
            add_finding(nfail >= 2 ? "warning" : "info", detail, tx);
        }
        stage_done();
    }

    /* Gaming platforms: Blizzard / Battle.net, Steam, Epic, Riot, … */
    if (stage_begin("Игры", "Battle.net / Blizzard, Steam и популярные игровые платформы")) {
        char game_fail[64][64];
        int ngame = 0;
        int n = g_ngame_tcp;
        for (i = 0; i < n; i++) {
            stage_item(g_game_tcp[i].name, i + 1, n);
            check_tcp_ep("Игры", g_game_tcp[i].name, g_game_tcp[i].host, g_game_tcp[i].port,
                         4000, g_game_tcp[i].crit, 0, &ngame, game_fail, 64);
        }
        stage_item("Steam CM", n + 1, n + 1);
        check_steam_cm(&ngame, game_fail, 64);

        {
            int nh = g_ngame_https;
            char host[128], ip[64], ua_sum[256];
            int ua_mismatch;
            for (i = 0; i < nh; i++) {
                HttpResult r;
                stage_item(g_game_https[i].name, i + 1, nh);
                r = http_probe_agents(g_game_https[i].url, 5, 1, ua_sum, sizeof ua_sum, &ua_mismatch);
                host_from_url(g_game_https[i].url, host, sizeof host);
                ip[0] = 0;
                if (host[0]) dns_resolve(host, ip, sizeof ip);
                if (r.code > 0) {
                    if (r.code >= 300 && r.code < 400) {
                        snprintf(detail, sizeof detail, "HTTP %d (редирект → %s), %d ms [%s]",
                                 r.code, r.redirect[0] ? r.redirect : "?", r.ms, ua_sum);
                        add_check_ex("Игры", g_game_https[i].name, "ok", detail,
                                     "HTTP-редирект: платформа отвечает. Не сбой доступности.",
                                     ip, g_game_https[i].url, 0);
                    } else {
                    st = (r.ms > 3000 || ua_mismatch) ? "warn" : "ok";
                    if (r.redirect[0])
                        snprintf(detail, sizeof detail, "HTTP %d (финал ← %s), %d ms [%s]",
                                 r.code, r.redirect, r.ms, ua_sum);
                    else
                        snprintf(detail, sizeof detail, "HTTP %d, %d ms [%s]", r.code, r.ms, ua_sum);
                    add_check_ex("Игры", g_game_https[i].name, st, detail,
                                 ua_mismatch ? "Ответ зависит от User-Agent."
                                 : (r.ms > 3000 ? "Медленный ответ игровой платформы" : ""),
                                 ip, g_game_https[i].url, 0);
                    }
                } else if (host_unresolved(host, ip)) {
                    snprintf(detail, sizeof detail, "DNS не резолвит %s", host);
                    add_check_ex("Игры", g_game_https[i].name, "warn", detail,
                                 "Имя не резолвится — это сбой DNS, а не недоступность платформы.",
                                 NULL, g_game_https[i].url, 0);
                } else {
                    snprintf(detail, sizeof detail, "%s [%s]",
                             r.error[0] ? r.error : "таймаут", ua_sum[0] ? ua_sum : "—");
                    add_check_ex("Игры", g_game_https[i].name, "fail", detail,
                                 "HTTPS к игровой платформе недоступен (DPI/фильтр).",
                                 ip, g_game_https[i].url, 0);
                    if (ngame < 64) snprintf(game_fail[ngame++], 64, "%s", g_game_https[i].name);
                }
            }
        }

        if (ngame > 0) {
            char names[LONGSTR] = "", tx[LONGSTR];
            for (i = 0; i < ngame; i++) {
                if (i) strcat(names, ", ");
                strcat(names, game_fail[i]);
            }
            snprintf(detail, sizeof detail, "Недоступны игровые сервисы (%d)", ngame);
            snprintf(tx, sizeof tx,
                     "Не отвечают: %s. Браузер может работать, а лаунчер/игра — нет. "
                     "Проверьте DNS, DPI и Battle.net (HTTPS + login :1119 на *.actual.battle.net) и Steam.", names);
            add_finding(ngame >= 3 ? "critical" : "warning", detail, tx);
        }
        stage_done();
    } else if (!g_sys_dns_broken) {
        add_check("Игры", "Этап", "info", "пропущен пользователем", "");
    }

    /* AI / LLM platforms */
    if (stage_begin("AI / LLM", "Cursor, OpenAI, Claude, Grok, Gemini и другие AI-платформы")) {
        char ai_fail[48][64];
        int nai_fail = 0;
        int n = g_nai;
        for (i = 0; i < n; i++) {
            char host[128], ip[64], ua_sum[256];
            int ua_mismatch = 0;
            HttpResult r;
            stage_item(g_ai[i].name, i + 1, n);
            r = http_probe_agents(g_ai[i].url, 5, 1, ua_sum, sizeof ua_sum, &ua_mismatch);
            host_from_url(g_ai[i].url, host, sizeof host);
            ip[0] = 0;
            if (host[0]) dns_resolve(host, ip, sizeof ip);
            if (r.code > 0) {
                if (r.code >= 300 && r.code < 400) {
                    snprintf(detail, sizeof detail, "HTTP %d (редирект → %s), %d ms [%s]",
                             r.code, r.redirect[0] ? r.redirect : "?", r.ms, ua_sum);
                    add_check_ex("AI / LLM", g_ai[i].name, "ok", detail,
                                 "HTTP-редирект: сервис отвечает. Не сбой доступности.",
                                 ip, g_ai[i].url, 0);
                } else {
                st = (r.ms > 3000 || ua_mismatch) ? "warn" : "ok";
                if (r.redirect[0])
                    snprintf(detail, sizeof detail, "HTTP %d (финал ← %s), %d ms [%s]",
                             r.code, r.redirect, r.ms, ua_sum);
                else
                    snprintf(detail, sizeof detail, "HTTP %d, %d ms [%s]", r.code, r.ms, ua_sum);
                add_check_ex("AI / LLM", g_ai[i].name, st, detail,
                             ua_mismatch ? "Ответ зависит от User-Agent."
                             : (r.ms > 3000 ? "Медленный ответ AI-сервиса" : ""),
                             ip, g_ai[i].url, 0);
                }
            } else if (host_unresolved(host, ip)) {
                snprintf(detail, sizeof detail, "DNS не резолвит %s", host);
                add_check_ex("AI / LLM", g_ai[i].name, "warn", detail,
                             "Имя не резолвится — это сбой DNS, а не недоступность AI-платформы.",
                             NULL, g_ai[i].url, 0);
            } else {
                snprintf(detail, sizeof detail, "%s [%s]",
                         r.error[0] ? r.error : "таймаут", ua_sum[0] ? ua_sum : "—");
                add_check_ex("AI / LLM", g_ai[i].name, "fail", detail,
                             "AI-платформа недоступна (блок/DPI/маршрут).",
                             ip, g_ai[i].url, 0);
                if (g_ai[i].crit && nai_fail < 48)
                    snprintf(ai_fail[nai_fail++], 64, "%s", g_ai[i].name);
            }
        }
        if (nai_fail > 0) {
            char names[LONGSTR] = "", tx[LONGSTR];
            for (i = 0; i < nai_fail; i++) {
                if (i) strcat(names, ", ");
                strcat(names, ai_fail[i]);
            }
            snprintf(detail, sizeof detail, "Недоступны AI-платформы (%d)", nai_fail);
            snprintf(tx, sizeof tx,
                     "Не отвечают: %s. IDE/чат-боты могут падать при «живом» браузере — "
                     "проверьте фильтр HTTPS/SNI и DNS.", names);
            add_finding(nai_fail >= 2 ? "critical" : "warning", detail, tx);
        }
        stage_done();
    } else if (!g_sys_dns_broken) {
        add_check("AI / LLM", "Этап", "info", "пропущен пользователем", "");
    }

    /* Video hosts: homepage + video path (full «первое видео» — probe-video) */
    if (!opt_skip_video && stage_begin("Видео",
                    "Яндекс Видео, VK Видео, IVI, Okko, Rutube — сайт и видео-путь")) {
        int nv = g_nvideo;
        int vfail = 0;
        for (i = 0; i < nv; i++) {
            char ua_sum[256], host[128], ip[64];
            int ua_mismatch = 0;
            HttpResult r, rv;
            stage_item(g_video[i].name, i + 1, nv);
            r = http_probe_agents(g_video[i].home, 8, 1, ua_sum, sizeof ua_sum, &ua_mismatch);
            host_from_url(g_video[i].home, host, sizeof host);
            ip[0] = 0;
            if (host[0]) dns_resolve(host, ip, sizeof ip);
            rv = http_probe_agents(g_video[i].video, 10, 1, ua_sum, sizeof ua_sum, &ua_mismatch);
            if (r.code > 0 && rv.code > 0 && r.code < 500 && rv.code < 500) {
                snprintf(detail, sizeof detail,
                         "сайт HTTP %d (%d ms); лента/видео HTTP %d (%d ms) [%s]",
                         r.code, r.ms, rv.code, rv.ms, ua_sum);
                add_check_ex("Видео", g_video[i].name, "ok", detail,
                             "Детально (первое видео с главной): ./probe-video -n 1",
                             ip, g_video[i].home, 0);
            } else if (host_unresolved(host, ip)) {
                snprintf(detail, sizeof detail, "DNS не резолвит %s", host);
                add_check_ex("Видео", g_video[i].name, "warn", detail,
                             "Имя не резолвится — это сбой DNS, а не недоступность видео.",
                             NULL, g_video[i].home, 0);
            } else {
                snprintf(detail, sizeof detail, "сайт HTTP %d; видео HTTP %d [%s]",
                         r.code, rv.code, ua_sum[0] ? ua_sum : "—");
                add_check_ex("Видео", g_video[i].name, "fail", detail,
                             "Не открылся сайт или видео-путь.", ip, g_video[i].home, 0);
                vfail++;
            }
        }
        if (vfail >= 3)
            add_finding("warning", "Видеохостинги недоступны",
                        "Яндекс/VK/IVI/Okko/Rutube — проверьте DPI/DNS. "
                        "Детальный прогон: ./probe-video");
        stage_done();
    } else if (opt_skip_video) {
        add_check("Видео", "Этап", "info", "пропущен (--skip-video)", "");
    }

    /* Speed: РФ (Москва/Selectel) + Европа (OVH), плюс краткий Яндекс IP */
    if (!opt_skip_speed && stage_begin("Скорость",
                    "Download ~10 МБ: Москва / Selectel РФ и Европа (OVH) — ориентир «оптималки»")) {
        char body[4096], ip[64], probe_url[STR];
        long bytes = 0;
        int ms = 0, code;
        double mbps_ru = -1, mbps_eu = -1;
        struct {
            const char *name;
            const char *url;
            const char *geo;
            double *out_mbps;
            int critical;
        } probes[] = {
            /* LibreSpeed MSK — явная Москва; с части сетей может не открываться */
            {"Download Москва (LibreSpeed)",
             "https://speed-msk.park-web.ru/10mb.bin", "Москва", NULL, 0},
            /* Selectel — крупные ДЦ в РФ (часто СПб/Мск по anycast маршруту) */
            {"Download РФ (Selectel 10MB)",
             "https://speedtest.selectel.ru/10MB", "РФ · Selectel", &mbps_ru, 1},
            /* OVH proof — Франция, стабильный европейский эталон */
            {"Download Европа (OVH FR 10MB)",
             "https://proof.ovh.net/files/10Mb.dat", "Европа · OVH FR", &mbps_eu, 1},
        };
        int np = (int)(sizeof probes / sizeof probes[0]);
        int pi;

        stage_progress("пробы download", 1, np + 2);
        for (pi = 0; pi < np; pi++) {
            char host[128], rip[64];
            stage_item(probes[pi].name, pi + 1, np);
            host_from_url(probes[pi].url, host, sizeof host);
            rip[0] = 0;
            if (host[0]) dns_resolve(host, rip, sizeof rip);
            bytes = 0;
            ms = 0;
            if (http_download_bytes(probes[pi].url, 35, &bytes, &ms) && ms > 0 && bytes > 200000) {
                double mbps = (bytes * 8.0) / (ms * 1000.0);
                if (probes[pi].out_mbps) *probes[pi].out_mbps = mbps;
                st = mbps < 8 ? "warn" : "ok";
                snprintf(detail, sizeof detail,
                         "%.2f Мбит/с (%ld байт за %d ms) · %s",
                         mbps, bytes, ms, probes[pi].geo);
                add_check_ex("Скорость", probes[pi].name, st, detail,
                             mbps < 8
                                 ? "Ниже ~8 Мбит/с до этой точки — узкое место на маршруте или Wi‑Fi."
                                 : "",
                             rip[0] ? rip : NULL, probes[pi].url, 0);
            } else if (probes[pi].critical) {
                snprintf(detail, sizeof detail, "%s",
                         ms > 0 ? "скачано слишком мало / обрыв" : "таймаут / нет ответа");
                add_check_ex("Скорость", probes[pi].name, "fail", detail,
                             "Не удалось скачать пробник — фильтр, маршрут или перегруз.",
                             rip[0] ? rip : NULL, probes[pi].url, 0);
            } else {
                add_check_ex("Скорость", probes[pi].name, "info",
                             "недоступен с этой сети (норма, если не из РФ)",
                             "Запасная проба РФ — Selectel.",
                             rip[0] ? rip : NULL, probes[pi].url, 0);
            }
        }

        if (mbps_ru >= 0 && mbps_eu >= 0) {
            if (mbps_ru >= 15 && mbps_eu >= 0 && mbps_eu < mbps_ru * 0.25 && mbps_eu < 10)
                add_finding("warning", "До Европы заметно медленнее, чем до РФ",
                            "Selectel быстрый, OVH Europe проседает — типично для международного "
                            "маршрута/пиринга. Для сервисов в ЕС (игры, AI API) это может быть узким местом.");
            else if (mbps_ru < 8 && mbps_eu < 8)
                add_finding("warning", "Низкая скорость и до РФ, и до Европы",
                            "Похоже на ограничение канала/Wi‑Fi/шлюза, а не только «зарубежье».");
        }

        /* Яндекс: страница + IP (коротко); CDN 100kb — лёгкий доп. ориентир */
        stage_progress("Яндекс IP", np + 1, np + 2);
        code = http_fetch_text("https://ipv4-internet.yandex.net/api/v0/ip",
                               body, sizeof body, 8, &ms);
        if (code == 200 && extract_ipv4(body, ip, sizeof ip)) {
            if (!external_ip[0])
                snprintf(external_ip, sizeof external_ip, "%s", ip);
            snprintf(detail, sizeof detail, "%s (%d ms)", ip, ms);
            add_check_ex("Скорость", "Внешний IP (Яндекс)", "ok", detail, "",
                         ip, "https://ipv4-internet.yandex.net/api/v0/ip", 0);
        } else {
            add_check("Скорость", "Внешний IP (Яндекс)", "warn", "не получен", "");
        }

        stage_progress("Яндекс CDN 100kb", np + 2, np + 2);
        probe_url[0] = 0;
        if (yandex_speed_probe_url(probe_url, sizeof probe_url) &&
            http_download_bytes(probe_url, 15, &bytes, &ms) && ms > 0 && bytes > 1000) {
            double mbps = (bytes * 8.0) / (ms * 1000.0);
            snprintf(detail, sizeof detail, "%.2f Мбит/с (%ld байт за %d ms) · CDN Интернетометра",
                     mbps, bytes, ms);
            add_check_ex("Скорость", "Яндекс CDN (100kb)", mbps < 5 ? "warn" : "ok", detail,
                         "Мелкая проба CDN — для сравнения с Selectel/OVH.",
                         NULL, "https://internet.yandex.ru/", 0);
        } else {
            add_check("Скорость", "Яндекс CDN (100kb)", "info",
                      "проба недоступна — не критично",
                      "Основные замеры — Selectel и OVH.");
        }
        stage_done();
    }

    /* DNS bulk — по умолчанию пропускаем (долгий); Enter = запустить */
    if (opt_skip_dns_bulk) {
        add_check("DNS-прогон", "Этап", "info", "пропущен (--skip-dns-bulk)", "");
    } else if (opt_force_dns_bulk ||
               stage_begin_ex("DNS-прогон",
                              "Долгий прогон популярных доменов через НСДИ / Яндекс DNS / публичные "
                              "(по умолчанию пропускается)",
                              0)) {
        static char domains[MAX_DOMAINS][128];
        int used_embed = 0;
        int nd = load_domains(domains, MAX_DOMAINS, &used_embed);
        struct { const char *name, *ip; } resolvers[] = {
            {"НСДИ a.res-nsdi.ru", "195.208.4.1"},
            {"НСДИ b.res-nsdi.ru", "195.208.5.1"},
            {"Яндекс DNS", "77.88.8.8"},
            {"Яндекс DNS 2", "77.88.8.1"},
            {"Cloudflare", "1.1.1.1"},
            {"Google", "8.8.8.8"},
            {"Quad9", "9.9.9.9"},
        };
        int nr = (int)(sizeof resolvers / sizeof resolvers[0]);
        int limit = opt_dns_limit;
        if (opt_force_dns_bulk && opt_yes) {
            printf("\n▶ DNS-прогон\n  принудительно (--dns-bulk)\n");
            fflush(stdout);
        }
        if (nd == 0) {
            add_check("DNS-прогон", "Список доменов", "fail",
                      domains_path[0] ? "не удалось прочитать --domains FILE"
                                      : "пустой список доменов",
                      "Укажите --domains FILE или пересоберите с wordlists/top_domains.txt.");
        } else {
            if (limit > nd) limit = nd;
            snprintf(detail, sizeof detail,
                     "%s: %d доменов, прогон по %d на резолвер",
                     used_embed ? "встроенный список" : "файл", nd, limit);
            add_check("DNS-прогон", "Список доменов", "info", detail, "");
            for (i = 0; i < nr; i++) {
                int ok = 0, fail = 0, sum_ms = 0, j, rcode, ms;
                char name[96];
                printf("  резолвер %s (%s)\n", resolvers[i].name, resolvers[i].ip);
                fflush(stdout);
                for (j = 0; j < limit; j++) {
                    if ((j % 50) == 0 || j + 1 == limit)
                        stage_progress(resolvers[i].name, j + 1, limit);
                    if (dns_query_udp(resolvers[i].ip, domains[j], 400, &rcode, &ms)) {
                        ok++;
                        sum_ms += ms;
                    } else {
                        fail++;
                    }
                }
                stage_done();
                snprintf(name, sizeof name, "%s", resolvers[i].name);
                if (ok == 0) {
                    add_check_ex("DNS-прогон", name, "fail",
                                 "нет ответов UDP/53",
                                 "Резолвер недоступен с этой сети (фильтр/маршрут).",
                                 resolvers[i].ip, NULL, 0);
                } else {
                    int avg = sum_ms / ok;
                    double pct = 100.0 * ok / limit;
                    st = (pct < 90.0 || avg > 250) ? "warn" : "ok";
                    snprintf(detail, sizeof detail,
                             "ok=%d/%d (%.1f%%), fail=%d, avg=%d ms",
                             ok, limit, pct, fail, avg);
                    add_check_ex("DNS-прогон", name, st, detail,
                                 pct < 90.0 ? "Много таймаутов — резолвер фильтруется или перегружен." : "",
                                 resolvers[i].ip, NULL, 0);
                }
            }
            for (i = 0; i < ndns && i < 3; i++) {
                int ok = 0, fail = 0, sum_ms = 0, j, rcode, ms;
                char name[96];
                int sample = limit > 200 ? 200 : limit;
                snprintf(name, sizeof name, "Системный DNS %s", dns_list[i]);
                printf("  %s (выборка %d)\n", name, sample);
                fflush(stdout);
                for (j = 0; j < sample; j++) {
                    if ((j % 50) == 0 || j + 1 == sample)
                        stage_progress(name, j + 1, sample);
                    if (dns_query_udp(dns_list[i], domains[j], 400, &rcode, &ms)) {
                        ok++;
                        sum_ms += ms;
                    } else fail++;
                }
                stage_done();
                if (ok == 0)
                    add_check_ex("DNS-прогон", name, "fail", "нет ответов", "", dns_list[i], NULL, 0);
                else {
                    snprintf(detail, sizeof detail, "ok=%d/%d, fail=%d, avg=%d ms",
                             ok, sample, fail, sum_ms / ok);
                    add_check_ex("DNS-прогон", name, "ok", detail, "", dns_list[i], NULL, 0);
                }
            }
        }
    } else {
        add_check("DNS-прогон", "Этап", "info", "пропущен (Enter не нажат)", "");
    }

    /* RU banks / services */
    if (stage_begin("Банки и сервисы РФ", "Доступность популярных банков и порталов")) {
        int n = g_nbanks;
        for (i = 0; i < n; i++) {
            stage_item(g_banks[i].name, i + 1, n);
            check_ru(g_banks[i].cat, g_banks[i].name, g_banks[i].url, "", 0, 0,
                     fail_names, &nfail, slow_names, &nslow);
        }
        stage_done();
    }

    if (nfail > 0) {
        char names[LONGSTR] = "", tx[LONGSTR];
        for (i = 0; i < nfail; i++) {
            if (i) strcat(names, ", ");
            strcat(names, fail_names[i]);
        }
        snprintf(detail, sizeof detail, "Недоступны сервисы РФ (%d)", nfail);
        snprintf(tx, sizeof tx,
                 "Не отвечают: %s. Если captive OK — маршрут/DNS/фильтр или сбой сервиса.", names);
        add_finding("warning", detail, tx);
    }
    if (nslow >= 3) {
        char names[LONGSTR] = "", tx[LONGSTR];
        for (i = 0; i < nslow; i++) {
            if (i) strcat(names, ", ");
            strcat(names, slow_names[i]);
        }
        snprintf(detail, sizeof detail, "Медленные сервисы РФ (%d)", nslow);
        snprintf(tx, sizeof tx, "Медленнее 2000 ms: %s.", names);
        add_finding("warning", detail, tx);
    }

    if (nfindings == 0 && warn_n == 0 && fail_n == 0) {
        add_finding("info", "Сейчас сеть выглядит здоровой",
                    "Основные проверки проходят. При редких сбоях запускайте в момент проблемы "
                    "и проверьте DFS-канал на AP.");
    }

    write_html();
    printf("\nОтчёт: %s\n", report_path);
    printf("Итого: OK=%d WARN=%d FAIL=%d\n", ok_n, warn_n, fail_n);

    if (!no_open) {
#ifdef _WIN32
        ShellExecuteA(NULL, "open", report_path, NULL, NULL, SW_SHOWNORMAL);
#else
        {
            char cmd[STR];
            snprintf(cmd, sizeof cmd, "open '%s' 2>/dev/null || xdg-open '%s' 2>/dev/null",
                     report_path, report_path);
            system(cmd);
        }
#endif
    }

#ifdef _WIN32
    WSACleanup();
#endif
    return fail_n > 0 ? 1 : 0;
}

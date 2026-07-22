/*
 * probe-captive.c — captive portal + Google/Яндекс + DNS + DoT + DoH.
 * Раз в ≤2 мин: HTTP-проверки связности ОС, DNS (UDP/53), DoT (TLS:853), DoH (dns-json).
 *
 *   make -f Makefile.probes captive
 *   ./probe-captive              # цикл каждые 120 с
 *   ./probe-captive -i 60
 *   ./probe-captive -n 1
 */

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "version.h"
#include <errno.h>

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  pragma comment(lib, "ws2_32.lib")
typedef SOCKET sock_t;
#  define SOCK_INVALID INVALID_SOCKET
#  define sock_close closesocket
#else
#  include <unistd.h>
#  include <sys/types.h>
#  include <sys/socket.h>
#  include <sys/time.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <netdb.h>
#  include <fcntl.h>
#  include <signal.h>
typedef int sock_t;
#  define SOCK_INVALID (-1)
#  define sock_close close
#endif

static volatile int g_run = 1;
#ifndef _WIN32
static void on_sig(int s) { (void)s; g_run = 0; }
#endif

static long long now_ms(void) {
#ifdef _WIN32
    return (long long)GetTickCount64();
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (long long)tv.tv_sec * 1000 + tv.tv_usec / 1000;
#endif
}

static void stamp(char *buf, size_t n) {
    time_t t = time(NULL);
    struct tm tm;
#ifdef _WIN32
    localtime_s(&tm, &t);
#else
    localtime_r(&t, &tm);
#endif
    strftime(buf, n, "%Y-%m-%d %H:%M:%S", &tm);
}

static void host_from_url(const char *url, char *host, size_t n) {
    const char *p = strstr(url, "://");
    size_t i = 0;
    host[0] = 0;
    if (!p) {
        snprintf(host, n, "%s", url);
        return;
    }
    p += 3;
    while (p[i] && p[i] != '/' && p[i] != ':' && p[i] != '?' && i + 1 < n) {
        host[i] = p[i];
        i++;
    }
    host[i] = 0;
}

static int resolve_ip(const char *host, char *ip, size_t iplen) {
    struct addrinfo hints, *res = NULL;
    ip[0] = 0;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, NULL, &hints, &res) != 0 || !res) return 0;
    if (res->ai_family == AF_INET)
        inet_ntop(AF_INET, &((struct sockaddr_in *)res->ai_addr)->sin_addr, ip, (socklen_t)iplen);
    else if (res->ai_family == AF_INET6)
        inet_ntop(AF_INET6, &((struct sockaddr_in6 *)res->ai_addr)->sin6_addr, ip, (socklen_t)iplen);
    freeaddrinfo(res);
    return ip[0] != 0;
}

/* HTTP GET: follow=0 для captive (редирект = портал). Возвращает код или 0. */
static int http_get(const char *url, int follow, int expect, int *ms_out, char *redir, size_t redir_n) {
    char cmd[1024], out[256];
    FILE *f;
    long long t0 = now_ms();
    int code = 0;

    if (ms_out) *ms_out = 0;
    if (redir && redir_n) redir[0] = 0;

#ifdef _WIN32
    snprintf(cmd, sizeof cmd,
             "curl.exe -sS --max-time 8 --connect-timeout 5 --http1.1 "
             "%s -w \"%%{http_code}\\t%%{redirect_url}\" -o NUL \"%s\" 2>NUL",
             follow ? "-L --max-redirs 5" : "--max-redirs 0", url);
#else
    snprintf(cmd, sizeof cmd,
             "curl -sS --max-time 8 --connect-timeout 5 --http1.1 "
             "%s -w '%%{http_code}\\t%%{redirect_url}' -o /dev/null '%s' 2>/dev/null",
             follow ? "-L --max-redirs 5" : "--max-redirs 0", url);
#endif
    (void)expect;
    f = popen(cmd, "r");
    if (!f) return 0;
    out[0] = 0;
    if (fgets(out, sizeof out, f)) {
        char *tab;
        code = atoi(out);
        tab = strchr(out, '\t');
        if (tab && redir && redir_n) {
            tab++;
            while (*tab == ' ' || *tab == '\t') tab++;
            snprintf(redir, redir_n, "%s", tab);
            {
                size_t L = strlen(redir);
                while (L > 0 && (redir[L - 1] == '\n' || redir[L - 1] == '\r'))
                    redir[--L] = 0;
            }
            if (strcmp(redir, "0") == 0) redir[0] = 0;
        }
    }
    pclose(f);
    if (ms_out) *ms_out = (int)(now_ms() - t0);
    return code;
}

/* Минимальный DNS A-запрос к резолверу (UDP/53). */
static int dns_query_a(const char *server, const char *name, int timeout_ms,
                       char *ip_out, size_t ip_n, int *ms_out) {
    unsigned char pkt[512], resp[512];
    struct addrinfo hints, *res = NULL;
    sock_t s;
    fd_set rset;
    struct timeval tv;
    size_t i, off = 0;
    const char *p;
    long long t0;
    int n, ok = 0;

    if (ip_out && ip_n) ip_out[0] = 0;
    if (ms_out) *ms_out = 0;

    memset(pkt, 0, sizeof pkt);
    pkt[0] = 0x12; pkt[1] = 0x34; /* id */
    pkt[2] = 0x01; pkt[3] = 0x00; /* RD */
    pkt[4] = 0x00; pkt[5] = 0x01; /* QDCOUNT=1 */
    off = 12;
    p = name;
    while (*p) {
        const char *dot = strchr(p, '.');
        size_t lab = dot ? (size_t)(dot - p) : strlen(p);
        if (lab == 0 || lab > 63 || off + 1 + lab >= sizeof pkt) return 0;
        pkt[off++] = (unsigned char)lab;
        memcpy(pkt + off, p, lab);
        off += lab;
        p = dot ? dot + 1 : p + lab;
        if (!dot) break;
    }
    pkt[off++] = 0;
    pkt[off++] = 0x00; pkt[off++] = 0x01; /* A */
    pkt[off++] = 0x00; pkt[off++] = 0x01; /* IN */

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    if (getaddrinfo(server, "53", &hints, &res) != 0 || !res) return 0;

    s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s == SOCK_INVALID) { freeaddrinfo(res); return 0; }

    t0 = now_ms();
    if (sendto(s, (const char *)pkt, (int)off, 0, res->ai_addr, (int)res->ai_addrlen) < 0) {
        sock_close(s);
        freeaddrinfo(res);
        return 0;
    }

    FD_ZERO(&rset);
    FD_SET(s, &rset);
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    if (select((int)s + 1, &rset, NULL, NULL, &tv) > 0) {
        n = (int)recvfrom(s, (char *)resp, sizeof resp, 0, NULL, NULL);
        if (n > 12 && (resp[3] & 0x0f) == 0) {
            /* ищем A в ответах: грубый разбор — первые 4 октета после TYPE=A */
            for (i = 12; i + 12 < (size_t)n; i++) {
                if (resp[i] == 0x00 && resp[i + 1] == 0x01 && /* TYPE A */
                    resp[i + 2] == 0x00 && resp[i + 3] == 0x01 && /* CLASS IN */
                    i + 10 < (size_t)n && resp[i + 8] == 0x00 && resp[i + 9] == 0x04) {
                    snprintf(ip_out, ip_n, "%u.%u.%u.%u",
                             resp[i + 10], resp[i + 11], resp[i + 12], resp[i + 13]);
                    ok = 1;
                    break;
                }
            }
            if (!ok && ip_out && ip_n)
                snprintf(ip_out, ip_n, "(ответ без A)");
            ok = 1; /* ответ получен */
        }
    }
    if (ms_out) *ms_out = (int)(now_ms() - t0);
    sock_close(s);
    freeaddrinfo(res);
    return ok;
}

static int wait_recv(sock_t s, unsigned char *buf, int buflen, int timeout_ms) {
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
    n = (int)recv(s, (char *)buf, buflen, 0);
    return n > 0 ? n : 0;
}

static sock_t tcp_connect(const char *host, int port, int timeout_ms) {
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
    if (getaddrinfo(host, portstr, &hints, &res) != 0) return SOCK_INVALID;
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
    return SOCK_INVALID;
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
                err = 0; errlen = sizeof err;
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

static int tls_clienthello_sni(sock_t s, const char *sni, int timeout_ms) {
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
    n = wait_recv(s, resp, sizeof resp, timeout_ms);
    return n > 0 && (resp[0] == 0x16 || resp[0] == 0x15 || resp[0] == 0x14);
}

static const char *dot_sni_for(const char *host) {
    if (!host) return "dns.google";
    if (strcmp(host, "1.1.1.1") == 0 || strcmp(host, "1.0.0.1") == 0)
        return "cloudflare-dns.com";
    if (strcmp(host, "8.8.8.8") == 0 || strcmp(host, "8.8.4.4") == 0)
        return "dns.google";
    if (strcmp(host, "9.9.9.9") == 0) return "dns.quad9.net";
    return host;
}

/* 2=TLS OK, 1=TCP only, 0=fail */
static int dot_probe(const char *host, int *ms_out) {
    const char *sni = dot_sni_for(host);
    sock_t s;
    long long t0 = now_ms();
    int rc = 0;
    if (ms_out) *ms_out = 0;
    s = tcp_connect(host, 853, 3000);
    if (s == SOCK_INVALID) {
        if (ms_out) *ms_out = (int)(now_ms() - t0);
        return 0;
    }
    rc = tls_clienthello_sni(s, sni, 3000) ? 2 : 1;
    sock_close(s);
    if (ms_out) *ms_out = (int)(now_ms() - t0);
    return rc;
}

static int doh_get(const char *url, int *ms_out) {
    char cmd[1024], out[64];
    FILE *f;
    long long t0 = now_ms();
    int code = 0;
    if (ms_out) *ms_out = 0;
#ifdef _WIN32
    snprintf(cmd, sizeof cmd,
             "curl.exe -sS -o NUL -w \"%%{http_code}\" --max-time 8 "
             "-H \"Accept: application/dns-json\" --http1.1 -k \"%s\" 2>NUL", url);
#else
    snprintf(cmd, sizeof cmd,
             "curl -sS -o /dev/null -w '%%{http_code}' --max-time 8 "
             "-H 'Accept: application/dns-json' --http1.1 -k '%s' 2>/dev/null", url);
#endif
    f = popen(cmd, "r");
    if (!f) return 0;
    out[0] = 0;
    if (fgets(out, sizeof out, f)) code = atoi(out);
    pclose(f);
    if (ms_out) *ms_out = (int)(now_ms() - t0);
    return code;
}

typedef struct {
    const char *name;
    const char *host;
} DotTarget;

static const DotTarget dot_targets[] = {
    {"DoT dns.google", "dns.google"},
    {"DoT 1.1.1.1", "1.1.1.1"},
    {"DoT 8.8.8.8", "8.8.8.8"},
    {"DoT 9.9.9.9", "9.9.9.9"},
};
static const int ndot = (int)(sizeof dot_targets / sizeof dot_targets[0]);

typedef struct {
    const char *name;
    const char *url;
} DohTarget;

static const DohTarget doh_targets[] = {
    {"DoH Cloudflare", "https://cloudflare-dns.com/dns-query?name=example.com&type=A"},
    {"DoH Google JSON", "https://dns.google/resolve?name=example.com&type=A"},
};
static const int ndoh = (int)(sizeof doh_targets / sizeof doh_targets[0]);

typedef struct {
    const char *name;
    const char *url;
    int expect;   /* ожидаемый HTTP-код; 0 = любой 2xx/3xx после follow */
    int follow;
    int captive;  /* 1 = captive (редирект = FAIL) */
} HttpTarget;

static const HttpTarget captives[] = {
    {"Google gstatic",  "http://connectivitycheck.gstatic.com/generate_204", 204, 0, 1},
    {"Google android",  "http://connectivitycheck.android.com/generate_204", 204, 0, 1},
    {"Apple captive",   "http://captive.apple.com/hotspot-detect.html",       200, 0, 1},
    {"Microsoft NCSI",  "http://www.msftconnecttest.com/connecttest.txt",     200, 0, 1},
    {"Xiaomi MIUI",     "http://connect.rom.miui.com/generate_204",           204, 0, 1},
    {"Huawei HiCloud",  "http://connectivitycheck.platform.hicloud.com/generate_204", 204, 0, 1},
    {"OPPO / Realme",   "http://conn1.oppomobile.com/generate_204",           204, 0, 1},
};
static const int ncaptives = (int)(sizeof captives / sizeof captives[0]);

static const HttpTarget resources[] = {
    {"Google",     "https://www.google.com/", 0, 1, 0},
    {"Ya.ru",      "https://ya.ru/",          0, 1, 0},
    {"DNS Google", "https://dns.google/",     0, 1, 0},
    {"Cloudflare", "https://1.1.1.1/",        0, 1, 0},
    {"Yandex DNS", "https://dns.yandex.ru/",  0, 1, 0},
    {"2ip.ru",     "https://2ip.ru/",          0, 1, 0},
    {"Интернетометр", "https://internet.yandex.ru/", 0, 1, 0},
};
static const int nresources = (int)(sizeof resources / sizeof resources[0]);

typedef struct {
    const char *name;
    const char *server; /* NULL = системный getaddrinfo */
    const char *qname;
} DnsTarget;

static const DnsTarget dns_targets[] = {
    {"sys → gstatic",   NULL,      "connectivitycheck.gstatic.com"},
    {"sys → google.com", NULL,     "www.google.com"},
    {"sys → ya.ru",     NULL,      "ya.ru"},
    {"@8.8.8.8 gstatic", "8.8.8.8", "connectivitycheck.gstatic.com"},
    {"@1.1.1.1 gstatic", "1.1.1.1", "connectivitycheck.gstatic.com"},
    {"@8.8.8.8 ya.ru",   "8.8.8.8", "ya.ru"},
    {"@77.88.8.8 ya.ru", "77.88.8.8", "ya.ru"}, /* Яндекс DNS */
};
static const int ndns = (int)(sizeof dns_targets / sizeof dns_targets[0]);

static void print_http(const HttpTarget *t, int *ok_n) {
    char host[128], ip[64], redir[256];
    int ms = 0, code, good;

    host_from_url(t->url, host, sizeof host);
    resolve_ip(host, ip, sizeof ip);
    code = http_get(t->url, t->follow, t->expect, &ms, redir, sizeof redir);

    printf("── %s\n", t->name);
    printf("   SNI:      %s\n", host[0] ? host : "(нет)");
    printf("   URL:      %s\n", t->url);
    printf("   IP:       %s\n", ip[0] ? ip : "(DNS fail)");

    if (t->captive && redir[0]) {
        printf("   status:   FAIL  редирект → %s (HTTP %d) — captive/подмена  %d ms\n",
               redir, code, ms);
        return;
    }
    if (t->expect > 0)
        good = (code == t->expect && !redir[0]);
    else
        good = (code >= 200 && code < 400);

    if (good) {
        printf("   status:   OK  HTTP %d  %d ms\n", code, ms);
        (*ok_n)++;
    } else if (code > 0) {
        printf("   status:   FAIL  HTTP %d%s%s  %d ms\n",
               code, redir[0] ? " → " : "", redir[0] ? redir : "", ms);
    } else {
        printf("   status:   FAIL  нет ответа  %d ms\n", ms);
    }
}

static void print_dns(const DnsTarget *t, int *ok_n) {
    char ip[64];
    int ms = 0, ok;

    printf("── DNS %s\n", t->name);
    printf("   SNI/host: %s\n", t->qname);
    printf("   URL:      dns://%s/%s\n", t->server ? t->server : "system", t->qname);

    if (!t->server) {
        ok = resolve_ip(t->qname, ip, sizeof ip);
        ms = 0;
        printf("   IP:       %s\n", ok ? ip : "(DNS fail)");
        if (ok) {
            printf("   status:   OK  system resolve\n");
            (*ok_n)++;
        } else {
            printf("   status:   FAIL  getaddrinfo\n");
        }
        return;
    }

    ok = dns_query_a(t->server, t->qname, 2500, ip, sizeof ip, &ms);
    printf("   IP:       %s\n", ip[0] ? ip : "(нет)");
    printf("   resolver: %s:53/udp\n", t->server);
    if (ok && ip[0] && ip[0] != '(') {
        printf("   status:   OK  %d ms\n", ms);
        (*ok_n)++;
    } else if (ok) {
        printf("   status:   WARN  ответ без A  %d ms\n", ms);
    } else {
        printf("   status:   FAIL  нет UDP-ответа  %d ms\n", ms);
    }
}

static void print_dot(const DotTarget *t, int *ok_n) {
    char ip[64];
    const char *sni = dot_sni_for(t->host);
    int ms = 0, rc;

    resolve_ip(t->host, ip, sizeof ip);
    rc = dot_probe(t->host, &ms);
    printf("── %s\n", t->name);
    printf("   SNI:      %s\n", sni);
    printf("   URL:      tls://%s:853\n", t->host);
    printf("   IP:       %s\n", ip[0] ? ip : "(DNS fail)");
    printf("   port:     853/tcp (DoT)\n");
    if (rc == 2) {
        printf("   status:   OK  TLS+SNI handshake %d ms\n", ms);
        (*ok_n)++;
    } else if (rc == 1) {
        printf("   status:   WARN  TCP открыт, TLS нет  %d ms\n", ms);
    } else {
        printf("   status:   FAIL  закрыт/таймаут  %d ms\n", ms);
    }
}

static void print_doh(const DohTarget *t, int *ok_n) {
    char host[128], ip[64];
    int ms = 0, code;

    host_from_url(t->url, host, sizeof host);
    resolve_ip(host, ip, sizeof ip);
    code = doh_get(t->url, &ms);
    printf("── %s\n", t->name);
    printf("   SNI:      %s\n", host[0] ? host : "(нет)");
    printf("   URL:      %s\n", t->url);
    printf("   IP:       %s\n", ip[0] ? ip : "(DNS fail)");
    if (code == 200) {
        printf("   status:   OK  HTTP 200 dns-json  %d ms\n", ms);
        (*ok_n)++;
    } else if (code > 0) {
        printf("   status:   FAIL  HTTP %d  %d ms\n", code, ms);
    } else {
        printf("   status:   FAIL  нет ответа  %d ms\n", ms);
    }
}

static void run_round(int round) {
    char ts[32];
    int i, ok = 0, total;

    stamp(ts, sizeof ts);
    total = ncaptives + nresources + ndns + ndot + ndoh;
    printf("\n========== captive/DNS round #%d  %s ==========\n", round, ts);
    fflush(stdout);

    printf("\n— Captive / OS —\n");
    for (i = 0; i < ncaptives && g_run; i++)
        print_http(&captives[i], &ok);

    printf("\n— Ресурсы —\n");
    for (i = 0; i < nresources && g_run; i++)
        print_http(&resources[i], &ok);

    printf("\n— DNS —\n");
    for (i = 0; i < ndns && g_run; i++)
        print_dns(&dns_targets[i], &ok);

    printf("\n— DoT (TCP/853 + TLS) —\n");
    for (i = 0; i < ndot && g_run; i++)
        print_dot(&dot_targets[i], &ok);

    printf("\n— DoH (HTTPS dns-json) —\n");
    for (i = 0; i < ndoh && g_run; i++)
        print_doh(&doh_targets[i], &ok);

    printf("── итог: %d/%d OK\n", ok, total);
    fflush(stdout);
}

static void usage(const char *argv0) {
    fprintf(stderr,
            "Usage: %s [-i seconds] [-n rounds] [-h] [-V]\n"
            "  -i N   интервал между раундами (по умолчанию 120, макс. 120)\n"
            "  -n N   число раундов (0 = бесконечно)\n",
            argv0);
}

int main(int argc, char **argv) {
    int interval = 120;
    int max_rounds = 0;
    int round = 0;
    int i;

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-V") || !strcmp(argv[i], "--version")) {
            printf("%s %s\n", argv[0], CONNECT_CHECK_VERSION);
            return 0;
        }
        if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            usage(argv[0]);
            return 0;
        } else if (!strcmp(argv[i], "-i") && i + 1 < argc) {
            interval = atoi(argv[++i]);
            if (interval < 5) interval = 5;
            if (interval > 120) interval = 120;
        } else if (!strcmp(argv[i], "-n") && i + 1 < argc) {
            max_rounds = atoi(argv[++i]);
        } else {
            usage(argv[0]);
            return 1;
        }
    }

#ifdef _WIN32
    {
        WSADATA wsa;
        WSAStartup(MAKEWORD(2, 2), &wsa);
    }
#else
    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);
#endif

    printf("probe-captive — captive / DNS / DoT / DoH каждые %d с\n", interval);
    printf("Ctrl+C — выход. Проверок: %d\n", ncaptives + nresources + ndns + ndot + ndoh);

    while (g_run) {
        round++;
        run_round(round);
        if (max_rounds > 0 && round >= max_rounds) break;
        if (!g_run) break;
        printf("… следующий раунд через %d с\n", interval);
        fflush(stdout);
        for (i = 0; i < interval && g_run; i++) {
#ifdef _WIN32
            Sleep(1000);
#else
            sleep(1);
#endif
        }
    }

#ifdef _WIN32
    WSACleanup();
#endif
    printf("\nостановлено.\n");
    return 0;
}

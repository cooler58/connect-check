/*
 * probe-quic.c — периодическая проверка QUIC (UDP/443).
 * Раз в ≤2 мин поднимает сессию к каждому хосту, печатает SNI / URL / IP / порт.
 *
 *   make -f Makefile.probes quic
 *   ./probe-quic              # цикл каждые 120 с
 *   ./probe-quic -i 60       # интервал 60 с
 *   ./probe-quic -n 1        # один проход и выход
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

static int resolve_ip(const char *host, char *ip, size_t iplen) {
    struct addrinfo hints, *res = NULL;
    int rc;
    ip[0] = 0;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    rc = getaddrinfo(host, "443", &hints, &res);
    if (rc != 0 || !res) return 0;
    if (res->ai_family == AF_INET) {
        struct sockaddr_in *a = (struct sockaddr_in *)res->ai_addr;
        inet_ntop(AF_INET, &a->sin_addr, ip, (socklen_t)iplen);
    } else if (res->ai_family == AF_INET6) {
        struct sockaddr_in6 *a = (struct sockaddr_in6 *)res->ai_addr;
        inet_ntop(AF_INET6, &a->sin6_addr, ip, (socklen_t)iplen);
    }
    freeaddrinfo(res);
    return ip[0] != 0;
}

/* QUIC path probe: long-header with unknown version → Version Negotiation (RFC 9000).
 * Битый Initial v1 многие (Google/CF) молча дропают; unknown version — надёжный признак QUIC. */
static int quic_session(const char *host, int timeout_ms, int *ms_out, char *peer_ip, size_t peer_n) {
    struct addrinfo hints, *res = NULL, *ai;
    unsigned char pkt[1252];
    fd_set rset;
    struct timeval tv;
    long long t0;
    int ok = 0;

    if (ms_out) *ms_out = 0;
    if (peer_ip && peer_n) peer_ip[0] = 0;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    if (getaddrinfo(host, "443", &hints, &res) != 0) return 0;

    memset(pkt, 0, sizeof pkt);
    pkt[0] = 0xc0; /* long header, Initial type bits */
    /* unknown/grease version → сервер отвечает Version Negotiation */
    pkt[1] = 0x1a; pkt[2] = 0x1a; pkt[3] = 0x1a; pkt[4] = 0x1a;
    pkt[5] = 8;  /* DCID len */
    pkt[6] = 0xde; pkt[7] = 0xad; pkt[8] = 0xbe; pkt[9] = 0xef;
    pkt[10] = 0x01; pkt[11] = 0x02; pkt[12] = 0x03; pkt[13] = 0x04;
    pkt[14] = 0; /* SCID len */
    pkt[15] = 0; /* token length */
    pkt[16] = 0x40; pkt[17] = 0;

    for (ai = res; ai && !ok; ai = ai->ai_next) {
        sock_t s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s == SOCK_INVALID) continue;

        if (peer_ip && peer_n) {
            if (ai->ai_family == AF_INET) {
                struct sockaddr_in *a = (struct sockaddr_in *)ai->ai_addr;
                inet_ntop(AF_INET, &a->sin_addr, peer_ip, (socklen_t)peer_n);
            } else if (ai->ai_family == AF_INET6) {
                struct sockaddr_in6 *a = (struct sockaddr_in6 *)ai->ai_addr;
                inet_ntop(AF_INET6, &a->sin6_addr, peer_ip, (socklen_t)peer_n);
            }
        }

        t0 = now_ms();
        if (sendto(s, (const char *)pkt, 1200, 0, ai->ai_addr, (int)ai->ai_addrlen) > 0) {
            FD_ZERO(&rset);
            FD_SET(s, &rset);
            tv.tv_sec = timeout_ms / 1000;
            tv.tv_usec = (timeout_ms % 1000) * 1000;
#ifdef _WIN32
            if (select(0, &rset, NULL, NULL, &tv) > 0) {
#else
            if (select((int)s + 1, &rset, NULL, NULL, &tv) > 0) {
#endif
                char buf[1500];
                if (recvfrom(s, buf, sizeof buf, 0, NULL, NULL) > 0) ok = 1;
            }
            if (ms_out) *ms_out = (int)(now_ms() - t0);
        }
        sock_close(s);
    }
    freeaddrinfo(res);
    return ok;
}

typedef struct {
    const char *sni;
    const char *url;
} Target;

static Target targets[] = {
    /* База: Яндекс реально отвечает QUIC (контрольная «QUIC жив») */
    {"ya.ru",               "https://ya.ru/"},
    {"www.yandex.ru",       "https://www.yandex.ru/"},
    {"yastatic.net",        "https://yastatic.net/"},
    /* Зарубежные с Alt-Svc: h3 — если TCP/443 жив, а тут FAIL → DPI режет UDP/443 */
    {"www.google.com",      "https://www.google.com/"},
    {"www.youtube.com",     "https://www.youtube.com/"},
    {"cloudflare.com",      "https://cloudflare.com/"},
    {"discord.com",         "https://discord.com/"},
};
static const int ntargets = (int)(sizeof targets / sizeof targets[0]);

static void run_round(int round) {
    char ts[32];
    int i, ok_n = 0;
    stamp(ts, sizeof ts);
    printf("\n========== QUIC round #%d  %s ==========\n", round, ts);
    fflush(stdout);

    for (i = 0; i < ntargets && g_run; i++) {
        char ip[64] = "";
        int ms = 0, ok;
        const char *sni = targets[i].sni;
        const char *url = targets[i].url;

        resolve_ip(sni, ip, sizeof ip);
        ok = quic_session(sni, 2500, &ms, ip[0] ? NULL : ip, sizeof ip);

        printf("── %s\n", sni);
        printf("   SNI:    %s\n", sni);
        printf("   URL:    %s\n", url);
        printf("   IP:     %s\n", ip[0] ? ip : "(DNS fail)");
        printf("   port:   443/udp (QUIC)\n");
        if (ok) {
            printf("   status: OK  QUIC path (Version Negotiation) %d ms\n", ms);
            ok_n++;
        } else {
            printf("   status: FAIL  нет UDP-ответа на :443\n");
        }
        fflush(stdout);
    }
    printf("── итог: %d/%d OK\n", ok_n, ntargets);
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
            if (interval > 120) interval = 120; /* не реже 1 раза / 2 мин */
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

    printf("probe-quic — сессии QUIC (UDP/443) каждые %d с\n", interval);
    printf("Ctrl+C — выход. Хостов: %d\n", ntargets);

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

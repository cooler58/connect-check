/*
 * probe-mqtt.c — периодическая проверка MQTT (:1883) и MQTT/TLS (:8883).
 * Раз в ≤2 мин поднимает сессию к каждому брокеру, печатает SNI / URL / IP / порт.
 *
 * Plain MQTT: CONNECT → ждём CONNACK.
 * MQTTS: TCP + TLS ClientHello с SNI (путь TLS), затем hold.
 *
 *   make -f Makefile.probes mqtt
 *   ./probe-mqtt
 *   ./probe-mqtt -i 60 -n 1
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
#  include <fcntl.h>
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

static int resolve_ip(const char *host, int port, char *ip, size_t iplen) {
    struct addrinfo hints, *res = NULL;
    char portstr[16];
    ip[0] = 0;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(portstr, sizeof portstr, "%d", port);
    if (getaddrinfo(host, portstr, &hints, &res) != 0 || !res) return 0;
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

static int tcp_connect(const char *host, int port, int connect_ms,
                       char *peer_ip, size_t peer_n, sock_t *out) {
    struct addrinfo hints, *res = NULL, *ai;
    char portstr[16];
    sock_t s = SOCK_INVALID;
    int connected = 0, err = 0;
#ifdef _WIN32
    u_long nb = 1;
    int errlen = sizeof err;
#else
    int flags;
    socklen_t errlen = sizeof err;
#endif
    fd_set wset;
    struct timeval tv;

    *out = SOCK_INVALID;
    if (peer_ip && peer_n) peer_ip[0] = 0;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(portstr, sizeof portstr, "%d", port);
    if (getaddrinfo(host, portstr, &hints, &res) != 0) return -1;

    for (ai = res; ai && !connected; ai = ai->ai_next) {
        s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
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
#ifdef _WIN32
        ioctlsocket(s, FIONBIO, &nb);
        if (connect(s, ai->ai_addr, (int)ai->ai_addrlen) == 0) { connected = 1; break; }
        if (WSAGetLastError() == WSAEWOULDBLOCK) {
            FD_ZERO(&wset); FD_SET(s, &wset);
            tv.tv_sec = connect_ms / 1000; tv.tv_usec = (connect_ms % 1000) * 1000;
            if (select(0, NULL, &wset, NULL, &tv) > 0) {
                getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&err, &errlen);
                if (err == 0) { connected = 1; break; }
            }
        }
#else
        flags = fcntl(s, F_GETFL, 0);
        fcntl(s, F_SETFL, flags | O_NONBLOCK);
        if (connect(s, ai->ai_addr, ai->ai_addrlen) == 0) { connected = 1; break; }
        if (errno == EINPROGRESS) {
            FD_ZERO(&wset); FD_SET(s, &wset);
            tv.tv_sec = connect_ms / 1000; tv.tv_usec = (connect_ms % 1000) * 1000;
            if (select((int)s + 1, NULL, &wset, NULL, &tv) > 0) {
                getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &errlen);
                if (err == 0) { connected = 1; break; }
            }
        }
#endif
        sock_close(s); s = SOCK_INVALID;
    }
    freeaddrinfo(res);
    if (!connected) return -1;
#ifdef _WIN32
    nb = 0; ioctlsocket(s, FIONBIO, &nb);
#else
    flags = fcntl(s, F_GETFL, 0);
    fcntl(s, F_SETFL, flags & ~O_NONBLOCK);
#endif
    *out = s;
    return 0;
}

static int wait_recv(sock_t s, unsigned char *buf, int buflen, int timeout_ms) {
    fd_set rset;
    struct timeval tv;
    FD_ZERO(&rset);
    FD_SET(s, &rset);
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
#ifdef _WIN32
    if (select(0, &rset, NULL, NULL, &tv) <= 0) return -1;
#else
    if (select((int)s + 1, &rset, NULL, NULL, &tv) <= 0) return -1;
#endif
    return (int)recv(s, (char *)buf, buflen, 0);
}

/* MQTT 3.1.1 CONNECT (clean session, keepalive 60), expect CONNACK */
static int mqtt_connect_session(sock_t s, const char *client_id, int *ms_out) {
    unsigned char pkt[128];
    unsigned char resp[16];
    size_t id_len = strlen(client_id);
    size_t rem;
    int n;
    long long t0 = now_ms();

    if (id_len > 40) id_len = 40;

    /* Fixed header: CONNECT (0x10), Remaining Length */
    rem = 10 + 2 + id_len; /* variable header 10 + payload */
    pkt[0] = 0x10;
    pkt[1] = (unsigned char)rem;
    /* Protocol Name "MQTT" */
    pkt[2] = 0x00; pkt[3] = 0x04;
    pkt[4] = 'M'; pkt[5] = 'Q'; pkt[6] = 'T'; pkt[7] = 'T';
    pkt[8] = 0x04; /* protocol level 4 = 3.1.1 */
    pkt[9] = 0x02; /* clean session */
    pkt[10] = 0x00; pkt[11] = 60; /* keepalive */
    pkt[12] = 0x00; pkt[13] = (unsigned char)id_len;
    memcpy(pkt + 14, client_id, id_len);

    if (send(s, (const char *)pkt, (int)(14 + id_len), 0) <= 0) return 0;
    n = wait_recv(s, resp, sizeof resp, 4000);
    if (ms_out) *ms_out = (int)(now_ms() - t0);
    /* CONNACK: 0x20, len 0x02, flags, return code 0 */
    if (n >= 4 && resp[0] == 0x20 && resp[3] == 0x00) return 1;
    return 0;
}

static int tls_clienthello_sni(sock_t s, const char *sni, int timeout_ms) {
    unsigned char pkt[512];
    unsigned char *p = pkt;
    size_t sni_len = strlen(sni);
    size_t ext_len, hello_len, rec_len;
    unsigned char resp[1500];
    int n;

    if (sni_len > 200) return 0;
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

static void hold_idle(sock_t s, int hold_ms) {
    long long end = now_ms() + hold_ms;
    fd_set rset;
    struct timeval tv;
    char junk[8];
    while (now_ms() < end && g_run) {
        long long left = end - now_ms();
        int slice = left > 400 ? 400 : (int)left;
        if (slice < 1) break;
        FD_ZERO(&rset);
        FD_SET(s, &rset);
        tv.tv_sec = slice / 1000;
        tv.tv_usec = (slice % 1000) * 1000;
#ifdef _WIN32
        if (select(0, &rset, NULL, NULL, &tv) > 0) {
#else
        if (select((int)s + 1, &rset, NULL, NULL, &tv) > 0) {
#endif
            if (recv(s, junk, sizeof junk, 0) <= 0) return;
        }
    }
}

typedef struct {
    const char *name;
    const char *host; /* SNI */
    const char *url;
    int port;
    int mqtt_plain; /* 1 = MQTT CONNECT on wire; 0 = MQTTS path (TLS+SNI) */
} Target;

static Target targets[] = {
    {"Mosquitto MQTT :1883",   "test.mosquitto.org",   "mqtt://test.mosquitto.org:1883",     1883, 1},
    {"Mosquitto MQTTS :8883",  "test.mosquitto.org",   "mqtts://test.mosquitto.org:8883",    8883, 0},
    {"Tuya MQTT EU mb",        "mq.mb.tuyaeu.com",     "mqtts://mq.mb.tuyaeu.com:8883",      8883, 0},
    {"Tuya MQTT GW EU",        "mq.gw.tuyaeu.com",     "mqtts://mq.gw.tuyaeu.com:8883",      8883, 0},
    {"Tuya MQTT US",           "mq.mb.tuyaus.com",     "mqtts://mq.mb.tuyaus.com:8883",      8883, 0},
    {"HiveMQ public :1883",    "broker.hivemq.com",    "mqtt://broker.hivemq.com:1883",      1883, 1},
};
static const int ntargets = (int)(sizeof targets / sizeof targets[0]);

static void run_round(int round) {
    char ts[32];
    int i, ok_n = 0;
    stamp(ts, sizeof ts);
    printf("\n========== MQTT round #%d  %s ==========\n", round, ts);
    fflush(stdout);

    for (i = 0; i < ntargets && g_run; i++) {
        Target *t = &targets[i];
        char ip[64] = "";
        char cid[48];
        sock_t s = SOCK_INVALID;
        int ms = 0, ok = 0;
        long long t0;

        resolve_ip(t->host, t->port, ip, sizeof ip);
        snprintf(cid, sizeof cid, "cc-%d-%d", (int)(now_ms() % 100000), i);

        t0 = now_ms();
        if (tcp_connect(t->host, t->port, 5000, ip[0] ? NULL : ip, sizeof ip, &s) == 0) {
            if (t->mqtt_plain) {
                if (mqtt_connect_session(s, cid, &ms)) {
                    hold_idle(s, 1200);
                    ok = 1;
                }
            } else {
                /* MQTTS: TLS ClientHello with SNI — проверяем путь TLS к брокеру */
                if (tls_clienthello_sni(s, t->host, 4000)) {
                    ms = (int)(now_ms() - t0);
                    hold_idle(s, 1200);
                    ok = 1;
                } else {
                    ms = (int)(now_ms() - t0);
                }
            }
            sock_close(s);
        } else {
            ms = (int)(now_ms() - t0);
        }

        printf("── %s\n", t->name);
        printf("   SNI:    %s\n", t->host);
        printf("   URL:    %s\n", t->url);
        printf("   IP:     %s\n", ip[0] ? ip : "(DNS fail)");
        printf("   port:   %d/tcp (%s)\n", t->port, t->mqtt_plain ? "MQTT" : "MQTT/TLS");
        if (ok) {
            if (t->mqtt_plain)
                printf("   status: OK  CONNECT/CONNACK %d ms, session held\n", ms);
            else
                printf("   status: OK  TLS+SNI handshake path %d ms, session held\n", ms);
            ok_n++;
        } else {
            printf("   status: FAIL  нет сессии\n");
        }
        fflush(stdout);
    }
    printf("── итог: %d/%d OK\n", ok_n, ntargets);
    fflush(stdout);
}

static void usage(const char *argv0) {
    fprintf(stderr,
            "Usage: %s [-i seconds] [-n rounds] [-h] [-V]\n"
            "  -i N   интервал (по умолчанию 120, макс. 120)\n"
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
    { WSADATA wsa; WSAStartup(MAKEWORD(2, 2), &wsa); }
#else
    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);
#endif

    printf("probe-mqtt — MQTT / MQTT-TLS сессии каждые %d с\n", interval);
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

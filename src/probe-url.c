/*
 * probe-url.c — непрерывно долбит заданный URL.
 *
 *   make -f Makefile.probes url
 *   ./probe-url https://ya.ru/
 *   ./probe-url -i 30 https://www.google.com/generate_204
 *   ./probe-url -n 5 http://connectivitycheck.gstatic.com/generate_204
 *   ./probe-url -f https://example.com/   # follow redirects
 */

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "version.h"

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  pragma comment(lib, "ws2_32.lib")
#else
#  include <unistd.h>
#  include <sys/types.h>
#  include <sys/socket.h>
#  include <sys/time.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <netdb.h>
#  include <signal.h>
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

static int http_get(const char *url, int follow, int *ms_out, char *redir, size_t redir_n,
                    char *final_url, size_t final_n) {
    char cmd[1536], out[512];
    FILE *f;
    long long t0 = now_ms();
    int code = 0;

    if (ms_out) *ms_out = 0;
    if (redir && redir_n) redir[0] = 0;
    if (final_url && final_n) final_url[0] = 0;

#ifdef _WIN32
    snprintf(cmd, sizeof cmd,
             "curl.exe -sS --max-time 15 --connect-timeout 8 --http1.1 "
             "-A \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
             "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36\" "
             "%s -w \"%%{http_code}\\t%%{time_total}\\t%%{url_effective}\\t%%{redirect_url}\" "
             "-o NUL \"%s\" 2>NUL",
             follow ? "-L --max-redirs 8" : "--max-redirs 0", url);
#else
    snprintf(cmd, sizeof cmd,
             "curl -sS --max-time 15 --connect-timeout 8 --http1.1 "
             "-A 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
             "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36' "
             "%s -w '%%{http_code}\\t%%{time_total}\\t%%{url_effective}\\t%%{redirect_url}' "
             "-o /dev/null '%s' 2>/dev/null",
             follow ? "-L --max-redirs 8" : "--max-redirs 0", url);
#endif
    f = popen(cmd, "r");
    if (!f) return 0;
    out[0] = 0;
    if (fgets(out, sizeof out, f)) {
        char *p = out;
        char *tab;
        double sec;
        code = atoi(p);
        tab = strchr(p, '\t');
        if (tab) {
            sec = atof(tab + 1);
            if (ms_out) *ms_out = (int)(sec * 1000 + 0.5);
            tab = strchr(tab + 1, '\t');
            if (tab && final_url && final_n) {
                char *tab2 = strchr(tab + 1, '\t');
                size_t len;
                tab++;
                if (tab2) len = (size_t)(tab2 - tab);
                else len = strlen(tab);
                while (len > 0 && (tab[len - 1] == '\n' || tab[len - 1] == '\r')) len--;
                if (len >= final_n) len = final_n - 1;
                memcpy(final_url, tab, len);
                final_url[len] = 0;
                if (tab2 && redir && redir_n) {
                    tab2++;
                    while (*tab2 == ' ' || *tab2 == '\t') tab2++;
                    snprintf(redir, redir_n, "%s", tab2);
                    len = strlen(redir);
                    while (len > 0 && (redir[len - 1] == '\n' || redir[len - 1] == '\r'))
                        redir[--len] = 0;
                    if (strcmp(redir, "0") == 0) redir[0] = 0;
                }
            }
        }
    }
    pclose(f);
    if (ms_out && *ms_out == 0) *ms_out = (int)(now_ms() - t0);
    return code;
}

static void usage(const char *argv0) {
    fprintf(stderr,
            "Usage: %s [options] <url>\n"
            "  -i N   интервал между запросами, сек (по умолчанию 5, макс. 120)\n"
            "  -n N   число запросов (0 = бесконечно)\n"
            "  -f     следовать редиректам (по умолчанию нет — виден Location)\n"
            "         301/302/303 без -f = REDIR (не FAIL): сервер отвечает\n"
            "  -h     справка\n"
            "  -V     версия\n"
            "\n"
            "Примеры:\n"
            "  %s https://ya.ru/\n"
            "  %s -i 10 -f https://www.google.com/\n"
            "  %s -i 2 http://connectivitycheck.gstatic.com/generate_204\n",
            argv0, argv0, argv0, argv0);
}

int main(int argc, char **argv) {
    const char *url = NULL;
    int interval = 5;
    int max_rounds = 0;
    int follow = 0;
    int round = 0;
    int ok_n = 0, fail_n = 0;
    int i;
    char host[256], ip[64];

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
            if (interval < 1) interval = 1;
            if (interval > 120) interval = 120;
        } else if (!strcmp(argv[i], "-n") && i + 1 < argc) {
            max_rounds = atoi(argv[++i]);
        } else if (!strcmp(argv[i], "-f") || !strcmp(argv[i], "--follow")) {
            follow = 1;
        } else if (argv[i][0] == '-') {
            usage(argv[0]);
            return 1;
        } else if (!url) {
            url = argv[i];
        } else {
            usage(argv[0]);
            return 1;
        }
    }

    if (!url || (strncmp(url, "http://", 7) != 0 && strncmp(url, "https://", 8) != 0)) {
        fprintf(stderr, "Нужен URL вида http://… или https://…\n\n");
        usage(argv[0]);
        return 1;
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

    host_from_url(url, host, sizeof host);
    resolve_ip(host, ip, sizeof ip);

    printf("probe-url — непрерывно → %s\n", url);
    printf("host=%s  IP=%s  interval=%ds  follow=%s\n",
           host, ip[0] ? ip : "(DNS?)", interval, follow ? "yes" : "no");
    printf("Ctrl+C — выход.\n");

    while (g_run) {
        char ts[32], redir[512], finalu[512];
        int ms = 0, code;
        round++;
        stamp(ts, sizeof ts);
        resolve_ip(host, ip, sizeof ip);
        code = http_get(url, follow, &ms, redir, sizeof redir, finalu, sizeof finalu);

        printf("\n── #%d  %s\n", round, ts);
        printf("   SNI/host: %s\n", host);
        printf("   URL:      %s\n", url);
        printf("   IP:       %s\n", ip[0] ? ip : "(DNS fail)");
        if (finalu[0] && strcmp(finalu, url) != 0)
            printf("   final:    %s\n", finalu);
        if (redir[0])
            printf("   redirect: %s\n", redir);

        if (code > 0) {
            if (code >= 200 && code < 300) {
                printf("   status:   OK  HTTP %d  %d ms\n", code, ms);
                ok_n++;
            } else if (code >= 300 && code < 400) {
                /* 301/302/303/307/308 — сервер ответил, просто редирект (не сбой) */
                printf("   status:   REDIR  HTTP %d  %d ms%s\n", code, ms,
                       follow ? "" : "  (без -f цепочку не идём)");
                ok_n++;
            } else {
                printf("   status:   FAIL  HTTP %d  %d ms\n", code, ms);
                fail_n++;
            }
        } else {
            printf("   status:   FAIL  нет ответа  %d ms\n", ms);
            fail_n++;
        }
        printf("   tally:    OK/REDIR=%d FAIL=%d\n", ok_n, fail_n);
        fflush(stdout);

        if (max_rounds > 0 && round >= max_rounds) break;
        if (!g_run) break;
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
    printf("\nостановлено. OK=%d FAIL=%d\n", ok_n, fail_n);
    return fail_n > 0 && ok_n == 0 ? 1 : 0;
}

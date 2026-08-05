/* In-process cyclic probes (formerly probe-* binaries). */
#define _CRT_SECURE_NO_WARNINGS
#include "cc_engine.h"
#include "version.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <stdarg.h>

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#  include <winsock2.h>
#  include <ws2tcpip.h>
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
typedef int sock_t;
#  define SOCK_INVALID (-1)
#  define sock_close close
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

static void plog(void (*log_line)(void *, const char *), void *ud, const char *line) {
    if (log_line) log_line(ud, line ? line : "");
}

static void plogf(void (*log_line)(void *, const char *), void *ud, const char *fmt, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    plog(log_line, ud, buf);
}

static int cancelled(volatile int *cancel) {
    return cancel && *cancel;
}

static void sleep_sec(int sec, volatile int *cancel) {
    int i;
    for (i = 0; i < sec && !cancelled(cancel); i++) {
#ifdef _WIN32
        Sleep(1000);
#else
        sleep(1);
#endif
    }
}

static int tcp_open_host(const char *host, int port, int timeout_ms, int *ms_out) {
    struct addrinfo hints, *res = NULL, *rp;
    char portstr[16];
    long long t0 = now_ms();
    int ok = 0;
    if (ms_out) *ms_out = 0;
    memset(&hints, 0, sizeof hints);
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
    snprintf(portstr, sizeof portstr, "%d", port);
    if (getaddrinfo(host, portstr, &hints, &res) != 0) return 0;
    for (rp = res; rp; rp = rp->ai_next) {
        sock_t s = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (s == SOCK_INVALID) continue;
#ifdef _WIN32
        {
            DWORD t = (DWORD)timeout_ms;
            setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&t, sizeof t);
            setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char *)&t, sizeof t);
        }
#else
        {
            struct timeval tv;
            tv.tv_sec = timeout_ms / 1000;
            tv.tv_usec = (timeout_ms % 1000) * 1000;
            setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
            setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
        }
#endif
        if (connect(s, rp->ai_addr, (socklen_t)rp->ai_addrlen) == 0) {
            ok = 1;
            sock_close(s);
            break;
        }
        sock_close(s);
    }
    freeaddrinfo(res);
    if (ms_out) *ms_out = (int)(now_ms() - t0);
    return ok;
}

static int http_code(const char *url, int follow, int *ms_out) {
    char cmd[1536], out[64];
    FILE *fp;
    long long t0 = now_ms();
    int code = 0;
    if (ms_out) *ms_out = 0;
#ifdef _WIN32
    snprintf(cmd, sizeof cmd,
             "curl.exe -sS -o NUL -w \"%%{http_code}\" --max-time 10 --connect-timeout 8 "
             "%s \"%s\" 2>NUL",
             follow ? "-L --max-redirs 5" : "--max-redirs 0", url);
#else
    snprintf(cmd, sizeof cmd,
             "curl -sS -o /dev/null -w '%%{http_code}' --max-time 10 --connect-timeout 8 "
             "%s '%s' 2>/dev/null",
             follow ? "-L --max-redirs 5" : "--max-redirs 0", url);
#endif
    fp = popen(cmd, "r");
    if (!fp) return 0;
    if (fgets(out, sizeof out, fp)) code = atoi(out);
    pclose(fp);
    if (ms_out) *ms_out = (int)(now_ms() - t0);
    return code;
}

const char *cc_probe_kind_name(CcProbeKind kind) {
    switch (kind) {
    case CC_PROBE_CAPTIVE: return "Captive / DNS";
    case CC_PROBE_QUIC: return "QUIC";
    case CC_PROBE_BATTLENET: return "Battle.net";
    case CC_PROBE_MQTT: return "MQTT";
    case CC_PROBE_VIDEO: return "Видео";
    case CC_PROBE_URL: return "URL";
    default: return "probe";
    }
}

static int run_url(const CcProbeOpts *opts,
                   void (*log_line)(void *, const char *), void *ud,
                   volatile int *cancel) {
    int interval = opts && opts->interval_sec > 0 ? opts->interval_sec : 5;
    int max_rounds = opts ? opts->rounds : 0;
    int follow = opts ? opts->follow : 0;
    const char *url = opts ? opts->url : "";
    int round = 0, ok_n = 0, fail_n = 0;
    if (!url[0]) {
        plog(log_line, ud, "URL: укажите адрес http(s)://…");
        return -1;
    }
    plogf(log_line, ud, "URL-проба → %s (interval=%ds follow=%s)",
          url, interval, follow ? "yes" : "no");
    while (!cancelled(cancel)) {
        char ts[32];
        int ms = 0, code;
        round++;
        stamp(ts, sizeof ts);
        code = http_code(url, follow, &ms);
        if (code >= 200 && code < 400) {
            plogf(log_line, ud, "#%d %s OK HTTP %d %d ms", round, ts, code, ms);
            ok_n++;
        } else {
            plogf(log_line, ud, "#%d %s FAIL HTTP %d %d ms", round, ts, code, ms);
            fail_n++;
        }
        if (max_rounds > 0 && round >= max_rounds) break;
        sleep_sec(interval, cancel);
    }
    plogf(log_line, ud, "остановлено. OK=%d FAIL=%d", ok_n, fail_n);
    return fail_n > 0 && ok_n == 0 ? 1 : 0;
}

static int run_captive(const CcProbeOpts *opts,
                       void (*log_line)(void *, const char *), void *ud,
                       volatile int *cancel) {
    static const struct { const char *name, *url; int expect; } targets[] = {
        {"Google gstatic", "http://connectivitycheck.gstatic.com/generate_204", 204},
        {"Apple captive", "http://captive.apple.com/hotspot-detect.html", 200},
        {"Microsoft NCSI", "http://www.msftconnecttest.com/connecttest.txt", 200},
        {"Ya.ru", "https://ya.ru/", 0},
        {"Google", "https://www.google.com/", 0},
    };
    int interval = opts && opts->interval_sec > 0 ? opts->interval_sec : 120;
    int max_rounds = opts ? opts->rounds : 0;
    int round = 0;
    plogf(log_line, ud, "Captive/DNS-проба каждые %d с", interval);
    while (!cancelled(cancel)) {
        char ts[32];
        int i, ok = 0;
        round++;
        stamp(ts, sizeof ts);
        plogf(log_line, ud, "── #%d  %s", round, ts);
        for (i = 0; i < (int)(sizeof targets / sizeof targets[0]) && !cancelled(cancel); i++) {
            int ms = 0, code = http_code(targets[i].url, targets[i].expect ? 0 : 1, &ms);
            int good = targets[i].expect ? (code == targets[i].expect)
                                         : (code >= 200 && code < 400);
            plogf(log_line, ud, "  %s: %s HTTP %d %d ms",
                  targets[i].name, good ? "OK" : "FAIL", code, ms);
            if (good) ok++;
        }
        plogf(log_line, ud, "  tally OK-ish=%d/%d", ok, (int)(sizeof targets / sizeof targets[0]));
        if (max_rounds > 0 && round >= max_rounds) break;
        sleep_sec(interval, cancel);
    }
    return 0;
}

static int run_tcp_list(const char *title, const char *hosts[][2], int nhosts,
                        const CcProbeOpts *opts,
                        void (*log_line)(void *, const char *), void *ud,
                        volatile int *cancel) {
    int interval = opts && opts->interval_sec > 0 ? opts->interval_sec : 120;
    int max_rounds = opts ? opts->rounds : 0;
    int round = 0;
    plogf(log_line, ud, "%s каждые %d с", title, interval);
    while (!cancelled(cancel)) {
        char ts[32];
        int i, ok = 0;
        round++;
        stamp(ts, sizeof ts);
        plogf(log_line, ud, "── #%d  %s", round, ts);
        for (i = 0; i < nhosts && !cancelled(cancel); i++) {
            int port = atoi(hosts[i][1]);
            int ms = 0, good = tcp_open_host(hosts[i][0], port, 5000, &ms);
            plogf(log_line, ud, "  %s:%d %s %d ms", hosts[i][0], port,
                  good ? "OK" : "FAIL", ms);
            if (good) ok++;
        }
        plogf(log_line, ud, "  tally OK=%d/%d", ok, nhosts);
        if (max_rounds > 0 && round >= max_rounds) break;
        sleep_sec(interval, cancel);
    }
    return 0;
}

static int run_http_list(const char *title, const char *urls[], int nurl,
                         const CcProbeOpts *opts,
                         void (*log_line)(void *, const char *), void *ud,
                         volatile int *cancel) {
    int interval = opts && opts->interval_sec > 0 ? opts->interval_sec : 120;
    int max_rounds = opts ? opts->rounds : 0;
    int round = 0;
    plogf(log_line, ud, "%s каждые %d с", title, interval);
    while (!cancelled(cancel)) {
        char ts[32];
        int i, ok = 0;
        round++;
        stamp(ts, sizeof ts);
        plogf(log_line, ud, "── #%d  %s", round, ts);
        for (i = 0; i < nurl && !cancelled(cancel); i++) {
            int ms = 0, code = http_code(urls[i], 1, &ms);
            int good = code >= 200 && code < 500;
            plogf(log_line, ud, "  %s → HTTP %d %s %d ms", urls[i], code,
                  good ? "OK" : "FAIL", ms);
            if (good) ok++;
        }
        plogf(log_line, ud, "  tally OK=%d/%d", ok, nurl);
        if (max_rounds > 0 && round >= max_rounds) break;
        sleep_sec(interval, cancel);
    }
    return 0;
}

int cc_probe_run(CcProbeKind kind, const CcProbeOpts *opts,
                 void (*log_line)(void *ud, const char *line), void *ud,
                 volatile int *cancel) {
#ifdef _WIN32
    {
        WSADATA wsa;
        static int once;
        if (!once) {
            if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return -1;
            once = 1;
        }
    }
#endif
    switch (kind) {
    case CC_PROBE_URL:
        return run_url(opts, log_line, ud, cancel);
    case CC_PROBE_CAPTIVE:
        return run_captive(opts, log_line, ud, cancel);
    case CC_PROBE_BATTLENET: {
        static const char *hosts[][2] = {
            {"battle.net", "443"},
            {"account.battle.net", "443"},
            {"eu.actual.battle.net", "1119"},
        };
        return run_tcp_list("Battle.net", hosts, 3, opts, log_line, ud, cancel);
    }
    case CC_PROBE_MQTT: {
        static const char *hosts[][2] = {
            {"mq.mb.tuyaeu.com", "8883"},
            {"mq.gw.tuyaeu.com", "8883"},
            {"test.mosquitto.org", "8883"},
        };
        return run_tcp_list("MQTT/TLS", hosts, 3, opts, log_line, ud, cancel);
    }
    case CC_PROBE_QUIC: {
        /* QUIC full handshake is heavy; TCP:443 canary + note */
        static const char *hosts[][2] = {
            {"ya.ru", "443"},
            {"www.google.com", "443"},
            {"cloudflare.com", "443"},
        };
        plog(log_line, ud, "QUIC: TCP:443 canary (полный UDP/QUIC — в диагностике DPI)");
        return run_tcp_list("QUIC canary", hosts, 3, opts, log_line, ud, cancel);
    }
    case CC_PROBE_VIDEO: {
        static const char *urls[] = {
            "https://ya.ru/video/",
            "https://vkvideo.ru/",
            "https://www.ivi.ru/",
            "https://rutube.ru/",
        };
        return run_http_list("Видео РФ", urls, 4, opts, log_line, ud, cancel);
    }
    default:
        plog(log_line, ud, "неизвестный тип пробы");
        return -1;
    }
}

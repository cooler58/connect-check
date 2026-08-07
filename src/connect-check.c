/*
 * connect-check.c — диагностика доступа в интернет (ПК, TV, IoT, телефоны).
 *
 * Windows:  make -f Makefile.diagnose win
 * Unix:     make -f Makefile.diagnose
 */

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>

#include "version.h"
#include "selfupdate.h"
#include "cc_engine.h"

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <iphlpapi.h>
#  include <icmpapi.h>
#  include <wininet.h>
#  include <shellapi.h>
#  include <process.h>
#  include <io.h>
#  pragma comment(lib, "ws2_32.lib")
#  pragma comment(lib, "iphlpapi.lib")
#  pragma comment(lib, "wininet.lib")
#  pragma comment(lib, "shell32.lib")
#else
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <termios.h>
#include <signal.h>
#include <pthread.h>
/* macOS: системный curl/LibreSSL ломает TLS к части госсайтов (gosuslugi и др.). */
#ifdef __APPLE__
#define CURL_SSL_ENV "CURL_SSL_BACKEND=secure-transport "
#else
#define CURL_SSL_ENV ""
#endif
#endif

#define MAX_CHECKS   1024
#define MAX_FINDINGS 160
#define MAX_DNS      8
#define MAX_DOMAINS  10000
#define STR          512
#define LONGSTR      1024
#define PING_STR     768
#define TRACE_STR    4096
#define DEFAULT_JOBS 32

typedef struct {
    char category[96];
    char name[128];
    char status[12];
    char detail[STR];
    char hint[STR];
    char resolved_ip[64];
    char diag_url[256];
    char ping_text[PING_STR];
    char trace_text[TRACE_STR];
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
    int ms;         /* для multi-UA — среднее; иначе время пробы */
    int xfer_ms;    /* время именно той пробы, что дала .bytes (для скорости) */
    long bytes;     /* размер скачанного документа (после decompress) */
    int antibot;    /* 1 = WAF/captcha/JS-challenge, хост отвечает */
    char redirect[STR];
    char error[STR];
    char body[512]; /* префикс тела для детекта antibot */
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
static int opt_jobs = DEFAULT_JOBS; /* параллельные пробы внутри этапа */
static int opt_dns_limit = 1000; /* полный прогон: --dns-limit 10000 */
static int g_sys_dns_broken; /* getaddrinfo не резолвит известные имена — remote-этапы бессмысленны */
static char domains_path[STR];
static char resources_path[STR]; /* --resources FILE; иначе автопоиск */
static char resources_loaded[STR]; /* фактический путь загруженного conf (для отчёта) */
static char output_dir[STR];
static char report_path[STR];
static char stamp[32];
static char generated[64];
static char exe_dir[STR];
static int g_resources_from_file; /* 1 = resources.conf (или --resources) */

/* ---- engine callbacks (GUI / library) ---- */
static const CcCallbacks *g_engine_cb;
static volatile int g_engine_cancel;
static int g_engine_lib_mode; /* 1 = quiet console, prefer callbacks */

void cc_engine_request_cancel(void) { g_engine_cancel = 1; }
void cc_engine_clear_cancel(void) { g_engine_cancel = 0; }
int cc_engine_cancel_requested(void) { return g_engine_cancel ? 1 : 0; }

static void engine_log(const char *line) {
    if (g_engine_cb && g_engine_cb->on_log)
        g_engine_cb->on_log(g_engine_cb->userdata, line ? line : "");
    else if (!g_engine_lib_mode && line)
        printf("%s\n", line);
}

static void engine_logf(const char *fmt, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    engine_log(buf);
}

/* прогресс этапа (в т.ч. подшаги UA) */
static char g_prog_item[48];
static int g_prog_cur;
static int g_prog_total;
static void stage_progress(const char *msg, int cur, int total);
static void stage_done(void);
static void host_from_url(const char *url, char *host, size_t hostlen);

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
    if (g_engine_cb && g_engine_cb->on_check)
        g_engine_cb->on_check(g_engine_cb->userdata, cat, name, st, detail ? detail : "");
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
    if (g_engine_cb && g_engine_cb->on_finding)
        g_engine_cb->on_finding(g_engine_cb->userdata, level ? level : "", title ? title : "",
                                text ? text : "");
}

/* ---------- parallel jobs ---------- */

#ifdef _WIN32
static CRITICAL_SECTION g_out_cs;
static volatile LONG g_out_cs_init;
static void out_lock_init(void) {
    if (InterlockedCompareExchange(&g_out_cs_init, 1, 0) == 0)
        InitializeCriticalSection(&g_out_cs);
}
static void out_lock(void) { out_lock_init(); EnterCriticalSection(&g_out_cs); }
static void out_unlock(void) { LeaveCriticalSection(&g_out_cs); }
static int atomic_fetch_add(volatile int *p) {
    return (int)InterlockedIncrement((volatile LONG *)p) - 1;
}
#else
static pthread_mutex_t g_out_mu = PTHREAD_MUTEX_INITIALIZER;
static void out_lock(void) { pthread_mutex_lock(&g_out_mu); }
static void out_unlock(void) { pthread_mutex_unlock(&g_out_mu); }
static int atomic_fetch_add(volatile int *p) {
    return __sync_fetch_and_add(p, 1);
}
#endif

typedef void (*JobFn)(int idx, void *ctx);

typedef struct {
    volatile int next;
    volatile int done;
    int n;
    JobFn fn;
    void *ctx;
    const char *prog_label;
} ParallelState;

static void stage_progress(const char *msg, int cur, int total);
static void stage_done(void);

#ifdef _WIN32
static unsigned __stdcall parallel_worker(void *arg) {
#else
static void *parallel_worker(void *arg) {
#endif
    ParallelState *st = (ParallelState *)arg;
    for (;;) {
        int i = atomic_fetch_add(&st->next);
        int done;
        if (i >= st->n) break;
        st->fn(i, st->ctx);
        done = atomic_fetch_add(&st->done) + 1;
        if (st->prog_label) {
            out_lock();
            stage_progress(st->prog_label, done, st->n);
            out_unlock();
        }
    }
#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

static int jobs_clamp(int n, int jobs) {
    if (jobs < 1) jobs = 1;
    if (jobs > 256) jobs = 256;
    if (n < 1) return 1;
    if (jobs > n) jobs = n;
    return jobs;
}

static void run_parallel(int n, int jobs, JobFn fn, void *ctx, const char *prog_label) {
    ParallelState st;
    int w, nw;
    if (n <= 0 || !fn) return;
    if (n == 1 || jobs <= 1) {
        int i;
        for (i = 0; i < n; i++) {
            fn(i, ctx);
            if (prog_label) stage_progress(prog_label, i + 1, n);
        }
        return;
    }
    nw = jobs_clamp(n, jobs);
    memset(&st, 0, sizeof st);
    st.n = n;
    st.fn = fn;
    st.ctx = ctx;
    st.prog_label = prog_label;
#ifdef _WIN32
    {
        HANDLE *ths = (HANDLE *)calloc((size_t)nw, sizeof(HANDLE));
        if (!ths) {
            for (w = 0; w < n; w++) fn(w, ctx);
            return;
        }
        for (w = 0; w < nw; w++)
            ths[w] = (HANDLE)_beginthreadex(NULL, 0, parallel_worker, &st, 0, NULL);
        for (w = 0; w < nw; w++) {
            if (ths[w]) {
                WaitForSingleObject(ths[w], INFINITE);
                CloseHandle(ths[w]);
            }
        }
        free(ths);
    }
#else
    {
        pthread_t *ths = (pthread_t *)calloc((size_t)nw, sizeof(pthread_t));
        if (!ths) {
            for (w = 0; w < n; w++) fn(w, ctx);
            return;
        }
        for (w = 0; w < nw; w++) {
            if (pthread_create(&ths[w], NULL, parallel_worker, &st) != 0)
                ths[w] = 0;
        }
        for (w = 0; w < nw; w++) {
            if (ths[w]) pthread_join(ths[w], NULL);
        }
        free(ths);
    }
#endif
}

static void check_set(Check *c, const char *cat, const char *name, const char *st,
                      const char *detail, const char *hint,
                      const char *ip, const char *url, int spoiler) {
    memset(c, 0, sizeof *c);
    snprintf(c->category, sizeof c->category, "%s", cat ? cat : "");
    snprintf(c->name, sizeof c->name, "%s", name ? name : "");
    snprintf(c->status, sizeof c->status, "%s", st ? st : "info");
    snprintf(c->detail, sizeof c->detail, "%s", detail ? detail : "");
    snprintf(c->hint, sizeof c->hint, "%s", hint ? hint : "");
    if (ip && ip[0]) snprintf(c->resolved_ip, sizeof c->resolved_ip, "%s", ip);
    if (url && url[0]) snprintf(c->diag_url, sizeof c->diag_url, "%s", url);
    c->spoiler = spoiler;
}

static void add_check_from(const Check *src) {
    Check *c;
    if (!src || nchecks >= MAX_CHECKS) return;
    c = &checks[nchecks++];
    *c = *src;
    if (strcmp(c->status, "ok") == 0) ok_n++;
    else if (strcmp(c->status, "warn") == 0) warn_n++;
    else if (strcmp(c->status, "fail") == 0) fail_n++;
    if (g_engine_cb && g_engine_cb->on_check)
        g_engine_cb->on_check(g_engine_cb->userdata, c->category, c->name, c->status, c->detail);
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
    if (strcmp(host, "77.88.8.8") == 0 || strcmp(host, "77.88.8.1") == 0)
        return "common.dot.dns.yandex.net";
    if (strcmp(host, "94.140.14.14") == 0 || strcmp(host, "94.140.15.15") == 0)
        return "dns.adguard-dns.com";
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

static void check_tcp_ep_fill(Check *out, const char *cat, const char *name,
                              const char *host, int port, int timeout_ms,
                              int critical, int spoiler, int *crit_fail) {
    char detail[STR], hint[STR], ip[64], url[256];
    long long t0;
    int open;
    if (crit_fail) *crit_fail = 0;
    snprintf(url, sizeof url, "https://%s/", host);
    if (!dns_resolve(host, ip, sizeof ip)) {
        snprintf(detail, sizeof detail, "DNS не резолвит %s", host);
        check_set(out, cat, name, "warn", detail,
                  "Имя не резолвится — это сбой DNS, а не доказательство недоступности сервиса. "
                  "Проверьте системный DNS / фильтр / Private DNS.",
                  NULL, url, spoiler);
        return;
    }
    t0 = now_ms();
    open = tcp_open(host, port, timeout_ms);
    if (open) {
        snprintf(detail, sizeof detail, "%s:%d открыт, %lld ms",
                 host, port, (long long)(now_ms() - t0));
        check_set(out, cat, name, "ok", detail, "", ip, url, spoiler);
        return;
    }
    snprintf(detail, sizeof detail, "%s:%d закрыт/фильтр", host, port);
    snprintf(hint, sizeof hint,
             "Типичный симптом DPI/firewall: TCP connect не проходит. "
             "Для IoT нужны allowlist хостов и портов (часто 443/8883).");
    check_set(out, cat, name, "fail", detail, hint, ip, url, spoiler);
    if (critical && crit_fail) *crit_fail = 1;
}

static void check_tcp_ep(const char *cat, const char *name, const char *host,
                         int port, int timeout_ms, int critical, int spoiler,
                         int *fail_n, char fail_names[][64], int fail_cap) {
    Check c;
    int crit_fail = 0;
    check_tcp_ep_fill(&c, cat, name, host, port, timeout_ms, critical, spoiler, &crit_fail);
    add_check_from(&c);
    if (crit_fail && fail_n && *fail_n < fail_cap)
        snprintf(fail_names[(*fail_n)++], 64, "%s", name);
}

/*
 * Steam CM: старые cm2-1.steampowered.com — NXDOMAIN.
 * Берём IP:port из GetCMList WebAPI и пробуем TCP (как клиент Steam).
 * Если api.steampowered.com режется (часто в РФ) — fallback на известные
 * *.steamserver.net :27017 (то, куда реально ходит клиент).
 */
static int steam_cm_try_host(const char *host, int port, char *ip, size_t iplen,
                             long long *ms_out) {
    long long t0;
    ip[0] = 0;
    if (!dns_resolve(host, ip, iplen) || !ip[0])
        return 0;
    t0 = now_ms();
    if (!tcp_open(ip, port, 3500))
        return 0;
    if (ms_out)
        *ms_out = now_ms() - t0;
    return 1;
}

static void check_steam_cm(int *fail_n, char fail_names[][64], int fail_cap) {
    char out[16384], detail[STR], ip[64];
    const char *p;
    int tried = 0, ok = 0, port = 0, list_ok = 0;
    long long ms = 0;
    /* EU/ближние CM — если GetCMList недоступен (API/DPI). */
    static const char *const cm_fallback[] = {
        "ext1-fra1.steamserver.net",
        "ext2-fra1.steamserver.net",
        "ext1-ams1.steamserver.net",
        "ext1-waw1.steamserver.net",
        "ext1-vie1.steamserver.net",
        "ext1-lhr1.steamserver.net",
    };
    size_t fi;
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
    if (run_capture(cmd, out, sizeof out) == 0 && out[0])
        list_ok = 1;

    if (list_ok) {
        p = out;
        ip[0] = 0;
        while (tried < 10 && !ok) {
            int a, b, c, d, po, n = 0;
            long long t0;
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
                    snprintf(detail, sizeof detail,
                             "CM %s:%d открыт, %lld ms (из GetCMList, попытка %d)",
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
        return;
    }

    /* GetCMList недоступен — пробуем известные CM (как клиент без свежего списка). */
    add_check_ex("Игры", "Steam CM (GetCMList)", "warn",
                 "GetCMList недоступен (api.steampowered.com)",
                 "Витрина/API часто режутся; проверяем TCP к известным CM steamserver.net.",
                 NULL,
                 "https://api.steampowered.com/ISteamDirectory/GetCMList/v1/?cellid=0",
                 0);

    for (fi = 0; fi < sizeof cm_fallback / sizeof cm_fallback[0]; fi++) {
        if (steam_cm_try_host(cm_fallback[fi], 27017, ip, sizeof ip, &ms)) {
            snprintf(detail, sizeof detail,
                     "CM %s:27017 открыт, %lld ms (fallback, GetCMList недоступен)",
                     cm_fallback[fi], ms);
            add_check_ex("Игры", "Steam CM TCP", "ok", detail,
                         "Клиентский порт CM доступен; WebAPI GetCMList может быть заблокирован отдельно.",
                         ip, cm_fallback[fi], 0);
            return;
        }
    }

    add_check_ex("Игры", "Steam CM TCP", "fail",
                 "GetCMList недоступен и fallback CM :27017 не открылись",
                 "Нужны HTTPS к api.steampowered.com и/или TCP 27017 к *.steamserver.net.",
                 NULL,
                 "https://api.steampowered.com/ISteamDirectory/GetCMList/v1/?cellid=0",
                 0);
    if (fail_n && *fail_n < fail_cap)
        snprintf(fail_names[(*fail_n)++], 64, "%s", "Steam CM");
}

/* UDP: send probe, wait for any datagram (Steam SDR relays often reply ~28 B). */
static int udp_probe_any(const char *ip, int port, int timeout_ms, int *ms_out) {
#ifdef _WIN32
    SOCKET s;
#else
    int s;
#endif
    struct sockaddr_in sa;
    unsigned char req[32], resp[256];
    fd_set rset;
    struct timeval tv;
    long long t0;
    int n;

    if (ms_out) *ms_out = 0;
    if (!ip || !ip[0] || port <= 0 || port > 65535) return 0;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons((unsigned short)port);
    if (inet_pton(AF_INET, ip, &sa.sin_addr) != 1) return 0;

#ifdef _WIN32
    s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) return 0;
#else
    s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s < 0) return 0;
#endif
    memset(req, 0, sizeof req);
    req[0] = 0x00;
    t0 = now_ms();
    if (sendto(s, (const char *)req, 20, 0, (struct sockaddr *)&sa, sizeof sa) < 0) {
#ifdef _WIN32
        closesocket(s);
#else
        close(s);
#endif
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
    if (n > 0) {
#ifdef _WIN32
        n = recvfrom(s, (char *)resp, sizeof resp, 0, NULL, NULL);
#else
        n = (int)recvfrom(s, resp, sizeof resp, 0, NULL, NULL);
#endif
        if (ms_out) *ms_out = (int)(now_ms() - t0);
#ifdef _WIN32
        closesocket(s);
#else
        close(s);
#endif
        return n > 0 ? 1 : 0;
    }
#ifdef _WIN32
    closesocket(s);
#else
    close(s);
#endif
    if (ms_out) *ms_out = (int)(now_ms() - t0);
    return 0;
}

/*
 * Steam Datagram Relay (UDP) — голос/матчмейкинг CS2/Dota.
 * Список из GetSDRConfig; fallback — известные EU POP.
 */
static void check_steam_sdr(int *fail_n, char fail_names[][64], int fail_cap) {
    char out[65536], detail[STR], ip[64];
    char ips[8][64];
    const char *labels[8];
    int ports[8];
    int n = 0, ok = 0, i, ms;

    ip[0] = 0;
    detail[0] = 0;
    static const struct { const char *label, *ip; int port; } fallback[] = {
        {"FRA", "155.133.226.68", 27015},
        {"STO", "162.254.198.41", 27015},
        {"WAW", "155.133.230.98", 27015},
        {"AMS", "155.133.248.36", 27015},
        {"VIE", "146.66.155.66", 27015},
        {"LHR", "162.254.196.66", 27015},
    };
#ifdef _WIN32
    const char *cmd =
        "curl.exe -sS --max-time 12 "
        "\"https://api.steampowered.com/ISteamApps/GetSDRConfig/v1?appid=730\" 2>nul";
#else
    const char *cmd =
        CURL_SSL_ENV
        "curl -sS --max-time 12 "
        "'https://api.steampowered.com/ISteamApps/GetSDRConfig/v1?appid=730' 2>/dev/null";
#endif

    out[0] = 0;
    if (run_capture(cmd, out, sizeof out) == 0 && out[0] && strstr(out, "\"ipv4\"")) {
        const char *p = out;
        while (n < 6 && (p = strstr(p, "\"ipv4\"")) != NULL) {
            int a, b, c, d;
            p += 6;
            while (*p && (*p < '0' || *p > '9')) p++;
            if (sscanf(p, "%d.%d.%d.%d", &a, &b, &c, &d) == 4 &&
                a >= 0 && a < 256 && b >= 0 && b < 256 &&
                c >= 0 && c < 256 && d >= 0 && d < 256) {
                snprintf(ips[n], sizeof ips[n], "%d.%d.%d.%d", a, b, c, d);
                ports[n] = 27015;
                labels[n] = "SDR";
                n++;
            }
            if (*p) p++;
        }
    }
    if (n == 0) {
        for (i = 0; i < (int)(sizeof fallback / sizeof fallback[0]) && n < 6; i++) {
            snprintf(ips[n], sizeof ips[n], "%s", fallback[i].ip);
            ports[n] = fallback[i].port;
            labels[n] = fallback[i].label;
            n++;
        }
        add_check_ex("Игры", "Steam SDR (GetSDRConfig)", "warn",
                     "GetSDRConfig недоступен — UDP к известным EU POP",
                     "API часто режется; проверяем SDR UDP напрямую.",
                     NULL,
                     "https://api.steampowered.com/ISteamApps/GetSDRConfig/v1?appid=730",
                     0);
    }

    for (i = 0; i < n; i++) {
        char piece[96];
        if (udp_probe_any(ips[i], ports[i], 1500, &ms)) {
            ok++;
            snprintf(piece, sizeof piece, "%s %s:%d %dms",
                     labels[i] ? labels[i] : "SDR", ips[i], ports[i], ms);
            if (!ip[0]) snprintf(ip, sizeof ip, "%s", ips[i]);
        } else {
            snprintf(piece, sizeof piece, "%s %s:%d —",
                     labels[i] ? labels[i] : "SDR", ips[i], ports[i]);
        }
        if (detail[0]) {
            size_t L = strlen(detail);
            if (L + 2 < sizeof detail) { detail[L] = ','; detail[L + 1] = ' '; detail[L + 2] = 0; }
        }
        {
            size_t L = strlen(detail);
            snprintf(detail + L, sizeof detail - L, "%s", piece);
        }
    }

    {
        char sum[STR];
        snprintf(sum, sizeof sum, "UDP ответ %d/%d · %s", ok, n, detail);
        if (ok >= 2) {
            add_check_ex("Игры", "Steam SDR UDP", "ok", sum, "",
                         ip[0] ? ip : NULL,
                         "https://api.steampowered.com/ISteamApps/GetSDRConfig/v1?appid=730", 0);
        } else if (ok == 1) {
            add_check_ex("Игры", "Steam SDR UDP", "warn", sum,
                         "Мало ответов SDR — голос/матчмейкинг могут лагать (UDP-фильтр ТСПУ).",
                         ip[0] ? ip : NULL,
                         "https://api.steampowered.com/ISteamApps/GetSDRConfig/v1?appid=730", 0);
        } else {
            add_check_ex("Игры", "Steam SDR UDP", "fail", sum,
                         "Нет UDP-ответов от Steam Datagram Relay — типичный дружеский огонь "
                         "при фильтрации VoIP/VPN (Steam Voice / CS2 / Dota).",
                         NULL,
                         "https://api.steampowered.com/ISteamApps/GetSDRConfig/v1?appid=730", 0);
            if (fail_n && *fail_n < fail_cap)
                snprintf(fail_names[(*fail_n)++], 64, "%s", "Steam SDR");
        }
    }
}

static int http_download_bytes(const char *url, int timeout_sec, long *bytes_out, int *ms_out);
static int http_fetch_text_ex(const char *url, char *buf, size_t buflen, int timeout_sec,
                              int *ms_out, const char *cookie);

/* Cloudflare ~16KB throttle canary (TSPU): request 100KB, see if cut early. */
static void check_cloudflare_throttle(void) {
    const char *url = "https://speed.cloudflare.com/__down?bytes=100000";
    char detail[STR], rip[64], host[128];
    long bytes = 0;
    int ms = 0;

    host_from_url(url, host, sizeof host);
    rip[0] = 0;
    if (host[0]) dns_resolve(host, rip, sizeof rip);

    if (!http_download_bytes(url, 20, &bytes, &ms) || bytes <= 0) {
        add_check_ex("Гео / IX", "Cloudflare 100KB canary", "fail",
                     ms > 0 ? "0 байт / обрыв на старте" : "таймаут / нет ответа",
                     "Нет загрузки с speed.cloudflare.com — блок/throttle CF или маршрут.",
                     rip[0] ? rip : NULL, url, 0);
        add_finding("warning", "Cloudflare недоступен",
                    "Канарейка 100KB не скачалась. Часто ТСПУ режет AS13335 (в т.ч. лимит ~16KB).");
        return;
    }

    snprintf(detail, sizeof detail, "%ld байт за %d ms (цель 100000)", bytes, ms);
    if (bytes >= 80000) {
        add_check_ex("Гео / IX", "Cloudflare 100KB canary", "ok", detail,
                     "Полный ответ — нет типичного CF 16KB throttle.",
                     rip[0] ? rip : NULL, url, 0);
    } else if (bytes > 0 && bytes < 25000) {
        add_check_ex("Гео / IX", "Cloudflare 100KB canary", "fail", detail,
                     "Обрыв ≈16KB — классический throttle Cloudflare на ТСПУ "
                     "(сайты за CF «открываются и виснут»).",
                     rip[0] ? rip : NULL, url, 0);
        add_finding("critical", "Похоже на throttle Cloudflare (~16KB)",
                    "Скачано меньше 25KB из 100KB с speed.cloudflare.com. "
                    "Типичный дружеский огонь ТСПУ по AS13335 — ломает тысячи сайтов на CF.");
    } else {
        add_check_ex("Гео / IX", "Cloudflare 100KB canary", "warn", detail,
                     "Скачано частично — нестабильный маршрут или мягкий throttle.",
                     rip[0] ? rip : NULL, url, 0);
    }
}

/* ---------- HTTP ---------- */

typedef struct {
    const char *id; /* short label in report */
    const char *ua;
} UaProfile;

/* Desktop Win / non-Win, mobile, Smart TV / embed — актуальный Chrome, меньше antibot */
static const UaProfile UA_PROFILES[] = {
    {"win",
     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
     "Chrome/138.0.0.0 Safari/537.36"},
    {"mac",
     "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7) AppleWebKit/537.36 (KHTML, like Gecko) "
     "Chrome/138.0.0.0 Safari/537.36"},
    {"android",
     "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) "
     "Chrome/138.0.0.0 Mobile Safari/537.36"},
    {"tv",
     "Mozilla/5.0 (SMART-TV; Linux; Tizen 7.0) AppleWebKit/537.36 (KHTML, like Gecko) "
     "Chrome/120.0.0.0 TV Safari/537.36"},
    {"embed",
     "Mozilla/5.0 (X11; Linux armv7l) AppleWebKit/537.36 (KHTML, like Gecko) "
     "Chrome/120.0.0.0 Safari/537.36 CrKey/1.56.500000"},
};
#define N_UA_PROFILES ((int)(sizeof UA_PROFILES / sizeof UA_PROFILES[0]))

static const char *ua_default(void) {
    return UA_PROFILES[0].ua; /* Windows desktop */
}

/* Заголовки как у навигации Chrome — меньше JS-challenge / «бот» у WAF. */
static const char *http_browser_hdrs_curl(void) {
    return "-H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,"
           "image/avif,image/webp,image/apng,*/*;q=0.8' "
           "-H 'Accept-Language: ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7' "
           "-H 'Cache-Control: no-cache' "
           "-H 'Upgrade-Insecure-Requests: 1' "
           "-H 'Sec-Fetch-Dest: document' "
           "-H 'Sec-Fetch-Mode: navigate' "
           "-H 'Sec-Fetch-Site: none' "
           "-H 'Sec-Fetch-User: ?1' "
           "-H 'sec-ch-ua: \"Chromium\";v=\"138\", \"Not=A?Brand\";v=\"24\", \"Google Chrome\";v=\"138\"' "
           "-H 'sec-ch-ua-mobile: ?0' "
           "-H 'sec-ch-ua-platform: \"Windows\"'";
}

#ifdef _WIN32
static const char *http_browser_hdrs_wininet(void) {
    return "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,"
           "image/avif,image/webp,image/apng,*/*;q=0.8\r\n"
           "Accept-Language: ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7\r\n"
           "Cache-Control: no-cache\r\n"
           "Upgrade-Insecure-Requests: 1\r\n"
           "Sec-Fetch-Dest: document\r\n"
           "Sec-Fetch-Mode: navigate\r\n"
           "Sec-Fetch-Site: none\r\n"
           "Sec-Fetch-User: ?1\r\n";
}
#endif

/* Cloudflare / DDoS-Guard / Qrator / hCaptcha / типовой HTML 403. */
static int body_looks_antibot(int code, const char *body) {
    if (!body || !body[0]) {
        return (code == 403 || code == 429 || code == 503) ? 1 : 0;
    }
    if (strstr(body, "cf-browser-verification") ||
        strstr(body, "cf-challenge") ||
        strstr(body, "_cf_chl") ||
        strstr(body, "challenge-platform") ||
        strstr(body, "Just a moment") ||
        strstr(body, "Attention Required") ||
        strstr(body, "Checking your browser") ||
        strstr(body, "Enable JavaScript and cookies") ||
        strstr(body, "managed_checking_msg") ||
        strstr(body, "ddos-guard") ||
        strstr(body, "DDoS-Guard") ||
        strstr(body, "qrator") ||
        strstr(body, "Qrator") ||
        strstr(body, "hcaptcha") ||
        strstr(body, "HCaptcha") ||
        strstr(body, "recaptcha") ||
        strstr(body, "g-recaptcha") ||
        strstr(body, "geetest") ||
        strstr(body, "Geetest") ||
        strstr(body, "captcha-delivery") ||
        strstr(body, "px-captcha") ||
        strstr(body, "PerimeterX") ||
        strstr(body, "Please enable JS") ||
        strstr(body, "robot check") ||
        strstr(body, "Access denied") ||
        strstr(body, "error-code"))
        return 1;
    if ((code == 403 || code == 429 || code == 503) &&
        (strstr(body, "<html") || strstr(body, "<!DOCTYPE") || strstr(body, "<!doctype")))
        return 1;
    return 0;
}

static void fmt_doc_speed(char *out, size_t n, long bytes, int ms) {
    double kb, mbps;
    if (!out || n == 0) return;
    out[0] = 0;
    if (bytes <= 0 || ms <= 0) return;
    kb = bytes / 1024.0;
    mbps = (bytes * 8.0) / (ms * 1000.0);
    if (kb >= 1024.0)
        snprintf(out, n, " · %.2f МБ · %.2f Мбит/с", kb / 1024.0, mbps);
    else
        snprintf(out, n, " · %.1f КБ · %.2f Мбит/с", kb, mbps);
}

/* ---------- страница + ассеты/CDN (не только HTML-stub) ---------- */

#define PAGE_HTML_CAP   (384 * 1024)
#define PAGE_ASSET_MAX  8
#define PAGE_ASSET_TO   5   /* сек на ассет */
#define PAGE_ASSET_BUDGET_MS 10000
#define PAGE_FAIL_HOSTS 256
#define PAGE_FAIL_ASSETS 320

typedef struct {
    long html_bytes;
    long asset_bytes;
    int n_try;
    int n_ok;
    int n_fail;
    int n_cdn;       /* ассеты с другого хоста (CDN/static) */
    int n_cdn_fail;
    int wall_ms;     /* HTML fetch + ассеты */
    char fail_hosts[PAGE_FAIL_HOSTS];   /* уникальные хосты через ", " */
    char fail_assets[PAGE_FAIL_ASSETS]; /* короткие host/file … */
    int n_fail_listed;
} PageLoadStats;

static int host_ieq(const char *a, const char *b);

/* агрегация CDN-сбоев по всему прогону → finding */
#define CDN_TRACK_HOSTS 32
#define CDN_TRACK_SITES 48
static struct { char host[80]; int n; } g_cdn_hosts[CDN_TRACK_HOSTS];
static int g_cdn_nhosts;
static char g_cdn_sites_fail[CDN_TRACK_SITES][64];
static char g_cdn_sites_warn[CDN_TRACK_SITES][64];
static int g_cdn_nfail_sites, g_cdn_nwarn_sites;
/* сбои канареек этапа «CDN / счётчики» (yastatic/yadro); 0 = канарейки OK */
static int g_cdn_canary_fail;

static void pl_add_fail_asset(PageLoadStats *st, const char *host, const char *url) {
    char piece[96];
    const char *base;
    char *q;
    size_t left;

    if (!st) return;
    if (host && host[0]) {
        if (!st->fail_hosts[0]) {
            snprintf(st->fail_hosts, sizeof st->fail_hosts, "%s", host);
        } else if (!strstr(st->fail_hosts, host)) {
            left = sizeof st->fail_hosts - strlen(st->fail_hosts) - 1;
            if (left > strlen(host) + 2) {
                strncat(st->fail_hosts, ", ", left);
                strncat(st->fail_hosts, host, left - 2);
            }
        }
    }
    if (!url || !url[0] || st->n_fail_listed >= 5) return;
    base = strrchr(url, '/');
    if (base && base[1] && host && host[0])
        snprintf(piece, sizeof piece, "%s/%s", host, base + 1);
    else if (host && host[0])
        snprintf(piece, sizeof piece, "%s", host);
    else
        snprintf(piece, sizeof piece, "%s", url);
    q = strchr(piece, '?');
    if (q) *q = 0;
    if ((int)strlen(piece) > 72) {
        piece[69] = '.'; piece[70] = '.'; piece[71] = '.'; piece[72] = 0;
    }
    if (!st->fail_assets[0]) {
        snprintf(st->fail_assets, sizeof st->fail_assets, "%s", piece);
    } else {
        left = sizeof st->fail_assets - strlen(st->fail_assets) - 1;
        if (left > strlen(piece) + 2) {
            strncat(st->fail_assets, "; ", left);
            strncat(st->fail_assets, piece, left - 2);
        }
    }
    st->n_fail_listed++;
}

static void cdn_track_host(const char *host) {
    int i;
    if (!host || !host[0]) return;
    for (i = 0; i < g_cdn_nhosts; i++) {
        if (host_ieq(g_cdn_hosts[i].host, host)) {
            g_cdn_hosts[i].n++;
            return;
        }
    }
    if (g_cdn_nhosts >= CDN_TRACK_HOSTS) return;
    snprintf(g_cdn_hosts[g_cdn_nhosts].host, sizeof g_cdn_hosts[0].host, "%s", host);
    g_cdn_hosts[g_cdn_nhosts].n = 1;
    g_cdn_nhosts++;
}

static void cdn_note_site(const char *site, const PageLoadStats *pl, int severe) {
    const char *p, *next;
    char host[80];
    size_t n;

    if (!site || !site[0] || !pl) return;
    out_lock();
    if (severe) {
        if (g_cdn_nfail_sites < CDN_TRACK_SITES)
            snprintf(g_cdn_sites_fail[g_cdn_nfail_sites++], 64, "%s", site);
    } else {
        if (g_cdn_nwarn_sites < CDN_TRACK_SITES)
            snprintf(g_cdn_sites_warn[g_cdn_nwarn_sites++], 64, "%s", site);
    }
    p = pl->fail_hosts;
    while (p && *p) {
        while (*p == ' ' || *p == ',') p++;
        if (!*p) break;
        next = strstr(p, ", ");
        n = next ? (size_t)(next - p) : strlen(p);
        if (n >= sizeof host) n = sizeof host - 1;
        memcpy(host, p, n);
        host[n] = 0;
        cdn_track_host(host);
        p = next ? next + 2 : NULL;
    }
    out_unlock();
}

/* 1 = много ассетов (hint жёстче); 0 = частичный; -1 = нет сбоя.
 * Статус проверки при живом HTML всегда warn — не fail (канарейки — этап CDN). */
static int page_cdn_severity(const PageLoadStats *pl) {
    int denom, nfail;
    if (!pl) return -1;
    nfail = pl->n_cdn_fail > 0 ? pl->n_cdn_fail : pl->n_fail;
    if (nfail <= 0) return -1;
    denom = pl->n_cdn > 0 ? pl->n_cdn : pl->n_try;
    if (denom < 1) denom = nfail;
    if ((denom >= 2 && nfail * 2 >= denom) || nfail >= 3 ||
        (nfail == denom && denom >= 2))
        return 1;
    return 0;
}

static void fmt_cdn_asset_hint(char *hint, size_t hintlen, const char *note,
                               const PageLoadStats *pl, int severe) {
    const char *list;
    int denom, nfail;
    char prefix[STR];

    if (!hint || !hintlen || !pl) return;
    denom = pl->n_cdn > 0 ? pl->n_cdn : pl->n_try;
    nfail = pl->n_cdn_fail > 0 ? pl->n_cdn_fail : pl->n_fail;
    list = pl->fail_assets[0] ? pl->fail_assets :
           (pl->fail_hosts[0] ? pl->fail_hosts : "—");
    prefix[0] = 0;
    if (note && note[0])
        snprintf(prefix, sizeof prefix, "%s ", note);
    if (severe) {
        if (g_cdn_canary_fail == 0)
            snprintf(hint, hintlen,
                     "%sМного ассетов/CDN не отдались (%d/%d): %s. "
                     "Канарейки yastatic/yadro при этом OK — скорее точечный URL, "
                     "antibot или выборка, не падение CDN.",
                     prefix, nfail, denom > 0 ? denom : nfail, list);
        else
            snprintf(hint, hintlen,
                     "%sМного ассетов/CDN не отдались (%d/%d): %s — страница может "
                     "открываться без стилей/JS. Смотрите этап «CDN / счётчики».",
                     prefix, nfail, denom > 0 ? denom : nfail, list);
    } else {
        if (g_cdn_canary_fail == 0)
            snprintf(hint, hintlen,
                     "%sЧасть ассетов/CDN недоступна (%d/%d): %s "
                     "(канарейки CDN OK — не считаем сбоем сайта).",
                     prefix, nfail, denom > 0 ? denom : nfail, list);
        else
            snprintf(hint, hintlen,
                     "%sЧасть ассетов/CDN недоступна (%d/%d): %s.",
                     prefix, nfail, denom > 0 ? denom : nfail, list);
    }
}

static void flush_cdn_findings(void) {
    char common[STR], sites[LONGSTR], detail[STR], tx[LONGSTR];
    int i, ncommon = 0, total;
    size_t used;

    total = g_cdn_nfail_sites + g_cdn_nwarn_sites;
    if (total < 1) return;

    common[0] = 0;
    for (i = 0; i < g_cdn_nhosts; i++) {
        if (g_cdn_hosts[i].n < 2) continue;
        if (common[0]) {
            used = strlen(common);
            if (used + 2 + strlen(g_cdn_hosts[i].host) < sizeof common) {
                strcat(common, ", ");
                strcat(common, g_cdn_hosts[i].host);
            }
        } else {
            snprintf(common, sizeof common, "%s", g_cdn_hosts[i].host);
        }
        ncommon++;
    }

    sites[0] = 0;
    for (i = 0; i < g_cdn_nfail_sites && i < 12; i++) {
        size_t left = sizeof sites - strlen(sites) - 1;
        if (left < 8) break;
        if (sites[0]) { strncat(sites, ", ", left); left = sizeof sites - strlen(sites) - 1; }
        strncat(sites, g_cdn_sites_fail[i], left);
    }
    for (i = 0; i < g_cdn_nwarn_sites && i < 8; i++) {
        size_t left = sizeof sites - strlen(sites) - 1;
        if (left < 8) break;
        if (sites[0]) { strncat(sites, ", ", left); left = sizeof sites - strlen(sites) - 1; }
        strncat(sites, g_cdn_sites_warn[i], left);
    }

    /* Ассеты на страницах → finding уровня warning; critical только если
     * канарейки CDN тоже легли и картина массовая. */
    if (total >= 4 && ncommon > 0) {
        snprintf(detail, sizeof detail, "Частичная недоступность CDN/ассетов (%d сайт%s)",
                 total, total == 1 ? "" : (total < 5 ? "а" : "ов"));
        if (g_cdn_canary_fail == 0)
            snprintf(tx, sizeof tx,
                     "На %d сайт%s HTML отвечает, но часть ресурсов страницы "
                     "(стили/JS/CDN) не отдалась%s%s. Примеры: %s. "
                     "Канарейки yastatic/yadro при этом OK — скорее точечные URL/"
                     "antibot/выборка, не падение самих сайтов или CDN.",
                     total,
                     total == 1 ? "е" : "ах",
                     ncommon > 0 ? ". Повторяющиеся хосты: " : "",
                     ncommon > 0 ? common : "",
                     sites[0] ? sites : "—");
        else
            snprintf(tx, sizeof tx,
                     "На %d сайт%s HTML отвечает, но ресурсы страницы "
                     "(стили/JS/CDN) часто не грузятся%s%s. Примеры: %s. "
                     "Канарейки CDN тоже с проблемами — смотрите этап «CDN / счётчики».",
                     total,
                     total == 1 ? "е" : "ах",
                     ncommon > 0 ? ". Повторяющиеся хосты: " : "",
                     ncommon > 0 ? common : "",
                     sites[0] ? sites : "—");
        add_finding(g_cdn_canary_fail >= 2 && ncommon >= 2 ? "critical" : "warning",
                    detail, tx);
    } else if (total >= 2 && ncommon > 0) {
        snprintf(detail, sizeof detail, "Частичная недоступность CDN/ассетов (%d)", total);
        snprintf(tx, sizeof tx,
                 "На части сайтов не отдались ассеты%s%s. Сайты: %s.%s",
                 ncommon > 0 ? " (" : "",
                 ncommon > 0 ? common : "",
                 sites[0] ? sites : "—",
                 g_cdn_canary_fail == 0
                     ? " Канарейки CDN OK — не считаем общим сбоем."
                     : " Проверьте этап «CDN / счётчики».");
        add_finding("warning", detail, tx);
    }
}

static int html_looks_like_page(const char *html) {
    if (!html || !html[0]) return 0;
    if (strstr(html, "<html") || strstr(html, "<HTML") ||
        strstr(html, "<!DOCTYPE") || strstr(html, "<!doctype") ||
        strstr(html, "<script") || strstr(html, "<link") ||
        strstr(html, "<img") || strstr(html, "<head"))
        return 1;
    return 0;
}

static int host_looks_cdn(const char *host) {
    if (!host || !host[0]) return 0;
    if (strstr(host, "cdn") || strstr(host, "static") || strstr(host, "assets") ||
        strstr(host, "akamai") || strstr(host, "cloudfront") || strstr(host, "fastly") ||
        strstr(host, "yastatic") || strstr(host, "mzstatic") || strstr(host, "edgekey") ||
        strstr(host, "edgecast") || strstr(host, "kxcdn") || strstr(host, "bunnycdn") ||
        strstr(host, "jsdelivr") || strstr(host, "unpkg") || strstr(host, "cloudflare") ||
        strstr(host, "googleusercontent") || strstr(host, "gstatic") ||
        strstr(host, "fbcdn") || strstr(host, "twimg") || strstr(host, "rbxcdn") ||
        strstr(host, "steamstatic") || strstr(host, "steamcontent") ||
        strstr(host, "vkuser") || strstr(host, "userapi") || strstr(host, "mycdn") ||
        strstr(host, "guce") || strstr(host, "s3.") || strstr(host, "storage."))
        return 1;
    return 0;
}

static int host_ieq(const char *a, const char *b) {
    if (!a || !b) return 0;
    for (; *a && *b; a++, b++) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) return 0;
    }
    return *a == *b;
}

/* base — финальный URL страницы; ref — href/src (возможен //, /, относительный). */
static int url_resolve(const char *base, const char *ref, char *out, size_t n) {
    char scheme[16], origin[STR], dir[STR];
    const char *p, *path;
    size_t i;

    if (!base || !ref || !out || n < 8) return 0;
    out[0] = 0;
    while (*ref && isspace((unsigned char)*ref)) ref++;
    if (!ref[0] || ref[0] == '#' || starts_with(ref, "data:") ||
        starts_with(ref, "javascript:") || starts_with(ref, "mailto:"))
        return 0;
    if (starts_with(ref, "http://") || starts_with(ref, "https://")) {
        snprintf(out, n, "%s", ref);
        return 1;
    }

    scheme[0] = 0;
    if (starts_with(base, "https://")) { snprintf(scheme, sizeof scheme, "https"); p = base + 8; }
    else if (starts_with(base, "http://")) { snprintf(scheme, sizeof scheme, "http"); p = base + 7; }
    else return 0;

    i = 0;
    while (p[i] && p[i] != '/' && p[i] != '?' && p[i] != '#' && i + 1 < sizeof origin)
        origin[i] = p[i], i++;
    origin[i] = 0;
    path = p + i; /* starts with / or empty */

    if (starts_with(ref, "//")) {
        snprintf(out, n, "%s:%s", scheme[0] ? scheme : "https", ref);
        return 1;
    }
    if (ref[0] == '/') {
        snprintf(out, n, "%s://%s%s", scheme, origin, ref);
        return 1;
    }

    /* директория base (без query) */
    {
        char tmp[STR];
        char *slash, *q;
        snprintf(tmp, sizeof tmp, "%s", path[0] ? path : "/");
        q = strchr(tmp, '?');
        if (q) *q = 0;
        q = strchr(tmp, '#');
        if (q) *q = 0;
        slash = strrchr(tmp, '/');
        if (slash) slash[1] = 0;
        else snprintf(tmp, sizeof tmp, "/");
        snprintf(dir, sizeof dir, "%s", tmp);
    }
    snprintf(out, n, "%s://%s%s%s", scheme, origin, dir, ref);
    return 1;
}

static int url_already(char urls[][STR], int n, const char *u) {
    int i;
    for (i = 0; i < n; i++)
        if (strcmp(urls[i], u) == 0) return 1;
    return 0;
}

/* Вытащить src/href из HTML; CDN/чужой хост — в начало списка. */
static int html_collect_assets(const char *html, const char *base_url,
                               char urls[][STR], int max_urls) {
    const char *tags[] = {"script", "link", "img", "source", "video", "audio"};
    char page_host[128];
    char found[48][STR];
    int pri[48];
    int nf = 0, t, i, j, n_out = 0;

    if (!html || !base_url || max_urls <= 0) return 0;
    host_from_url(base_url, page_host, sizeof page_host);

    for (t = 0; t < (int)(sizeof tags / sizeof tags[0]) && nf < 48; t++) {
        const char *p = html;
        size_t tlen = strlen(tags[t]);
        while (nf < 48 && (p = strstr(p, tags[t])) != NULL) {
            const char *tag_end, *attr, *q1, *q2;
            char ref[STR], abs[STR], ahost[128];
            int is_link = (strcmp(tags[t], "link") == 0);
            /* убедиться что это начало тега <tag ...> */
            if (p > html && p[-1] != '<') { p += tlen; continue; }
            tag_end = strchr(p, '>');
            if (!tag_end || (size_t)(tag_end - p) > 800) { p += tlen; continue; }
            if (is_link) {
                const char *chunk = p;
                char tmp[900];
                size_t clen = (size_t)(tag_end - p);
                if (clen >= sizeof tmp) clen = sizeof tmp - 1;
                memcpy(tmp, chunk, clen);
                tmp[clen] = 0;
                if (!strstr(tmp, "stylesheet") && !strstr(tmp, "preload") &&
                    !strstr(tmp, "icon") && !strstr(tmp, "font")) {
                    p = tag_end + 1;
                    continue;
                }
            }
            attr = NULL;
            {
                const char *s1 = strstr(p, "src=\"");
                const char *s2 = strstr(p, "src='");
                const char *h1 = strstr(p, "href=\"");
                const char *h2 = strstr(p, "href='");
                if (s1 && s1 < tag_end) attr = s1 + 5;
                else if (s2 && s2 < tag_end) attr = s2 + 5;
                else if (h1 && h1 < tag_end) attr = h1 + 6;
                else if (h2 && h2 < tag_end) attr = h2 + 6;
            }
            if (!attr || attr >= tag_end) { p = tag_end + 1; continue; }
            q1 = attr;
            {
                char quote = *(attr - 1);
                q2 = strchr(q1, quote);
            }
            if (!q2 || q2 > tag_end || q2 <= q1) { p = tag_end + 1; continue; }
            if ((size_t)(q2 - q1) >= sizeof ref) { p = tag_end + 1; continue; }
            memcpy(ref, q1, (size_t)(q2 - q1));
            ref[q2 - q1] = 0;
            if (!url_resolve(base_url, ref, abs, sizeof abs)) { p = tag_end + 1; continue; }
            /* обрезать query для дедупа картинок с cache-bust — оставляем полный URL */
            if (url_already(found, nf, abs)) { p = tag_end + 1; continue; }
            host_from_url(abs, ahost, sizeof ahost);
            snprintf(found[nf], sizeof found[nf], "%s", abs);
            pri[nf] = 0;
            if (ahost[0] && page_host[0] && !host_ieq(ahost, page_host))
                pri[nf] += 10;
            if (host_looks_cdn(ahost)) pri[nf] += 5;
            {
                const char *ext = strrchr(abs, '.');
                if (ext && (strncmp(ext, ".js", 3) == 0 || strncmp(ext, ".css", 4) == 0 ||
                            strncmp(ext, ".woff", 5) == 0 || strncmp(ext, ".mjs", 4) == 0))
                    pri[nf] += 2;
            }
            nf++;
            p = tag_end + 1;
        }
    }

    /* сортировка по приоритету (убыв.) — простой selection */
    for (i = 0; i < nf; i++) {
        for (j = i + 1; j < nf; j++) {
            if (pri[j] > pri[i]) {
                char tmpu[STR];
                int tmpp = pri[i];
                pri[i] = pri[j]; pri[j] = tmpp;
                snprintf(tmpu, sizeof tmpu, "%s", found[i]);
                snprintf(found[i], sizeof found[i], "%s", found[j]);
                snprintf(found[j], sizeof found[j], "%s", tmpu);
            }
        }
    }
    for (i = 0; i < nf && n_out < max_urls; i++) {
        snprintf(urls[n_out], STR, "%s", found[i]);
        n_out++;
    }
    return n_out;
}

static int http_download_asset(const char *url, int timeout_sec, long *bytes_out, int *ms_out) {
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
        hNet = InternetOpenA(ua_default(), INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
        if (!hNet) return 0;
        InternetSetOptionA(hNet, INTERNET_OPTION_RECEIVE_TIMEOUT, &to, sizeof to);
        InternetSetOptionA(hNet, INTERNET_OPTION_CONNECT_TIMEOUT, &to, sizeof to);
        flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE |
                INTERNET_FLAG_SECURE | INTERNET_FLAG_IGNORE_CERT_CN_INVALID |
                INTERNET_FLAG_IGNORE_CERT_DATE_INVALID;
        hUrl = InternetOpenUrlA(hNet, url, NULL, 0, flags, 0);
        if (!hUrl) { InternetCloseHandle(hNet); return 0; }
        while (InternetReadFile(hUrl, buf, sizeof buf, &read) && read > 0) {
            bytes += read;
            if (bytes > 2 * 1024 * 1024) break;
        }
        InternetCloseHandle(hUrl);
        InternetCloseHandle(hNet);
    }
#else
    {
        char cmd[LONGSTR * 2], out[64];
        snprintf(cmd, sizeof cmd,
                 CURL_SSL_ENV
                 "curl -k -sS -L --max-time %d --connect-timeout %d "
                 "--max-filesize 2097152 -o /dev/null -w '%%{size_download}' "
                 "-A '%s' "
                 "-H 'Accept: */*' "
                 "-H 'Sec-Fetch-Dest: empty' "
                 "-H 'Sec-Fetch-Mode: no-cors' "
                 "'%s' 2>/dev/null",
                 timeout_sec, timeout_sec > 1 ? timeout_sec - 1 : timeout_sec,
                 ua_default(), url);
        if (run_capture(cmd, out, sizeof out) != 0) return 0;
        str_trim(out);
        bytes = atol(out);
    }
#endif
    if (ms_out) *ms_out = (int)(now_ms() - t0);
    if (bytes_out) *bytes_out = bytes;
    return bytes > 0;
}

/*
 * Скачать HTML страницы, вытащить JS/CSS/img (приоритет CDN), замерить суммарную скорость.
 * page_url — исходный или финальный (после редиректа) URL.
 * Возвращает 1 если удалось хоть что-то померить.
 */
static int page_load_with_assets(const char *page_url, PageLoadStats *st) {
    char *html = NULL;
    char assets[PAGE_ASSET_MAX][STR];
    char page_host[128];
    int code, html_ms = 0, n_assets, i;
    long long t0;

    if (!page_url || !st) return 0;
    memset(st, 0, sizeof *st);
    t0 = now_ms();

    html = (char *)malloc(PAGE_HTML_CAP);
    if (!html) return 0;
    code = http_fetch_text_ex(page_url, html, PAGE_HTML_CAP, 12, &html_ms, NULL);
    if (code < 200 || code >= 400 || !html[0]) {
        free(html);
        return 0;
    }
    (void)html_ms;
    st->html_bytes = (long)strlen(html);
    if (st->html_bytes < 64 || !html_looks_like_page(html) || body_looks_antibot(code, html)) {
        st->wall_ms = (int)(now_ms() - t0);
        free(html);
        return 1; /* только HTML / challenge — без ассетов */
    }

    host_from_url(page_url, page_host, sizeof page_host);
    n_assets = html_collect_assets(html, page_url, assets, PAGE_ASSET_MAX);
    free(html);
    html = NULL;

    for (i = 0; i < n_assets; i++) {
        char ahost[128];
        long abytes = 0;
        int ams = 0;
        int is_cdn;
        if ((int)(now_ms() - t0) > PAGE_ASSET_BUDGET_MS) break;
        host_from_url(assets[i], ahost, sizeof ahost);
        is_cdn = (ahost[0] && page_host[0] && !host_ieq(ahost, page_host)) ||
                 host_looks_cdn(ahost);
        st->n_try++;
        if (is_cdn) st->n_cdn++;
        if (http_download_asset(assets[i], PAGE_ASSET_TO, &abytes, &ams) && abytes > 0) {
            st->n_ok++;
            st->asset_bytes += abytes;
        } else {
            st->n_fail++;
            if (is_cdn) st->n_cdn_fail++;
            pl_add_fail_asset(st, ahost[0] ? ahost : "?", assets[i]);
        }
    }
    st->wall_ms = (int)(now_ms() - t0);
    if (st->wall_ms < 1) st->wall_ms = 1;
    return 1;
}

static void fmt_page_speed(char *out, size_t n, const PageLoadStats *st) {
    long tot;
    double mb, mbps;
    if (!out || n == 0 || !st) return;
    out[0] = 0;
    tot = st->html_bytes + st->asset_bytes;
    if (tot <= 0 || st->wall_ms <= 0) return;
    mb = tot / (1024.0 * 1024.0);
    mbps = (tot * 8.0) / (st->wall_ms * 1000.0);
    if (st->n_try > 0) {
        if (mb >= 1.0)
            snprintf(out, n, " · стр+CDN %.2f МБ · %.2f Мбит/с (ассеты %d/%d)",
                     mb, mbps, st->n_ok, st->n_try);
        else
            snprintf(out, n, " · стр+CDN %.1f КБ · %.2f Мбит/с (ассеты %d/%d)",
                     tot / 1024.0, mbps, st->n_ok, st->n_try);
    } else {
        fmt_doc_speed(out, n, st->html_bytes, st->wall_ms);
    }
}

#ifdef _WIN32
static HttpResult http_probe_ua(const char *url, int timeout_sec, int insecure, const char *ua, int follow) {
    HttpResult r;
    HINTERNET hNet = NULL, hUrl = NULL;
    DWORD flags, code = 0, code_len = sizeof code, read;
    char buf[8192];
    char redir[STR];
    char final_url[STR];
    const char *hdrs;
    DWORD redir_len = sizeof redir;
    DWORD final_len = sizeof final_url;
    long long t0;
    DWORD to = (DWORD)timeout_sec * 1000;
    long total = 0;

    memset(&r, 0, sizeof r);
    (void)insecure;
    t0 = now_ms();
    hdrs = http_browser_hdrs_wininet();

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

    hUrl = InternetOpenUrlA(hNet, url, hdrs, (DWORD)strlen(hdrs), flags, 0);
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
        if (r.code >= 300 && r.code < 400) {
            redir_len = sizeof redir;
            if (HttpQueryInfoA(hUrl, HTTP_QUERY_LOCATION, redir, &redir_len, NULL) && redir[0])
                snprintf(r.redirect, sizeof r.redirect, "%s", redir);
        }
    }

    /* читаем весь документ (лимит 4 МБ) — для скорости и детекта antibot */
    while (total < 4 * 1024 * 1024 &&
           InternetReadFile(hUrl, buf, sizeof buf, &read) && read > 0) {
        if (total < (long)(sizeof r.body - 1)) {
            DWORD copy = read;
            if (total + (long)copy > (long)(sizeof r.body - 1))
                copy = (DWORD)((sizeof r.body - 1) - (size_t)total);
            memcpy(r.body + total, buf, copy);
            r.body[total + (long)copy] = 0;
        }
        total += (long)read;
    }
    r.bytes = total;
    str_trim(r.body);
    r.antibot = body_looks_antibot(r.code, r.body);

    r.ms = (int)(now_ms() - t0);
    r.xfer_ms = r.ms;
    if (follow)
        r.ok = (r.code >= 200 && r.code < 400) || r.antibot;
    else
        r.ok = ((r.code >= 200 && r.code < 400) || r.antibot) && r.redirect[0] == 0;
    InternetCloseHandle(hUrl);
    InternetCloseHandle(hNet);
    return r;
}
#else
static HttpResult http_probe_ua(const char *url, int timeout_sec, int insecure, const char *ua, int follow) {
    HttpResult r;
    char cmd[LONGSTR * 2];
    char out[STR];
    char tmp[] = "/tmp/netdiag_body_XXXXXX";
    char *p, *q;
    long long t0 = now_ms();
    const char *agent = ua && ua[0] ? ua : ua_default();
    int nredir = 0, fd;
    FILE *bf;

    memset(&r, 0, sizeof r);
    fd = mkstemp(tmp);
    if (fd < 0) {
        snprintf(r.error, sizeof r.error, "tmpfile failed");
        return r;
    }
    close(fd);

    /* follow: финальный код + документ; size_download = полный документ (gzip уже разжат).
     * Браузерные Sec-Fetch / Accept — меньше challenge у CF/WAF. */
    snprintf(cmd, sizeof cmd,
             CURL_SSL_ENV
             "curl -sS -o '%s' -w "
             "'%%{http_code}\\t%%{time_total}\\t%%{url_effective}\\t%%{num_redirects}\\t%%{redirect_url}\\t%%{size_download}' "
             "--max-time %d --connect-timeout %d --max-filesize 4194304 "
             "-A '%s' %s "
             "%s --max-redirs %d %s '%s' 2>/dev/null",
             tmp,
             timeout_sec, timeout_sec > 2 ? timeout_sec - 1 : timeout_sec, agent,
             http_browser_hdrs_curl(),
             follow ? "-L" : "",
             follow ? 8 : 0,
             insecure ? "-k" : "", url);
    if (run_capture(cmd, out, sizeof out) != 0 || !out[0]) {
        unlink(tmp);
        snprintf(r.error, sizeof r.error, "curl failed");
        r.ms = (int)(now_ms() - t0);
        return r;
    }
    {
        /* code \t time \t effective \t nredir \t redirect_url \t size_download */
        char *fields[6];
        int nf = 0;
        char effective[STR];
        p = out;
        while (nf < 6) {
            fields[nf++] = p;
            q = strchr(p, '\t');
            if (!q) break;
            *q = 0;
            p = q + 1;
        }
        r.code = atoi(fields[0]);
        if (nf > 1) {
            double sec = atof(fields[1]);
            r.ms = (int)(sec * 1000 + 0.5);
        } else {
            r.ms = (int)(now_ms() - t0);
        }
        effective[0] = 0;
        if (nf > 2) {
            snprintf(effective, sizeof effective, "%s", fields[2]);
            str_trim(effective);
        }
        if (nf > 3) nredir = atoi(fields[3]);
        if (!follow && nf > 4 && fields[4][0] && strcmp(fields[4], "0") != 0) {
            snprintf(r.redirect, sizeof r.redirect, "%s", fields[4]);
            str_trim(r.redirect);
        }
        if (nf > 5) r.bytes = atol(fields[5]);
        if (follow) {
            if (nredir > 0 && effective[0] && strcmp(effective, url) != 0)
                snprintf(r.redirect, sizeof r.redirect, "%s", effective);
            if (r.code >= 300 && r.code < 400 && !r.redirect[0] && effective[0])
                snprintf(r.redirect, sizeof r.redirect, "%s", effective);
        }
    }

    bf = fopen(tmp, "rb");
    if (bf) {
        size_t n = fread(r.body, 1, sizeof r.body - 1, bf);
        r.body[n] = 0;
        str_trim(r.body);
        if (r.bytes <= 0) {
            long pos;
            if (fseek(bf, 0, SEEK_END) == 0) {
                pos = ftell(bf);
                if (pos > 0) r.bytes = pos;
            }
        }
        fclose(bf);
    }
    unlink(tmp);

    if (r.ms <= 0) r.ms = (int)(now_ms() - t0);
    r.xfer_ms = r.ms;
    r.antibot = body_looks_antibot(r.code, r.body);
    if (follow)
        r.ok = (r.code >= 200 && r.code < 400) || r.antibot;
    else
        r.ok = ((r.code >= 200 && r.code < 400) || r.antibot) && r.redirect[0] == 0;
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
    long long sum_bytes = 0;
    long sum_xfer = 0;
    int n_xfer = 0;
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
        if (r.bytes > 0 && r.xfer_ms > 0 &&
            ((r.code >= 200 && r.code < 400) || r.antibot)) {
            sum_bytes += r.bytes;
            sum_xfer += r.xfer_ms;
            n_xfer++;
        }
        if (r.code >= 200 && r.code < 500) any_ok = 1;
        if (i == 0) {
            best = r;
        } else {
            int r_good = (r.code >= 200 && r.code < 400) || r.antibot;
            int b_good = (best.code >= 200 && best.code < 400) || best.antibot;
            int r_clean = (r.code >= 200 && r.code < 400) && !r.antibot;
            int b_clean = (best.code >= 200 && best.code < 400) && !best.antibot;
            if ((!best.code && r.code) ||
                (r_clean && !b_clean) ||
                (r_good && !b_good) ||
                (r_good && b_good && r.bytes > best.bytes) ||
                (r_good && b_good && r.bytes == best.bytes && r.ms < best.ms))
                best = r;
        }
        if (i > 0 && codes[i] != codes[0]) all_same = 0;
    }

    /* среднее время ответа по UA; скорость документа — средняя по успешным пробам;
     * размер в отчёте — у лучшей (самой полной) пробы */
    if (n_done > 0)
        best.ms = sum_ms / n_done;
    if (n_xfer > 0 && best.bytes > 0 && sum_xfer > 0) {
        double avg_mbps = (sum_bytes * 8.0) / ((double)sum_xfer * 1000.0);
        if (avg_mbps > 0.0) {
            best.xfer_ms = (int)((best.bytes * 8.0) / (avg_mbps * 1000.0) + 0.5);
            if (best.xfer_ms < 1) best.xfer_ms = 1;
        }
    }

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

#ifdef _WIN32
/* ICMP API — без парсинга локализованного вывода ping.exe (OEM/UTF-8). */
static int ping_summary(const char *target, int count, int *loss, double *avg) {
    HANDLE h;
    IN_ADDR ina;
    IPAddr dest;
    char send[32];
    unsigned char reply_buf[sizeof(ICMP_ECHO_REPLY) + 64];
    int i, ok = 0;
    double sum = 0;

    *loss = 100;
    *avg = 0;
    if (!target || !target[0] || count < 1) return -1;
    if (InetPtonA(AF_INET, target, &ina) != 1) return -1;
    dest = ina.S_un.S_addr;

    h = IcmpCreateFile();
    if (h == INVALID_HANDLE_VALUE) return -1;

    memset(send, 0x5a, sizeof send);
    for (i = 0; i < count; i++) {
        DWORD n = IcmpSendEcho(h, dest, send, (WORD)sizeof send, NULL,
                               reply_buf, (DWORD)sizeof reply_buf, 1000);
        if (n > 0) {
            const ICMP_ECHO_REPLY *r = (const ICMP_ECHO_REPLY *)reply_buf;
            if (r->Status == IP_SUCCESS) {
                ok++;
                sum += (double)r->RoundTripTime;
            }
        }
    }
    IcmpCloseHandle(h);

    *loss = ((count - ok) * 100) / count;
    *avg = ok ? (sum / (double)ok) : 0.0;
    return 0;
}
#else
static int ping_summary(const char *target, int count, int *loss, double *avg) {
    char cmd[256], out[4096];
    *loss = 100;
    *avg = 0;
    snprintf(cmd, sizeof cmd, "ping -c %d -W 1000 %s 2>&1", count, target);
    if (run_capture(cmd, out, sizeof out) != 0) return -1;
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
    return 0;
}
#endif

static int host_cmd_safe(const char *h) {
    size_t i;
    if (!h || !h[0]) return 0;
    for (i = 0; h[i]; i++) {
        unsigned char c = (unsigned char)h[i];
        if (!(isalnum(c) || c == '.' || c == '-' || c == ':' || c == '%'))
            return 0;
    }
    return 1;
}

static void host_from_check(const Check *c, char *host, size_t hostlen) {
    host[0] = 0;
    if (!c) return;
    if (c->diag_url[0]) {
        host_from_url(c->diag_url, host, hostlen);
        if (host[0]) return;
    }
    if (c->resolved_ip[0] && host_cmd_safe(c->resolved_ip))
        snprintf(host, hostlen, "%s", c->resolved_ip);
}

static void net_ping_text(const char *target, char *buf, size_t buflen) {
    char cmd[320], out[8192];
    buf[0] = 0;
    if (!host_cmd_safe(target) || buflen < 8) return;
#ifdef _WIN32
    {
        /* Сводка через ICMP API — не зависит от языка Windows */
        int loss = 100;
        double avg = 0;
        if (ping_summary(target, 4, &loss, &avg) == 0) {
            snprintf(buf, buflen,
                     "ping %s (ICMP API)\nloss=%d%%, avg=%.1f ms (4 probes)",
                     target, loss, avg);
            return;
        }
        snprintf(cmd, sizeof cmd, "ping -n 4 -w 1000 %s", target);
    }
#else
    snprintf(cmd, sizeof cmd, "ping -c 4 -W 1000 %s 2>&1", target);
#endif
    if (run_capture(cmd, out, sizeof out) != 0 || !out[0]) {
        snprintf(buf, buflen, "ping %s: нет вывода", target);
        return;
    }
    snprintf(buf, buflen, "ping %s\n%s", target, out);
    buf[buflen - 1] = 0;
}

static void net_traceroute_text(const char *target, char *buf, size_t buflen) {
    char cmd[384], out[16384];
    buf[0] = 0;
    if (!host_cmd_safe(target) || buflen < 8) return;
#ifdef _WIN32
    snprintf(cmd, sizeof cmd, "tracert -d -w 1000 -h 15 %s", target);
#elif defined(__APPLE__)
    snprintf(cmd, sizeof cmd, "traceroute -n -w 1 -q 1 -m 15 %s 2>&1", target);
#else
    snprintf(cmd, sizeof cmd,
             "(command -v traceroute >/dev/null && traceroute -n -w 1 -q 1 -m 15 %s) || "
             "(command -v tracepath >/dev/null && tracepath -n -m 15 %s) || "
             "echo 'traceroute/tracepath не найден'",
             target, target);
#endif
    if (run_capture(cmd, out, sizeof out) != 0 || !out[0]) {
        snprintf(buf, buflen, "traceroute %s: нет вывода", target);
        return;
    }
    snprintf(buf, buflen, "%s", out);
    buf[buflen - 1] = 0;
}

typedef struct {
    int *idxs;
} NetDiagCtx;

static void netdiag_job(int idx, void *v) {
    NetDiagCtx *ctx = (NetDiagCtx *)v;
    Check *c;
    char host[128];
    int ci = ctx->idxs[idx];
    if (ci < 0 || ci >= nchecks) return;
    c = &checks[ci];
    host_from_check(c, host, sizeof host);
    if (!host[0] && c->resolved_ip[0] && host_cmd_safe(c->resolved_ip))
        snprintf(host, sizeof host, "%s", c->resolved_ip);
    if (!host[0]) return;
    net_ping_text(host, c->ping_text, sizeof c->ping_text);
    net_traceroute_text(host, c->trace_text, sizeof c->trace_text);
}

static void enrich_fail_netdiag(void) {
    int idxs[MAX_CHECKS];
    int n = 0, i;
    NetDiagCtx ctx;
    for (i = 0; i < nchecks && n < MAX_CHECKS; i++) {
        char host[128];
        if (strcmp(checks[i].status, "fail") != 0) continue;
        host_from_check(&checks[i], host, sizeof host);
        if (!host[0] && !(checks[i].resolved_ip[0] && host_cmd_safe(checks[i].resolved_ip)))
            continue;
        idxs[n++] = i;
    }
    if (n == 0) return;
    printf("\n▶ Сеть (ping/traceroute) для недоступных (%d)\n", n);
    fflush(stdout);
    ctx.idxs = idxs;
    run_parallel(n, opt_jobs, netdiag_job, &ctx, "net-diag");
    stage_done();
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

    if (g_engine_cancel) return 0;

    if (g_engine_cb && g_engine_cb->on_stage)
        g_engine_cb->on_stage(g_engine_cb->userdata, title ? title : "", desc ? desc : "");
    engine_logf("▶ %s", title ? title : "");
    if (desc && desc[0]) engine_logf("  %s", desc);

    if (g_sys_dns_broken && default_run) {
        engine_log("  ⏭ пропущено: системный DNS не резолвит имена");
        if (!g_engine_lib_mode) {
        printf("\n▶ %s\n  ⏭ пропущено: системный DNS не резолвит имена\n", title);
        fflush(stdout);
        }
        add_check(title, "Этап", "info",
                  "пропущен — DNS не резолвит имена",
                  "Без резолва проверки по hostname дают ложные сбои недоступности.");
        return 0;
    }

    if (!g_engine_lib_mode) {
        printf("\n▶ %s\n  %s\n", title, desc ? desc : "");
        fflush(stdout);
    }

    if (opt_yes || g_engine_lib_mode) return default_run ? 1 : 0;

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
    if (g_engine_cb && g_engine_cb->on_progress)
        g_engine_cb->on_progress(g_engine_cb->userdata, msg ? msg : "", cur, total);
    if (g_engine_lib_mode) {
        engine_log(line);
        return;
    }
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
    const char *pub[] = {"8.8.8.8", "1.1.1.1", "77.88.8.8", "195.208.4.1"};
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
                        "getaddrinfo не решает известные домены, при этом публичные резолверы "
                        "(8.8.8.8 / 1.1.1.1 / Яндекс 77.88.8.8 / НСДИ) отвечают. "
                        "Почините DNS на роутере/ОС (или отключите Private DNS). "
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

/*
 * Скачать ответ и проверить «живость» по magic/размеру (не только TCP).
 * magic: "PNG" | "GIF" | "HTML" | NULL (только min_bytes).
 * Возврат: 1 = ок, 0 = нет.
 */
static int http_fetch_verify(const char *url, int timeout_sec,
                             const char *magic, long min_bytes,
                             long *bytes_out, int *code_out, int *ms_out) {
    unsigned char head[16];
    long bytes = 0;
    int code = 0;
    long long t0 = now_ms();
    size_t head_n = 0;

    if (bytes_out) *bytes_out = 0;
    if (code_out) *code_out = 0;
    if (ms_out) *ms_out = 0;
    memset(head, 0, sizeof head);

#ifdef _WIN32
    {
        HINTERNET hNet, hUrl;
        DWORD flags, read;
        char buf[8192];
        DWORD to = (DWORD)timeout_sec * 1000;
        hNet = InternetOpenA(ua_default(), INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
        if (!hNet) return 0;
        InternetSetOptionA(hNet, INTERNET_OPTION_RECEIVE_TIMEOUT, &to, sizeof to);
        InternetSetOptionA(hNet, INTERNET_OPTION_CONNECT_TIMEOUT, &to, sizeof to);
        flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_SECURE |
                INTERNET_FLAG_IGNORE_CERT_CN_INVALID | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID;
        hUrl = InternetOpenUrlA(hNet, url, NULL, 0, flags, 0);
        if (!hUrl) { InternetCloseHandle(hNet); return 0; }
        {
            DWORD scode = 0, slen = sizeof scode;
            if (HttpQueryInfoA(hUrl, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &scode, &slen, NULL))
                code = (int)scode;
        }
        while (InternetReadFile(hUrl, buf, sizeof buf, &read) && read > 0) {
            if (head_n < sizeof head) {
                size_t copy = read;
                if (head_n + copy > sizeof head) copy = sizeof head - head_n;
                memcpy(head + head_n, buf, copy);
                head_n += copy;
            }
            bytes += read;
            if (bytes > 2 * 1024 * 1024) break;
        }
        InternetCloseHandle(hUrl);
        InternetCloseHandle(hNet);
    }
#else
    {
        char cmd[LONGSTR * 2], meta[64];
        char tmp[] = "/tmp/netdiag_canary_XXXXXX";
        FILE *f;
        int fd;
        fd = mkstemp(tmp);
        if (fd < 0) return 0;
        close(fd);
        snprintf(cmd, sizeof cmd,
                 CURL_SSL_ENV
                 "curl -k -sS -L --max-time %d --max-filesize 2097152 "
                 "-o '%s' -w '%%{http_code}\\t%%{size_download}' '%s' 2>/dev/null",
                 timeout_sec, tmp, url);
        if (run_capture(cmd, meta, sizeof meta) != 0) {
            unlink(tmp);
            return 0;
        }
        {
            char *tab = strchr(meta, '\t');
            code = atoi(meta);
            if (tab) bytes = atol(tab + 1);
        }
        f = fopen(tmp, "rb");
        if (f) {
            head_n = fread(head, 1, sizeof head, f);
            if (bytes <= 0) {
                if (fseek(f, 0, SEEK_END) == 0) {
                    long pos = ftell(f);
                    if (pos > 0) bytes = pos;
                }
            }
            fclose(f);
        }
        unlink(tmp);
    }
#endif
    if (ms_out) *ms_out = (int)(now_ms() - t0);
    if (bytes_out) *bytes_out = bytes;
    if (code_out) *code_out = code;
    if (code > 0 && (code < 200 || code >= 400)) return 0;
    if (min_bytes > 0 && bytes < min_bytes) return 0;
    if (magic && magic[0]) {
        if (strcmp(magic, "PNG") == 0) {
            if (head_n < 8 || head[0] != 0x89 || head[1] != 'P' || head[2] != 'N' || head[3] != 'G')
                return 0;
        } else if (strcmp(magic, "GIF") == 0) {
            if (head_n < 6 || memcmp(head, "GIF8", 4) != 0) return 0;
        } else if (strcmp(magic, "HTML") == 0) {
            int ok = 0;
            size_t i;
            for (i = 0; i + 4 < head_n; i++) {
                if ((head[i] == '<' && (head[i + 1] == '!' || head[i + 1] == 'h' || head[i + 1] == 'H')) ||
                    (head[i] == '<' && head[i + 1] == 'H' && head[i + 2] == 'T')) {
                    ok = 1; break;
                }
            }
            if (!ok && bytes >= min_bytes && min_bytes >= 200) ok = 1; /* крупный HTML без BOM в head */
            if (!ok) return 0;
        }
    }
    return bytes > 0;
}

/* Баннер почтового протокола или TLS ClientHello на SMTPS/IMAPS/POP3S.
 * kind: "smtp" | "imap" | "pop3" | "tls"
 * Возврат: 2 = баннер/TLS ок, 1 = TCP открыт без баннера, 0 = закрыт. */
static int mail_proto_probe(const char *host, int port, const char *kind, int use_tls,
                            int timeout_ms, int *ms_out, char *banner_out, size_t banner_len) {
    net_sock s;
    long long t0 = now_ms();
    unsigned char buf[256];
    int n, rc = 0;

    if (ms_out) *ms_out = 0;
    if (banner_out && banner_len) banner_out[0] = 0;
    s = tcp_connect_sock(host, port, timeout_ms);
    if (s == NET_SOCK_BAD) {
        if (ms_out) *ms_out = (int)(now_ms() - t0);
        return 0;
    }
    if (use_tls) {
        if (tls_clienthello_sni(s, host, timeout_ms))
            rc = 2;
        else
            rc = 1;
        net_sock_close(s);
        if (ms_out) *ms_out = (int)(now_ms() - t0);
        if (banner_out && banner_len && rc == 2)
            snprintf(banner_out, banner_len, "TLS ServerHello OK (SNI %s)", host);
        return rc;
    }
    n = net_wait_recv(s, buf, sizeof buf - 1, timeout_ms);
    net_sock_close(s);
    if (ms_out) *ms_out = (int)(now_ms() - t0);
    if (n <= 0) return 1;
    buf[n] = 0;
    {
        char *p;
        for (p = (char *)buf; *p; p++)
            if (*p == '\r' || *p == '\n') { *p = 0; break; }
    }
    if (banner_out && banner_len)
        snprintf(banner_out, banner_len, "%s", (char *)buf);
    if (kind && strcmp(kind, "smtp") == 0 && strncmp((char *)buf, "220", 3) == 0) return 2;
    if (kind && strcmp(kind, "imap") == 0 && strstr((char *)buf, "OK")) return 2;
    if (kind && strcmp(kind, "pop3") == 0 && strncmp((char *)buf, "+OK", 3) == 0) return 2;
    if (kind && strcmp(kind, "tls") == 0) return 1;
    return 1;
}

static int extract_yastatic_asset(const char *html, char *url_out, size_t n) {
    const char *p;
    if (!html || !url_out || n < 32) return 0;
    url_out[0] = 0;
    p = html;
    while ((p = strstr(p, "https://yastatic.net/")) != NULL) {
        size_t i = 0;
        while (p[i] && p[i] != '"' && p[i] != '\'' && p[i] != ' ' &&
               p[i] != ')' && p[i] != '<' && p[i] != '>' && i + 1 < n) {
            url_out[i] = p[i];
            i++;
        }
        url_out[i] = 0;
        if (strstr(url_out, ".png") || strstr(url_out, ".jpg") || strstr(url_out, ".js") ||
            strstr(url_out, ".css") || strstr(url_out, ".svg") || strstr(url_out, ".woff"))
            return 1;
        p += 22;
    }
    return 0;
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

#define MAX_RES      160
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
static ResSig g_ru[MAX_RES];
static int g_nru;
static ResTcp g_game_tcp[MAX_RES];
static int g_ngame_tcp;
static ResTcp g_infra_tcp[MAX_RES];
static int g_ninfra_tcp;
static ResHttp g_infra_https[MAX_RES];
static int g_ninfra_https;
static ResHttp g_game_https[MAX_RES];
static int g_ngame_https;
static ResHttp g_geo[MAX_RES];
static int g_ngeo;
static ResHttp g_updates[MAX_RES];
static int g_nupdates;
static ResTcp g_ai[MAX_RES];
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
    static const struct { const char *name, *url, *note; int eb; } ru[] = {
        /* Значимые ресурсы (Белые списки МЦ) */
        {"Госуслуги", "https://www.gosuslugi.ru/", "", 0},
        {"Президент РФ", "http://www.kremlin.ru/",
         "HTTP; :443 часто недоступен", 0},
        {"Правительство РФ", "http://government.ru/",
         "HTTP; :443 часто недоступен", 0},
        {"Госдума", "http://duma.gov.ru/",
         "HTTP; :443 часто недоступен", 0},
        {"Совет Федерации", "http://www.council.gov.ru/",
         "HTTP; :443 часто недоступен", 0},
        {"ЦБ РФ", "https://www.cbr.ru/", "", 0},
        {"Почта России", "https://www.pochta.ru/", "", 0},
        {"Честный знак", "https://crpt.ru/", "", 0},
        {"Платёжная система Мир", "https://vamprivet.ru/", "", 0},
        {"ГИС ЖКХ", "https://dom.gosuslugi.ru/", "", 0},
        {"Объясняем.рф", "https://xn--90aivcdt6dxbc.xn--p1ai/", "", 0},
        {"Движение первых", "https://xn--90acagbhgpca7c8c7f.xn--p1ai/", "", 0},
        {"Московская биржа", "https://www.moex.com/", "", 0},
        {"МВД", "https://xn--b1aew.xn--p1ai/", "", 0},
        {"МЧС", "https://www.mchs.gov.ru/", "", 0},
        {"ФНС", "https://www.nalog.gov.ru/", "", 0},
        {"Роскачество", "https://rskrf.ru/", "", 0},
        {"Яндекс (yandex.ru)", "https://yandex.ru/", "", 0},
        {"Яндекс (ya.ru)", "https://ya.ru/", "", 0},
        {"Яндекс Карты", "https://yandex.ru/maps/", "", 0},
        {"Яндекс Маркет", "https://market.yandex.ru/", "", 0},
        {"Яндекс Музыка", "https://music.yandex.ru/", "", 0},
        {"Яндекс Go", "https://go.yandex/", "", 0},
        {"Яндекс Еда", "https://eda.yandex.ru/", "", 0},
        {"Яндекс Лавка", "https://lavka.yandex.ru/", "", 0},
        {"VK (vk.com)", "https://vk.com/", "", 0},
        {"VK (vk.ru)", "https://vk.ru/", "", 0},
        {"VK Видео", "https://vkvideo.ru/", "", 0},
        {"OK.ru", "https://ok.ru/", "", 0},
        {"Mail.ru", "https://mail.ru/", "", 0},
        {"MAX", "https://max.ru/", "", 0},
        {"Дзен", "https://dzen.ru/", "", 0},
        {"Rutube", "https://rutube.ru/", "", 0},
        {"IVI", "https://www.ivi.ru/", "", 0},
        {"Okko", "https://okko.tv/", "", 0},
        {"Premier", "https://premier.one/", "", 0},
        {"Кинопоиск", "https://www.kinopoisk.ru/", "", 0},
        {"РИА Новости", "https://ria.ru/", "", 0},
        {"ТАСС", "https://tass.ru/", "", 0},
        {"РБК", "https://www.rbc.ru/", "", 0},
        {"Лента.ру", "https://lenta.ru/", "", 0},
        {"Комсомольская правда", "https://www.kp.ru/", "", 0},
        {"Газета.ру", "https://www.gazeta.ru/", "", 0},
        {"Известия", "https://iz.ru/", "", 0},
        {"Аргументы и факты", "https://aif.ru/", "", 0},
        {"Российская газета", "https://rg.ru/", "", 0},
        {"Ведомости", "https://www.vedomosti.ru/", "", 0},
        {"МК", "https://www.mk.ru/", "", 0},
        {"Коммерсантъ", "https://www.kommersant.ru/", "", 0},
        {"Первый канал", "https://www.1tv.ru/", "", 0},
        {"НТВ", "https://www.ntv.ru/", "", 0},
        {"RT", "https://russian.rt.com/", "", 0},
        {"Матч ТВ", "https://matchtv.ru/", "", 0},
        {"Рувики", "https://ru.ruwiki.ru/", "", 0},
        {"Ozon", "https://www.ozon.ru/", "", 0},
        {"Wildberries", "https://napi.wildberries.ru/",
         "главная www — antibot/JS; проба через napi API", 0},
        {"Мегамаркет", "https://megamarket.ru/", "", 0},
        {"Avito", "https://www.avito.ru/", "", 0},
        {"Домклик", "https://domclick.ru/", "", 0},
        {"HH.ru", "https://hh.ru/", "", 0},
        {"Детский мир", "https://www.detmir.ru/", "", 0},
        {"РЖД", "https://www.rzd.ru/", "", 0},
        {"Туту.ру", "https://www.tutu.ru/", "", 0},
        {"2ГИС", "https://mapgl.2gis.com/api/js",
         "главная 2gis.ru — antibot/TLS; проба MapGL API", 0},
        {"Такси Максим", "https://taximaxim.ru/", "", 0},
        {"Делимобиль", "https://delimobil.ru/", "", 0},
        {"Ситидрайв", "https://citydrive.ru/", "", 0},
        {"Деловые линии", "https://www.dellin.ru/", "", 0},
        {"Аэрофлот", "https://www.aeroflot.ru/", "", 0},
        {"ВкусВилл", "https://vkusvill.ru/", "", 0},
        {"Ашан", "https://www.auchan.ru/", "", 0},
        {"Самокат", "https://samokat.ru/", "", 0},
        {"СДЭК", "https://www.cdek.ru/", "", 0},
        {"Магнит", "https://magnit.ru/", "", 0},
        {"Пятёрочка", "https://5ka.ru/", "", 0},
        {"Лента", "https://lenta.com/", "", 0},
        {"МТС", "https://www.mts.ru/", "", 0},
        {"МегаФон", "https://www.megafon.ru/", "", 0},
        {"Билайн", "https://www.beeline.ru/", "", 0},
        {"t2", "https://t2.ru/", "", 0},
        {"Ростелеком", "https://www.rt.ru/", "", 0},
        {"Gismeteo", "https://www.gismeteo.ru/", "", 0},
        {"Россети", "https://www.rosseti.ru/", "", 0},
        {"СКБ Контур", "https://kontur.ru/", "", 0},
        {"1С", "https://1c.ru/", "", 0},
        {"КХЛ", "https://www.khl.ru/", "", 0},
        {"Медси", "https://medsi.ru/", "", 0},
        {"Добро.рф", "https://dobro.ru/", "", 0},
        {"ЛизаАлерт", "https://lizaalert.org/", "", 0},
    };
    static const struct { const char *name, *url, *note; int eb; } sig[] = {
        /* зарубежные / контроль (блок РФ ≠ сбой сети) */
        {"Google", "https://www.google.com/", "", 0},
        {"Gmail", "https://mail.google.com/", "", 0},
        {"Google Play", "https://play.google.com/", "", 0},
        {"App Store", "https://apps.apple.com/", "", 0},
        {"Microsoft", "https://www.microsoft.com/", "", 0},
        {"Microsoft Teams", "https://go.trouter.teams.microsoft.com/",
         "веб teams.microsoft.com часто таймаут/antibot; проба Trouter (realtime Teams)", 0},
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
        {"Steam CM EU (fra1)", "ext1-fra1.steamserver.net", 27017, 0},
        {"Epic Games :443", "www.epicgames.com", 443, 0},
        {"Epic account API", "account-public-service-prod03.ol.epicgames.com", 443, 0},
        {"Epic CDN :443", "cdn1.epicgames.com", 443, 0},
        {"Epic launcher API", "launcher-public-service-prod06.ol.epicgames.com", 443, 0},
        {"Riot clientconfig", "clientconfig.rpg.riotgames.com", 443, 0},
        {"Riot auth", "auth.riotgames.com", 443, 0},
        {"Xbox Live", "xboxlive.com", 443, 0},
        {"PlayStation", "www.playstation.com", 443, 0},
        {"PSN Store", "store.playstation.com", 443, 0},
        {"EA / Origin", "www.ea.com", 443, 0},
        {"Ubisoft Connect", "www.ubisoft.com", 443, 0},
        {"Ubisoft Services", "public-ubiservices.ubi.com", 443, 0},
        {"Ubisoft CDN", "static2.cdn.ubi.com", 443, 0},
        {"GOG", "www.gog.com", 443, 0},
        {"Faceit", "api.faceit.com", 443, 0},
        {"Roblox", "www.roblox.com", 443, 1},
        {"Roblox economy", "economy.roblox.com", 443, 0},
        {"Roblox CDN", "setup.rbxcdn.com", 443, 1},
        {"Roblox CSS CDN", "css.rbxcdn.com", 443, 0},
        {"Lesta", "lesta.ru", 443, 0},
        {"Мир танков", "tanki.su", 443, 1},
        {"Мир танков CDN", "tanki-media-content.tanki.su", 443, 1},
        {"Lesta vol", "vol.lesta.ru", 443, 0},
        {"Мир кораблей", "korabli.su", 443, 1},
        {"World of Warships RU", "worldofwarships.ru", 443, 0},
        {"Wargaming RCDS", "rcds.wargaming.net", 443, 0},
        {"War Thunder", "www.warthunder.com", 443, 0},
        {"Escape from Tarkov", "www.escapefromtarkov.com", 443, 0},
        {"Twitch", "www.twitch.tv", 443, 1},
        {"Twitch CDN", "static.twitchcdn.net", 443, 0},
        {"Twitch static CDN", "static-cdn.jtvnw.net", 443, 1},
        {"Twitch usher CDN", "usher.ttvnw.net", 443, 0},
        {"Twitch VOD CDN", "vod-secure.twitch.tv", 443, 0},
        {"Kick", "kick.com", 443, 1},
        {"Kick files CDN", "files.kick.com", 443, 1},
        {"Kick images CDN", "images.kick.com", 443, 0},
        {"loot.farm", "loot.farm", 443, 0},
        {"loot.farm tags CDN", "tags.loot.farm", 443, 0},
        {"loot.farm API CDN", "cbcntvf.loot.farm", 443, 0},
        {"HoYoverse", "www.hoyoverse.com", 443, 1},
        {"Genshin Impact", "genshin.hoyoverse.com", 443, 1},
        {"HoYoLAB", "www.hoyolab.com", 443, 0},
        {"HoYoLAB API", "sg-public-api.hoyolab.com", 443, 0},
        {"HoYoverse webstatic CDN", "webstatic.hoyoverse.com", 443, 1},
        {"HoYoverse fastcdn", "fastcdn.hoyoverse.com", 443, 1},
        {"HoYoverse upload CDN", "upload-static.hoyoverse.com", 443, 0},
        {"PSN image CDN", "image.api.playstation.com", 443, 1},
        {"PSN download CDN", "apollo2.dl.playstation.net", 443, 0},
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
        {"Cloudflare :443", "www.cloudflare.com", 443, 1},
        {"Cloudflare 1.1.1.1 :443", "1.1.1.1", 443, 0},
        {"Cloudflare speed :443", "speed.cloudflare.com", 443, 1},
        {"Hetzner Console :443", "console.hetzner.cloud", 443, 1},
        {"Hetzner www :443", "www.hetzner.com", 443, 0},
        {"DigitalOcean :443", "www.digitalocean.com", 443, 1},
        {"DigitalOcean cloud :443", "cloud.digitalocean.com", 443, 0},
        {"OVH :443", "www.ovh.com", 443, 0},
        {"OVH Cloud :443", "www.ovhcloud.com", 443, 0},
        {"OVH proof :443", "proof.ovh.net", 443, 0},
        {"GitHub :443", "github.com", 443, 1},
        {"GitHub API :443", "api.github.com", 443, 0},
        {"GitHub Assets :443", "github.githubassets.com", 443, 0},
    };
    /* HTTPS-проверки облаков: 200/301/403 XML от S3 = сервис отвечает */
    static const struct { const char *name, *url; } ihttps[] = {
        {"AWS Health", "https://health.aws.amazon.com/health/status"},
        {"AWS Status", "https://status.aws.amazon.com/"},
        {"AWS S3 (landsat-pds)", "https://landsat-pds.s3.amazonaws.com/"},
        {"AWS S3 CDN (amazonlinux)", "https://cdn.amazonlinux.com/"},
        {"Cloudflare trace", "https://www.cloudflare.com/cdn-cgi/trace"},
        {"Cloudflare speed 20KB", "https://speed.cloudflare.com/__down?bytes=20000"},
        {"Hetzner Console", "https://console.hetzner.cloud/"},
        {"DigitalOcean", "https://www.digitalocean.com/"},
        {"OVH proof 1MB", "https://proof.ovh.net/files/1Mb.dat"},
        {"GitHub", "https://github.com/"},
        {"GitHub Assets", "https://github.githubassets.com/favicons/favicon.svg"},
        {"GitHub raw", "https://raw.githubusercontent.com/github/gitignore/main/C.gitignore"},
    };
    static const struct { const char *name, *url; } geo[] = {
        {"HE Looking Glass (US)", "https://lg.he.net/"},
        {"Hurricane Electric (US)", "https://www.he.net/"},
        {"DE-CIX (DE · IX)", "https://www.de-cix.net/"},
        {"DE-CIX LG (DE · IX)", "https://lg.de-cix.net/"},
        {"AMS-IX (NL · IX)", "https://www.ams-ix.net/"},
        {"AMS-IX LG (NL · IX)", "https://lg.ams-ix.net/"},
        {"LINX (UK · IX)", "https://www.linx.net/"},
        {"DATAIX (RU · IX)", "https://www.dataix.ru/"},
        {"Eurasia Peering (RU · IX)", "https://www.eurasiapeering.ru/"},
        {"Selectel speed 10MB (RU)", "https://speedtest.selectel.ru/10MB"},
    };
    /* Репозитории Linux / зеркала + точки обновлений ОС и пакетных экосистем.
     * 401/403 от registry часто = OK (ok_403 на этапе). */
    static const struct { const char *name, *url; } updates[] = {
        /* --- Linux: официальные репо / зеркала --- */
        {"Debian (deb.debian.org)", "https://deb.debian.org/debian/dists/stable/Release"},
        {"Debian security", "https://security.debian.org/debian-security/dists/stable-security/Release"},
        {"Ubuntu archive", "https://archive.ubuntu.com/ubuntu/dists/noble/InRelease"},
        {"Ubuntu security", "https://security.ubuntu.com/ubuntu/dists/noble-security/InRelease"},
        {"Yandex mirror Debian", "https://mirror.yandex.ru/debian/dists/stable/Release"},
        {"Yandex mirror Ubuntu", "https://mirror.yandex.ru/ubuntu/dists/noble/InRelease"},
        {"Fedora", "https://dl.fedoraproject.org/pub/fedora/linux/releases/"},
        {"Rocky Linux", "https://dl.rockylinux.org/pub/rocky/"},
        {"AlmaLinux", "https://repo.almalinux.org/almalinux/"},
        {"Arch Linux geo mirror", "https://geo.mirror.pkgbuild.com/core/os/x86_64/"},
        {"Alpine CDN", "https://dl-cdn.alpinelinux.org/alpine/latest-stable/main/x86_64/APKINDEX.tar.gz"},
        {"openSUSE download", "https://download.opensuse.org/distribution/leap/"},
        {"Kali rolling", "https://http.kali.org/kali/dists/kali-rolling/InRelease"},
        {"Amazon Linux CDN", "https://cdn.amazonlinux.com/"},
        /* --- Windows / Microsoft --- */
        {"Windows Update CTL",
         "https://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/authrootstl.cab"},
        {"Microsoft download CDN", "https://download.microsoft.com/"},
        {"Winget CDN cache", "https://cdn.winget.microsoft.com/cache/"},
        {"Chocolatey community", "https://community.chocolatey.org/api/v2/"},
        /* --- Apple --- */
        {"Apple software catalog (gdmf)", "https://gdmf.apple.com/v2/pmv"},
        {"Apple mesu", "https://mesu.apple.com/assets/"},
        {"Apple configuration",
         "https://configuration.apple.com/configurations/internetservices/configuration.plist"},
        /* --- Android / Google --- */
        {"Android repository XML", "https://dl.google.com/android/repository/repository2-1.xml"},
        {"Google update service", "https://update.googleapis.com/service/update2"},
        {"Chrome updates (Omaha)", "https://update.googleapis.com/chrome"},
        /* --- контейнеры / язык. экосистемы --- */
        {"Docker Hub registry", "https://registry-1.docker.io/v2/"},
        {"Docker Hub auth", "https://auth.docker.io/token"},
        {"npm registry", "https://registry.npmjs.org/"},
        {"PyPI", "https://pypi.org/simple/"},
        {"crates.io", "https://static.crates.io/config.json"},
        {"Maven Central", "https://repo1.maven.org/maven2/"},
        {"NuGet", "https://api.nuget.org/v3/index.json"},
        {"Homebrew formulae API", "https://formulae.brew.sh/api/formula.json"},
        {"Flathub API", "https://flathub.org/api/v2/collection/recently-updated"},
        {"Snapcraft API", "https://api.snapcraft.io/v2/snaps/info/core"},
        {"Mozilla CDN", "https://download-installer.cdn.mozilla.net/"},
        {"VS Code updates", "https://update.code.visualstudio.com/api/update/darwin/stable/latest"},
    };
    static const struct { const char *name, *url; } ghttps[] = {
        {"Battle.net", "https://battle.net/"},
        {"Blizzard", "https://www.blizzard.com/"},
        {"Battle.net login", "https://account.battle.net/login/"},
        {"Battle.net support", "https://eu.battle.net/support/"},
        /* Витрины store/community/api часто antibot/DPI; CDN и account API — рабочие сигналы. */
        {"Steam CDN (Dota)", "https://cdn.cloudflare.steamstatic.com/steam/apps/570/header.jpg"},
        {"Steam CDN (CS2)",
         "https://shared.cloudflare.steamstatic.com/store_item_assets/steam/apps/730/header.jpg"},
        {"Epic account API",
         "https://account-public-service-prod03.ol.epicgames.com/account/api/public/account"},
        {"Epic CDN", "https://cdn1.epicgames.com/"},
        {"Epic Unreal CDN", "https://cdn2.unrealengine.com/"},
        {"Riot Games", "https://www.riotgames.com/"},
        {"Xbox", "https://www.xbox.com/"},
        {"PlayStation Network", "https://www.playstation.com/"},
        {"PSN Store", "https://store.playstation.com/"},
        {"EA App", "https://www.ea.com/ea-app"},
        {"Ubisoft Services", "https://public-ubiservices.ubi.com/"},
        {"Ubisoft CDN", "https://static2.cdn.ubi.com/"},
        {"GOG Galaxy", "https://www.gog.com/"},
        {"Nintendo", "https://www.nintendo.com/"},
        {"Roblox", "https://www.roblox.com/"},
        {"Roblox CSS CDN",
         "https://css.rbxcdn.com/"
         "7dfc7837b5da6850e13413c630b37da7e88aeb610ca2c7d4e8b71b02cbdc6ba6.css"},
        {"Roblox setup CDN", "https://setup.rbxcdn.com/"},
        {"Minecraft / Mojang", "https://www.minecraft.net/"},
        {"VK Play", "https://vkplay.ru/"},
        {"Мир танков", "https://tanki.su/"},
        {"Мир танков CDN",
         "https://tanki-media-content.tanki.su/tanki-media/fonts/MT-sans/index.css"},
        {"Lesta", "https://lesta.ru/"},
        {"Мир кораблей", "https://korabli.su/"},
        {"World of Warships RU", "https://worldofwarships.ru/"},
        {"War Thunder", "https://www.warthunder.com/"},
        {"Escape from Tarkov", "https://www.escapefromtarkov.com/"},
        {"Twitch", "https://www.twitch.tv/"},
        {"Twitch static CDN",
         "https://static-cdn.jtvnw.net/ttv-static-metadata/twitch_logo3.jpg"},
        {"Twitch VOD CDN", "https://vod-secure.twitch.tv/"},
        {"Kick", "https://kick.com/"},
        {"Kick files CDN", "https://files.kick.com/"},
        {"Kick images CDN", "https://images.kick.com/"},
        {"loot.farm", "https://loot.farm/"},
        {"loot.farm tags CDN", "https://tags.loot.farm/gtm.js"},
        {"HoYoverse", "https://www.hoyoverse.com/"},
        {"Genshin Impact", "https://genshin.hoyoverse.com/"},
        {"HoYoLAB", "https://www.hoyolab.com/"},
        {"HoYoverse webstatic CDN",
         "https://webstatic.hoyoverse.com/dora/base/jquery-1.11.1.js"},
        {"HoYoverse upload CDN",
         "https://upload-static.hoyoverse.com/hk4e/upload/fb/common.jpg"},
        {"PSN image CDN",
         "https://image.api.playstation.com/vulcan/ap/rnd/202506/2509/"
         "ec1eec85d9130210701491db769cb9874cc09f6512ebca20.png"},
    };
    /* AI: только TCP :443 — HTTPS часто «умный» таймаут/DPI при живом connect. */
    static const struct { const char *name, *host; int port, crit; } ai[] = {
        {"Cursor", "www.cursor.com", 443, 1},
        {"Cursor API", "api2.cursor.sh", 443, 1},
        {"OpenAI", "openai.com", 443, 1},
        {"ChatGPT", "chatgpt.com", 443, 1},
        {"OpenAI API", "api.openai.com", 443, 1},
        {"Claude / Anthropic", "claude.ai", 443, 1},
        {"Anthropic API", "api.anthropic.com", 443, 1},
        {"Anthropic console", "console.anthropic.com", 443, 0},
        {"Grok / xAI", "grok.x.ai", 443, 1},
        {"xAI", "x.ai", 443, 0},
        {"xAI API", "api.x.ai", 443, 0},
        {"Gemini", "gemini.google.com", 443, 1},
        {"Google AI Studio", "aistudio.google.com", 443, 0},
        {"Google AI / Generative", "generativelanguage.googleapis.com", 443, 0},
        {"Microsoft Copilot", "copilot.microsoft.com", 443, 0},
        {"Perplexity", "www.perplexity.ai", 443, 0},
        {"DeepSeek", "www.deepseek.com", 443, 0},
        {"DeepSeek Chat", "chat.deepseek.com", 443, 0},
        {"Mistral", "mistral.ai", 443, 0},
        {"Mistral Chat", "chat.mistral.ai", 443, 0},
        {"Hugging Face", "huggingface.co", 443, 0},
        {"Groq", "groq.com", 443, 0},
        {"Together AI", "www.together.ai", 443, 0},
        {"Poe", "poe.com", 443, 0},
        {"YandexGPT / Alice AI", "alice.yandex.ru", 443, 0},
        {"GigaChat", "giga.chat", 443, 0},
    };
    static const struct { const char *name, *home, *video; } vids[] = {
        {"Яндекс Видео", "https://ya.ru/video/", "https://ya.ru/video/search?text=news"},
        {"VK Видео", "https://vkvideo.ru/", "https://vkvideo.ru/sitemaps/sitemap-video-1.xml"},
        {"IVI", "https://www.ivi.ru/", "https://www.ivi.ru/watch/masha_i_medved"},
        {"Okko", "https://okko.tv/", "https://okko.tv/movie/avatar"},
        {"Кинопоиск", "https://www.kinopoisk.ru/", "https://www.kinopoisk.ru/lists/movies/popular/"},
        {"Rutube", "https://rutube.ru/", "https://rutube.ru/feeds/top/"},
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
        {"Сервисы РФ", "DNS Shop", "https://www.dns-shop.ru/"},
        {"Сервисы РФ", "ЦИАН", "https://www.cian.ru/"},
        {"Проблемы провайдера", "Zoom", "https://www.zoom.com/"},
        {"Проблемы провайдера", "Bitrix24", "https://www.bitrix24.ru/"},
    };
    int i, n;

    n = (int)(sizeof ru / sizeof ru[0]);
    if (n > MAX_RES) n = MAX_RES;
    g_nru = n;
    for (i = 0; i < n; i++) {
        snprintf(g_ru[i].name, sizeof g_ru[i].name, "%s", ru[i].name);
        snprintf(g_ru[i].url, sizeof g_ru[i].url, "%s", ru[i].url);
        snprintf(g_ru[i].note, sizeof g_ru[i].note, "%s", ru[i].note);
        g_ru[i].expected_block = ru[i].eb;
    }

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

    n = (int)(sizeof geo / sizeof geo[0]);
    if (n > MAX_RES) n = MAX_RES;
    g_ngeo = n;
    for (i = 0; i < n; i++) {
        snprintf(g_geo[i].name, sizeof g_geo[i].name, "%s", geo[i].name);
        snprintf(g_geo[i].url, sizeof g_geo[i].url, "%s", geo[i].url);
    }

    n = (int)(sizeof updates / sizeof updates[0]);
    if (n > MAX_RES) n = MAX_RES;
    g_nupdates = n;
    for (i = 0; i < n; i++) {
        snprintf(g_updates[i].name, sizeof g_updates[i].name, "%s", updates[i].name);
        snprintf(g_updates[i].url, sizeof g_updates[i].url, "%s", updates[i].url);
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
        snprintf(g_ai[i].host, sizeof g_ai[i].host, "%s", ai[i].host);
        g_ai[i].port = ai[i].port;
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
 * Буферы на куче — на pthread-стеке GUI (~512KB) иначе SIGBUS (Thread stack size exceeded).
 */
static int resources_load_file(const char *path) {
    FILE *f;
    char line[1024];
    char section[64] = "";
    int got_sig = 0, got_ru = 0, got_gtcp = 0, got_itcp = 0, got_ihttps = 0, got_ghttps = 0, got_geo = 0, got_updates = 0, got_ai = 0, got_vid = 0, got_bank = 0;
    int nsig = 0, nru = 0, ngtcp = 0, nitcp = 0, nihttps = 0, nghttps = 0, ngeo = 0, nupdates = 0, nai = 0, nvid = 0, nbank = 0;
    ResSig *sig = NULL, *ru = NULL;
    ResTcp *gtcp = NULL, *itcp = NULL, *ai = NULL;
    ResHttp *ihttps = NULL, *ghttps = NULL, *geo = NULL, *updates = NULL;
    ResVideo *vids = NULL;
    ResBank *banks = NULL;
    int ok = 0;

    if (!path || !path[0]) return 0;
    f = fopen(path, "r");
    if (!f) return 0;

    sig = (ResSig *)calloc((size_t)MAX_RES, sizeof *sig);
    ru = (ResSig *)calloc((size_t)MAX_RES, sizeof *ru);
    gtcp = (ResTcp *)calloc((size_t)MAX_RES, sizeof *gtcp);
    itcp = (ResTcp *)calloc((size_t)MAX_RES, sizeof *itcp);
    ihttps = (ResHttp *)calloc((size_t)MAX_RES, sizeof *ihttps);
    ghttps = (ResHttp *)calloc((size_t)MAX_RES, sizeof *ghttps);
    geo = (ResHttp *)calloc((size_t)MAX_RES, sizeof *geo);
    updates = (ResHttp *)calloc((size_t)MAX_RES, sizeof *updates);
    ai = (ResTcp *)calloc((size_t)MAX_RES, sizeof *ai);
    vids = (ResVideo *)calloc((size_t)MAX_RES, sizeof *vids);
    banks = (ResBank *)calloc((size_t)MAX_RES, sizeof *banks);
    if (!sig || !ru || !gtcp || !itcp || !ihttps || !ghttps || !geo || !updates || !ai || !vids || !banks) {
        fclose(f);
        goto out;
    }

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

        if (strcmp(section, "popular_ru") == 0 && nru < MAX_RES) {
            snprintf(ru[nru].name, sizeof ru[nru].name, "%s", fields[0]);
            snprintf(ru[nru].url, sizeof ru[nru].url, "%s", fields[1]);
            snprintf(ru[nru].note, sizeof ru[nru].note, "%s", nf > 2 ? fields[2] : "");
            ru[nru].expected_block = (nf > 3 && fields[3][0] == '1') ? 1 : 0;
            nru++;
            got_ru = 1;
        } else if (strcmp(section, "significant") == 0 && nsig < MAX_RES) {
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
        } else if (strcmp(section, "geo") == 0 && ngeo < MAX_RES) {
            snprintf(geo[ngeo].name, sizeof geo[ngeo].name, "%s", fields[0]);
            snprintf(geo[ngeo].url, sizeof geo[ngeo].url, "%s", fields[1]);
            ngeo++;
            got_geo = 1;
        } else if (strcmp(section, "updates") == 0 && nupdates < MAX_RES) {
            snprintf(updates[nupdates].name, sizeof updates[nupdates].name, "%s", fields[0]);
            snprintf(updates[nupdates].url, sizeof updates[nupdates].url, "%s", fields[1]);
            nupdates++;
            got_updates = 1;
        } else if (strcmp(section, "ai") == 0 && nai < MAX_RES) {
            snprintf(ai[nai].name, sizeof ai[nai].name, "%s", fields[0]);
            if (nf >= 3 && fields[1][0] &&
                !(starts_with(fields[1], "http://") || starts_with(fields[1], "https://"))) {
                snprintf(ai[nai].host, sizeof ai[nai].host, "%s", fields[1]);
                ai[nai].port = atoi(fields[2]);
                if (ai[nai].port <= 0) ai[nai].port = 443;
                ai[nai].crit = (nf > 3 && fields[3][0] == '1') ? 1 : 0;
            } else {
                host_from_url(fields[1], ai[nai].host, sizeof ai[nai].host);
                ai[nai].port = 443;
                ai[nai].crit = (nf > 2 && fields[2][0] == '1') ? 1 : 0;
            }
            if (ai[nai].host[0]) {
                nai++;
                got_ai = 1;
            }
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
    f = NULL;

    if (got_ru) {
        memcpy(g_ru, ru, (size_t)nru * sizeof ru[0]);
        g_nru = nru;
    }
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
    if (got_geo) {
        memcpy(g_geo, geo, (size_t)ngeo * sizeof geo[0]);
        g_ngeo = ngeo;
    }
    if (got_updates) {
        memcpy(g_updates, updates, (size_t)nupdates * sizeof updates[0]);
        g_nupdates = nupdates;
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
    ok = 1;

out:
    if (f) fclose(f);
    free(sig); free(ru); free(gtcp); free(itcp);
    free(ihttps); free(ghttps); free(geo); free(updates);
    free(ai); free(vids); free(banks);
    return ok;
}

/* Базовое имя каталога (mac / linux / win) — без пути. */
static int is_os_cli_dirname(const char *base) {
    return base && (!strcmp(base, "mac") || !strcmp(base, "linux") || !strcmp(base, "win"));
}

static int resources_try_load(const char *path) {
    if (!path || !path[0]) return 0;
    if (!resources_load_file(path)) return 0;
    g_resources_from_file = 1;
    snprintf(resources_loaded, sizeof resources_loaded, "%s", path);
    printf("Списки ресурсов: %s\n", resources_loaded);
    return 1;
}

/*
 * Порядок (важно для GUI/пакета: conf в корне архива, CLI в mac|linux|win/):
 *  1) --resources FILE
 *  2) resources.conf в родителе exe, если exe в …/mac|linux|win (корень пакета)
 *  3) resources.conf в cwd
 *  4) resources.conf рядом с exe
 *  иначе — встроенные списки
 *
 * Корень пакета раньше cwd: иначе при запуске из win/ подхватывается устаревшая
 * копия mac|linux|win/resources.conf вместо отредактированного файла в корне.
 */
static void resources_init(void) {
    char try1[STR];

    resources_load_defaults();
    g_resources_from_file = 0;
    resources_loaded[0] = 0;

    if (resources_path[0]) {
        if (!resources_try_load(resources_path))
            fprintf(stderr, "Не удалось прочитать --resources %s — встроенные списки\n",
                    resources_path);
        return;
    }

    if (exe_dir[0]) {
        const char *base;
#ifdef _WIN32
        {
            char *slash = strrchr(exe_dir, '\\');
            char *slash2 = strrchr(exe_dir, '/');
            if (slash2 && (!slash || slash2 > slash)) slash = slash2;
            base = slash ? slash + 1 : exe_dir;
        }
#else
        {
            const char *slash = strrchr(exe_dir, '/');
            base = slash ? slash + 1 : exe_dir;
        }
#endif
        if (is_os_cli_dirname(base) && base > exe_dir) {
            char parent[STR];
            size_t n = (size_t)(base - exe_dir);
            if (n > 0) n--; /* убрать trailing sep */
            if (n > 0 && n < sizeof parent) {
                memcpy(parent, exe_dir, n);
                parent[n] = 0;
#ifdef _WIN32
                snprintf(try1, sizeof try1, "%s\\resources.conf", parent);
#else
                snprintf(try1, sizeof try1, "%s/resources.conf", parent);
#endif
                if (resources_try_load(try1))
                    return;
            }
        }
    }

    if (resources_try_load("resources.conf"))
        return;

    if (exe_dir[0]) {
#ifdef _WIN32
        snprintf(try1, sizeof try1, "%s\\resources.conf", exe_dir);
#else
        snprintf(try1, sizeof try1, "%s/resources.conf", exe_dir);
#endif
        if (resources_try_load(try1))
            return;
    }
}

/* ---------- HTML ---------- */

static const char *status_label(const char *st) {
    if (strcmp(st, "ok") == 0) return "OK";
    if (strcmp(st, "warn") == 0) return "Внимание";
    if (strcmp(st, "fail") == 0) return "Сбой";
    return "Инфо";
}

static void json_esc(FILE *f, const char *s) {
    if (!s) return;
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\') { fputc('\\', f); fputc((char)c, f); }
        else if (c == '\n') fputs("\\n", f);
        else if (c == '\r') fputs("\\r", f);
        else if (c == '\t') fputs("\\t", f);
        else if (c < 0x20) fprintf(f, "\\u%04x", c);
        else fputc((char)c, f);
    }
}

/* PORT / PROTO / SNI / URL из diag_url + эвристик по имени/detail. */
static void check_endpoint_fields(const Check *c,
                                  char *ip, size_t iplen,
                                  char *port, size_t portlen,
                                  char *proto, size_t protolen,
                                  char *sni, size_t snilen,
                                  char *url, size_t urllen) {
    const char *p;

    if (ip && iplen) ip[0] = 0;
    if (port && portlen) port[0] = 0;
    if (proto && protolen) proto[0] = 0;
    if (sni && snilen) sni[0] = 0;
    if (url && urllen) url[0] = 0;
    if (!c) return;

    if (ip && iplen && c->resolved_ip[0])
        snprintf(ip, iplen, "%s", c->resolved_ip);
    if (url && urllen && c->diag_url[0])
        snprintf(url, urllen, "%s", c->diag_url);

    if (c->diag_url[0]) {
        host_from_url(c->diag_url, sni, snilen);
        p = c->diag_url;
        if (starts_with(p, "https://")) {
            p += 8;
            if (proto && protolen) snprintf(proto, protolen, "HTTPS");
            if (port && portlen) snprintf(port, portlen, "443");
        } else if (starts_with(p, "http://")) {
            p += 7;
            if (proto && protolen) snprintf(proto, protolen, "HTTP");
            if (port && portlen) snprintf(port, portlen, "80");
        }
        while (p && *p && *p != '/' && *p != '?' && *p != '#') {
            if (*p == ':' && isdigit((unsigned char)p[1])) {
                int pr = atoi(p + 1);
                if (pr > 0 && pr <= 65535 && port && portlen)
                    snprintf(port, portlen, "%d", pr);
                break;
            }
            p++;
        }
    }

    /* эвристики по типу проверки */
    if (strstr(c->name, "DoT") || strstr(c->detail, ":853") || strstr(c->detail, "853")) {
        if (proto && protolen) snprintf(proto, protolen, "DoT/TLS");
        if (port && portlen) snprintf(port, portlen, "853");
    } else if (strstr(c->name, "DoH") || strstr(c->category, "DoH")) {
        if (proto && protolen) snprintf(proto, protolen, "DoH/HTTPS");
        if (port && portlen && !port[0]) snprintf(port, portlen, "443");
    } else if (strstr(c->name, "QUIC") || strstr(c->detail, "QUIC")) {
        if (proto && protolen) snprintf(proto, protolen, "QUIC/UDP");
        if (port && portlen && !port[0]) snprintf(port, portlen, "443");
    } else if (strstr(c->name, "Ping ") || starts_with(c->name, "Ping")) {
        if (proto && protolen) snprintf(proto, protolen, "ICMP");
        if (port && portlen) snprintf(port, portlen, "-");
    } else if (strstr(c->name, "NTP") || strcmp(c->category, "NTP") == 0) {
        if (proto && protolen) snprintf(proto, protolen, "NTP/UDP");
        if (port && portlen) snprintf(port, portlen, "123");
    } else if (strstr(c->name, "Резолвер") || strstr(c->name, "DNS ") ||
               strcmp(c->category, "DNS") == 0 || strcmp(c->category, "DNS-прогон") == 0) {
        if (proto && protolen && (!proto[0] || strcmp(proto, "HTTPS") != 0))
            snprintf(proto, protolen, "DNS/UDP");
        if (port && portlen && (!port[0] || strcmp(port, "443") == 0) &&
            !c->diag_url[0])
            snprintf(port, portlen, "53");
    } else if (strstr(c->detail, "MQTT") || strstr(c->name, "MQTT") || strstr(c->detail, ":8883")) {
        if (proto && protolen) snprintf(proto, protolen, "MQTT/TLS");
        if (port && portlen) snprintf(port, portlen, "8883");
    } else if (strstr(c->detail, "UDP") && (!proto || !proto[0])) {
        if (proto && protolen) snprintf(proto, protolen, "UDP");
    }

    /* порт из detail вида host:443 / TCP :443 */
    if (port && portlen && (!port[0] || strcmp(port, "-") == 0)) {
        const char *t = c->detail;
        for (; t && *t; t++) {
            if (*t == ':' && isdigit((unsigned char)t[1])) {
                int pr = atoi(t + 1);
                if (pr > 0 && pr <= 65535) {
                    snprintf(port, portlen, "%d", pr);
                    if (proto && protolen && !proto[0])
                        snprintf(proto, protolen, "TCP");
                    break;
                }
            }
        }
    }

    if (proto && protolen && !proto[0] && c->diag_url[0])
        snprintf(proto, protolen, "TCP");
    if (sni && snilen && !sni[0] && c->diag_url[0])
        host_from_url(c->diag_url, sni, snilen);
    /* SNI из имени, если IP-проверка с hostname в detail */
    if (sni && snilen && !sni[0]) {
        const char *t = c->detail;
        if (t && (strstr(t, ".ru") || strstr(t, ".com") || strstr(t, ".net"))) {
            /* оставить пустым — надёжнее не угадывать */
        }
    }
    if (ip && iplen && !ip[0] && sni && sni[0] &&
        isdigit((unsigned char)sni[0])) {
        /* diag host is IP */
        snprintf(ip, iplen, "%s", sni);
    }
}

static void ip_for_filename(const char *ip, char *out, size_t n, const char *fallback) {
    size_t i, j = 0;
    if (!out || n == 0) return;
    out[0] = 0;
    if (!ip || !ip[0]) {
        snprintf(out, n, "%s", fallback ? fallback : "unknown");
        return;
    }
    for (i = 0; ip[i] && j + 1 < n; i++) {
        unsigned char c = (unsigned char)ip[i];
        if (isalnum(c) || c == '.' || c == '-')
            out[j++] = (char)c;
        else if (c == ':' || c == '%')
            out[j++] = '-';
    }
    out[j] = 0;
    if (!out[0])
        snprintf(out, n, "%s", fallback ? fallback : "unknown");
}

/* Имя: net_diag_<stamp>_<lan>_<wan>.html — после сбора local/external IP */
static void report_path_rebuild(const char *dir) {
    char lan[72], wan[72];
    const char *base = (dir && dir[0]) ? dir : ".";
    ip_for_filename(local_ip, lan, sizeof lan, "no-lan");
    ip_for_filename(external_ip, wan, sizeof wan, "no-wan");
#ifdef _WIN32
    snprintf(report_path, sizeof report_path, "%s\\net_diag_%s_%s_%s.html",
             base, stamp, lan, wan);
#else
    snprintf(report_path, sizeof report_path, "%s/net_diag_%s_%s_%s.html",
             base, stamp, lan, wan);
#endif
}

static void write_html(void) {
    FILE *f;
    int i;
    const char *prev_cat = "";
    char wifi_line[256];
    char dns_line[256];
    int di;

    report_path_rebuild(output_dir);
    f = fopen(report_path, "wb");
    if (!f) {
        /* Read-only том (DMG) или нет прав — пишем в домашний каталог */
        char alt_dir[STR];
        const char *home = NULL;
#ifdef _WIN32
        home = getenv("USERPROFILE");
        if (home && home[0]) {
            snprintf(alt_dir, sizeof alt_dir, "%s\\Documents\\ConnectCheck", home);
            CreateDirectoryA(alt_dir, NULL);
            report_path_rebuild(alt_dir);
        } else
            alt_dir[0] = 0;
#else
        home = getenv("HOME");
        if (home && home[0]) {
            char cmd[STR];
            snprintf(alt_dir, sizeof alt_dir, "%s/Documents/ConnectCheck", home);
            snprintf(cmd, sizeof cmd, "mkdir -p '%s'", alt_dir);
            system(cmd);
            report_path_rebuild(alt_dir);
        } else
            alt_dir[0] = 0;
#endif
        if (alt_dir[0])
            f = fopen(report_path, "wb");
        if (f) {
            engine_logf("Каталог отчёта недоступен — записано в %s", report_path);
        } else {
            engine_logf("Не удалось записать отчёт: %s", report_path);
            return;
        }
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
        "h1{font-size:1.5rem;margin:0 0 4px;font-weight:650}.sub{color:var(--muted);margin-bottom:12px}\n"
        ".disclaimer{margin:0 0 18px;padding:10px 14px;border-radius:10px;border:1px solid var(--line);"
        "background:rgba(102,179,255,.06);color:var(--muted);font-size:.88rem;line-height:1.4;"
        "border-left:3px solid var(--info)}\n"
        ".disclaimer strong{color:var(--text);font-weight:650}\n"
        ".cards{display:flex;flex-wrap:wrap;gap:12px;margin-bottom:20px;align-items:stretch}\n"
        ".card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px 16px;min-width:120px}\n"
        ".card .n{font-size:1.6rem;font-weight:700}.card .l{color:var(--muted);font-size:.85rem}\n"
        ".card.ok .n{color:var(--ok)}.card.warn .n{color:var(--warn)}.card.fail .n{color:var(--fail)}\n"
        ".card.fail{min-width:160px;padding:18px 22px;border-color:rgba(243,18,96,.35)}\n"
        ".card.fail .n{font-size:2.1rem}.card.ok{min-width:100px;opacity:.92}\n"
        ".card.warn{min-width:140px;border-color:rgba(255,184,0,.35)}\n"
        ".finding{border-radius:12px;padding:14px 16px;margin-bottom:10px;border:1px solid var(--line);background:var(--panel)}\n"
        ".finding.critical{border-left:4px solid var(--fail)}.finding.warning{border-left:4px solid var(--warn)}"
        ".finding.info{border-left:4px solid var(--info)}.finding p{margin:6px 0 0;color:var(--muted)}\n"
        ".problems{margin-bottom:18px}.prob{display:flex;flex-wrap:wrap;gap:8px 12px;align-items:baseline;"
        "border-radius:12px;padding:12px 14px;margin-bottom:8px;border:1px solid var(--line);background:var(--panel)}\n"
        ".prob.fail{border-left:4px solid var(--fail)}.prob.warn{border-left:4px solid var(--warn)}\n"
        ".prob .meta{color:var(--muted);font-size:.85rem;flex:1 1 180px}.prob .det{color:var(--muted);font-size:.9rem;"
        "flex:2 1 240px;min-width:0;word-break:break-word}\n"
        "details.warn-fold{margin:10px 0 0;border:1px solid var(--line);border-radius:12px;"
        "background:var(--panel);padding:10px 14px}\n"
        "details.warn-fold>summary{cursor:pointer;color:var(--warn);font-weight:650;user-select:none;"
        "list-style:none;display:flex;gap:10px;align-items:baseline;flex-wrap:wrap}\n"
        "details.warn-fold>summary::-webkit-details-marker{display:none}\n"
        "details.warn-fold>summary .n{font-size:1.35rem;font-weight:700;color:var(--warn)}\n"
        "details.warn-fold>summary .hint{color:var(--muted);font-weight:400;font-size:.85rem}\n"
        "details.warn-fold[open]>summary{margin-bottom:10px}\n"
        "details.warn-fold .prob{margin-bottom:6px}\n"
        "a.jumplink{color:var(--info);text-decoration:none;font-weight:650;white-space:nowrap}"
        "a.jumplink:hover{text-decoration:underline}\n"
        "a.extlink{color:var(--info);text-decoration:none;word-break:break-all}"
        "a.extlink:hover{text-decoration:underline}a.extlink code{color:inherit}\n"
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
        ".toolbar{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin:0 0 18px}\n"
        "button.btn-dl{background:#243040;border:1px solid var(--info);color:var(--text);border-radius:10px;"
        "padding:10px 16px;font-size:.95rem;font-weight:650;cursor:pointer}\n"
        "button.btn-dl:hover{background:#2c3a4c}.toolbar .muted{color:var(--muted);font-size:.85rem}\n"
        "pre.netdiag{margin:6px 0 4px;padding:8px 10px;background:#0c1015;border-radius:8px;"
        "border:1px solid var(--line);white-space:pre-wrap;word-break:break-word;max-height:280px;"
        "overflow:auto;font-size:.78rem;line-height:1.35;color:var(--text)}\n"
        ".netdiag-block{margin-top:8px}.netdiag-block .lbl{font-weight:600;color:var(--muted)}\n"
        ".howto{margin-top:22px;padding:16px;border-radius:12px;background:var(--panel);border:1px solid var(--line);color:var(--muted)}\n"
        ".howto h2{color:var(--text);font-size:1.1rem;margin:0 0 8px}code{background:#0c1015;padding:1px 6px;border-radius:4px}\n"
        "</style>\n"
        "<script>\n"
        "async function copyText(t,btn){try{await navigator.clipboard.writeText(t);"
        "if(btn){const o=btn.textContent;btn.textContent='Скопировано';setTimeout(()=>btn.textContent=o,1200)}}"
        "catch(e){prompt('Скопируйте:',t)}}\n"
        "function copyPre(btn){const b=btn.closest('.netdiag-block');"
        "const pre=b&&b.querySelector('pre');if(pre)copyText(pre.textContent,btn)}\n"
        "function revealTarget(){const id=location.hash.slice(1);if(!id)return;"
        "const el=document.getElementById(id);if(!el)return;"
        "let p=el.parentElement;while(p){if(p.tagName==='DETAILS')p.open=true;p=p.parentElement}"
        "document.querySelectorAll('tr.target-hl').forEach(r=>r.classList.remove('target-hl'));"
        "el.classList.add('target-hl');"
        "setTimeout(()=>el.scrollIntoView({behavior:'smooth',block:'center'}),30)}\n"
        "window.addEventListener('hashchange',revealTarget);"
        "window.addEventListener('DOMContentLoaded',revealTarget);\n"
        "function downloadProblemsTxt(){\n"
        "const rows=window.CC_PROBLEMS||[];\n"
        "const stamp=window.CC_STAMP||'report';\n"
        "let t='# connect-check problem nodes (fail only)\\n';\n"
        "t+='# generated: '+stamp+' · connect-check '+((window.CC_VER)||'')+'\\n';\n"
        "t+='# NAME | CHECKED | STATUS | IP | PORT | PROTO | SNI | URL\\n\\n';\n"
        "if(!rows.length){t+='(нет сбоев)\\n';}\n"
        "for(const r of rows){\n"
        "  t+=r.name+'\\n';\n"
        "  t+='  checked: '+r.cat+'\\n';\n"
        "  t+='  status:  '+r.status+'\\n';\n"
        "  t+='  IP: '+r.ip+'  PORT: '+r.port+'  PROTO: '+r.proto+'\\n';\n"
        "  t+='  SNI: '+r.sni+'\\n';\n"
        "  t+='  URL: '+r.url+'\\n';\n"
        "  if(r.detail)t+='  detail: '+r.detail+'\\n';\n"
        "  t+='\\n';\n"
        "}\n"
        "const blob=new Blob([t],{type:'text/plain;charset=utf-8'});\n"
        "const a=document.createElement('a');\n"
        "a.href=URL.createObjectURL(blob);\n"
        "a.download='connect-check-problems-'+stamp+'.txt';\n"
        "document.body.appendChild(a);a.click();a.remove();\n"
        "setTimeout(()=>URL.revokeObjectURL(a.href),1500);\n"
        "}\n"
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

    fputs("<div class=\"disclaimer\"><strong>Дисклеймер.</strong> "
          "Отчёт не является авторизованным заключением и служит только для быстрого "
          "понимания ситуации. Проверки несовершенны и могут не проходить капчи и антиботы — "
          "перепроверяйте важные ресурсы вручную.</div>\n", f);

    /* Шапка: крупно только Сбои; OK мелко; Внимание — в свёртке ниже */
    fprintf(f,
        "<div class=\"cards\">"
        "<div class=\"card fail\"><div class=\"n\">%d</div><div class=\"l\">Сбои</div></div>"
        "<div class=\"card ok\"><div class=\"n\">%d</div><div class=\"l\">OK</div></div>"
        "</div>\n", fail_n, ok_n);

    /* Кнопка TXT проблемных узлов + данные для скачивания */
    {
        int nprob = 0, first = 1;
        fputs("<div class=\"toolbar\">"
              "<button type=\"button\" class=\"btn-dl\" onclick=\"downloadProblemsTxt()\">"
              "Скачать TXT сбоев</button>"
              "<span class=\"muted\">только fail · имя, что проверяли, IP : PORT PROTO SNI URL</span>"
              "</div>\n", f);
        fputs("<script>\nwindow.CC_STAMP=\"", f);
        json_esc(f, stamp);
        fputs("\";\nwindow.CC_VER=\"", f);
        json_esc(f, CONNECT_CHECK_VERSION);
        fputs("\";\nwindow.CC_PROBLEMS=[", f);
        for (i = 0; i < nchecks; i++) {
            Check *c = &checks[i];
            char ip[64], port[16], proto[32], sni[128], url[256];
            if (strcmp(c->status, "fail") != 0)
                continue;
            check_endpoint_fields(c, ip, sizeof ip, port, sizeof port,
                                  proto, sizeof proto, sni, sizeof sni, url, sizeof url);
            if (!first) fputc(',', f);
            first = 0;
            fputs("\n{", f);
            fputs("\"name\":\"", f); json_esc(f, c->name); fputs("\",", f);
            fputs("\"cat\":\"", f); json_esc(f, c->category); fputs("\",", f);
            fputs("\"status\":\"", f); json_esc(f, c->status); fputs("\",", f);
            fputs("\"ip\":\"", f); json_esc(f, ip[0] ? ip : "-"); fputs("\",", f);
            fputs("\"port\":\"", f); json_esc(f, port[0] ? port : "-"); fputs("\",", f);
            fputs("\"proto\":\"", f); json_esc(f, proto[0] ? proto : "-"); fputs("\",", f);
            fputs("\"sni\":\"", f); json_esc(f, sni[0] ? sni : "-"); fputs("\",", f);
            fputs("\"url\":\"", f); json_esc(f, url[0] ? url : "-"); fputs("\",", f);
            fputs("\"detail\":\"", f); json_esc(f, c->detail); fputs("\"}", f);
            nprob++;
        }
        fputs("\n];\n</script>\n", f);
        (void)nprob;
    }

    /* Проблемы сверху: Сбои крупно/открыто; Внимание — свёртка */
    {
        int nfail_prob = 0, nwarn_prob = 0, nwarn_find = 0;
        fputs("<div class=\"problems\"><h2 style=\"font-size:1.15rem;margin:0 0 10px\">Сбои</h2>\n", f);
        for (i = 0; i < nchecks; i++) {
            Check *c = &checks[i];
            if (strcmp(c->status, "fail") != 0) continue;
            nfail_prob++;
            fputs("<div class=\"prob fail\"><span class=\"badge\">Сбой</span>"
                  "<span class=\"meta\">", f);
            html_esc(f, c->category);
            fputs(" · ", f);
            html_esc(f, c->name);
            fputs("</span><span class=\"det\">", f);
            html_esc(f, c->detail[0] ? c->detail : (c->hint[0] ? c->hint : "—"));
            fprintf(f, "</span><a class=\"jumplink\" href=\"#c%d\">к проверке →</a></div>\n", i);
        }
        if (nfail_prob == 0)
            fputs("<div class=\"finding info\"><strong>Сбоев нет</strong>"
                  "<p>Критичных FAIL нет"
                  " (ожидаемые блокировки в РФ и «Внимание» не считаются сбоем).</p></div>\n", f);

        for (i = 0; i < nchecks; i++)
            if (strcmp(checks[i].status, "warn") == 0) nwarn_prob++;
        if (nwarn_prob > 0) {
            fprintf(f,
                "<details class=\"warn-fold\">"
                "<summary><span class=\"n\">%d</span> Внимание"
                "<span class=\"hint\">— развернуть карточки</span></summary>\n",
                nwarn_prob);
            for (i = 0; i < nchecks; i++) {
                Check *c = &checks[i];
                if (strcmp(c->status, "warn") != 0) continue;
                fputs("<div class=\"prob warn\"><span class=\"badge\">Внимание</span>"
                      "<span class=\"meta\">", f);
                html_esc(f, c->category);
                fputs(" · ", f);
                html_esc(f, c->name);
                fputs("</span><span class=\"det\">", f);
                html_esc(f, c->detail[0] ? c->detail : (c->hint[0] ? c->hint : "—"));
                fprintf(f, "</span><a class=\"jumplink\" href=\"#c%d\">к проверке →</a></div>\n", i);
            }
            fputs("</details>\n", f);
        }
        fputs("</div>\n", f);

        fputs("<h2 style=\"font-size:1.1rem;margin:0 0 10px\">Выводы</h2>\n", f);
        for (i = 0; i < nfindings; i++) {
            if (strcmp(findings[i].level, "warning") == 0) {
                nwarn_find++;
                continue;
            }
            fprintf(f, "<div class=\"finding %s\"><strong>", findings[i].level);
            html_esc(f, findings[i].title);
            fputs("</strong><p>", f);
            html_esc(f, findings[i].text);
            fputs("</p></div>\n", f);
        }
        if (nwarn_find > 0) {
            fprintf(f,
                "<details class=\"warn-fold\">"
                "<summary><span class=\"n\">%d</span> выводы · Внимание"
                "<span class=\"hint\">— развернуть</span></summary>\n",
                nwarn_find);
            for (i = 0; i < nfindings; i++) {
                if (strcmp(findings[i].level, "warning") != 0) continue;
                fprintf(f, "<div class=\"finding %s\"><strong>", findings[i].level);
                html_esc(f, findings[i].title);
                fputs("</strong><p>", f);
                html_esc(f, findings[i].text);
                fputs("</p></div>\n", f);
            }
            fputs("</details>\n", f);
        }
        if (nfindings == 0)
            fputs("<div class=\"finding info\"><strong>Выводов нет</strong>"
                  "<p>Автоматические выводы по итогам прогона не сформированы.</p></div>\n", f);
    }

    fputs("<h2 id=\"checks\" style=\"font-size:1.1rem;margin:18px 0 10px\">Проверки</h2>\n"
          "<table><thead><tr><th>Проверка</th><th>Статус</th><th>Детали</th><th>Что делать</th></tr></thead><tbody>\n", f);

    {
        for (i = 0; i < nchecks; i++) {
            Check *c = &checks[i];
            int j, cat_n = 0;
            if (strcmp(c->category, prev_cat) != 0) {
                for (j = i; j < nchecks && strcmp(checks[j].category, c->category) == 0; j++)
                    cat_n++;
                fputs("<tr class=\"cat\"><td colspan=\"4\">", f);
                html_esc(f, c->category);
                if (cat_n > 1)
                    fprintf(f, " <span style=\"color:var(--muted);font-weight:400\">(%d)</span>", cat_n);
                fputs("</td></tr>\n", f);
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
            if (c->resolved_ip[0] || c->diag_url[0] || c->ping_text[0] || c->trace_text[0]) {
                int captive_row = (strcmp(c->category, "Captive / OS") == 0);
                int has_net = (c->ping_text[0] || c->trace_text[0]);
                fprintf(f, "<details class=\"diag\"%s><summary>%s</summary><div class=\"copyrow\">",
                        captive_row ? " open" : "",
                        has_net ? "SNI / IP / URL / сеть" : "SNI / IP / URL");
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
                    fputs("<span>URL: <a class=\"extlink\" href=\"", f);
                    html_esc(f, c->diag_url);
                    fputs("\" target=\"_blank\" rel=\"noopener noreferrer\" title=\"Открыть в новой вкладке\">"
                          "<code>", f);
                    html_esc(f, c->diag_url);
                    fputs("</code></a> "
                          "<a class=\"jumplink\" href=\"", f);
                    html_esc(f, c->diag_url);
                    fputs("\" target=\"_blank\" rel=\"noopener noreferrer\">открыть ↗</a> "
                          "<button type=\"button\" class=\"copy\" onclick=\"copyText('", f);
                    html_esc(f, c->diag_url);
                    fputs("',this)\">копировать</button></span>", f);
                }
                fputs("</div>", f);
                if (c->ping_text[0]) {
                    fputs("<div class=\"netdiag-block\"><div class=\"lbl\">Ping "
                          "<button type=\"button\" class=\"copy\" onclick=\"copyPre(this)\">копировать</button>"
                          "</div><pre class=\"netdiag\">", f);
                    html_esc(f, c->ping_text);
                    fputs("</pre></div>", f);
                }
                if (c->trace_text[0]) {
                    fputs("<div class=\"netdiag-block\"><div class=\"lbl\">Traceroute "
                          "<button type=\"button\" class=\"copy\" onclick=\"copyPre(this)\">копировать</button>"
                          "</div><pre class=\"netdiag\">", f);
                    html_esc(f, c->trace_text);
                    fputs("</pre></div>", f);
                }
                if (has_net) {
                    fputs("<div class=\"copyrow\" style=\"margin-top:8px\">"
                          "<button type=\"button\" class=\"copy\" onclick=\""
                          "const b=this.closest('details');"
                          "let t='';"
                          "b.querySelectorAll('code').forEach(c=>{t+=c.textContent+'\\n'});"
                          "b.querySelectorAll('pre.netdiag').forEach(p=>{t+=p.textContent+'\\n\\n'});"
                          "copyText(t.trim(),this)"
                          "\">копировать всё</button></div>", f);
                }
                fputs("</details>", f);
            }
            fputs("</td><td class=\"hintcol\">", f);
            html_esc(f, c->hint);
            fputs("</td></tr>\n", f);
        }
    }

    fputs(
        "</tbody></table>\n"
        "<div class=\"howto\"><h2>Как читать отчёт</h2><ul>"
        "<li><strong>Шапка</strong> — крупно только <em>Сбои</em>; <em>Внимание</em> свёрнуто "
        "(карточки и warning-выводы по клику). Critical-выводы открыты. "
        "Кнопка TXT сбоев (только fail; имя, IP, PORT, PROTO, SNI, URL), затем таблицы проверок.</li>"
        "<li><strong>SNI / IP / URL / сеть</strong> — в спойлере у проверки: хост, IP, URL; "
        "для сбоев (fail) дополнительно ping и traceroute с кнопками копирования.</li>"
        "<li><strong>Captive / OS</strong> — URL, по которым телефон/ПК решают «есть ли интернет». "
        "Для Android важен HTTP <code>204</code> без редиректа на gstatic/OEM.</li>"
        "<li><strong>Private DNS / DoT / DoH</strong> — DoT это DNS поверх TLS на TCP/<code>853</code>; "
        "DoH — тот же DNS, но через HTTPS (обычно <code>443</code>). "
        "Сети часто режут одно и оставляют другое: если DoH падает, а DoT открыт — на клиентах "
        "ставьте Private DNS с именем хоста (DoT), а не DoH-приложения; наоборот — выключите "
        "Private DNS «Автоматически», обычный DNS роутера и при необходимости DoH в браузере.</li>"
        "<li><strong>CDN / счётчики</strong> — yastatic.net и counter.yadro.ru: скачивание реального PNG/GIF/HTML (magic), не только открытый порт.</li>"
        "<li><strong>Значимые ресурсы (Белые списки МЦ)</strong> — госуслуги, медиа, маркетплейсы, операторы, Яндекс/VK.</li>"
        "<li><strong>Зарубежные ресурсы</strong> — контроль зарубежных сервисов (блок в РФ ≠ сбой сети).</li>"
        "<li><strong>Почта</strong> — веб-интерфейсы и SMTP/IMAP/POP3 (баннер или TLS на :587/:465/:993/:995).</li>"
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

/* После неудачной HTTP(S)-пробы: TCP :443/:80 — живой порт ≠ полный блок хоста. */
static void tcp_http_fallback(const char *host, char *extra, size_t extralen, int *any_open) {
    int o443 = 0, o80 = 0;
    if (any_open) *any_open = 0;
    if (extra && extralen) extra[0] = 0;
    if (!host || !host[0]) return;
    o443 = tcp_open(host, 443, 2500);
    o80 = tcp_open(host, 80, 2500);
    if (any_open) *any_open = (o443 || o80) ? 1 : 0;
    if (extra && extralen)
        snprintf(extra, extralen, "TCP :443 %s / :80 %s",
                 o443 ? "открыт" : "закрыт", o80 ? "открыт" : "закрыт");
}

static void check_captive_fill(Check *out, const char *name, const char *url,
                               int expect, int *want_finding, char *ftitle, size_t ftlen,
                               char *ftext, size_t ftextlen) {
    HttpResult r = http_probe_nofollow(url, 5, 0);
    char detail[STR], hint[STR], host[128], ip[64];
    const char *st;

    if (want_finding) *want_finding = 0;
    host_from_url(url, host, sizeof host);
    ip[0] = 0;
    if (host[0]) dns_resolve(host, ip, sizeof ip);

    if (host_unresolved(host, ip) && r.code != expect && !r.redirect[0]) {
        snprintf(detail, sizeof detail, "SNI %s · DNS не резолвит имя", host);
        check_set(out, "Captive / OS", name, "warn", detail,
                  "Имя не резолвится — это не доказательство captive portal / «нет интернета».",
                  NULL, url, 0);
        return;
    }

    if (r.redirect[0]) {
        snprintf(detail, sizeof detail, "SNI %s · редирект → %s (HTTP %d)",
                 host[0] ? host : "?", r.redirect, r.code);
        check_set(out, "Captive / OS", name, "fail", detail,
                  "Captive portal или подмена HTTP.", ip, url, 0);
        if (want_finding) {
            *want_finding = 1;
            snprintf(ftitle, ftlen, "Подмена %s", name);
            snprintf(ftext, ftextlen, "Запрос к %s уходит на редирект. Проверьте Hotspot/Web-proxy на MikroTik.", url);
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
        check_set(out, "Captive / OS", name, st, detail, hint, ip, url, 0);
        return;
    }
    if (host[0] && !dns_has_ipv4(host) && r.code != expect) {
        snprintf(detail, sizeof detail, "SNI %s · %s (хост без A-записи)",
                 host, r.error[0] ? r.error : "нет ответа");
        check_set(out, "Captive / OS", name, "info", detail,
                  "Проверка только по IPv6. На сети без IPv6 ожидаемо недоступна — не проблема.",
                  ip, url, 0);
        return;
    }
    if (r.error[0])
        snprintf(detail, sizeof detail, "SNI %s · %s", host[0] ? host : "?", r.error);
    else
        snprintf(detail, sizeof detail, "SNI %s · HTTP %d, %d ms",
                 host[0] ? host : "?", r.code, r.ms);
    check_set(out, "Captive / OS", name, "fail", detail,
              "URL проверки связности ОС/устройства.", ip, url, 0);
    if (want_finding) {
        *want_finding = 1;
        snprintf(ftitle, ftlen, "Не проходит %s", name);
        snprintf(ftext, ftextlen, "%s — %s", url, detail);
    }
}

static void check_captive(const char *name, const char *url, int expect, int critical) {
    Check c;
    int want = 0;
    char ftitle[256], ftext[LONGSTR];
    check_captive_fill(&c, name, url, expect, critical ? &want : NULL,
                       ftitle, sizeof ftitle, ftext, sizeof ftext);
    add_check_from(&c);
    if (critical && want)
        add_finding("critical", ftitle, ftext);
}

static void check_ru_fill(Check *out, const char *cat, const char *name, const char *url,
                          const char *note, int spoiler, int multi_ua,
                          int *failed, int *slow_ms) {
    char ua_sum[256];
    int ua_mismatch = 0;
    HttpResult r;
    char detail[STR], hint[STR], host[128], ip[64];
    const char *st;

    if (failed) *failed = 0;
    if (slow_ms) *slow_ms = 0;

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
        check_set(out, cat, name, "warn", detail,
                  "Имя не резолвится — это сбой DNS, а не недоступность ресурса.",
                  NULL, url, spoiler);
        return;
    }

    if (r.code <= 0) {
        char fb[96];
        int tcp_ok = 0;
        tcp_http_fallback(host, fb, sizeof fb, &tcp_ok);
        snprintf(detail, sizeof detail, "%s [%s]%s%s",
                 r.error[0] ? r.error : "таймаут/нет ответа",
                 ua_sum[0] ? ua_sum : "—",
                 fb[0] ? " · " : "", fb);
        if (tcp_ok) {
            snprintf(hint, sizeof hint,
                     "%s%sHTTP(S)-проба не ответила, но TCP :80/:443 открыт — "
                     "скорее DPI/TLS/маршрут HTTP, не полный блок хоста.",
                     note && note[0] ? note : "", note && note[0] ? " " : "");
            check_set(out, cat, name, "warn", detail, hint, ip, url, spoiler);
            /* не считаем fail ресурса для finding */
            return;
        }
        snprintf(hint, sizeof hint, "%s%sНедоступен по HTTPS-пробе (браузер может работать при другом маршруте/QUIC).",
                 note && note[0] ? note : "", note && note[0] ? " " : "");
        check_set(out, cat, name, "fail", detail, hint, ip, url, spoiler);
        if (failed) *failed = 1;
        return;
    }

    if (r.antibot) {
        char spd[64];
        int sms = r.xfer_ms > 0 ? r.xfer_ms : r.ms;
        fmt_doc_speed(spd, sizeof spd, r.bytes, sms);
        if (r.redirect[0])
            snprintf(detail, sizeof detail, "HTTP %d (финал ← %s), %d ms%s [%s]",
                     r.code, r.redirect, r.ms, spd, ua_sum);
        else
            snprintf(detail, sizeof detail, "HTTP %d, %d ms%s [%s]",
                     r.code, r.ms, spd, ua_sum);
        snprintf(hint, sizeof hint,
                 "%s%sАнтибот/WAF/капча (Cloudflare и т.п.) — документ получен, JS-challenge; "
                 "для сети это не сбой доступности. Ассеты/CDN не качаем (challenge).",
                 note && note[0] ? note : "", note && note[0] ? " " : "");
        check_set(out, cat, name, "ok", detail, hint, ip, url, spoiler);
        return;
    }
    if (r.code >= 300 && r.code < 400) {
        char spd[64];
        fmt_doc_speed(spd, sizeof spd, r.bytes, r.xfer_ms > 0 ? r.xfer_ms : r.ms);
        if (r.redirect[0])
            snprintf(detail, sizeof detail, "HTTP %d (финал ← %s), %d ms%s [%s]",
                     r.code, r.redirect, r.ms, spd, ua_sum);
        else
            snprintf(detail, sizeof detail, "HTTP %d, %d ms%s [%s]",
                     r.code, r.ms, spd, ua_sum);
        check_set(out, cat, name, "ok", detail,
                  "HTTP-редирект (301/302/…): хост отвечает. Не считаем сбоем доступности.",
                  ip, url, spoiler);
        return;
    }
    if (r.code >= 500) {
        char spd[64];
        fmt_doc_speed(spd, sizeof spd, r.bytes, r.xfer_ms > 0 ? r.xfer_ms : r.ms);
        snprintf(detail, sizeof detail, "HTTP %d, %d ms%s [%s]",
                 r.code, r.ms, spd, ua_sum);
        check_set(out, cat, name, "fail", detail, "Сервер отвечает 5xx.", ip, url, spoiler);
        if (failed) *failed = 1;
        return;
    }

    /* 2xx: HTML + выборка ассетов/CDN — реальная загрузка страницы */
    {
        PageLoadStats pl;
        char spd[96];
        const char *final_u = r.redirect[0] ? r.redirect : url;
        int have_pl = page_load_with_assets(final_u, &pl);

        if (have_pl && (pl.html_bytes + pl.asset_bytes) > 0)
            fmt_page_speed(spd, sizeof spd, &pl);
        else
            fmt_doc_speed(spd, sizeof spd, r.bytes, r.xfer_ms > 0 ? r.xfer_ms : r.ms);

        if (r.redirect[0])
            snprintf(detail, sizeof detail, "HTTP %d (финал ← %s), %d ms%s [%s]",
                     r.code, r.redirect, r.ms, spd, ua_sum);
        else
            snprintf(detail, sizeof detail, "HTTP %d, %d ms%s [%s]",
                     r.code, r.ms, spd, ua_sum);

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
            if (slow_ms) *slow_ms = r.ms;
        }
        {
            int cdn_sev = have_pl ? page_cdn_severity(&pl) : -1;
            if (cdn_sev >= 0) {
                char more[160];
                /* живой HTML + битые ассеты → Внимание, не Сбой */
                st = "warn";
                fmt_cdn_asset_hint(hint, sizeof hint, note, &pl, cdn_sev);
                if (pl.fail_hosts[0] && strlen(detail) + 24 < sizeof detail) {
                    snprintf(more, sizeof more, " · ассеты✗ %s", pl.fail_hosts);
                    if (strlen(detail) + strlen(more) < sizeof detail)
                        strcat(detail, more);
                }
                cdn_note_site(name, &pl, 0);
            } else if (have_pl && pl.n_try > 0) {
                long tot = pl.html_bytes + pl.asset_bytes;
                if (tot >= 48 * 1024 && pl.wall_ms > 0) {
                    double mbps = (tot * 8.0) / (pl.wall_ms * 1000.0);
                    if (mbps < 0.5 && st[0] == 'o') {
                        st = "warn";
                        snprintf(hint, sizeof hint,
                                 "%s%sНизкая скорость стр+CDN (%.2f Мбит/с) — узкое место или throttle.",
                                 note && note[0] ? note : "", note && note[0] ? " " : "", mbps);
                    }
                }
            }
        }
        check_set(out, cat, name, st, detail, hint, ip, url, spoiler);
    }
}

static void check_ru(const char *cat, const char *name, const char *url,
                     const char *note, int spoiler, int multi_ua,
                     char fail_names[][64], int *nfail,
                     char slow_names[][80], int *nslow) {
    Check c;
    int failed = 0, slow_ms = 0;
    check_ru_fill(&c, cat, name, url, note, spoiler, multi_ua, &failed, &slow_ms);
    add_check_from(&c);
    if (failed && nfail && *nfail < 40) snprintf(fail_names[(*nfail)++], 64, "%s", name);
    if (slow_ms && nslow && *nslow < 40)
        snprintf(slow_names[(*nslow)++], 80, "%s %dms", name, slow_ms);
}

/* ---------- parallel stage helpers ---------- */

typedef struct {
    Check *outs;
    int *failed;
    int *slow_ms;
} SigJobCtx;

static void ru_job(int idx, void *v) {
    SigJobCtx *ctx = (SigJobCtx *)v;
    check_ru_fill(&ctx->outs[idx], "Значимые ресурсы (Белые списки МЦ)", g_ru[idx].name, g_ru[idx].url,
                  g_ru[idx].note, 1, 0, &ctx->failed[idx], &ctx->slow_ms[idx]);
}

static void sig_job(int idx, void *v) {
    SigJobCtx *ctx = (SigJobCtx *)v;
    check_ru_fill(&ctx->outs[idx], "Зарубежные ресурсы", g_sig[idx].name, g_sig[idx].url,
                  g_sig[idx].note, 1, 0, &ctx->failed[idx], &ctx->slow_ms[idx]);
}

typedef struct {
    Check *outs;
    int *failed;
    int *slow_ms;
} BankJobCtx;

static void bank_job(int idx, void *v) {
    BankJobCtx *ctx = (BankJobCtx *)v;
    check_ru_fill(&ctx->outs[idx], g_banks[idx].cat, g_banks[idx].name, g_banks[idx].url,
                  "", 0, 0, &ctx->failed[idx], &ctx->slow_ms[idx]);
}

typedef struct {
    Check *outs;
    int *critf;
    ResTcp *items;
    const char *cat;
    int spoiler;
    int timeout_ms;
} TcpResJobCtx;

static void tcp_res_job(int idx, void *v) {
    TcpResJobCtx *ctx = (TcpResJobCtx *)v;
    check_tcp_ep_fill(&ctx->outs[idx], ctx->cat, ctx->items[idx].name, ctx->items[idx].host,
                      ctx->items[idx].port, ctx->timeout_ms, ctx->items[idx].crit,
                      ctx->spoiler, &ctx->critf[idx]);
}

typedef struct {
    Check *outs;
    ResHttp *items;
    const char *cat;
    int multi_ua;
    int timeout_sec;
    int ok_403; /* 401/403 = ok (S3/CDN) */
} HttpsResJobCtx;

static void https_res_job(int idx, void *v) {
    HttpsResJobCtx *ctx = (HttpsResJobCtx *)v;
    HttpResult r;
    char host[128], ip[64], ua_sum[256], detail[STR];
    int ua_mismatch = 0;
    const char *st;

    if (ctx->multi_ua)
        r = http_probe_agents(ctx->items[idx].url, ctx->timeout_sec, 1, ua_sum, sizeof ua_sum, &ua_mismatch);
    else {
        r = http_probe_ua(ctx->items[idx].url, ctx->timeout_sec, 1, ua_default(), 1);
        if (r.code > 0) snprintf(ua_sum, sizeof ua_sum, "chrome=%d", r.code);
        else snprintf(ua_sum, sizeof ua_sum, "chrome=нет ответа");
    }
    host_from_url(ctx->items[idx].url, host, sizeof host);
    ip[0] = 0;
    if (host[0]) dns_resolve(host, ip, sizeof ip);

    if (r.code > 0 || r.antibot) {
        char spd[96], hint[STR];
        int sms = r.xfer_ms > 0 ? r.xfer_ms : r.ms;

        if (r.antibot) {
            fmt_doc_speed(spd, sizeof spd, r.bytes, sms);
            if (r.redirect[0])
                snprintf(detail, sizeof detail, "HTTP %d (редирект → %s), %d ms%s [%s]",
                         r.code, r.redirect, r.ms, spd, ua_sum);
            else
                snprintf(detail, sizeof detail, "HTTP %d, %d ms%s [%s]",
                         r.code, r.ms, spd, ua_sum);
            check_set(&ctx->outs[idx], ctx->cat, ctx->items[idx].name, "ok", detail,
                      "Антибот/WAF/капча — хост отвечает, JS-challenge; не сбой сети. "
                      "Ассеты/CDN не качаем (challenge).",
                      ip, ctx->items[idx].url, 0);
        } else if (r.code >= 300 && r.code < 400) {
            fmt_doc_speed(spd, sizeof spd, r.bytes, sms);
            if (r.redirect[0])
                snprintf(detail, sizeof detail, "HTTP %d (редирект → %s), %d ms%s [%s]",
                         r.code, r.redirect, r.ms, spd, ua_sum);
            else
                snprintf(detail, sizeof detail, "HTTP %d, %d ms%s [%s]",
                         r.code, r.ms, spd, ua_sum);
            check_set(&ctx->outs[idx], ctx->cat, ctx->items[idx].name, "ok", detail,
                      "HTTP-редирект: хост отвечает.", ip, ctx->items[idx].url, 0);
        } else if (ctx->ok_403 && (r.code == 401 || r.code == 403)) {
            fmt_doc_speed(spd, sizeof spd, r.bytes, sms);
            snprintf(detail, sizeof detail, "HTTP %d, %d ms%s [%s]",
                     r.code, r.ms, spd, ua_sum);
            check_set(&ctx->outs[idx], ctx->cat, ctx->items[idx].name, "ok", detail,
                      "HTTP 403/401 без ключа — CDN/S3 доступен (ожидаемо, не сбой).",
                      ip, ctx->items[idx].url, 0);
        } else if (r.code >= 500) {
            fmt_doc_speed(spd, sizeof spd, r.bytes, sms);
            snprintf(detail, sizeof detail, "HTTP %d, %d ms%s [%s]",
                     r.code, r.ms, spd, ua_sum);
            check_set(&ctx->outs[idx], ctx->cat, ctx->items[idx].name, "fail", detail,
                      "Сервер отвечает 5xx.", ip, ctx->items[idx].url, 0);
        } else if (ctx->ok_403) {
            /* канарейки/S3/API — не HTML-страницы, только документ */
            fmt_doc_speed(spd, sizeof spd, r.bytes, sms);
            snprintf(detail, sizeof detail, "HTTP %d, %d ms%s [%s]",
                     r.code, r.ms, spd, ua_sum);
            st = (r.ms > 3000 || ua_mismatch) ? "warn" : "ok";
            check_set(&ctx->outs[idx], ctx->cat, ctx->items[idx].name, st, detail,
                      ua_mismatch ? "Ответ зависит от User-Agent."
                      : (r.ms > 3000 ? "Медленный ответ" : ""),
                      ip, ctx->items[idx].url, 0);
        } else {
            PageLoadStats pl;
            const char *final_u = r.redirect[0] ? r.redirect : ctx->items[idx].url;
            int have_pl = page_load_with_assets(final_u, &pl);

            if (have_pl && (pl.html_bytes + pl.asset_bytes) > 0)
                fmt_page_speed(spd, sizeof spd, &pl);
            else
                fmt_doc_speed(spd, sizeof spd, r.bytes, sms);

            if (r.redirect[0])
                snprintf(detail, sizeof detail, "HTTP %d (редирект → %s), %d ms%s [%s]",
                         r.code, r.redirect, r.ms, spd, ua_sum);
            else
                snprintf(detail, sizeof detail, "HTTP %d, %d ms%s [%s]",
                         r.code, r.ms, spd, ua_sum);

            st = (r.ms > 3000 || ua_mismatch) ? "warn" : "ok";
            hint[0] = 0;
            if (ua_mismatch)
                snprintf(hint, sizeof hint, "Ответ зависит от User-Agent.");
            else if (r.ms > 3000)
                snprintf(hint, sizeof hint, "Медленный ответ");
            {
                int cdn_sev = have_pl ? page_cdn_severity(&pl) : -1;
                if (cdn_sev >= 0) {
                    char more[160];
                    st = "warn";
                    fmt_cdn_asset_hint(hint, sizeof hint, NULL, &pl, cdn_sev);
                    if (pl.fail_hosts[0] && strlen(detail) + 24 < sizeof detail) {
                        snprintf(more, sizeof more, " · ассеты✗ %s", pl.fail_hosts);
                        if (strlen(detail) + strlen(more) < sizeof detail)
                            strcat(detail, more);
                    }
                    cdn_note_site(ctx->items[idx].name, &pl, 0);
                } else if (have_pl && pl.n_try > 0) {
                    long tot = pl.html_bytes + pl.asset_bytes;
                    if (tot >= 48 * 1024 && pl.wall_ms > 0) {
                        double mbps = (tot * 8.0) / (pl.wall_ms * 1000.0);
                        if (mbps < 0.5 && st[0] == 'o') {
                            st = "warn";
                            snprintf(hint, sizeof hint,
                                     "Низкая скорость стр+CDN (%.2f Мбит/с) — узкое место или throttle.",
                                     mbps);
                        }
                    }
                }
            }
            check_set(&ctx->outs[idx], ctx->cat, ctx->items[idx].name, st, detail, hint,
                      ip, ctx->items[idx].url, 0);
        }
    } else if (host_unresolved(host, ip)) {
        snprintf(detail, sizeof detail, "DNS не резолвит %s", host);
        check_set(&ctx->outs[idx], ctx->cat, ctx->items[idx].name, "warn", detail,
                  "Имя не резолвится — сбой DNS.", NULL, ctx->items[idx].url, 0);
    } else {
        char fb[96];
        int tcp_ok = 0;
        tcp_http_fallback(host, fb, sizeof fb, &tcp_ok);
        snprintf(detail, sizeof detail, "%s [%s]%s%s",
                 r.error[0] ? r.error : "таймаут", ua_sum[0] ? ua_sum : "—",
                 fb[0] ? " · " : "", fb);
        if (tcp_ok) {
            check_set(&ctx->outs[idx], ctx->cat, ctx->items[idx].name, "warn", detail,
                      "HTTPS-проба не ответила, но TCP :80/:443 открыт — DPI/TLS, не полный блок.",
                      ip, ctx->items[idx].url, 0);
        } else {
            check_set(&ctx->outs[idx], ctx->cat, ctx->items[idx].name, "fail", detail,
                      "HTTPS недоступен (DPI/фильтр/маршрут).", ip, ctx->items[idx].url, 0);
        }
    }
}

typedef struct {
    Check *outs;
} VideoJobCtx;

static void video_job(int idx, void *v) {
    VideoJobCtx *ctx = (VideoJobCtx *)v;
    char ua_sum[256], host[128], ip[64], detail[STR];
    int ua_mismatch = 0;
    HttpResult r, rv;
    r = http_probe_agents(g_video[idx].home, 8, 1, ua_sum, sizeof ua_sum, &ua_mismatch);
    host_from_url(g_video[idx].home, host, sizeof host);
    ip[0] = 0;
    if (host[0]) dns_resolve(host, ip, sizeof ip);
    rv = http_probe_agents(g_video[idx].video, 10, 1, ua_sum, sizeof ua_sum, &ua_mismatch);
    if (((r.code > 0 && r.code < 500) || r.antibot) &&
        ((rv.code > 0 && rv.code < 500) || rv.antibot)) {
        char spd[64], spdv[64];
        fmt_doc_speed(spd, sizeof spd, r.bytes, r.xfer_ms > 0 ? r.xfer_ms : r.ms);
        fmt_doc_speed(spdv, sizeof spdv, rv.bytes, rv.xfer_ms > 0 ? rv.xfer_ms : rv.ms);
        snprintf(detail, sizeof detail,
                 "сайт HTTP %d (%d ms%s)%s; лента/видео HTTP %d (%d ms%s)%s [%s]",
                 r.code, r.ms, spd, r.antibot ? " antibot" : "",
                 rv.code, rv.ms, spdv, rv.antibot ? " antibot" : "", ua_sum);
        check_set(&ctx->outs[idx], "Видео", g_video[idx].name, "ok", detail,
                  r.antibot || rv.antibot
                      ? "Антибот на сайте/ленте — хост отвечает; детально: ./probe-video -n 1"
                      : "Детально (первое видео с главной): ./probe-video -n 1",
                  ip, g_video[idx].home, 0);
    } else if (host_unresolved(host, ip)) {
        snprintf(detail, sizeof detail, "DNS не резолвит %s", host);
        check_set(&ctx->outs[idx], "Видео", g_video[idx].name, "warn", detail,
                  "Имя не резолвится — это сбой DNS, а не недоступность видео.",
                  NULL, g_video[idx].home, 0);
    } else {
        char fb[96];
        int tcp_ok = 0;
        tcp_http_fallback(host, fb, sizeof fb, &tcp_ok);
        snprintf(detail, sizeof detail, "сайт HTTP %d; видео HTTP %d [%s]%s%s",
                 r.code, rv.code, ua_sum[0] ? ua_sum : "—",
                 fb[0] ? " · " : "", fb);
        if (tcp_ok) {
            check_set(&ctx->outs[idx], "Видео", g_video[idx].name, "warn", detail,
                      "HTTP(S) к сайту/видео не прошёл, но TCP :80/:443 открыт.",
                      ip, g_video[idx].home, 0);
        } else {
            check_set(&ctx->outs[idx], "Видео", g_video[idx].name, "fail", detail,
                      "Не открылся сайт или видео-путь.", ip, g_video[idx].home, 0);
        }
    }
}

typedef struct {
    Check *outs;
    int *wantf;
    char *ftitles; /* nc * 256 */
    char *ftexts;  /* nc * LONGSTR */
    const char **names;
    const char **urls;
    int *expects;
    int *crits;
} CapParCtx;

static void captive_par_job(int idx, void *v) {
    CapParCtx *ctx = (CapParCtx *)v;
    char *ft = ctx->ftitles + (size_t)idx * 256;
    char *fx = ctx->ftexts + (size_t)idx * LONGSTR;
    check_captive_fill(&ctx->outs[idx], ctx->names[idx], ctx->urls[idx], ctx->expects[idx],
                       ctx->crits[idx] ? &ctx->wantf[idx] : NULL,
                       ft, 256, fx, LONGSTR);
}

typedef struct {
    Check *outs;
    int *count_fail;   /* 1 = добавить в dpi_fail */
    int *dot_tls_ok;   /* 1 = DoT TLS+SNI OK */
    const char **names;
    const char **hosts;
    int *ports;
    int *expect_open;
} DpiPortCtx;

static void dpi_port_job(int idx, void *v) {
    DpiPortCtx *ctx = (DpiPortCtx *)v;
    char ip[64], url[256], detail[STR];
    const char *name = ctx->names[idx];
    const char *host = ctx->hosts[idx];
    ctx->count_fail[idx] = 0;
    ctx->dot_tls_ok[idx] = 0;
    snprintf(url, sizeof url, "https://%s/", host);
    if (!dns_resolve(host, ip, sizeof ip)) {
        snprintf(detail, sizeof detail, "DNS fail %s", host);
        check_set(&ctx->outs[idx], "DPI", name, "warn", detail, "", NULL, url, 0);
        return;
    }
    if (strncmp(name, "DoT ", 4) == 0) {
        int ms = 0, rc = dot_probe(host, 3000, &ms);
        const char *sni = dot_sni_for(host);
        if (rc == 2) {
            snprintf(detail, sizeof detail, "DoT TLS+SNI OK (%s) %d ms", sni, ms);
            check_set(&ctx->outs[idx], "DPI", name, "ok", detail, "", ip, url, 0);
            ctx->dot_tls_ok[idx] = 1;
        } else if (rc == 1) {
            snprintf(detail, sizeof detail, "TCP :853 есть, TLS нет (%s) %d ms", sni, ms);
            check_set(&ctx->outs[idx], "DPI", name, "warn", detail,
                      "Порт открыт, но DoT-handshake не проходит.", ip, url, 0);
        } else {
            check_set(&ctx->outs[idx], "DPI", name, "warn",
                      "TCP :853 закрыт (может быть нормой)",
                      "Не критично само по себе; смотрите DoH и Private DNS.",
                      ip, url, 0);
        }
        return;
    }
    if (tcp_open(host, ctx->ports[idx], 3000)) {
        check_set(&ctx->outs[idx], "DPI", name, "ok", "TCP открыт", "", ip, url, 0);
    } else if (ctx->expect_open[idx]) {
        check_set(&ctx->outs[idx], "DPI", name, "fail", "TCP закрыт/фильтр",
                  "Порт часто режется DPI. IoT и push могут страдать при живом HTTPS.",
                  ip, url, 0);
        ctx->count_fail[idx] = 1;
    } else {
        check_set(&ctx->outs[idx], "DPI", name, "warn",
                  "TCP закрыт (может быть нормой)",
                  "Не критично само по себе; смотрите в связке с IoT/VPN.",
                  ip, url, 0);
    }
}

typedef struct {
    Check *outs;
    int *is_fail;
    const char **names;
    const char **urls;
} DohCtx;

static void doh_job(int idx, void *v) {
    DohCtx *ctx = (DohCtx *)v;
    HttpResult r = doh_probe(ctx->urls[idx], 5);
    char detail[STR];
    ctx->is_fail[idx] = 0;
    if (r.code == 200) {
        snprintf(detail, sizeof detail, "HTTP %d, %d ms (dns-json)", r.code, r.ms);
        check_set(&ctx->outs[idx], "DPI", ctx->names[idx], "ok", detail, "", NULL, NULL, 0);
    } else if (r.code > 0) {
        snprintf(detail, sizeof detail, "HTTP %d, %d ms", r.code, r.ms);
        check_set(&ctx->outs[idx], "DPI", ctx->names[idx], "warn", detail,
                  idx == 0 ? "Ожидали 200 с Accept: application/dns-json — возможна подмена/фильтр DoH." : "",
                  NULL, NULL, 0);
    } else {
        check_set(&ctx->outs[idx], "DPI", ctx->names[idx], "fail",
                  r.error[0] ? r.error : "таймаут",
                  idx == 0
                      ? "DoH часто режет DPI. Private DNS/DoH может ломать связность на клиентах."
                      : "Фильтр DoH Google — частый признак DPI.",
                  NULL, NULL, 0);
        ctx->is_fail[idx] = 1;
    }
}

typedef struct {
    Check *outs;
    int *sni_fail;
    const char **names;
    const char **urls;
    int *expected_ru;
} SniCtx;

static void sni_job(int idx, void *v) {
    SniCtx *ctx = (SniCtx *)v;
    HttpResult r;
    char host[128], ip[64], detail[STR];
    ctx->sni_fail[idx] = 0;
    r = http_probe(ctx->urls[idx], 6, 1);
    host_from_url(ctx->urls[idx], host, sizeof host);
    ip[0] = 0;
    if (host[0]) dns_resolve(host, ip, sizeof ip);
    if (r.code > 0 && r.code < 500) {
        snprintf(detail, sizeof detail, "HTTP %d, %d ms", r.code, r.ms);
        check_set(&ctx->outs[idx], "DPI", ctx->names[idx], "ok", detail, "", ip, ctx->urls[idx], 0);
    } else if (ctx->expected_ru[idx]) {
        check_set(&ctx->outs[idx], "DPI", ctx->names[idx], "info",
                  r.error[0] ? r.error : "таймаут/блок",
                  "Ожидаемо в РФ — не считается проблемой сети / DPI.",
                  ip, ctx->urls[idx], 0);
    } else if (host_unresolved(host, ip)) {
        check_set(&ctx->outs[idx], "DPI", ctx->names[idx], "warn",
                  "DNS не резолвит имя", "Сбой DNS, не SNI/DPI.",
                  NULL, ctx->urls[idx], 0);
    } else {
        check_set(&ctx->outs[idx], "DPI", ctx->names[idx], "fail",
                  r.error[0] ? r.error : "таймаут/блок",
                  "SNI/DPI-фильтр: сайт режется по имени, не по «интернету вообще».",
                  ip, ctx->urls[idx], 0);
        ctx->sni_fail[idx] = 1;
    }
}

typedef struct {
    Check *outs;
    int *qok;
    const char **names;
    const char **hosts;
    int *expected_ru;
} QuicCtx;

static void quic_job(int idx, void *v) {
    QuicCtx *ctx = (QuicCtx *)v;
    int ms = 0;
    char ip[64], url[256], detail[STR];
    ctx->qok[idx] = 0;
    ip[0] = 0;
    dns_resolve(ctx->hosts[idx], ip, sizeof ip);
    snprintf(url, sizeof url, "https://%s/", ctx->hosts[idx]);
    if (quic_probe(ctx->hosts[idx], 2500, &ms)) {
        ctx->qok[idx] = 1;
        snprintf(detail, sizeof detail, "QUIC VN (UDP/443) за %d ms", ms);
        check_set(&ctx->outs[idx], "DPI", ctx->names[idx], "ok", detail, "", ip, url, 0);
    } else if (ctx->expected_ru[idx]) {
        check_set(&ctx->outs[idx], "DPI", ctx->names[idx], "info", "нет UDP-ответа на :443",
                  "Ожидаемо в РФ для этого хоста — не считается проблемой.",
                  ip, url, 0);
    } else {
        check_set(&ctx->outs[idx], "DPI", ctx->names[idx], "warn", "нет UDP-ответа на :443",
                  "QUIC/HTTP3 может резаться DPI при живом TCP/443. "
                  "Браузеры откатятся на TCP; часть CDN/видео — нет.",
                  ip, url, 0);
    }
}

typedef struct {
    Check *outs;
    int *ok;
    const char **hosts;
} NtpCtx;

static void ntp_job(int idx, void *v) {
    NtpCtx *ctx = (NtpCtx *)v;
    char name[80];
    snprintf(name, sizeof name, "NTP %s", ctx->hosts[idx]);
    if (ntp_probe(ctx->hosts[idx], 2500)) {
        ctx->ok[idx] = 1;
        check_set(&ctx->outs[idx], "NTP / время", name, "ok", "UDP/123 ответ получен", "",
                  NULL, NULL, 0);
    } else {
        ctx->ok[idx] = 0;
        check_set(&ctx->outs[idx], "NTP / время", name, "warn", "нет ответа UDP/123",
                  "Без NTP часы на IoT сбиваются → TLS handshake fail → туннель не поднимается.",
                  NULL, NULL, 0);
    }
}

typedef struct {
    int *ok; /* 1 = 204 без редиректа */
    int *ms;
} GstCtx;

static void gstatic_job(int idx, void *v) {
    GstCtx *ctx = (GstCtx *)v;
    HttpResult r = http_probe_nofollow("http://connectivitycheck.gstatic.com/generate_204", 3, 0);
    if (r.code == 204 && !r.redirect[0]) {
        ctx->ok[idx] = 1;
        ctx->ms[idx] = r.ms;
    } else {
        ctx->ok[idx] = 0;
        ctx->ms[idx] = r.ms;
    }
}

typedef struct {
    Check *outs;
    double *mbps;
    const char **names;
    const char **urls;
    const char **geo;
    int *critical;
} SpeedCtx;

static void speed_job(int idx, void *v) {
    SpeedCtx *ctx = (SpeedCtx *)v;
    char host[128], rip[64], detail[STR];
    long bytes = 0;
    int ms = 0;
    ctx->mbps[idx] = -1;
    host_from_url(ctx->urls[idx], host, sizeof host);
    rip[0] = 0;
    if (host[0]) dns_resolve(host, rip, sizeof rip);
    if (http_download_bytes(ctx->urls[idx], 35, &bytes, &ms) && ms > 0 && bytes > 200000) {
        double mbps = (bytes * 8.0) / (ms * 1000.0);
        ctx->mbps[idx] = mbps;
        snprintf(detail, sizeof detail, "%.2f Мбит/с (%ld байт за %d ms) · %s",
                 mbps, bytes, ms, ctx->geo[idx]);
        check_set(&ctx->outs[idx], "Скорость", ctx->names[idx],
                  mbps < 8 ? "warn" : "ok", detail,
                  mbps < 8 ? "Ниже ~8 Мбит/с до этой точки — узкое место на маршруте или Wi‑Fi." : "",
                  rip[0] ? rip : NULL, ctx->urls[idx], 0);
    } else if (ctx->critical[idx]) {
        snprintf(detail, sizeof detail, "%s",
                 ms > 0 ? "скачано слишком мало / обрыв" : "таймаут / нет ответа");
        check_set(&ctx->outs[idx], "Скорость", ctx->names[idx], "fail", detail,
                  "Не удалось скачать пробник — фильтр, маршрут или перегруз.",
                  rip[0] ? rip : NULL, ctx->urls[idx], 0);
    } else {
        check_set(&ctx->outs[idx], "Скорость", ctx->names[idx], "info",
                  "недоступен с этой сети (норма, если не из РФ)",
                  "Запасная проба РФ — Selectel.",
                  rip[0] ? rip : NULL, ctx->urls[idx], 0);
    }
}

#ifndef CC_ENGINE_LIBRARY
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
        "  --jobs N               параллельные пробы внутри этапа (по умолчанию %d, env CONNECT_CHECK_JOBS)\n"
        "  --check-update         проверить GitHub Releases (exit 0 актуально, 2 есть новее, 1 ошибка)\n"
        "  --self-update          скачать latest release и заменить пакет (см. docs/UPDATE.md)\n"
        "Клавиши на этапах: Enter — далее/запустить, Space — пропустить (без эха).\n",
        argv0, CONNECT_CHECK_VERSION, DEFAULT_JOBS);
}
#endif


static int diagnose_core(void) {
    int i;
    time_t now;
    struct tm *tm;
    static const struct { const char *name; const char *ip; } dns_pub[] = {
        {"Cloudflare", "1.1.1.1"},
        {"Google", "8.8.8.8"},
        {"Quad9", "9.9.9.9"},
        {"Яндекс DNS", "77.88.8.8"},
        {"Яндекс DNS 2", "77.88.8.1"},
        {"НСДИ a.res-nsdi.ru", "195.208.4.1"},
        {"НСДИ b.res-nsdi.ru", "195.208.5.1"},
        {"AdGuard DNS", "94.140.14.14"},
    };
    const int n_dns_pub = (int)(sizeof dns_pub / sizeof dns_pub[0]);
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

    resources_init();
    local_ip[0] = 0;
    external_ip[0] = 0;
    gateway[0] = 0;

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
    /* Финальное имя с IP — в write_html(); здесь черновик со stamp */
    report_path_rebuild(output_dir);

    engine_logf("Диагностика интернета (connect-check %s) — сбор данных...", CONNECT_CHECK_VERSION);
    if (!g_engine_lib_mode)
        printf("Клавиши: Enter — далее, Space — пропустить (DNS: Enter — запустить, иначе пропуск).\n");
    if (opt_yes) engine_log("Режим -y: без вопросов; DNS-прогон пропускается (нужен --dns-bulk).");
    engine_logf("Параллельность: %d jobs", opt_jobs);

    if (stage_begin("Сеть и Wi‑Fi", "Локальный IP, шлюз, DNS, Wi‑Fi, ping")) {
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
        /* ICMP до публичных DNS: CF/Google/Quad9 + Яндекс + НСДИ + AdGuard */
        static const struct { const char *label; const char *ip; } ping_dns[] = {
            {"Cloudflare", "1.1.1.1"},
            {"Google", "8.8.8.8"},
            {"Quad9", "9.9.9.9"},
            {"Яндекс DNS", "77.88.8.8"},
            {"НСДИ", "195.208.4.1"},
            {"AdGuard", "94.140.14.14"},
        };
        const int np = (int)(sizeof ping_dns / sizeof ping_dns[0]);
        char name[80];
        for (i = 0; i < np; i++) {
            snprintf(name, sizeof name, "Ping %s (%s)", ping_dns[i].label, ping_dns[i].ip);
            stage_progress(name, 4, 6);
            ping_summary(ping_dns[i].ip, 5, &loss, &avg);
            st = (loss == 0) ? "ok" : (loss < 20 ? "warn" : "fail");
            snprintf(detail, sizeof detail, "loss=%d%%, avg=%.1f ms", loss, avg);
            add_check("Связность", name, st, detail, "");
        }
    }

    /* DNS targets: системные + публичные (Яндекс / НСДИ / AdGuard / …) */
    {
        char targets[16][64];
        const char *tnames[16];
        int nt = 0, j, k;
        for (i = 0; i < ndns && nt < 16; i++) {
            snprintf(targets[nt], 64, "%s", dns_list[i]);
            tnames[nt] = "системный";
            nt++;
        }
        for (i = 0; i < n_dns_pub && nt < 16; i++) {
            for (j = 0; j < nt; j++)
                if (strcmp(targets[j], dns_pub[i].ip) == 0) break;
            if (j == nt) {
                snprintf(targets[nt], 64, "%s", dns_pub[i].ip);
                tnames[nt] = dns_pub[i].name;
                nt++;
            }
        }
        for (i = 0; i < nt; i++) {
            int okc = 0, failc = 0, sum = 0, ms;
            char name[96];
            snprintf(name, sizeof name, "DNS %s", targets[i]);
            stage_progress(name, 5, 6);
            for (k = 0; k < 3; k++) {
                if (dns_ms_nslookup(targets[i], &ms)) {
                    okc++;
                    sum += ms;
                } else failc++;
            }
            snprintf(name, sizeof name, "Резолвер %s (%s)", tnames[i], targets[i]);
            if (okc == 0) {
                add_check_ex("DNS", name, "fail", "не отвечает",
                             "DNS не отвечает — проверки связности клиентов падают",
                             targets[i], NULL, 0);
                snprintf(detail, sizeof detail, "DNS %s (%s) недоступен", tnames[i], targets[i]);
                add_finding("critical", detail, "Устройства с этим DNS будут считать сеть без интернета.");
            } else {
                int a = sum / okc;
                st = (failc > 0 || a > 200) ? "warn" : "ok";
                snprintf(detail, sizeof detail, "avg=%d ms, fails=%d/3", a, failc);
                add_check_ex("DNS", name, st, detail,
                             a > 200 ? "Медленный DNS — таймауты проверок связности" : "",
                             targets[i], NULL, 0);
            }
        }
    }

    {
        const char *dots[] = {
            "dns.google", "1.1.1.1", "8.8.8.8", "9.9.9.9",
            "common.dot.dns.yandex.net", "dns.adguard-dns.com",
        };
        const int ndot = (int)(sizeof dots / sizeof dots[0]);
        char name[80];
        int any_dot_tls = 0;
        for (i = 0; i < ndot; i++) {
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
    } /* stage Сеть и Wi‑Fi */

    if (stage_begin("Captive / OS", "Мобильные и ПК connectivity-check / generate_204")) {
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
        {
            Check *outs = (Check *)calloc((size_t)nc, sizeof(Check));
            int *wantf = (int *)calloc((size_t)nc, sizeof(int));
            char *ftitles = (char *)calloc((size_t)nc, 256);
            char *ftexts = (char *)calloc((size_t)nc, LONGSTR);
            const char **names = (const char **)calloc((size_t)nc, sizeof(char *));
            const char **urls = (const char **)calloc((size_t)nc, sizeof(char *));
            int *expects = (int *)calloc((size_t)nc, sizeof(int));
            int *crits = (int *)calloc((size_t)nc, sizeof(int));
            if (outs && wantf && ftitles && ftexts && names && urls && expects && crits) {
                CapParCtx cctx;
                int j;
                for (j = 0; j < nc; j++) {
                    names[j] = caps[j].name;
                    urls[j] = caps[j].url;
                    expects[j] = caps[j].expect;
                    crits[j] = caps[j].critical;
                }
                cctx.outs = outs; cctx.wantf = wantf; cctx.ftitles = ftitles; cctx.ftexts = ftexts;
                cctx.names = names; cctx.urls = urls; cctx.expects = expects; cctx.crits = crits;
                run_parallel(nc, opt_jobs, captive_par_job, &cctx, "captive");
                for (j = 0; j < nc; j++) {
                    add_check_from(&outs[j]);
                    if (crits[j] && wantf[j])
                        add_finding("critical", ftitles + (size_t)j * 256,
                                    ftexts + (size_t)j * LONGSTR);
                }
            } else {
                for (i = 0; i < nc; i++) {
                    stage_progress(caps[i].name, i + 1, nc + 8);
                    check_captive(caps[i].name, caps[i].url, caps[i].expect, caps[i].critical);
                }
            }
            free(outs); free(wantf); free(ftitles); free(ftexts);
            free(names); free(urls); free(expects); free(crits);
        }
        {
            int gok[8], gms[8];
            GstCtx gctx;
            memset(gok, 0, sizeof gok);
            memset(gms, 0, sizeof gms);
            gctx.ok = gok;
            gctx.ms = gms;
            run_parallel(8, opt_jobs, gstatic_job, &gctx, "gstatic ×8");
            for (i = 0; i < 8; i++) {
                if (gok[i]) {
                    flaky_ok++;
                    flaky_sum += gms[i];
                } else flaky_fail++;
            }
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
    } /* stage Captive / OS */

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
    if (stage_begin("NTP", "UDP/123 — время для TLS на IoT")) {
        const char *ntp_hosts[] = {
            "time.google.com", "time.cloudflare.com", "pool.ntp.org"
        };
        int ntp_ok = 0;
        int ntp_n = (int)(sizeof ntp_hosts / sizeof ntp_hosts[0]);
        Check *nout = (Check *)calloc((size_t)ntp_n, sizeof(Check));
        int *nok = (int *)calloc((size_t)ntp_n, sizeof(int));
        if (nout && nok) {
            NtpCtx nctx;
            nctx.outs = nout; nctx.ok = nok; nctx.hosts = ntp_hosts;
            run_parallel(ntp_n, opt_jobs, ntp_job, &nctx, "NTP");
            for (i = 0; i < ntp_n; i++) {
                add_check_from(&nout[i]);
                if (nok[i]) ntp_ok++;
            }
        } else {
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
        }
        free(nout); free(nok);
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
            {"Philips Hue API", "api.meethue.com", 443, 0},
            {"Philips Hue discovery", "discovery.meethue.com", 443, 0},
            {"TP-Link Tapo", "n-wap-gw.tplinkcloud.com", 443, 0},
            {"TP-Link Tapo EU WAP", "eu-wap.tplinkcloud.com", 443, 0},
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
        {
            ResTcp *tmp = (ResTcp *)calloc((size_t)n, sizeof(ResTcp));
            Check *outs = (Check *)calloc((size_t)n, sizeof(Check));
            int *critf = (int *)calloc((size_t)n, sizeof(int));
            if (tmp && outs && critf) {
                TcpResJobCtx tctx;
                for (i = 0; i < n; i++) {
                    snprintf(tmp[i].name, sizeof tmp[i].name, "%s", eps[i].name);
                    snprintf(tmp[i].host, sizeof tmp[i].host, "%s", eps[i].host);
                    tmp[i].port = eps[i].port;
                    tmp[i].crit = eps[i].crit;
                }
                tctx.outs = outs; tctx.critf = critf; tctx.items = tmp;
                tctx.cat = "Умный дом / IoT"; tctx.spoiler = 1; tctx.timeout_ms = 4000;
                run_parallel(n, opt_jobs, tcp_res_job, &tctx, "IoT TCP");
                for (i = 0; i < n; i++) {
                    add_check_from(&outs[i]);
                    if (critf[i] && niot < 48)
                        snprintf(iot_fail[niot++], 64, "%s", eps[i].name);
                }
            } else {
                for (i = 0; i < n; i++) {
                    stage_item(eps[i].name, i + 1, n);
                    check_tcp_ep("Умный дом / IoT", eps[i].name, eps[i].host, eps[i].port,
                                 4000, eps[i].crit, 1, &niot, iot_fail, 48);
                }
            }
            free(tmp); free(outs); free(critf);
        }

        {
            struct { const char *name, *url; } https[] = {
                {"Tuya EU portal", "https://eu.iot.tuya.com/"},
                {"Tuya IoT platform", "https://iot.tuya.com/"},
                {"Яндекс IoT API HTTPS", "https://api.iot.yandex.net/"},
                {"Алиса HTTPS", "https://alice.yandex.ru/"},
                {"Xiaomi Home HTTPS", "https://home.mi.com/"},
                {"Sber Salute HTTPS", "https://salute.sber.ru/"},
                /* Витрины home-assistant.io / philips-hue.com / tapo.com — antibot/DPI;
                 * облака клиента: Nabu Casa, Hue discovery, Tapo WAP. */
                {"Home Assistant Cloud", "https://account.nabucasa.com/"},
                {"Philips Hue discovery", "https://discovery.meethue.com/"},
                {"Tapo cloud", "https://eu-wap.tplinkcloud.com/"},
            };
            int nh = (int)(sizeof https / sizeof https[0]);
            ResHttp *htmp = (ResHttp *)calloc((size_t)nh, sizeof(ResHttp));
            Check *houts = (Check *)calloc((size_t)nh, sizeof(Check));
            if (htmp && houts) {
                HttpsResJobCtx hctx;
                for (i = 0; i < nh; i++) {
                    snprintf(htmp[i].name, sizeof htmp[i].name, "%s", https[i].name);
                    snprintf(htmp[i].url, sizeof htmp[i].url, "%s", https[i].url);
                }
                hctx.outs = houts; hctx.items = htmp; hctx.cat = "Умный дом / IoT";
                hctx.multi_ua = 1; hctx.timeout_sec = 3; hctx.ok_403 = 0;
                run_parallel(nh, opt_jobs, https_res_job, &hctx, "IoT HTTPS");
                for (i = 0; i < nh; i++) {
                    houts[i].spoiler = 1;
                    add_check_from(&houts[i]);
                    if (strcmp(houts[i].status, "fail") == 0 && niot < 48)
                        snprintf(iot_fail[niot++], 64, "%s", https[i].name);
                }
            }
            free(htmp); free(houts);
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
        {
            Check *outs = (Check *)calloc((size_t)n, sizeof(Check));
            int *cf = (int *)calloc((size_t)n, sizeof(int));
            int *dt = (int *)calloc((size_t)n, sizeof(int));
            const char **names = (const char **)calloc((size_t)n, sizeof(char *));
            const char **hosts = (const char **)calloc((size_t)n, sizeof(char *));
            int *ports = (int *)calloc((size_t)n, sizeof(int));
            int *exp = (int *)calloc((size_t)n, sizeof(int));
            if (outs && cf && dt && names && hosts && ports && exp) {
                DpiPortCtx pctx;
                for (i = 0; i < n; i++) {
                    names[i] = dpi[i].name; hosts[i] = dpi[i].host;
                    ports[i] = dpi[i].port; exp[i] = dpi[i].expect_open;
                }
                pctx.outs = outs; pctx.count_fail = cf; pctx.dot_tls_ok = dt;
                pctx.names = names; pctx.hosts = hosts; pctx.ports = ports; pctx.expect_open = exp;
                run_parallel(n, opt_jobs, dpi_port_job, &pctx, "DPI ports");
                step += n;
                for (i = 0; i < n; i++) {
                    add_check_from(&outs[i]);
                    if (dt[i]) dot_open++;
                    if (cf[i] && ndpi < 40) snprintf(dpi_fail[ndpi++], 64, "%s", dpi[i].name);
                }
            } else {
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
            }
            free(outs); free(cf); free(dt); free(names); free(hosts); free(ports); free(exp);
        }

        {
            static const char *doh_names[] = {"DoH Cloudflare", "DoH Google JSON"};
            static const char *doh_urls[] = {
                "https://cloudflare-dns.com/dns-query?name=example.com&type=A",
                "https://dns.google/resolve?name=example.com&type=A",
            };
            Check *outs = (Check *)calloc(2, sizeof(Check));
            int is_fail[2] = {0, 0};
            int doh_ok = 0, doh_fail = 0;
            DohCtx dctx;
            if (outs) {
                dctx.outs = outs; dctx.is_fail = is_fail;
                dctx.names = doh_names; dctx.urls = doh_urls;
                run_parallel(2, opt_jobs, doh_job, &dctx, "DoH");
                step += 2;
                for (i = 0; i < 2; i++) {
                    add_check_from(&outs[i]);
                    if (strcmp(outs[i].status, "ok") == 0) doh_ok++;
                    if (is_fail[i]) {
                        doh_fail++;
                        if (ndpi < 40)
                            snprintf(dpi_fail[ndpi++], 64, "%s",
                                     i == 0 ? "DoH Cloudflare" : "DoH Google");
                    }
                }
            }
            free(outs);
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
            Check *outs = (Check *)calloc((size_t)nsni, sizeof(Check));
            int *sf = (int *)calloc((size_t)nsni, sizeof(int));
            const char **names = (const char **)calloc((size_t)nsni, sizeof(char *));
            const char **urls = (const char **)calloc((size_t)nsni, sizeof(char *));
            int *eru = (int *)calloc((size_t)nsni, sizeof(int));
            if (outs && sf && names && urls && eru) {
                SniCtx sctx;
                for (i = 0; i < nsni; i++) {
                    names[i] = sni[i].name; urls[i] = sni[i].url; eru[i] = sni[i].expected_ru;
                }
                sctx.outs = outs; sctx.sni_fail = sf; sctx.names = names;
                sctx.urls = urls; sctx.expected_ru = eru;
                run_parallel(nsni, opt_jobs, sni_job, &sctx, "SNI");
                step += nsni;
                for (i = 0; i < nsni; i++) {
                    add_check_from(&outs[i]);
                    if (sf[i]) sni_fail++;
                }
            }
            free(outs); free(sf); free(names); free(urls); free(eru);
            if (sni_fail >= 1)
                add_finding("warning", "Похоже на SNI/DPI фильтрацию",
                            "Неожиданно недоступны «обычные» зарубежные HTTPS (не YouTube/Telegram/Discord). "
                            "IoT-облака за рубежом (Tuya EU) могут попадать под те же правила.");
        }

        /* QUIC / HTTP3 path */
        {
            struct { const char *name, *host; int expected_ru; } qh[] = {
                {"QUIC ya.ru:443/udp", "ya.ru", 0},
                {"QUIC yandex.ru:443/udp", "www.yandex.ru", 0},
                {"QUIC google.com:443/udp", "www.google.com", 0},
                {"QUIC youtube.com:443/udp", "www.youtube.com", 1},
                {"QUIC cloudflare.com:443/udp", "cloudflare.com", 0},
                {"QUIC discord.com:443/udp", "discord.com", 1},
            };
            int qok = 0;
            int nq = (int)(sizeof qh / sizeof qh[0]);
            Check *outs = (Check *)calloc((size_t)nq, sizeof(Check));
            int *qo = (int *)calloc((size_t)nq, sizeof(int));
            const char **names = (const char **)calloc((size_t)nq, sizeof(char *));
            const char **hosts = (const char **)calloc((size_t)nq, sizeof(char *));
            int *eru = (int *)calloc((size_t)nq, sizeof(int));
            if (outs && qo && names && hosts && eru) {
                QuicCtx qctx;
                for (i = 0; i < nq; i++) {
                    names[i] = qh[i].name; hosts[i] = qh[i].host; eru[i] = qh[i].expected_ru;
                }
                qctx.outs = outs; qctx.qok = qo; qctx.names = names;
                qctx.hosts = hosts; qctx.expected_ru = eru;
                run_parallel(nq, opt_jobs, quic_job, &qctx, "QUIC");
                step += nq;
                for (i = 0; i < nq; i++) {
                    add_check_from(&outs[i]);
                    if (qo[i]) qok++;
                }
            }
            free(outs); free(qo); free(names); free(hosts); free(eru);
            (void)step;
            (void)dpi_total;
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

    /* CDN / счётчики — реальная отдача байтов (magic PNG/GIF/HTML), не только TCP */
    if (stage_begin("CDN / счётчики",
                    "yastatic.net, counter.yadro.ru — проверка содержимого (от них зависят многие сайты РФ)")) {
        char detail[STR], hint[STR], ip[64], host[128];
        long bytes = 0;
        int code = 0, ms = 0, ok_n_cdn = 0, fail_n_cdn = 0;

        /* 1) yastatic HTML root */
        host_from_url("https://yastatic.net/", host, sizeof host);
        ip[0] = 0;
        if (host[0]) dns_resolve(host, ip, sizeof ip);
        stage_progress("yastatic.net HTML", 1, 4);
        if (http_fetch_verify("https://yastatic.net/", 12, "HTML", 500, &bytes, &code, &ms)) {
            snprintf(detail, sizeof detail, "HTTP %d, %ld байт, %d ms · HTML OK", code, bytes, ms);
            add_check_ex("CDN / счётчики", "yastatic.net (HTML)", "ok", detail,
                         "Корень CDN Яндекса отдаёт документ — хост жив.",
                         ip[0] ? ip : NULL, "https://yastatic.net/", 0);
            ok_n_cdn++;
        } else {
            snprintf(detail, sizeof detail, "HTTP %d, %ld байт, %d ms", code, bytes, ms);
            add_check_ex("CDN / счётчики", "yastatic.net (HTML)", "fail", detail,
                         "Не получили HTML с yastatic.net — многие сайты Яндекса/партнёров "
                         "откроются «пустыми» без стилей/JS.",
                         ip[0] ? ip : NULL, "https://yastatic.net/", 0);
            fail_n_cdn++;
        }

        /* 2) yastatic asset: взять URL с ya.ru и проверить PNG/JS magic */
        {
            char *page = (char *)malloc(PAGE_HTML_CAP);
            char asset[STR];
            int pcode = 0, pms = 0;
            const char *magic = NULL;
            stage_progress("yastatic asset", 2, 4);
            asset[0] = 0;
            if (page)
                pcode = http_fetch_text_ex("https://ya.ru/", page, PAGE_HTML_CAP, 12, &pms, NULL);
            if (page && pcode >= 200 && pcode < 400 &&
                extract_yastatic_asset(page, asset, sizeof asset)) {
                if (strstr(asset, ".png")) magic = "PNG";
                else if (strstr(asset, ".gif")) magic = "GIF";
                else magic = NULL; /* js/css — по размеру */
                bytes = 0; code = 0; ms = 0;
                if (http_fetch_verify(asset, 12, magic, magic ? 64 : 200, &bytes, &code, &ms)) {
                    snprintf(detail, sizeof detail,
                             "HTTP %d, %ld байт, %d ms · %s · с ya.ru",
                             code, bytes, ms, magic ? magic : "тело OK");
                    add_check_ex("CDN / счётчики", "yastatic.net (asset)", "ok", detail,
                                 "Реальный статический файл с CDN скачался (magic/размер).",
                                 ip[0] ? ip : NULL, asset, 0);
                    ok_n_cdn++;
                } else {
                    snprintf(detail, sizeof detail, "HTTP %d, %ld байт · %s", code, bytes, asset);
                    add_check_ex("CDN / счётчики", "yastatic.net (asset)", "fail", detail,
                                 "HTML ya.ru ссылается на yastatic, но файл не отдался — "
                                 "типичный симптом блока/throttle CDN.",
                                 ip[0] ? ip : NULL, asset, 0);
                    fail_n_cdn++;
                }
            } else {
                /* fallback: фиксированный PNG (может устареть) + проверка magic */
                const char *fb =
                    "https://yastatic.net/s3/home-static/_/37/37a02b5dc7a51abac55d8a5b6c865f0e.png";
                bytes = 0; code = 0; ms = 0;
                if (http_fetch_verify(fb, 12, "PNG", 100, &bytes, &code, &ms)) {
                    snprintf(detail, sizeof detail, "HTTP %d, %ld байт PNG · fallback", code, bytes);
                    add_check_ex("CDN / счётчики", "yastatic.net (asset)", "ok", detail,
                                 "Запасной PNG с yastatic отдался.",
                                 ip[0] ? ip : NULL, fb, 0);
                    ok_n_cdn++;
                } else {
                    add_check_ex("CDN / счётчики", "yastatic.net (asset)", "warn",
                                 "не удалось взять asset с ya.ru и fallback PNG",
                                 "Смотрите проверку HTML yastatic.net.",
                                 ip[0] ? ip : NULL, "https://yastatic.net/", 0);
                }
            }
            free(page);
        }

        /* 3) LiveInternet counter GIF 1×1 */
        host_from_url("https://counter.yadro.ru/hit;0", host, sizeof host);
        ip[0] = 0;
        if (host[0]) dns_resolve(host, ip, sizeof ip);
        stage_progress("yadro hit GIF", 3, 4);
        bytes = 0; code = 0; ms = 0;
        if (http_fetch_verify("https://counter.yadro.ru/hit;0", 10, "GIF", 20, &bytes, &code, &ms)) {
            snprintf(detail, sizeof detail, "HTTP %d, %ld байт GIF, %d ms · пиксель hit", code, bytes, ms);
            add_check_ex("CDN / счётчики", "counter.yadro.ru (hit GIF)", "ok", detail,
                         "Счётчик LiveInternet отдал GIF — хост реально отвечает телом.",
                         ip[0] ? ip : NULL, "https://counter.yadro.ru/hit;0", 0);
            ok_n_cdn++;
        } else {
            snprintf(detail, sizeof detail, "HTTP %d, %ld байт, %d ms", code, bytes, ms);
            add_check_ex("CDN / счётчики", "counter.yadro.ru (hit GIF)", "fail", detail,
                         "Пиксель счётчика не скачался — на многих СМИ/блогах «ломается» аналитика "
                         "и часть вёрстки, завязанная на yadro.",
                         ip[0] ? ip : NULL, "https://counter.yadro.ru/hit;0", 0);
            fail_n_cdn++;
        }

        /* 4) logo GIF */
        stage_progress("yadro logo GIF", 4, 4);
        bytes = 0; code = 0; ms = 0;
        if (http_fetch_verify("https://counter.yadro.ru/logo?24.6", 10, "GIF", 40, &bytes, &code, &ms)) {
            snprintf(detail, sizeof detail, "HTTP %d, %ld байт GIF, %d ms · logo", code, bytes, ms);
            add_check_ex("CDN / счётчики", "counter.yadro.ru (logo GIF)", "ok", detail,
                         "Логотип-счётчик отдался как GIF.",
                         ip[0] ? ip : NULL, "https://counter.yadro.ru/logo?24.6", 0);
            ok_n_cdn++;
        } else {
            snprintf(detail, sizeof detail, "HTTP %d, %ld байт, %d ms", code, bytes, ms);
            add_check_ex("CDN / счётчики", "counter.yadro.ru (logo GIF)",
                         fail_n_cdn > 0 ? "fail" : "warn", detail,
                         "logo не отдался — смотрите hit GIF.",
                         ip[0] ? ip : NULL, "https://counter.yadro.ru/logo?24.6", 0);
            if (code <= 0 || bytes < 40) fail_n_cdn++;
        }

        g_cdn_canary_fail = fail_n_cdn;
        if (fail_n_cdn >= 2) {
            snprintf(hint, sizeof hint, "Сбои CDN/счётчиков (%d)", fail_n_cdn);
            add_finding("critical", hint,
                        "yastatic.net и/или counter.yadro.ru не отдают содержимое. "
                        "Сайты РФ часто открываются «пустым» каркасом без CSS/JS/счётчиков. "
                        "Проверьте фильтр по CDN/AS Яндекса и LiveInternet.");
        } else if (fail_n_cdn == 1) {
            add_finding("warning", "Частичный сбой CDN/счётчиков",
                        "Один из канареечных хостов (yastatic / yadro) не отдал файл. "
                        "Смотрите раздел «CDN / счётчики».");
        }
        (void)ok_n_cdn;
        stage_done();
    }

    /* Значимые ресурсы (Белые списки МЦ) — отдельный этап от зарубежного контроля */
    if (stage_begin("Значимые ресурсы (Белые списки МЦ)",
                    "Госуслуги, медиа, маркетплейсы, операторы, сервисы Яндекса и VK")) {
        char ru_fail[40][64];
        char ru_slow[40][80];
        int nru_fail = 0, nru_slow = 0;
        int n = g_nru;
        Check *outs = NULL;
        int *failed = NULL, *slow_ms = NULL;
        SigJobCtx ctx;
        if (g_resources_from_file)
            add_check("Значимые ресурсы (Белые списки МЦ)", "Список", "info",
                      resources_loaded[0] ? resources_loaded : "resources.conf", "");
        outs = (Check *)calloc((size_t)n, sizeof(Check));
        failed = (int *)calloc((size_t)n, sizeof(int));
        slow_ms = (int *)calloc((size_t)n, sizeof(int));
        if (outs && failed && slow_ms && n > 0) {
            ctx.outs = outs;
            ctx.failed = failed;
            ctx.slow_ms = slow_ms;
            run_parallel(n, opt_jobs, ru_job, &ctx, "значимые МЦ");
            for (i = 0; i < n; i++) {
                add_check_from(&outs[i]);
                if (failed[i] && nru_fail < 40)
                    snprintf(ru_fail[nru_fail++], 64, "%s", g_ru[i].name);
                if (slow_ms[i] && nru_slow < 40)
                    snprintf(ru_slow[nru_slow++], 80, "%s %dms", g_ru[i].name, slow_ms[i]);
            }
        } else {
            for (i = 0; i < n; i++) {
                stage_item(g_ru[i].name, i + 1, n);
                check_ru("Значимые ресурсы (Белые списки МЦ)", g_ru[i].name, g_ru[i].url, g_ru[i].note, 1, 0,
                         ru_fail, &nru_fail, ru_slow, &nru_slow);
            }
        }
        free(outs); free(failed); free(slow_ms);
        stage_done();
        if (nru_fail > 0) {
            char names[LONGSTR] = "", tx[LONGSTR];
            for (i = 0; i < nru_fail; i++) {
                if (i) strcat(names, ", ");
                strcat(names, ru_fail[i]);
            }
            snprintf(detail, sizeof detail, "Недоступны значимые ресурсы МЦ (%d)", nru_fail);
            snprintf(tx, sizeof tx, "Не отвечают: %s.", names);
            add_finding("warning", detail, tx);
        }
    }

    /* Зарубежные ресурсы — контроль; блок РФ (YouTube/Telegram/…) ≠ сбой сети */
    if (stage_begin("Зарубежные ресурсы",
                    "Контроль зарубежных сервисов; блок в РФ не считаем сбоем сети")) {
        char sig_fail[40][64];
        char sig_slow[40][80];
        int nsig_fail = 0, nsig_slow = 0;
        int n = g_nsig;
        Check *outs = NULL;
        int *failed = NULL, *slow_ms = NULL;
        SigJobCtx ctx;
        if (g_resources_from_file)
            add_check("Зарубежные ресурсы", "Список", "info",
                      resources_loaded[0] ? resources_loaded : "resources.conf", "");
        outs = (Check *)calloc((size_t)n, sizeof(Check));
        failed = (int *)calloc((size_t)n, sizeof(int));
        slow_ms = (int *)calloc((size_t)n, sizeof(int));
        if (outs && failed && slow_ms) {
            ctx.outs = outs;
            ctx.failed = failed;
            ctx.slow_ms = slow_ms;
            run_parallel(n, opt_jobs, sig_job, &ctx, "зарубежные");
            for (i = 0; i < n; i++) {
                if (g_sig[i].expected_block &&
                    (strcmp(outs[i].status, "fail") == 0 || strcmp(outs[i].status, "warn") == 0)) {
                    snprintf(outs[i].status, sizeof outs[i].status, "info");
                    if (g_sig[i].note[0])
                        snprintf(outs[i].hint, sizeof outs[i].hint, "%s", g_sig[i].note);
                    failed[i] = 0;
                }
                add_check_from(&outs[i]);
                if (failed[i] && nsig_fail < 40)
                    snprintf(sig_fail[nsig_fail++], 64, "%s", g_sig[i].name);
                if (slow_ms[i] && nsig_slow < 40)
                    snprintf(sig_slow[nsig_slow++], 80, "%s %dms", g_sig[i].name, slow_ms[i]);
            }
        } else {
            for (i = 0; i < n; i++) {
                stage_item(g_sig[i].name, i + 1, n);
                check_ru("Зарубежные ресурсы", g_sig[i].name, g_sig[i].url, g_sig[i].note, 1, 0,
                         sig_fail, &nsig_fail, sig_slow, &nsig_slow);
            }
        }
        free(outs); free(failed); free(slow_ms);
        stage_done();
        if (nsig_fail > 0) {
            char names[LONGSTR] = "", tx[LONGSTR];
            for (i = 0; i < nsig_fail; i++) {
                if (i) strcat(names, ", ");
                strcat(names, sig_fail[i]);
            }
            snprintf(detail, sizeof detail, "Недоступны зарубежные ресурсы (%d)", nsig_fail);
            snprintf(tx, sizeof tx,
                     "Не отвечают (кроме ожидаемо ограниченных в РФ): %s.", names);
            add_finding("warning", detail, tx);
        }
    }

    /* RU banks / services */
    if (stage_begin("Банки и сервисы РФ", "Доступность популярных банков и порталов")) {
        int n = g_nbanks;
        Check *outs = (Check *)calloc((size_t)n, sizeof(Check));
        int *failed = (int *)calloc((size_t)n, sizeof(int));
        int *slow_ms = (int *)calloc((size_t)n, sizeof(int));
        if (g_resources_from_file)
            add_check("Банки и сервисы РФ", "Список", "info",
                      resources_loaded[0] ? resources_loaded : "resources.conf", "");
        if (outs && failed && slow_ms && n > 0) {
            BankJobCtx bctx;
            bctx.outs = outs; bctx.failed = failed; bctx.slow_ms = slow_ms;
            run_parallel(n, opt_jobs, bank_job, &bctx, "банки");
            for (i = 0; i < n; i++) {
                add_check_from(&outs[i]);
                if (failed[i] && nfail < 40)
                    snprintf(fail_names[nfail++], 64, "%s", g_banks[i].name);
                if (slow_ms[i] && nslow < 40)
                    snprintf(slow_names[nslow++], 80, "%s %dms", g_banks[i].name, slow_ms[i]);
            }
        } else {
            for (i = 0; i < n; i++) {
                stage_item(g_banks[i].name, i + 1, n);
                check_ru(g_banks[i].cat, g_banks[i].name, g_banks[i].url, "", 0, 0,
                         fail_names, &nfail, slow_names, &nslow);
            }
        }
        free(outs); free(failed); free(slow_ms);
        stage_done();
    }

    /* Почта: веб-интерфейсы + SMTP/IMAP/POP3 (баннер или TLS) */
    if (stage_begin("Почта",
                    "Веб-почта и протоколы SMTP/IMAP/POP3 (баннер 220/+OK или TLS ServerHello)")) {
        struct { const char *name, *url; } web[] = {
            {"Яндекс Почта", "https://mail.yandex.ru/"},
            {"Mail.ru Почта", "https://e.mail.ru/"},
            {"Gmail", "https://mail.google.com/"},
            {"Outlook", "https://outlook.live.com/"},
            {"iCloud Mail", "https://www.icloud.com/"},
            {"Rambler Почта", "https://mail.rambler.ru/"},
            {"Proton Mail", "https://mail.proton.me/"},
        };
        struct {
            const char *name, *host, *kind;
            int port, use_tls, crit;
        } proto[] = {
            /* Яндекс */
            {"Яндекс SMTP :587", "smtp.yandex.ru", "smtp", 587, 0, 1},
            {"Яндекс SMTPS :465", "smtp.yandex.ru", "tls", 465, 1, 1},
            {"Яндекс SMTP :25", "smtp.yandex.ru", "smtp", 25, 0, 0},
            {"Яндекс IMAPS :993", "imap.yandex.ru", "tls", 993, 1, 1},
            {"Яндекс POP3S :995", "pop.yandex.ru", "tls", 995, 1, 0},
            /* Mail.ru */
            {"Mail.ru SMTP :587", "smtp.mail.ru", "smtp", 587, 0, 1},
            {"Mail.ru SMTPS :465", "smtp.mail.ru", "tls", 465, 1, 1},
            {"Mail.ru IMAPS :993", "imap.mail.ru", "tls", 993, 1, 1},
            {"Mail.ru POP3S :995", "pop.mail.ru", "tls", 995, 1, 0},
            /* Gmail */
            {"Gmail SMTP :587", "smtp.gmail.com", "smtp", 587, 0, 1},
            {"Gmail SMTPS :465", "smtp.gmail.com", "tls", 465, 1, 1},
            {"Gmail IMAPS :993", "imap.gmail.com", "tls", 993, 1, 1},
            {"Gmail POP3S :995", "pop.gmail.com", "tls", 995, 1, 0},
            /* Microsoft 365 / Outlook */
            {"Outlook SMTP :587", "smtp.office365.com", "smtp", 587, 0, 1},
            {"Outlook IMAPS :993", "outlook.office365.com", "tls", 993, 1, 1},
            /* iCloud */
            {"iCloud SMTP :587", "smtp.mail.me.com", "smtp", 587, 0, 0},
            {"iCloud IMAPS :993", "imap.mail.me.com", "tls", 993, 1, 0},
            /* Rambler */
            {"Rambler SMTP :587", "smtp.rambler.ru", "smtp", 587, 0, 0},
            {"Rambler IMAPS :993", "imap.rambler.ru", "tls", 993, 1, 0},
        };
        int nw = (int)(sizeof web / sizeof web[0]);
        int np = (int)(sizeof proto / sizeof proto[0]);
        int mail_fail = 0, i;
        char detail[STR], banner[192], ip[64];

        for (i = 0; i < nw; i++) {
            Check c;
            int failed = 0, slow_ms = 0;
            stage_progress(web[i].name, i + 1, nw + np);
            check_ru_fill(&c, "Почта", web[i].name, web[i].url,
                          "веб-интерфейс", 0, 0, &failed, &slow_ms);
            add_check_from(&c);
            if (failed) mail_fail++;
        }
        for (i = 0; i < np; i++) {
            int ms = 0, rc;
            char urlbuf[160];
            stage_progress(proto[i].name, nw + i + 1, nw + np);
            ip[0] = 0;
            dns_resolve(proto[i].host, ip, sizeof ip);
            rc = mail_proto_probe(proto[i].host, proto[i].port, proto[i].kind,
                                  proto[i].use_tls, 5000, &ms, banner, sizeof banner);
            /* https://host/ — чтобы SNI/host_from_url не ломались на smtp:// / tls:// */
            snprintf(urlbuf, sizeof urlbuf, "https://%s/", proto[i].host);
            if (rc == 2) {
                snprintf(detail, sizeof detail, "%s, %d ms",
                         banner[0] ? banner : (proto[i].use_tls ? "TLS OK" : "баннер OK"), ms);
                add_check_ex("Почта", proto[i].name, "ok", detail, "",
                             ip[0] ? ip : NULL, urlbuf, 0);
            } else if (rc == 1) {
                snprintf(detail, sizeof detail, "TCP открыт, баннер/TLS нет, %d ms", ms);
                add_check_ex("Почта", proto[i].name,
                             proto[i].crit ? "fail" : "warn", detail,
                             proto[i].use_tls
                                 ? "Порт открыт, TLS handshake не прошёл — клиент почты не подключится."
                                 : "Порт открыт, но нет SMTP/IMAP/POP3-баннера — возможна подмена/фильтр.",
                             ip[0] ? ip : NULL, urlbuf, 0);
                if (proto[i].crit) mail_fail++;
            } else {
                snprintf(detail, sizeof detail, "закрыт/таймаут, %d ms", ms);
                add_check_ex("Почта", proto[i].name,
                             proto[i].crit ? "fail" : "warn", detail,
                             proto[i].port == 25
                                 ? "TCP/25 часто режет провайдер — для клиентов важнее :587/:465."
                                 : "Клиент почты (Outlook/Thunderbird/телефон) не достучится до сервера.",
                             ip[0] ? ip : NULL, urlbuf, 0);
                if (proto[i].crit) mail_fail++;
            }
        }
        if (mail_fail >= 3)
            add_finding("warning", "Проблемы с почтой",
                        "Несколько веб/SMTP/IMAP проверок не прошли. "
                        "Проверьте DPI на :465/:587/:993 и доступ к mail.*. "
                        "Порт 25 у многих ISP закрыт исходящий — это норма.");
        stage_done();
    }

    /* Video hosts: homepage + video path (full «первое видео» — probe-video) */
    if (!opt_skip_video && stage_begin("Видео",
                    "Яндекс Видео, VK Видео, IVI, Okko, Кинопоиск, Rutube — сайт и видео-путь")) {
        int nv = g_nvideo;
        int vfail = 0;
        Check *outs = (Check *)calloc((size_t)nv, sizeof(Check));
        VideoJobCtx vctx;
        if (outs && nv > 0) {
            vctx.outs = outs;
            run_parallel(nv, opt_jobs, video_job, &vctx, "видео");
            for (i = 0; i < nv; i++) {
                add_check_from(&outs[i]);
                if (strcmp(outs[i].status, "fail") == 0) vfail++;
            }
        }
        free(outs);
        if (vfail >= 3)
            add_finding("warning", "Видеохостинги недоступны",
                        "Яндекс/VK/IVI/Okko/Кинопоиск/Rutube — проверьте DPI/DNS. "
                        "Детальный прогон: ./probe-video");
        stage_done();
    } else if (opt_skip_video) {
        add_check("Видео", "Этап", "info", "пропущен (--skip-video)", "");
    }

    /* Gaming platforms: Blizzard / Battle.net, Steam, Epic, Riot, … */
    if (stage_begin("Игры", "Battle.net / Blizzard, Steam и популярные игровые платформы")) {
        char game_fail[64][64];
        int ngame = 0;
        int n = g_ngame_tcp;
        Check *touts = NULL, *houts = NULL;
        int *critf = NULL;
        if (n > 0) {
            TcpResJobCtx tctx;
            touts = (Check *)calloc((size_t)n, sizeof(Check));
            critf = (int *)calloc((size_t)n, sizeof(int));
            if (touts && critf) {
                tctx.outs = touts; tctx.critf = critf; tctx.items = g_game_tcp;
                tctx.cat = "Игры"; tctx.spoiler = 0; tctx.timeout_ms = 4000;
                run_parallel(n, opt_jobs, tcp_res_job, &tctx, "игры TCP");
                for (i = 0; i < n; i++) {
                    add_check_from(&touts[i]);
                    if (critf[i] && ngame < 64)
                        snprintf(game_fail[ngame++], 64, "%s", g_game_tcp[i].name);
                }
            }
            free(touts); free(critf);
        }
        stage_item("Steam CM", n + 1, n + 2);
        check_steam_cm(&ngame, game_fail, 64);
        stage_item("Steam SDR", n + 2, n + 2);
        check_steam_sdr(&ngame, game_fail, 64);
        stage_item_clear();

        {
            int nh = g_ngame_https;
            HttpsResJobCtx hctx;
            houts = (Check *)calloc((size_t)nh, sizeof(Check));
            if (houts && nh > 0) {
                hctx.outs = houts; hctx.items = g_game_https; hctx.cat = "Игры";
                hctx.multi_ua = 1; hctx.timeout_sec = 5; hctx.ok_403 = 0;
                run_parallel(nh, opt_jobs, https_res_job, &hctx, "игры HTTPS");
                for (i = 0; i < nh; i++) {
                    add_check_from(&houts[i]);
                    if (strcmp(houts[i].status, "fail") == 0 && ngame < 64)
                        snprintf(game_fail[ngame++], 64, "%s", g_game_https[i].name);
                }
            }
            free(houts);
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

    /* Облака + канарейки ASN (CF/Hetzner/DO/OVH/GitHub) */
    if ((g_ninfra_tcp > 0 || g_ninfra_https > 0) &&
        stage_begin("Облако",
                    "Selectel / AWS / Azure + канарейки Cloudflare, Hetzner, DO, OVH, GitHub")) {
        char fail[64][64];
        int nfail = 0;
        int n = g_ninfra_tcp;
        int nh = g_ninfra_https;
        Check *touts = NULL, *houts = NULL;
        int *critf = NULL;
        if (n > 0) {
            TcpResJobCtx tctx;
            touts = (Check *)calloc((size_t)n, sizeof(Check));
            critf = (int *)calloc((size_t)n, sizeof(int));
            if (touts && critf) {
                tctx.outs = touts; tctx.critf = critf; tctx.items = g_infra_tcp;
                tctx.cat = "Облако"; tctx.spoiler = 0; tctx.timeout_ms = 4000;
                run_parallel(n, opt_jobs, tcp_res_job, &tctx, "облако TCP");
                for (i = 0; i < n; i++) {
                    add_check_from(&touts[i]);
                    if (critf[i] && nfail < 64)
                        snprintf(fail[nfail++], 64, "%s", g_infra_tcp[i].name);
                }
            }
            free(touts); free(critf);
        }
        if (nh > 0) {
            HttpsResJobCtx hctx;
            houts = (Check *)calloc((size_t)nh, sizeof(Check));
            if (houts) {
                hctx.outs = houts; hctx.items = g_infra_https; hctx.cat = "Облако";
                hctx.multi_ua = 0; hctx.timeout_sec = 10; hctx.ok_403 = 1;
                run_parallel(nh, opt_jobs, https_res_job, &hctx, "облако HTTPS");
                for (i = 0; i < nh; i++) {
                    add_check_from(&houts[i]);
                    if (strcmp(houts[i].status, "fail") == 0 && nfail < 64)
                        snprintf(fail[nfail++], 64, "%s", g_infra_https[i].name);
                }
            }
            free(houts);
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

    /* Репозитории Linux / зеркала + точки обновлений Windows/Apple/Android и пакетных экосистем */
    if (g_nupdates > 0 &&
        stage_begin("Репозитории / обновления",
                    "Зеркала Debian/Ubuntu/Fedora/Arch…, Windows Update, Apple, Android, "
                    "Docker/npm/PyPI/Homebrew/Flathub")) {
        int nh = g_nupdates;
        int nfail = 0;
        Check *houts = (Check *)calloc((size_t)nh, sizeof(Check));
        if (houts && nh > 0) {
            HttpsResJobCtx hctx;
            hctx.outs = houts; hctx.items = g_updates; hctx.cat = "Репозитории / обновления";
            hctx.multi_ua = 0; hctx.timeout_sec = 12; hctx.ok_403 = 1;
            run_parallel(nh, opt_jobs, https_res_job, &hctx, "репо/апдейты");
            for (i = 0; i < nh; i++) {
                add_check_from(&houts[i]);
                if (strcmp(houts[i].status, "fail") == 0) nfail++;
            }
        }
        free(houts);
        if (nfail >= 5)
            add_finding("warning", "Много сбоев репозиториев / обновлений",
                        "Недоступны сразу несколько зеркал Linux или точек обновления ОС — "
                        "возможен фильтр CDN/foreign AS или проблема исходящего HTTPS.");
        else if (nfail >= 2)
            add_finding("info", "Частичные сбои репозиториев / обновлений",
                        "Часть зеркал или update-CDN не отвечает — проверьте локальные "
                        "sources.list / зеркала и доступ к Windows/Apple update.");
        stage_done();
    }

    /* Гео / IX — как CheckHost, но с этой сети к точкам стран и peering IX */
    if (g_ngeo > 0 &&
        stage_begin("Гео / IX",
                    "Канарейки по странам + известные IX (DE-CIX, AMS-IX, LINX, DATAIX…) "
                    "и Cloudflare 100KB throttle")) {
        int nh = g_ngeo;
        int nfail = 0;
        Check *houts = (Check *)calloc((size_t)nh, sizeof(Check));
        stage_item("Cloudflare 100KB", 1, nh + 1);
        check_cloudflare_throttle();
        if (houts && nh > 0) {
            HttpsResJobCtx hctx;
            hctx.outs = houts; hctx.items = g_geo; hctx.cat = "Гео / IX";
            hctx.multi_ua = 0; hctx.timeout_sec = 12; hctx.ok_403 = 1;
            run_parallel(nh, opt_jobs, https_res_job, &hctx, "гео/IX");
            for (i = 0; i < nh; i++) {
                add_check_from(&houts[i]);
                if (strcmp(houts[i].status, "fail") == 0) nfail++;
            }
        }
        free(houts);
        if (nfail >= 4)
            add_finding("warning", "Много сбоев гео/IX",
                        "Недоступны сразу несколько зарубежных точек/IX — "
                        "похож фильтр по foreign AS или проблема международного пиринга.");
        stage_done();
    }

    /* AI / LLM: TCP :443 (HTTPS часто «умный» таймаут при живом connect) */
    if (stage_begin("AI / LLM",
                    "Cursor, OpenAI, Claude, Grok, Gemini — TCP connect :443 (без HTTPS-пробы)")) {
        char ai_fail[48][64];
        int nai_fail = 0;
        int n = g_nai;
        Check *outs = (Check *)calloc((size_t)n, sizeof(Check));
        int *critf = (int *)calloc((size_t)n, sizeof(int));
        if (outs && critf && n > 0) {
            TcpResJobCtx tctx;
            tctx.outs = outs; tctx.critf = critf; tctx.items = g_ai;
            tctx.cat = "AI / LLM"; tctx.spoiler = 0; tctx.timeout_ms = 4000;
            run_parallel(n, opt_jobs, tcp_res_job, &tctx, "AI TCP");
            for (i = 0; i < n; i++) {
                add_check_from(&outs[i]);
                if (critf[i] && nai_fail < 48)
                    snprintf(ai_fail[nai_fail++], 64, "%s", g_ai[i].name);
            }
        } else {
            for (i = 0; i < n; i++) {
                stage_item(g_ai[i].name, i + 1, n);
                check_tcp_ep("AI / LLM", g_ai[i].name, g_ai[i].host, g_ai[i].port,
                             4000, g_ai[i].crit, 0, &nai_fail, ai_fail, 48);
            }
        }
        free(outs); free(critf);
        if (nai_fail > 0) {
            char names[LONGSTR] = "", tx[LONGSTR];
            for (i = 0; i < nai_fail; i++) {
                if (i) strcat(names, ", ");
                strcat(names, ai_fail[i]);
            }
            snprintf(detail, sizeof detail, "Недоступны AI-платформы (%d)", nai_fail);
            snprintf(tx, sizeof tx,
                     "TCP :443 не открывается: %s. Порт закрыт/фильтруется — "
                     "IDE/чат-боты не достучатся до API.", names);
            add_finding(nai_fail >= 2 ? "critical" : "warning", detail, tx);
        }
        stage_done();
    } else if (!g_sys_dns_broken) {
        add_check("AI / LLM", "Этап", "info", "пропущен пользователем", "");
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
        Check *souts = (Check *)calloc((size_t)np, sizeof(Check));
        double *smbps = (double *)calloc((size_t)np, sizeof(double));
        const char **snames = (const char **)calloc((size_t)np, sizeof(char *));
        const char **surls = (const char **)calloc((size_t)np, sizeof(char *));
        const char **sgeo = (const char **)calloc((size_t)np, sizeof(char *));
        int *scrit = (int *)calloc((size_t)np, sizeof(int));

        stage_progress("пробы download", 1, np + 2);
        if (souts && smbps && snames && surls && sgeo && scrit) {
            SpeedCtx sctx;
            int pi;
            for (pi = 0; pi < np; pi++) {
                snames[pi] = probes[pi].name;
                surls[pi] = probes[pi].url;
                sgeo[pi] = probes[pi].geo;
                scrit[pi] = probes[pi].critical;
            }
            sctx.outs = souts; sctx.mbps = smbps; sctx.names = snames;
            sctx.urls = surls; sctx.geo = sgeo; sctx.critical = scrit;
            run_parallel(np, opt_jobs, speed_job, &sctx, "скорость");
            for (pi = 0; pi < np; pi++) {
                add_check_from(&souts[pi]);
                if (probes[pi].out_mbps && smbps[pi] >= 0)
                    *probes[pi].out_mbps = smbps[pi];
            }
        }
        free(souts); free(smbps); free(snames); free(surls); free(sgeo); free(scrit);

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
            {"AdGuard DNS", "94.140.14.14"},
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

    flush_cdn_findings();
    enrich_fail_netdiag();
    write_html();
    engine_logf("Отчёт: %s", report_path);
    engine_logf("Итого: OK=%d WARN=%d FAIL=%d", ok_n, warn_n, fail_n);
    if (g_engine_cb && g_engine_cb->on_done)
        g_engine_cb->on_done(g_engine_cb->userdata, report_path, ok_n, warn_n, fail_n);

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


int cc_engine_stages(const CcOpts *opts, char titles[][CC_STAGE_TITLE_LEN],
                     int *skipped, int max) {
    static const char *const all[] = {
        "Сеть и Wi‑Fi",
        "Captive / OS",
        "NTP",
        "Умный дом / IoT",
        "DPI",
        "CDN / счётчики",
        "Значимые ресурсы (Белые списки МЦ)",
        "Зарубежные ресурсы",
        "Банки и сервисы РФ",
        "Почта",
        "Видео",
        "Игры",
        "Облако",
        "Репозитории / обновления",
        "Гео / IX",
        "AI / LLM",
        "Скорость",
        "DNS-прогон",
    };
    int nall = (int)(sizeof all / sizeof all[0]);
    int skip_video = opts && opts->skip_video;
    int skip_speed = opts && opts->skip_speed;
    int skip_dns = opts && opts->skip_dns_bulk && !opts->force_dns_bulk;
    int i, n = 0;

    if (!titles || max <= 0) return 0;
    for (i = 0; i < nall && n < max; i++) {
        int sk = 0;
        if (strcmp(all[i], "Видео") == 0) sk = skip_video;
        else if (strcmp(all[i], "Скорость") == 0) sk = skip_speed;
        else if (strcmp(all[i], "DNS-прогон") == 0) sk = skip_dns;
        snprintf(titles[n], CC_STAGE_TITLE_LEN, "%s", all[i]);
        if (skipped) skipped[n] = sk ? 1 : 0;
        n++;
    }
    return n;
}

int cc_engine_run(const CcOpts *opts, const CcCallbacks *cb) {
    g_engine_cb = cb;
    g_engine_lib_mode = 1;
    g_engine_cancel = 0;

    nchecks = 0;
    nfindings = 0;
    ok_n = warn_n = fail_n = 0;
    g_cdn_nhosts = 0;
    g_cdn_nfail_sites = 0;
    g_cdn_nwarn_sites = 0;
    g_cdn_canary_fail = 0;
    g_sys_dns_broken = 0;
    report_path[0] = 0;
    nchecks = 0;

    no_open = 1;
    opt_yes = 1;
    opt_skip_dns_bulk = 1;
    opt_force_dns_bulk = 0;
    opt_skip_speed = 0;
    opt_skip_video = 0;
    opt_jobs = DEFAULT_JOBS;
    opt_dns_limit = 1000;
    domains_path[0] = 0;
    resources_path[0] = 0;
    output_dir[0] = 0;
    exe_dir[0] = 0;

    if (opts) {
        if (opts->yes) opt_yes = 1;
        opt_skip_dns_bulk = opts->skip_dns_bulk ? 1 : 0;
        opt_force_dns_bulk = opts->force_dns_bulk ? 1 : 0;
        opt_skip_video = opts->skip_video ? 1 : 0;
        opt_skip_speed = opts->skip_speed ? 1 : 0;
        no_open = opts->no_open ? 1 : 0;
        if (opts->jobs >= 1 && opts->jobs <= 256) opt_jobs = opts->jobs;
        if (opts->outdir[0])
            snprintf(output_dir, sizeof output_dir, "%s", opts->outdir);
        if (opts->resources[0])
            snprintf(resources_path, sizeof resources_path, "%s", opts->resources);
        if (opts->workdir[0]) {
            snprintf(exe_dir, sizeof exe_dir, "%s", opts->workdir);
#ifdef _WIN32
            SetCurrentDirectoryA(opts->workdir);
#else
            chdir(opts->workdir);
#endif
        }
    }
    opt_yes = 1; /* library: always non-interactive */

#ifdef _WIN32
    {
        WSADATA wsa;
        static int wsa_once;
        if (!wsa_once) {
            if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return -1;
            wsa_once = 1;
        }
    }
#endif

    if (!exe_dir[0]) {
#ifdef _WIN32
        char exe[MAX_PATH];
        char *slash;
        GetModuleFileNameA(NULL, exe, MAX_PATH);
        slash = strrchr(exe, '\\');
        if (slash) *slash = 0;
        snprintf(exe_dir, sizeof exe_dir, "%s", exe);
#else
        if (!getcwd(exe_dir, sizeof exe_dir))
            snprintf(exe_dir, sizeof exe_dir, ".");
#endif
    }
    if (!output_dir[0]) {
#ifdef _WIN32
        snprintf(output_dir, sizeof output_dir, "%s\\reports", exe_dir);
#else
        snprintf(output_dir, sizeof output_dir, "%s/reports", exe_dir);
#endif
    } else {
        /* Относительный -o → абсолютный от workdir/exe_dir */
        int abs = 0;
#ifdef _WIN32
        abs = (output_dir[0] == '\\' || output_dir[0] == '/' ||
               (output_dir[0] && output_dir[1] == ':'));
#else
        abs = (output_dir[0] == '/');
#endif
        if (!abs && exe_dir[0]) {
            char joined[STR];
#ifdef _WIN32
            snprintf(joined, sizeof joined, "%s\\%s", exe_dir, output_dir);
#else
            snprintf(joined, sizeof joined, "%s/%s", exe_dir, output_dir);
#endif
            snprintf(output_dir, sizeof output_dir, "%s", joined);
        }
    }

    /* stamp/report_path set inside diagnose_core after resources_init — need them before.
       diagnose_core currently starts at resources_init and sets stamp — OK. */

    /* Pre-create paths that diagnose_core expects already set: stamp/report set IN core after resources_init.
       Looking at core - stamp set AFTER resources_init. Good. But exe_dir/output_dir must be set - done. */

    {
        const char *ej = getenv("CONNECT_CHECK_JOBS");
        if (ej && ej[0] && !(opts && opts->jobs >= 1)) {
            int j = atoi(ej);
            if (j >= 1 && j <= 256) opt_jobs = j;
        }
    }

    return diagnose_core();
}



#ifndef CC_ENGINE_LIBRARY
int main(int argc, char **argv) {
    int i;
    int opt_check_update = 0, opt_self_update = 0;

    setvbuf(stdout, NULL, _IONBF, 0);

    {
        const char *ej = getenv("CONNECT_CHECK_JOBS");
        if (ej && ej[0]) {
            int j = atoi(ej);
            if (j >= 1 && j <= 256) opt_jobs = j;
        }
    }

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
        else if (strcmp(argv[i], "--check-update") == 0) opt_check_update = 1;
        else if (strcmp(argv[i], "--self-update") == 0) opt_self_update = 1;
        else if (strcmp(argv[i], "-y") == 0 || strcmp(argv[i], "--yes") == 0) opt_yes = 1;
        else if (strcmp(argv[i], "--dns-bulk") == 0) opt_force_dns_bulk = 1;
        else if (strcmp(argv[i], "--skip-dns-bulk") == 0) opt_skip_dns_bulk = 1;
        else if (strcmp(argv[i], "--skip-speed") == 0) opt_skip_speed = 1;
        else if (strcmp(argv[i], "--skip-video") == 0) opt_skip_video = 1;
        else if ((strcmp(argv[i], "--jobs") == 0) && i + 1 < argc) {
            opt_jobs = atoi(argv[++i]);
            if (opt_jobs < 1) opt_jobs = 1;
            if (opt_jobs > 256) opt_jobs = 256;
        } else if ((strcmp(argv[i], "--dns-limit") == 0) && i + 1 < argc) {
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

    if (opt_check_update || opt_self_update) {
        UpdateInfo ui;
        char err[256];
        char root[STR];
        char relaunch[STR];
        if (update_check(&ui, err, sizeof err) != 0) {
            fprintf(stderr, "check-update: %s\n", err);
            return 1;
        }
        printf("Локально: %s\n", CONNECT_CHECK_VERSION);
        printf("GitHub latest: %s (%s)\n", ui.tag, ui.html_url);
        if (ui.asset_name[0])
            printf("Ассет: %s\n", ui.asset_name);
        if (!update_semver_gt(ui.version, CONNECT_CHECK_VERSION)) {
            printf("Уже актуальная версия.\n");
            return 0;
        }
        printf("Доступно обновление: %s → %s\n", CONNECT_CHECK_VERSION, ui.version);
        if (opt_check_update && !opt_self_update)
            return 2;
        /* --self-update */
        update_detect_install_root(argv[0], root, sizeof root);
        printf("Корень установки: %s\n", root);
#ifdef _WIN32
        if (!GetModuleFileNameA(NULL, relaunch, (DWORD)sizeof relaunch))
            snprintf(relaunch, sizeof relaunch, "%s", argv[0]);
#else
        {
            char real[STR];
            if (realpath(argv[0], real))
                snprintf(relaunch, sizeof relaunch, "%s", real);
            else
                snprintf(relaunch, sizeof relaunch, "%s", argv[0]);
        }
#endif
        {
            char *rargv[2];
            rargv[0] = relaunch;
            rargv[1] = NULL;
            printf("Скачиваю и применяю обновление...\n");
            if (update_apply(&ui, root, relaunch, rargv, err, sizeof err) != 0) {
                fprintf(stderr, "self-update: %s\n", err);
                return 1;
            }
        }
        return 0; /* helper exits parent */
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


    g_engine_cb = NULL;
    g_engine_lib_mode = 0;
    g_engine_cancel = 0;
    nchecks = 0;
    nfindings = 0;
    ok_n = warn_n = fail_n = 0;
    g_cdn_nhosts = 0;
    g_cdn_nfail_sites = 0;
    g_cdn_nwarn_sites = 0;
    g_cdn_canary_fail = 0;
    return diagnose_core();
}

#endif /* CC_ENGINE_LIBRARY */


/*
 * connect-check-gui.c — GUI с in-process движком (без spawn CLI/probe-*).
 *   Windows: Nuklear + GDI+
 *   macOS/Linux: Nuklear + GLFW/OpenGL2
 *
 *   make -f Makefile.gui
 */

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <stdint.h>

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#  include <process.h>
#  include <shellapi.h>
#  include <direct.h>
#  define getcwd _getcwd
#else
#  include <unistd.h>
#  include <pthread.h>
#  include <signal.h>
#  include <limits.h>
#  ifdef __APPLE__
#    include <mach-o/dyld.h>
#  endif
#  define GL_SILENCE_DEPRECATION
#  include <GLFW/glfw3.h>
#endif

#define NK_INCLUDE_FIXED_TYPES
#define NK_INCLUDE_STANDARD_IO
#define NK_INCLUDE_STANDARD_VARARGS
#define NK_INCLUDE_DEFAULT_ALLOCATOR
#ifdef _WIN32
#  define NK_IMPLEMENTATION
#  define NK_GDIP_IMPLEMENTATION
#  include "nuklear.h"
#  include "nuklear_gdip.h"
#else
#  define NK_INCLUDE_VERTEX_BUFFER_OUTPUT
#  define NK_INCLUDE_FONT_BAKING
#  define NK_INCLUDE_DEFAULT_FONT
#  define NK_IMPLEMENTATION
#  define NK_GLFW_GL2_IMPLEMENTATION
#  include "nuklear.h"
#  include "nuklear_glfw_gl2.h"
#endif
#include "version.h"
#include "selfupdate.h"
#include "cc_engine.h"

#define LOG_LINE    768
#define PATH_MAX_G  1024
#define MAX_LOG     400
#define MAX_EVQ     512
#define MAX_STAGES  40
#define MAX_PROBE_W 6
#define STAGE_PANEL_H_DEFAULT 168
#define STAGE_PANEL_H_MIN     90
#define LOG_H_FLOOR           220
#define LOG_H_FLOOR_MIN       180

typedef struct {
    char lines[MAX_LOG][LOG_LINE];
    int n;
    int scroll_bottom;
} LogBuf;

typedef enum {
    ST_PENDING = 0,
    ST_RUNNING,
    ST_DONE,
    ST_SKIPPED
} StageState;

typedef struct {
    char title[CC_STAGE_TITLE_LEN];
    StageState state;
} StageItem;

typedef enum {
    EV_LOG = 0,
    EV_PROGRESS,
    EV_STAGE,
    EV_CHECK,
    EV_FINDING,
    EV_DONE,
    EV_STATUS
} EvKind;

typedef struct {
    EvKind kind;
    char a[160];
    char b[256];
    char c[512];
    int i1, i2, i3;
} Ev;

static char g_workdir[PATH_MAX_G];
static char g_resources[PATH_MAX_G];
static LogBuf g_log;
static int g_log_prog_idx = -1;
static char g_status[128] = "Готово";

static int opt_yes = 1, opt_skip_dns = 1, opt_skip_video, opt_dns_bulk;
static int opt_skip_speed, opt_no_open;
static char opt_outdir[256] = "reports";

static int probe_on[5] = {1, 0, 0, 0, 0};
static const char *probe_labels[] = {
    "Captive / DNS / DoT / DoH", "QUIC / UDP 443", "Battle.net", "MQTT / MQTTS", "Видео РФ"
};
static const CcProbeKind probe_kinds[] = {
    CC_PROBE_CAPTIVE, CC_PROBE_QUIC, CC_PROBE_BATTLENET, CC_PROBE_MQTT, CC_PROBE_VIDEO
};
static int probe_interval = 120, probe_rounds;

static char url_buf[512] = "https://ya.ru/";
static int url_interval = 5, url_rounds, url_follow;

static int g_tab; /* 0 diagnose, 1 probes, 2 url */

static int g_update_ready;
static UpdateInfo g_update;
static char g_update_err[256];
static char g_update_banner[192];

/* engine UI state */
static StageItem g_stages[MAX_STAGES];
static int g_stage_n;
static int g_ui_ok, g_ui_warn, g_ui_fail;
static char g_report_path[PATH_MAX_G];
static volatile int g_diag_busy;
static volatile int g_probe_busy[MAX_PROBE_W];
static volatile int g_probe_cancel[MAX_PROBE_W];
static int g_stage_panel_h = STAGE_PANEL_H_DEFAULT;

static Ev g_evq[MAX_EVQ];
static int g_ev_head, g_ev_tail, g_ev_count;
#ifdef _WIN32
static CRITICAL_SECTION g_ev_lock;
static int g_ev_lock_ok;
#else
static pthread_mutex_t g_ev_lock = PTHREAD_MUTEX_INITIALIZER;
#endif

/* ---------- utils ---------- */

static void utf8_trim(char *s) {
    size_t n, i;
    if (!s || !*s) return;
    n = strlen(s);
    while (n > 0) {
        unsigned char c = (unsigned char)s[n - 1];
        if ((c & 0x80) == 0) break;
        if ((c & 0xC0) == 0xC0) {
            s[--n] = 0;
            break;
        }
        i = n;
        while (i > 0 && ((unsigned char)s[i - 1] & 0xC0) == 0x80) i--;
        if (i == 0) { s[0] = 0; return; }
        {
            unsigned char lead = (unsigned char)s[i - 1];
            int need = (lead & 0xE0) == 0xC0 ? 2
                     : (lead & 0xF0) == 0xE0 ? 3
                     : (lead & 0xF8) == 0xF0 ? 4 : 0;
            if (need && (int)(n - (i - 1)) == need) break;
            s[i - 1] = 0;
            n = i - 1;
        }
    }
}

static void sanitize_log_text(char *s) {
    char *r, *w;
    int esc = 0;
    if (!s) return;
    for (r = w = s; *r; r++) {
        unsigned char c = (unsigned char)*r;
        if (esc == 1) {
            if (c == '[') { esc = 2; continue; }
            esc = 0;
            continue;
        }
        if (esc == 2) {
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'))
                esc = 0;
            continue;
        }
        if (c == 0x1B) { esc = 1; continue; }
        if (c == '\t') { *w++ = ' '; continue; }
        if (c < 0x20 && c != 0x09) continue;
        *w++ = (char)c;
    }
    *w = 0;
    r = s;
    while (*r == ' ') r++;
    if (r != s) memmove(s, r, strlen(r) + 1);
    w = s + strlen(s);
    while (w > s && w[-1] == ' ') *--w = 0;
    utf8_trim(s);
}

static void log_format_line(char *out, size_t n, const char *prefix, const char *msg) {
    time_t t = time(NULL);
    struct tm tm;
    char ts[16];
#ifdef _WIN32
    localtime_s(&tm, &t);
#else
    localtime_r(&t, &tm);
#endif
    strftime(ts, sizeof ts, "%H:%M:%S", &tm);
    if (prefix && prefix[0])
        snprintf(out, n, "%s [%s] %s", ts, prefix, msg ? msg : "");
    else
        snprintf(out, n, "%s %s", ts, msg ? msg : "");
    utf8_trim(out);
}

static void log_add(const char *prefix, const char *msg) {
    char line[LOG_LINE];
    g_log_prog_idx = -1;
    log_format_line(line, sizeof line, prefix, msg);
    if (g_log.n < MAX_LOG) {
        snprintf(g_log.lines[g_log.n++], LOG_LINE, "%s", line);
    } else {
        memmove(g_log.lines[0], g_log.lines[1], (MAX_LOG - 1) * LOG_LINE);
        snprintf(g_log.lines[MAX_LOG - 1], LOG_LINE, "%s", line);
    }
    g_log.scroll_bottom = 1;
}

static void log_progress(const char *prefix, const char *msg) {
    char line[LOG_LINE];
    if (!msg || !msg[0]) {
        if (g_log_prog_idx >= 0 && g_log_prog_idx == g_log.n - 1 && g_log.n > 0) {
            g_log.n--;
            g_log_prog_idx = -1;
            g_log.scroll_bottom = 1;
        }
        return;
    }
    log_format_line(line, sizeof line, prefix, msg);
    if (g_log_prog_idx >= 0 && g_log_prog_idx < g_log.n) {
        snprintf(g_log.lines[g_log_prog_idx], LOG_LINE, "%s", line);
    } else if (g_log.n < MAX_LOG) {
        g_log_prog_idx = g_log.n;
        snprintf(g_log.lines[g_log.n++], LOG_LINE, "%s", line);
    } else {
        memmove(g_log.lines[0], g_log.lines[1], (MAX_LOG - 1) * LOG_LINE);
        g_log_prog_idx = MAX_LOG - 1;
        snprintf(g_log.lines[MAX_LOG - 1], LOG_LINE, "%s", line);
    }
    g_log.scroll_bottom = 1;
}

static void path_join(char *out, size_t n, const char *a, const char *b) {
#ifdef _WIN32
    snprintf(out, n, "%s\\%s", a, b);
#else
    snprintf(out, n, "%s/%s", a, b);
#endif
}

static int file_exists(const char *p) {
#ifdef _WIN32
    DWORD a = GetFileAttributesA(p);
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
#else
    return access(p, R_OK) == 0;
#endif
}

static int path_is_dir(const char *p) {
#ifdef _WIN32
    DWORD a = GetFileAttributesA(p);
    return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY);
#else
    return access(p, R_OK) == 0; /* enough for .app bundle check via exists path */
#endif
}

/* ---------- paths ---------- */

static int gui_exe_dir(char *out, size_t n) {
#ifdef _WIN32
    DWORD len = GetModuleFileNameA(NULL, out, (DWORD)n);
    char *slash;
    if (!len || len >= n) return 0;
    slash = strrchr(out, '\\');
    if (!slash) return 0;
    *slash = 0;
    return 1;
#else
    char buf[PATH_MAX_G] = "", real[PATH_MAX_G];
    char *slash;
#  ifdef __APPLE__
    uint32_t sz = sizeof buf;
    if (_NSGetExecutablePath(buf, &sz) != 0) return 0;
#  else
    {
        ssize_t r = readlink("/proc/self/exe", buf, sizeof buf - 1);
        if (r <= 0) return 0;
        buf[r] = 0;
    }
#  endif
    if (realpath(buf, real))
        snprintf(buf, sizeof buf, "%s", real);
    slash = strrchr(buf, '/');
    if (!slash) return 0;
    *slash = 0;
    snprintf(out, n, "%s", buf);
    return 1;
#endif
}

static int package_root_from_gui(char *out, size_t n) {
    char exedir[PATH_MAX_G], up[PATH_MAX_G], real[PATH_MAX_G];
    if (!gui_exe_dir(exedir, sizeof exedir)) return 0;

#ifdef __APPLE__
    {
        size_t len = strlen(exedir);
        if (len > 15 && strcmp(exedir + len - 15, "/Contents/MacOS") == 0) {
            snprintf(up, sizeof up, "%s/../../..", exedir);
            if (realpath(up, real)) {
                snprintf(out, n, "%s", real);
                return 1;
            }
        }
    }
#endif
    snprintf(out, n, "%s", exedir);
    return 1;
}

static void resolve_resources(void) {
    char try[PATH_MAX_G], exedir[PATH_MAX_G], real[PATH_MAX_G];
    g_resources[0] = 0;
#ifdef __APPLE__
    /* Правильное место данных в .app — Contents/Resources (не MacOS/: ломает codesign). */
    if (gui_exe_dir(exedir, sizeof exedir)) {
        size_t len = strlen(exedir);
        if (len > 15 && strcmp(exedir + len - 15, "/Contents/MacOS") == 0) {
            snprintf(try, sizeof try, "%.*s/Contents/Resources/resources.conf",
                     (int)(len - 15), exedir);
            if (realpath(try, real))
                snprintf(try, sizeof try, "%s", real);
            if (file_exists(try)) {
                snprintf(g_resources, sizeof g_resources, "%s", try);
                return;
            }
        }
    }
#endif
    if (g_workdir[0]) {
        path_join(try, sizeof try, g_workdir, "resources.conf");
        if (file_exists(try)) {
            snprintf(g_resources, sizeof g_resources, "%s", try);
            return;
        }
    }
    if (gui_exe_dir(exedir, sizeof exedir)) {
        path_join(try, sizeof try, exedir, "resources.conf");
        if (file_exists(try)) {
            snprintf(g_resources, sizeof g_resources, "%s", try);
            return;
        }
    }
}

static int resolve_pkg(void) {
    g_workdir[0] = 0;
    g_resources[0] = 0;
    if (!package_root_from_gui(g_workdir, sizeof g_workdir))
        return 0;
    resolve_resources();
    return 1;
}

/* Только системные TTF (кириллица). Бандл DejaVu в пакет не кладём. */
static int find_font(char *out, size_t n) {
    size_t i;
#ifdef _WIN32
    char windir[PATH_MAX_G];
    char sysfonts[8][PATH_MAX_G];
    const char *paths[9];
    DWORD wlen = GetEnvironmentVariableA("WINDIR", windir, (DWORD)sizeof windir);
    if (!wlen || wlen >= sizeof windir)
        snprintf(windir, sizeof windir, "C:\\Windows");
    snprintf(sysfonts[0], sizeof sysfonts[0], "%s\\Fonts\\segoeui.ttf", windir);
    snprintf(sysfonts[1], sizeof sysfonts[1], "%s\\Fonts\\arial.ttf", windir);
    snprintf(sysfonts[2], sizeof sysfonts[2], "%s\\Fonts\\tahoma.ttf", windir);
    snprintf(sysfonts[3], sizeof sysfonts[3], "%s\\Fonts\\consola.ttf", windir);
    snprintf(sysfonts[4], sizeof sysfonts[4], "%s\\Fonts\\cour.ttf", windir);
    snprintf(sysfonts[5], sizeof sysfonts[5], "%s\\Fonts\\CascadiaMono.ttf", windir);
    snprintf(sysfonts[6], sizeof sysfonts[6], "%s\\Fonts\\cascadiamono.ttf", windir);
    snprintf(sysfonts[7], sizeof sysfonts[7], "%s\\Fonts\\lucon.ttf", windir);
    for (i = 0; i < 8; i++) paths[i] = sysfonts[i];
    paths[8] = NULL;
#elif defined(__APPLE__)
    const char *paths[] = {
        "/System/Library/Fonts/Supplemental/Arial Unicode.ttf",
        "/Library/Fonts/Arial Unicode.ttf",
        "/System/Library/Fonts/Supplemental/Arial.ttf",
        "/Library/Fonts/Arial.ttf",
        "/System/Library/Fonts/Supplemental/Helvetica.ttf",
        "/System/Library/Fonts/Supplemental/Verdana.ttf",
        "/System/Library/Fonts/Supplemental/Courier New.ttf",
        "/Library/Fonts/Courier New.ttf",
        "/System/Library/Fonts/Supplemental/Andale Mono.ttf",
        NULL
    };
#else
    const char *paths[] = {
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/TTF/DejaVuSans.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
        "/usr/share/fonts/truetype/noto/NotoSans-Regular.ttf",
        "/usr/share/fonts/opentype/noto/NotoSans-Regular.ttf",
        "/usr/share/fonts/truetype/freefont/FreeSans.ttf",
        "/usr/share/fonts/truetype/ubuntu/Ubuntu-R.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf",
        NULL
    };
#endif
    for (i = 0; paths[i]; i++) {
        if (file_exists(paths[i])) {
            snprintf(out, n, "%s", paths[i]);
            return 1;
        }
    }
    out[0] = 0;
    return 0;
}

/* ---------- event queue (worker → UI) ---------- */

static void ev_lock(void) {
#ifdef _WIN32
    if (g_ev_lock_ok) EnterCriticalSection(&g_ev_lock);
#else
    pthread_mutex_lock(&g_ev_lock);
#endif
}

static void ev_unlock(void) {
#ifdef _WIN32
    if (g_ev_lock_ok) LeaveCriticalSection(&g_ev_lock);
#else
    pthread_mutex_unlock(&g_ev_lock);
#endif
}

static void ev_push(const Ev *e) {
    ev_lock();
    if (g_ev_count >= MAX_EVQ) {
        /* drop oldest */
        g_ev_head = (g_ev_head + 1) % MAX_EVQ;
        g_ev_count--;
    }
    g_evq[g_ev_tail] = *e;
    g_ev_tail = (g_ev_tail + 1) % MAX_EVQ;
    g_ev_count++;
    ev_unlock();
}

static int ev_pop(Ev *out) {
    int ok = 0;
    ev_lock();
    if (g_ev_count > 0) {
        *out = g_evq[g_ev_head];
        g_ev_head = (g_ev_head + 1) % MAX_EVQ;
        g_ev_count--;
        ok = 1;
    }
    ev_unlock();
    return ok;
}

static void ev_log(const char *prefix, const char *msg) {
    Ev e;
    memset(&e, 0, sizeof e);
    e.kind = EV_LOG;
    snprintf(e.a, sizeof e.a, "%s", prefix ? prefix : "");
    snprintf(e.b, sizeof e.b, "%s", msg ? msg : "");
    ev_push(&e);
}

static void ev_status(const char *msg) {
    Ev e;
    memset(&e, 0, sizeof e);
    e.kind = EV_STATUS;
    snprintf(e.a, sizeof e.a, "%s", msg ? msg : "");
    ev_push(&e);
}

/* ---------- engine callbacks ---------- */

static void cb_on_log(void *ud, const char *line) {
    char buf[LOG_LINE];
    (void)ud;
    snprintf(buf, sizeof buf, "%s", line ? line : "");
    sanitize_log_text(buf);
    if (buf[0]) ev_log("engine", buf);
}

static void cb_on_progress(void *ud, const char *msg, int cur, int total) {
    Ev e;
    (void)ud;
    memset(&e, 0, sizeof e);
    e.kind = EV_PROGRESS;
    if (msg && msg[0]) {
        if (total > 0)
            snprintf(e.a, sizeof e.a, "%s (%d/%d)", msg, cur, total);
        else
            snprintf(e.a, sizeof e.a, "%s", msg);
    }
    e.i1 = cur;
    e.i2 = total;
    ev_push(&e);
}

static void cb_on_stage(void *ud, const char *title, const char *desc) {
    Ev e;
    (void)ud;
    memset(&e, 0, sizeof e);
    e.kind = EV_STAGE;
    snprintf(e.a, sizeof e.a, "%s", title ? title : "");
    snprintf(e.b, sizeof e.b, "%s", desc ? desc : "");
    ev_push(&e);
}

static void cb_on_check(void *ud, const char *cat, const char *name,
                        const char *status, const char *detail) {
    Ev e;
    (void)ud;
    memset(&e, 0, sizeof e);
    e.kind = EV_CHECK;
    snprintf(e.a, sizeof e.a, "%s", cat ? cat : "");
    snprintf(e.b, sizeof e.b, "%s", name ? name : "");
    snprintf(e.c, sizeof e.c, "%s%s%s",
             status ? status : "",
             (detail && detail[0]) ? " — " : "",
             detail ? detail : "");
    if (status && (strcmp(status, "fail") == 0 || strcmp(status, "FAIL") == 0))
        e.i1 = 2;
    else if (status && (strcmp(status, "warn") == 0 || strcmp(status, "WARN") == 0 ||
                        strcmp(status, "attention") == 0))
        e.i1 = 1;
    else
        e.i1 = 0;
    ev_push(&e);
}

static void cb_on_finding(void *ud, const char *level, const char *title, const char *text) {
    Ev e;
    (void)ud;
    memset(&e, 0, sizeof e);
    e.kind = EV_FINDING;
    snprintf(e.a, sizeof e.a, "%s", level ? level : "");
    snprintf(e.b, sizeof e.b, "%s", title ? title : "");
    snprintf(e.c, sizeof e.c, "%s", text ? text : "");
    ev_push(&e);
}

static void cb_on_done(void *ud, const char *report_path, int ok_n, int warn_n, int fail_n) {
    Ev e;
    (void)ud;
    memset(&e, 0, sizeof e);
    e.kind = EV_DONE;
    snprintf(e.a, sizeof e.a, "%s", report_path ? report_path : "");
    e.i1 = ok_n;
    e.i2 = warn_n;
    e.i3 = fail_n;
    ev_push(&e);
}

static void stages_rebuild_plan(void) {
    CcOpts opts;
    char titles[MAX_STAGES][CC_STAGE_TITLE_LEN];
    int skipped[MAX_STAGES];
    int n, i;
    memset(&opts, 0, sizeof opts);
    opts.skip_dns_bulk = opt_skip_dns && !opt_dns_bulk;
    opts.force_dns_bulk = opt_dns_bulk;
    opts.skip_video = opt_skip_video;
    opts.skip_speed = opt_skip_speed;
    n = cc_engine_stages(&opts, titles, skipped, MAX_STAGES);
    g_stage_n = 0;
    for (i = 0; i < n; i++) {
        snprintf(g_stages[i].title, sizeof g_stages[i].title, "%s", titles[i]);
        g_stages[i].state = skipped[i] ? ST_SKIPPED : ST_PENDING;
        g_stage_n++;
    }
}

static void stages_on_begin(const char *title) {
    int i, found = -1;
    if (!title || !title[0]) return;
    for (i = 0; i < g_stage_n; i++) {
        if (g_stages[i].state == ST_RUNNING)
            g_stages[i].state = ST_DONE;
        if (found < 0 && strcmp(g_stages[i].title, title) == 0)
            found = i;
    }
    if (found >= 0) {
        g_stages[found].state = ST_RUNNING;
        return;
    }
    if (g_stage_n < MAX_STAGES) {
        snprintf(g_stages[g_stage_n].title, sizeof g_stages[0].title, "%s", title);
        g_stages[g_stage_n].state = ST_RUNNING;
        g_stage_n++;
    }
}

static void stages_on_done(void) {
    int i;
    for (i = 0; i < g_stage_n; i++) {
        if (g_stages[i].state == ST_RUNNING)
            g_stages[i].state = ST_DONE;
        else if (g_stages[i].state == ST_PENDING)
            g_stages[i].state = ST_SKIPPED;
    }
}

static void drain_events(void) {
    Ev e;
    while (ev_pop(&e)) {
        switch (e.kind) {
        case EV_LOG:
            log_add(e.a, e.b);
            break;
        case EV_PROGRESS:
            if (e.a[0])
                log_progress("engine", e.a);
            else
                log_progress("engine", "");
            break;
        case EV_STAGE:
            stages_on_begin(e.a);
            {
                char msg[LOG_LINE];
                if (e.b[0])
                    snprintf(msg, sizeof msg, "▶ %s — %s", e.a, e.b);
                else
                    snprintf(msg, sizeof msg, "▶ %s", e.a);
                log_add("stage", msg);
            }
            snprintf(g_status, sizeof g_status, "Этап: %s", e.a[0] ? e.a : "…");
            break;
        case EV_CHECK:
            if (e.i1 == 2) {
                g_ui_fail++;
                {
                    char msg[LOG_LINE];
                    snprintf(msg, sizeof msg, "FAIL %s / %s — %s", e.a, e.b, e.c);
                    log_add("check", msg);
                }
            } else if (e.i1 == 1) {
                g_ui_warn++;
            } else {
                g_ui_ok++;
            }
            break;
        case EV_FINDING:
            {
                char msg[LOG_LINE];
                snprintf(msg, sizeof msg, "[%s] %s: %s", e.a, e.b, e.c);
                log_add("finding", msg);
            }
            break;
        case EV_DONE:
            snprintf(g_report_path, sizeof g_report_path, "%s", e.a);
            g_ui_ok = e.i1;
            g_ui_warn = e.i2;
            g_ui_fail = e.i3;
            stages_on_done();
            {
                char msg[LOG_LINE];
                snprintf(msg, sizeof msg, "готово: ok=%d warn=%d fail=%d", e.i1, e.i2, e.i3);
                log_add("engine", msg);
                if (e.a[0]) log_add("report", e.a);
            }
            snprintf(g_status, sizeof g_status, "Готово — сбоев: %d", e.i3);
            break;
        case EV_STATUS:
            snprintf(g_status, sizeof g_status, "%s", e.a);
            break;
        }
    }
}

static int any_busy(void) {
    int i;
    if (g_diag_busy) return 1;
    for (i = 0; i < MAX_PROBE_W; i++)
        if (g_probe_busy[i]) return 1;
    return 0;
}

/* ---------- workers ---------- */

#ifdef _WIN32
static unsigned __stdcall diag_thread(void *arg) {
#else
static void *diag_thread(void *arg) {
#endif
    CcOpts *opts = (CcOpts *)arg;
    CcCallbacks cb;
    int rc;
    memset(&cb, 0, sizeof cb);
    cb.on_log = cb_on_log;
    cb.on_progress = cb_on_progress;
    cb.on_stage = cb_on_stage;
    cb.on_check = cb_on_check;
    cb.on_finding = cb_on_finding;
    cb.on_done = cb_on_done;
    rc = cc_engine_run(opts, &cb);
    {
        char msg[64];
        snprintf(msg, sizeof msg, "диагностика завершена (код %d)", rc);
        ev_log("engine", msg);
    }
    g_diag_busy = 0;
    ev_status("Готово");
    free(opts);
#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

typedef struct {
    CcProbeKind kind;
    CcProbeOpts opts;
    int slot;
    char prefix[48];
} ProbeJob;

static void probe_log_line(void *ud, const char *line) {
    ProbeJob *job = (ProbeJob *)ud;
    char buf[LOG_LINE];
    snprintf(buf, sizeof buf, "%s", line ? line : "");
    sanitize_log_text(buf);
    if (buf[0]) ev_log(job->prefix, buf);
}

#ifdef _WIN32
static unsigned __stdcall probe_thread(void *arg) {
#else
static void *probe_thread(void *arg) {
#endif
    ProbeJob *job = (ProbeJob *)arg;
    int rc = cc_probe_run(job->kind, &job->opts, probe_log_line, job, &g_probe_cancel[job->slot]);
    {
        char msg[80];
        snprintf(msg, sizeof msg, "проба остановлена (код %d)", rc);
        ev_log(job->prefix, msg);
    }
    g_probe_busy[job->slot] = 0;
    free(job);
#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

static void run_diagnose(void) {
    CcOpts *opts;
    if (g_diag_busy) {
        log_add("engine", "диагностика уже идёт");
        return;
    }
    opts = (CcOpts *)calloc(1, sizeof *opts);
    if (!opts) return;
    opts->yes = opt_yes;
    opts->skip_dns_bulk = opt_skip_dns && !opt_dns_bulk;
    opts->force_dns_bulk = opt_dns_bulk;
    opts->skip_video = opt_skip_video;
    opts->skip_speed = opt_skip_speed;
    opts->no_open = opt_no_open;
    snprintf(opts->outdir, sizeof opts->outdir, "%s", opt_outdir);
    if (g_resources[0])
        snprintf(opts->resources, sizeof opts->resources, "%s", g_resources);
    if (g_workdir[0])
        snprintf(opts->workdir, sizeof opts->workdir, "%s", g_workdir);

    g_ui_ok = g_ui_warn = g_ui_fail = 0;
    g_report_path[0] = 0;
    stages_rebuild_plan();
    cc_engine_clear_cancel();
    g_diag_busy = 1;
    snprintf(g_status, sizeof g_status, "Диагностика…");
    log_add("engine", "старт диагностики (in-process)");
#ifdef _WIN32
    {
        /* 8 MiB — diagnose_core + resources parser на маленьком стеке падают SIGBUS */
        uintptr_t h = _beginthreadex(NULL, 8u * 1024u * 1024u, diag_thread, opts, 0, NULL);
        if (!h) {
            g_diag_busy = 0;
            free(opts);
            log_add("engine", "не удалось запустить поток");
        } else {
            CloseHandle((HANDLE)h);
        }
    }
#else
    {
        pthread_t th;
        pthread_attr_t attr;
        size_t stack = 8u * 1024u * 1024u;
        pthread_attr_init(&attr);
        pthread_attr_setstacksize(&attr, stack);
        if (pthread_create(&th, &attr, diag_thread, opts) != 0) {
            pthread_attr_destroy(&attr);
            g_diag_busy = 0;
            free(opts);
            log_add("engine", "не удалось запустить поток");
        } else {
            pthread_attr_destroy(&attr);
            pthread_detach(th);
        }
    }
#endif
}

static void stop_diagnose(void) {
    if (!g_diag_busy) return;
    cc_engine_request_cancel();
    log_add("engine", "запрошена остановка…");
}

static void run_probe_slot(int slot, CcProbeKind kind, const CcProbeOpts *popts, const char *prefix) {
    ProbeJob *job;
    if (slot < 0 || slot >= MAX_PROBE_W) return;
    if (g_probe_busy[slot]) {
        log_add(prefix, "уже запущена");
        return;
    }
    job = (ProbeJob *)calloc(1, sizeof *job);
    if (!job) return;
    job->kind = kind;
    job->opts = *popts;
    job->slot = slot;
    snprintf(job->prefix, sizeof job->prefix, "%s", prefix);
    g_probe_cancel[slot] = 0;
    g_probe_busy[slot] = 1;
    log_add(prefix, "старт (in-process)");
    snprintf(g_status, sizeof g_status, "Проба: %s", prefix);
#ifdef _WIN32
    {
        uintptr_t h = _beginthreadex(NULL, 0, probe_thread, job, 0, NULL);
        if (!h) {
            g_probe_busy[slot] = 0;
            free(job);
            log_add(prefix, "не удалось запустить поток");
        } else {
            CloseHandle((HANDLE)h);
        }
    }
#else
    {
        pthread_t th;
        if (pthread_create(&th, NULL, probe_thread, job) != 0) {
            g_probe_busy[slot] = 0;
            free(job);
            log_add(prefix, "не удалось запустить поток");
        } else {
            pthread_detach(th);
        }
    }
#endif
}

static void run_probes(void) {
    int i, started = 0;
    CcProbeOpts opts;
    memset(&opts, 0, sizeof opts);
    opts.interval_sec = probe_interval > 0 ? probe_interval : 1;
    opts.rounds = probe_rounds;
    for (i = 0; i < 5; i++) {
        if (!probe_on[i]) continue;
        run_probe_slot(i, probe_kinds[i], &opts, cc_probe_kind_name(probe_kinds[i]));
        started++;
    }
    if (!started) log_add("probes", "ничего не запущено — отметьте пробы");
}

static void run_url(void) {
    CcProbeOpts opts;
    if (!url_buf[0]) {
        log_add("url", "укажите URL");
        return;
    }
    memset(&opts, 0, sizeof opts);
    opts.interval_sec = url_interval > 0 ? url_interval : 1;
    opts.rounds = url_rounds;
    opts.follow = url_follow;
    snprintf(opts.url, sizeof opts.url, "%s", url_buf);
    run_probe_slot(5, CC_PROBE_URL, &opts, "url");
}

static void stop_probes(void) {
    int i;
    for (i = 0; i < MAX_PROBE_W; i++) {
        if (g_probe_busy[i])
            g_probe_cancel[i] = 1;
    }
    log_add("probes", "запрошена остановка…");
}

static void stop_all(void) {
    stop_diagnose();
    stop_probes();
}

static void open_path(const char *path) {
    if (!path || !path[0]) return;
#ifdef _WIN32
    ShellExecuteA(NULL, "open", path, NULL, NULL, SW_SHOWNORMAL);
#elif defined(__APPLE__)
    {
        char cmd[PATH_MAX_G + 32];
        snprintf(cmd, sizeof cmd, "open '%s'", path);
        system(cmd);
    }
#else
    {
        char cmd[PATH_MAX_G + 32];
        snprintf(cmd, sizeof cmd, "xdg-open '%s' >/dev/null 2>&1 &", path);
        system(cmd);
    }
#endif
}

/* ---------- self-update ---------- */

static void update_check_startup(void) {
    char err[256];
    g_update_ready = 0;
    g_update_err[0] = 0;
    g_update_banner[0] = 0;
    memset(&g_update, 0, sizeof g_update);
    if (update_check(&g_update, err, sizeof err) != 0) {
        snprintf(g_update_err, sizeof g_update_err, "%s", err);
        log_add("update", err);
        return;
    }
    if (update_semver_gt(g_update.version, CONNECT_CHECK_VERSION)) {
        g_update_ready = 1;
        snprintf(g_update_banner, sizeof g_update_banner,
                 "Доступна %s (сейчас %s)", g_update.tag, CONNECT_CHECK_VERSION);
        log_add("update", g_update_banner);
        if (g_update.html_url[0])
            log_add("update", g_update.html_url);
    } else {
        log_add("update", "версия актуальна");
    }
}

static void do_self_update(void) {
    char root[PATH_MAX_G], err[256];
    char relaunch[PATH_MAX_G];
    char *rargv[4];
    int n = 0;

    if (!g_update_ready) return;
    update_detect_install_root(g_workdir[0] ? g_workdir : NULL, root, sizeof root);
    log_add("update", root);
    snprintf(g_status, sizeof g_status, "Обновление до %s…", g_update.tag);

#if defined(__APPLE__)
    {
        char app[PATH_MAX_G];
        path_join(app, sizeof app, root, "ConnectCheck-mac.app");
        if (path_is_dir(app) || file_exists(app)) {
            snprintf(relaunch, sizeof relaunch, "/usr/bin/open");
            rargv[n++] = relaunch;
            rargv[n++] = app;
            rargv[n] = NULL;
        } else {
            uint32_t sz = sizeof relaunch;
            if (_NSGetExecutablePath(relaunch, &sz) != 0)
                snprintf(relaunch, sizeof relaunch, "%s", "connect-check-gui");
            rargv[n++] = relaunch;
            rargv[n] = NULL;
        }
    }
#elif defined(_WIN32)
    {
        char gui[PATH_MAX_G];
        path_join(gui, sizeof gui, root, "connect-check-gui-win.exe");
        if (GetFileAttributesA(gui) != INVALID_FILE_ATTRIBUTES)
            snprintf(relaunch, sizeof relaunch, "%s", gui);
        else if (!GetModuleFileNameA(NULL, relaunch, (DWORD)sizeof relaunch))
            snprintf(relaunch, sizeof relaunch, "connect-check-gui-win.exe");
        rargv[n++] = relaunch;
        rargv[n] = NULL;
    }
#else
    {
        char gui[PATH_MAX_G];
        path_join(gui, sizeof gui, root, "connect-check-gui-linux");
        if (access(gui, X_OK) == 0)
            snprintf(relaunch, sizeof relaunch, "%s", gui);
        else
            snprintf(relaunch, sizeof relaunch, "%s", "connect-check-gui-linux");
        rargv[n++] = relaunch;
        rargv[n] = NULL;
    }
#endif

    log_add("update", "скачивание и замена пакета…");
    if (update_apply(&g_update, root, relaunch, rargv, err, sizeof err) != 0) {
        log_add("update", err);
        snprintf(g_status, sizeof g_status, "Ошибка обновления");
        return;
    }
}

/* ---------- UI ---------- */

static void ui_tab_diagnose(struct nk_context *ctx) {
    int i;
    char sum[160];
    static int prev_skip_dns = -1, prev_skip_video = -1, prev_dns_bulk = -1, prev_skip_speed = -1;

    nk_layout_row_dynamic(ctx, 22, 1);
    nk_label(ctx, "Параметры диагностики", NK_TEXT_LEFT);
    nk_layout_row_dynamic(ctx, 24, 1);
    nk_checkbox_label(ctx, "Без вопросов", &opt_yes);
    nk_checkbox_label(ctx, "Пропустить DNS-прогон", &opt_skip_dns);
    nk_checkbox_label(ctx, "Пропустить видео", &opt_skip_video);
    nk_checkbox_label(ctx, "DNS-прогон (полный)", &opt_dns_bulk);
    nk_checkbox_label(ctx, "Пропустить скорость", &opt_skip_speed);
    nk_checkbox_label(ctx, "Не открывать HTML", &opt_no_open);
    nk_layout_row_begin(ctx, NK_STATIC, 28, 2);
    nk_layout_row_push(ctx, 140);
    nk_label(ctx, "Каталог отчётов:", NK_TEXT_LEFT);
    nk_layout_row_push(ctx, 280);
    nk_edit_string_zero_terminated(ctx, NK_EDIT_FIELD, opt_outdir, sizeof opt_outdir, nk_filter_default);
    nk_layout_row_end(ctx);

    if (!g_diag_busy &&
        (prev_skip_dns != opt_skip_dns || prev_skip_video != opt_skip_video ||
         prev_dns_bulk != opt_dns_bulk || prev_skip_speed != opt_skip_speed ||
         g_stage_n == 0)) {
        stages_rebuild_plan();
        prev_skip_dns = opt_skip_dns;
        prev_skip_video = opt_skip_video;
        prev_dns_bulk = opt_dns_bulk;
        prev_skip_speed = opt_skip_speed;
    }

    snprintf(sum, sizeof sum, "Сбои: %d   Внимание: %d   OK: %d", g_ui_fail, g_ui_warn, g_ui_ok);
    nk_layout_row_dynamic(ctx, 24, 1);
    nk_label_colored(ctx, sum, NK_TEXT_LEFT,
                     g_ui_fail > 0 ? nk_rgb(200, 90, 80) : nk_rgb(40, 140, 60));

    nk_layout_row_dynamic(ctx, (float)g_stage_panel_h, 1);
    if (nk_group_begin(ctx, "stages", NK_WINDOW_BORDER)) {
        nk_layout_row_dynamic(ctx, 18, 1);
        nk_label(ctx, "Этапы:", NK_TEXT_LEFT);
        for (i = 0; i < g_stage_n; i++) {
            char lab[140];
            const char *mark = "○";
            struct nk_color col = nk_rgb(120, 120, 130);
            if (g_stages[i].state == ST_RUNNING) {
                mark = "→";
                col = nk_rgb(80, 160, 220);
            } else if (g_stages[i].state == ST_DONE) {
                mark = "✓";
                col = nk_rgb(40, 140, 60);
            } else if (g_stages[i].state == ST_SKIPPED) {
                mark = "⏭";
                col = nk_rgb(150, 150, 155);
            }
            snprintf(lab, sizeof lab, "%s %s", mark, g_stages[i].title);
            nk_label_colored(ctx, lab, NK_TEXT_LEFT, col);
        }
        nk_group_end(ctx);
    }

    nk_layout_row_dynamic(ctx, 34, 3);
    if (nk_button_label(ctx, g_diag_busy ? "Идёт…" : "Запустить диагностику")) {
        if (!g_diag_busy) run_diagnose();
    }
    if (nk_button_label(ctx, "Остановить")) stop_diagnose();
    if (nk_button_label(ctx, "Открыть отчёт")) open_path(g_report_path);
}

static void ui_tab_probes(struct nk_context *ctx) {
    int i;
    nk_layout_row_dynamic(ctx, 22, 1);
    nk_label(ctx, "Циклические пробы (в процессе приложения)", NK_TEXT_LEFT);
    for (i = 0; i < 5; i++) {
        char lab[128];
        const char *st = g_probe_busy[i] ? " — идёт" : "";
        snprintf(lab, sizeof lab, "%s%s", probe_labels[i], st);
        nk_layout_row_dynamic(ctx, 24, 1);
        nk_checkbox_label(ctx, lab, &probe_on[i]);
    }
    nk_layout_row_begin(ctx, NK_STATIC, 28, 4);
    nk_layout_row_push(ctx, 100);
    nk_label(ctx, "Интервал:", NK_TEXT_LEFT);
    nk_layout_row_push(ctx, 80);
    nk_property_int(ctx, "#sec", 1, &probe_interval, 120, 1, 1);
    nk_layout_row_push(ctx, 100);
    nk_label(ctx, "Раунды 0=∞:", NK_TEXT_LEFT);
    nk_layout_row_push(ctx, 80);
    nk_property_int(ctx, "#n", 0, &probe_rounds, 99999, 1, 1);
    nk_layout_row_end(ctx);
    nk_layout_row_dynamic(ctx, 34, 2);
    if (nk_button_label(ctx, "Старт выбранных")) run_probes();
    if (nk_button_label(ctx, "Остановить пробы")) stop_probes();
}

static void ui_tab_url(struct nk_context *ctx) {
    nk_layout_row_dynamic(ctx, 22, 1);
    nk_label(ctx, g_probe_busy[5] ? "Проверка URL — идёт" : "Проверка URL", NK_TEXT_LEFT);
    nk_layout_row_begin(ctx, NK_STATIC, 28, 2);
    nk_layout_row_push(ctx, 50);
    nk_label(ctx, "URL:", NK_TEXT_LEFT);
    nk_layout_row_push(ctx, 500);
    nk_edit_string_zero_terminated(ctx, NK_EDIT_FIELD, url_buf, sizeof url_buf, nk_filter_default);
    nk_layout_row_end(ctx);
    nk_layout_row_begin(ctx, NK_STATIC, 28, 4);
    nk_layout_row_push(ctx, 80);
    nk_label(ctx, "Интервал:", NK_TEXT_LEFT);
    nk_layout_row_push(ctx, 70);
    nk_property_int(ctx, "#ui", 1, &url_interval, 120, 1, 1);
    nk_layout_row_push(ctx, 90);
    nk_label(ctx, "Раунды:", NK_TEXT_LEFT);
    nk_layout_row_push(ctx, 70);
    nk_property_int(ctx, "#ur", 0, &url_rounds, 99999, 1, 1);
    nk_layout_row_end(ctx);
    nk_layout_row_dynamic(ctx, 24, 1);
    nk_checkbox_label(ctx, "Следовать редиректам", &url_follow);
    nk_layout_row_dynamic(ctx, 34, 2);
    if (nk_button_label(ctx, "Старт")) run_url();
    if (nk_button_label(ctx, "Остановить")) {
        if (g_probe_busy[5]) g_probe_cancel[5] = 1;
    }
}

static void ui_frame(struct nk_context *ctx, int width, int height) {
    char hdr[PATH_MAX_G + 64];
    int log_h;
    /* Панель этапов: фиксированная высота; на низком окне — компактнее */
    g_stage_panel_h = (height < 720) ? STAGE_PANEL_H_MIN : STAGE_PANEL_H_DEFAULT;
    if (nk_begin(ctx, "Connect Check", nk_rect(0, 0, (float)width, (float)height),
                 NK_WINDOW_NO_SCROLLBAR)) {
        if (g_resources[0])
            snprintf(hdr, sizeof hdr, "Движок встроен · %s", g_resources);
        else
            snprintf(hdr, sizeof hdr, "Движок встроен · resources.conf не найден рядом с пакетом");
        nk_layout_row_dynamic(ctx, 22, 1);
        nk_label_colored(ctx, hdr, NK_TEXT_LEFT,
                         g_resources[0] ? nk_rgb(40, 140, 60) : nk_rgb(180, 120, 40));

        if (g_update_ready) {
            nk_layout_row_begin(ctx, NK_STATIC, 30, 2);
            nk_layout_row_push(ctx, (float)(width - 160));
            nk_label_colored(ctx, g_update_banner, NK_TEXT_LEFT, nk_rgb(160, 100, 20));
            nk_layout_row_push(ctx, 140);
            if (nk_button_label(ctx, "Обновить"))
                do_self_update();
            nk_layout_row_end(ctx);
        }

        nk_layout_row_dynamic(ctx, 28, 3);
        if (nk_button_label(ctx, g_tab == 0 ? "[ Диагностика ]" : "Диагностика")) g_tab = 0;
        if (nk_button_label(ctx, g_tab == 1 ? "[ Пробы ]" : "Пробы")) g_tab = 1;
        if (nk_button_label(ctx, g_tab == 2 ? "[ URL ]" : "URL")) g_tab = 2;

        if (g_tab == 0) ui_tab_diagnose(ctx);
        else if (g_tab == 1) ui_tab_probes(ctx);
        else ui_tab_url(ctx);

        nk_layout_row_dynamic(ctx, 32, 2);
        if (nk_button_label(ctx, "Остановить всё")) stop_all();
        if (nk_button_label(ctx, "Очистить лог")) {
            g_log.n = 0;
            g_log_prog_idx = -1;
        }

        log_h = height - (int)ctx->current->layout->at_y - 40;
        {
            int floor = (height < 720) ? LOG_H_FLOOR_MIN : LOG_H_FLOOR;
            if (log_h < floor) log_h = floor;
        }
        nk_layout_row_dynamic(ctx, (float)log_h, 1);
        if (nk_group_begin(ctx, "log", NK_WINDOW_BORDER)) {
            int i;
            nk_layout_row_dynamic(ctx, 18, 1);
            for (i = 0; i < g_log.n; i++) {
                const char *ln = g_log.lines[i];
                if (i == g_log_prog_idx || strstr(ln, " … "))
                    nk_label_colored(ctx, ln, NK_TEXT_LEFT, nk_rgb(140, 150, 160));
                else if (strstr(ln, "fail") || strstr(ln, "FAIL") || strstr(ln, "ошиб") ||
                         strstr(ln, "Error"))
                    nk_label_colored(ctx, ln, NK_TEXT_LEFT, nk_rgb(200, 90, 80));
                else
                    nk_label(ctx, ln, NK_TEXT_LEFT);
            }
            if (g_log.scroll_bottom)
                g_log.scroll_bottom = 0;
            nk_group_end(ctx);
        }

        nk_layout_row_dynamic(ctx, 22, 1);
        nk_label(ctx, g_status, NK_TEXT_LEFT);
    }
    nk_end(ctx);
}

static void gui_init_common(void) {
#ifdef _WIN32
    InitializeCriticalSection(&g_ev_lock);
    g_ev_lock_ok = 1;
#endif
    resolve_pkg();
    stages_rebuild_plan();
    log_add("", "Connect Check GUI " CONNECT_CHECK_VERSION " — движок встроен");
    if (g_workdir[0]) log_add("pkg", g_workdir);
    if (g_resources[0]) log_add("resources", g_resources);
    else log_add("resources", "resources.conf не найден — будут встроенные списки");
}

#ifdef _WIN32
static void win_dpi_aware(void) {
    HMODULE user32 = LoadLibraryA("user32.dll");
    if (user32) {
        typedef BOOL (WINAPI *SetDpiAwarenessContext_t)(void *);
        SetDpiAwarenessContext_t set_ctx =
            (SetDpiAwarenessContext_t)GetProcAddress(user32, "SetProcessDpiAwarenessContext");
        if (set_ctx)
            set_ctx((void *)(intptr_t)-4);
        else {
            typedef BOOL (WINAPI *SetProcessDPIAware_t)(void);
            SetProcessDPIAware_t legacy =
                (SetProcessDPIAware_t)GetProcAddress(user32, "SetProcessDPIAware");
            if (legacy) legacy();
        }
        FreeLibrary(user32);
    }
}

static LRESULT CALLBACK gui_wndproc(HWND wnd, UINT msg, WPARAM wparam, LPARAM lparam) {
    switch (msg) {
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    if (nk_gdip_handle_event(wnd, msg, wparam, lparam))
        return 0;
    return DefWindowProcW(wnd, msg, wparam, lparam);
}

static GdipFont *win_pick_font(void) {
    /* Системные шрифты Windows (GDI+ по имени); кириллица — Segoe UI / Arial. */
    static const char *names[] = {
        "Segoe UI", "Arial", "Tahoma", "Consolas", "Cascadia Mono",
        "Lucida Console", "Courier New", NULL
    };
    GdipFont *font = NULL;
    int i;
    for (i = 0; names[i]; i++) {
        font = nk_gdipfont_create(names[i], 18);
        if (font) {
            log_add("font", names[i]);
            return font;
        }
    }
    log_add("font", "fallback Arial");
    return nk_gdipfont_create("Arial", 18);
}

int main(int argc, char **argv) {
    struct nk_context *ctx;
    GdipFont *font;
    WNDCLASSW wc;
    RECT rect = {0, 0, 960, 720};
    DWORD style = WS_OVERLAPPEDWINDOW;
    DWORD exstyle = WS_EX_APPWINDOW;
    HWND wnd;
    int running = 1;
    int needs_refresh = 1;
    int width = 960, height = 720;
    char titlea[96];
    wchar_t titlew[128];

    (void)argc;
    (void)argv;
    win_dpi_aware();
    gui_init_common();

    memset(&wc, 0, sizeof wc);
    wc.style = CS_DBLCLKS;
    wc.lpfnWndProc = gui_wndproc;
    wc.hInstance = GetModuleHandleW(0);
    wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.lpszClassName = L"ConnectCheckGui";
    RegisterClassW(&wc);
    AdjustWindowRectEx(&rect, style, FALSE, exstyle);
    snprintf(titlea, sizeof titlea, "Connect Check %s — диагностика сети", CONNECT_CHECK_VERSION);
    MultiByteToWideChar(CP_UTF8, 0, titlea, -1, titlew, 128);
    wnd = CreateWindowExW(exstyle, wc.lpszClassName, titlew,
                          style | WS_VISIBLE, CW_USEDEFAULT, CW_USEDEFAULT,
                          rect.right - rect.left, rect.bottom - rect.top,
                          NULL, NULL, wc.hInstance, NULL);
    if (!wnd) {
        MessageBoxA(NULL, "Не удалось создать окно.", "Connect Check", MB_OK | MB_ICONERROR);
        return 1;
    }

    ctx = nk_gdip_init(wnd, (unsigned)width, (unsigned)height);
    font = win_pick_font();
    if (font) nk_gdip_set_font(font);

    update_check_startup();

    while (running) {
        MSG msg;
        nk_input_begin(ctx);
        if (!needs_refresh) {
            if (GetMessageW(&msg, NULL, 0, 0) <= 0)
                running = 0;
            else {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
            needs_refresh = 1;
        } else {
            needs_refresh = 0;
        }
        while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE)) {
            if (msg.message == WM_QUIT)
                running = 0;
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
            needs_refresh = 1;
        }
        nk_input_end(ctx);

        {
            RECT cr;
            if (GetClientRect(wnd, &cr)) {
                width = cr.right - cr.left;
                height = cr.bottom - cr.top;
                if (width < 320) width = 320;
                if (height < 240) height = 240;
            }
        }
        drain_events();
        if (any_busy()) needs_refresh = 1;
        ui_frame(ctx, width, height);
        nk_gdip_render(NK_ANTI_ALIASING_ON, nk_rgb(30, 30, 36));
    }

    stop_all();
    while (any_busy()) {
        drain_events();
        Sleep(50);
    }
    if (font) nk_gdipfont_del(font);
    nk_gdip_shutdown();
    if (g_ev_lock_ok) DeleteCriticalSection(&g_ev_lock);
    return 0;
}

#else /* macOS / Linux — GLFW */

static void error_callback(int e, const char *d) {
    fprintf(stderr, "GLFW %d: %s\n", e, d);
}

int main(int argc, char **argv) {
    GLFWwindow *win;
    struct nk_context *ctx;
    int width = 960, height = 720;

    (void)argc;
    (void)argv;
    signal(SIGPIPE, SIG_IGN);

    gui_init_common();

    glfwSetErrorCallback(error_callback);
    if (!glfwInit()) {
        fprintf(stderr, "glfwInit failed\n");
        return 1;
    }
    {
        char title[96];
        snprintf(title, sizeof title, "Connect Check %s — диагностика сети", CONNECT_CHECK_VERSION);
        glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 2);
        glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 1);
        win = glfwCreateWindow(width, height, title, NULL, NULL);
    }
    if (!win) {
        glfwTerminate();
        return 1;
    }
    glfwMakeContextCurrent(win);
    glfwSwapInterval(1);

    update_check_startup();

    ctx = nk_glfw3_init(win, NK_GLFW3_INSTALL_CALLBACKS);
    {
        struct nk_font_atlas *atlas;
        struct nk_font_config cfg;
        struct nk_font *font = NULL;
        char fontpath[PATH_MAX_G];
        static const nk_rune ranges[] = {
            0x0020, 0x00FF,
            0x0400, 0x052F,
            0x2010, 0x2027,
            0x2190, 0x21FF,
            0x2200, 0x22FF,
            0x2300, 0x23FF,
            0x2500, 0x25FF,
            0x2600, 0x26FF,
            0
        };

        cfg = nk_font_config(18.0f);
        cfg.range = ranges;
        nk_glfw3_font_stash_begin(&atlas);
        if (find_font(fontpath, sizeof fontpath)) {
            font = nk_font_atlas_add_from_file(atlas, fontpath, 18.0f, &cfg);
            if (font)
                log_add("font", fontpath);
            else
                log_add("font", "файл есть, но не загрузился — ASCII fallback");
        } else {
            log_add("font", "нет TTF — системный mono / кириллица может быть недоступна");
        }
        nk_glfw3_font_stash_end();
        if (font)
            nk_style_set_font(ctx, &font->handle);
    }

    while (!glfwWindowShouldClose(win)) {
        drain_events();
        glfwPollEvents();
        nk_glfw3_new_frame();
        glfwGetWindowSize(win, &width, &height);
        ui_frame(ctx, width, height);
        glViewport(0, 0, width, height);
        glClearColor(0.12f, 0.12f, 0.14f, 1);
        glClear(GL_COLOR_BUFFER_BIT);
        nk_glfw3_render(NK_ANTI_ALIASING_ON);
        glfwSwapBuffers(win);
    }

    stop_all();
    {
        int n = 0;
        while (any_busy() && n++ < 100) {
            drain_events();
#ifdef _WIN32
            Sleep(50);
#else
            usleep(50000);
#endif
        }
    }
    nk_glfw3_shutdown();
    glfwTerminate();
    return 0;
}
#endif

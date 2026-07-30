/*
 * connect-check-gui.c — GUI для connect-check / probe-*.
 *   Windows: Nuklear + GDI+ (без OpenGL/GLFW — нет ошибки 65542)
 *   macOS/Linux: Nuklear + GLFW/OpenGL2
 *
 *   make -f Makefile.gui
 *   make -f Makefile.gui package
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
#  include <direct.h>
#  define getcwd _getcwd
#else
#  include <unistd.h>
#  include <fcntl.h>
#  include <signal.h>
#  include <sys/wait.h>
#  include <libgen.h>
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

#define LOG_LINE    768
#define PATH_MAX_G  1024
#define ARG_MAX_N   24
#define MAX_PROCS   12
#define MAX_LOG     400
#define PIPE_ACC    2048  /* хвост незавершённой строки из pipe */

typedef struct {
    char lines[MAX_LOG][LOG_LINE];
    int n;
    int scroll_bottom;
} LogBuf;

typedef struct {
    char key[48];
    int alive;
    char acc[PIPE_ACC]; /* незавершённая строка между read() */
    int acc_n;
#ifdef _WIN32
    HANDLE proc;
    HANDLE rd;
#else
    pid_t pid;
    int fd;
#endif
} Child;

static char g_bindir[PATH_MAX_G];
static char g_workdir[PATH_MAX_G];
static LogBuf g_log;
static int g_log_prog_idx = -1; /* индекс перезаписываемой progress-строки (\r), или -1 */
static Child g_kids[MAX_PROCS];
static int g_nkids;
static char g_status[128] = "Готово";

/* diagnose options */
static int opt_yes = 1, opt_skip_dns = 1, opt_skip_video, opt_dns_bulk;
static int opt_skip_speed, opt_no_open;
static char opt_outdir[256] = "reports";

/* probes */
static int probe_on[5] = {1, 0, 0, 0, 0}; /* captive default */
static const char *probe_ids[] = {
    "probe-captive", "probe-quic", "probe-battlenet", "probe-mqtt", "probe-video"
};
static const char *probe_labels[] = {
    "Captive / DNS / DoT / DoH", "QUIC / UDP 443", "Battle.net", "MQTT / MQTTS", "Видео РФ"
};
static int probe_interval = 120, probe_rounds;

/* url */
static char url_buf[512] = "https://ya.ru/";
static int url_interval = 5, url_rounds, url_follow;

static int g_tab; /* 0 diagnose, 1 probes, 2 url */

/* self-update */
static int g_update_ready;
static UpdateInfo g_update;
static char g_update_err[256];
static char g_update_banner[192];

/* ---------- utils ---------- */

/* Обрезать битый хвост UTF-8 (после snprintf / разрыва pipe). */
static void utf8_trim(char *s) {
    size_t n, i;
    if (!s || !*s) return;
    n = strlen(s);
    while (n > 0) {
        unsigned char c = (unsigned char)s[n - 1];
        if ((c & 0x80) == 0) break;           /* ASCII */
        if ((c & 0xC0) == 0xC0) {             /* стартовый байт — неполный */
            s[--n] = 0;
            break;
        }
        /* continuation 10xxxxxx — ищем старт */
        i = n;
        while (i > 0 && ((unsigned char)s[i - 1] & 0xC0) == 0x80) i--;
        if (i == 0) { s[0] = 0; return; }
        {
            unsigned char lead = (unsigned char)s[i - 1];
            int need = (lead & 0xE0) == 0xC0 ? 2
                     : (lead & 0xF0) == 0xE0 ? 3
                     : (lead & 0xF8) == 0xF0 ? 4 : 0;
            if (need && (int)(n - (i - 1)) == need) break; /* полная последовательность */
            s[i - 1] = 0;
            n = i - 1;
        }
    }
}

/* Убрать CSI/ANSI (например \033[K из stage_progress) и лишние пробелы по краям. */
static void sanitize_log_text(char *s) {
    char *r, *w;
    int esc = 0; /* 0 normal, 1 ESC, 2 ESC[ */
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
        if (c < 0x20 && c != 0x09) continue; /* прочие control */
        *w++ = (char)c;
    }
    *w = 0;
    /* trim edges */
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

/* Финальная строка лога (обычный вывод с \n). */
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

/*
 * Progress из CLI (\r / \033[K): одна перезаписываемая строка, без спама.
 * Пустой msg — убрать progress-строку (stage_done).
 */
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

/* Дописать кусок pipe: \r = перезапись progress, \n = финальная строка, ANSI выкидываем. */
static void kid_feed(Child *c, const char *chunk, size_t len) {
    size_t i;
    int esc = 0; /* 0 normal, 1 ESC, 2 CSI */
    for (i = 0; i < len; i++) {
        unsigned char uch = (unsigned char)chunk[i];
        char ch = chunk[i];

        if (esc == 1) {
            if (uch == '[') { esc = 2; continue; }
            esc = 0;
            continue;
        }
        if (esc == 2) {
            if ((uch >= 'A' && uch <= 'Z') || (uch >= 'a' && uch <= 'z'))
                esc = 0;
            continue;
        }
        if (uch == 0x1B) { esc = 1; continue; }

        if (ch == '\r') {
            c->acc[c->acc_n] = 0;
            sanitize_log_text(c->acc);
            log_progress(c->key, c->acc);
            c->acc_n = 0;
            continue;
        }
        if (ch == '\n') {
            c->acc[c->acc_n] = 0;
            sanitize_log_text(c->acc);
            if (c->acc_n > 0)
                log_add(c->key, c->acc);
            else
                log_progress(c->key, ""); /* пустой \n после clear — снять progress */
            c->acc_n = 0;
            continue;
        }
        if (uch < 0x20) continue; /* прочий control */

        if (c->acc_n + 1 < PIPE_ACC)
            c->acc[c->acc_n++] = ch;
        else {
            c->acc[c->acc_n] = 0;
            sanitize_log_text(c->acc);
            log_add(c->key, c->acc);
            c->acc_n = 0;
            c->acc[c->acc_n++] = ch;
        }
    }
}

static void kid_flush_acc(Child *c) {
    if (c->acc_n > 0) {
        c->acc[c->acc_n] = 0;
        sanitize_log_text(c->acc);
        if (c->acc[0])
            log_add(c->key, c->acc);
        c->acc_n = 0;
    }
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
    return access(p, X_OK) == 0 || access(p, R_OK) == 0;
#endif
}

static void tool_name(char *out, size_t n, const char *base) {
#ifdef _WIN32
    snprintf(out, n, "%s.exe", base);
#else
    snprintf(out, n, "%s", base);
#endif
}

#if defined(_WIN32)
#  define OS_CLI_SUBDIR "win"
#elif defined(__APPLE__)
#  define OS_CLI_SUBDIR "mac"
#else
#  define OS_CLI_SUBDIR "linux"
#endif

/* Каталог GUI-бинарника (…/MacOS или папка с .exe). */
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

/* Корень пакета рядом с GUI: …/ConnectCheck-mac.app/Contents/MacOS → …/ */
static int package_root_from_gui(char *out, size_t n) {
    char exedir[PATH_MAX_G], up[PATH_MAX_G], real[PATH_MAX_G];
    if (!gui_exe_dir(exedir, sizeof exedir)) return 0;

#ifdef __APPLE__
    /* …/ConnectCheck-mac.app/Contents/MacOS → каталог, где лежит .app и mac/ */
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

static int bindir_has_tool(const char *dir, const char *tool) {
    char try[PATH_MAX_G];
    if (!dir || !dir[0]) return 0;
    path_join(try, sizeof try, dir, tool);
    return file_exists(try);
}

/*
 * CLI/probes рядом с GUI (раскладка архива), без env и без cwd:
 *   <pkg>/mac|linux|win/connect-check  или  <pkg>/connect-check
 */
static int resolve_bindir(void) {
    char pkg[PATH_MAX_G], sub[PATH_MAX_G], tool[64];

    tool_name(tool, sizeof tool, "connect-check");
    g_bindir[0] = 0;
    g_workdir[0] = 0;

    if (!package_root_from_gui(pkg, sizeof pkg))
        return 0;

    snprintf(g_workdir, sizeof g_workdir, "%s", pkg);

    path_join(sub, sizeof sub, pkg, OS_CLI_SUBDIR);
    if (bindir_has_tool(sub, tool)) {
        snprintf(g_bindir, sizeof g_bindir, "%s", sub);
        return 1;
    }
    if (bindir_has_tool(pkg, tool)) {
        snprintf(g_bindir, sizeof g_bindir, "%s", pkg);
        return 1;
    }
    return 0;
}

static int tool_path(const char *base, char *out, size_t n) {
    char name[64];
    tool_name(name, sizeof name, base);
    if (!g_bindir[0]) return 0;
    path_join(out, n, g_bindir, name);
    return file_exists(out);
}

/* Шрифт: рядом с GUI/пакетом → системные моноширинные TTF. */
static int find_font(char *out, size_t n) {
    char pkg[PATH_MAX_G], try[PATH_MAX_G], windir[PATH_MAX_G];
    size_t i;
    const char *bundled[] = {
        "DejaVuSansMono.ttf",
        "DejaVuSans.ttf",
        NULL
    };
#ifdef _WIN32
    const char *sysmono[6];
    char sysbuf[5][PATH_MAX_G];
#elif defined(__APPLE__)
    const char *sysmono[] = {
        "/System/Library/Fonts/Supplemental/Courier New.ttf",
        "/Library/Fonts/Courier New.ttf",
        "/System/Library/Fonts/Supplemental/Andale Mono.ttf",
        "/Library/Fonts/Andale Mono.ttf",
        NULL
    };
#else
    const char *sysmono[] = {
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        "/usr/share/fonts/TTF/DejaVuSansMono.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf",
        "/usr/share/fonts/truetype/noto/NotoSansMono-Regular.ttf",
        "/usr/share/fonts/truetype/freefont/FreeMono.ttf",
        "/usr/share/fonts/truetype/ubuntu/UbuntuMono-R.ttf",
        NULL
    };
#endif

    if (package_root_from_gui(pkg, sizeof pkg)) {
        for (i = 0; bundled[i]; i++) {
            path_join(try, sizeof try, pkg, bundled[i]);
            if (file_exists(try)) {
                snprintf(out, n, "%s", try);
                return 1;
            }
        }
#ifdef __APPLE__
        /* шрифт внутри .app/Contents/MacOS */
        if (gui_exe_dir(try, sizeof try)) {
            char f[PATH_MAX_G];
            for (i = 0; bundled[i]; i++) {
                path_join(f, sizeof f, try, bundled[i]);
                if (file_exists(f)) {
                    snprintf(out, n, "%s", f);
                    return 1;
                }
            }
        }
#endif
    }

#ifdef _WIN32
    {
        DWORD wlen = GetEnvironmentVariableA("WINDIR", windir, (DWORD)sizeof windir);
        if (!wlen || wlen >= sizeof windir)
            snprintf(windir, sizeof windir, "C:\\Windows");
        snprintf(sysbuf[0], sizeof sysbuf[0], "%s\\Fonts\\consola.ttf", windir);
        snprintf(sysbuf[1], sizeof sysbuf[1], "%s\\Fonts\\cour.ttf", windir);
        snprintf(sysbuf[2], sizeof sysbuf[2], "%s\\Fonts\\CascadiaMono.ttf", windir);
        snprintf(sysbuf[3], sizeof sysbuf[3], "%s\\Fonts\\cascadiamono.ttf", windir);
        snprintf(sysbuf[4], sizeof sysbuf[4], "%s\\Fonts\\lucon.ttf", windir);
        sysmono[0] = sysbuf[0];
        sysmono[1] = sysbuf[1];
        sysmono[2] = sysbuf[2];
        sysmono[3] = sysbuf[3];
        sysmono[4] = sysbuf[4];
        sysmono[5] = NULL;
    }
#else
    (void)windir;
#endif

    for (i = 0; sysmono[i]; i++) {
        if (file_exists(sysmono[i])) {
            snprintf(out, n, "%s", sysmono[i]);
            return 1;
        }
    }
    out[0] = 0;
    return 0;
}

/* ---------- process ---------- */

static Child *kid_slot(const char *key) {
    int i;
    for (i = 0; i < g_nkids; i++)
        if (strcmp(g_kids[i].key, key) == 0) return &g_kids[i];
    if (g_nkids >= MAX_PROCS) return NULL;
    memset(&g_kids[g_nkids], 0, sizeof g_kids[0]);
    snprintf(g_kids[g_nkids].key, sizeof g_kids[0].key, "%s", key);
    return &g_kids[g_nkids++];
}

static Child *kid_find(const char *key) {
    int i;
    for (i = 0; i < g_nkids; i++)
        if (strcmp(g_kids[i].key, key) == 0) return &g_kids[i];
    return NULL;
}

static void kid_reap_slot(Child *c) {
    if (!c) return;
#ifdef _WIN32
    if (c->rd && c->rd != INVALID_HANDLE_VALUE) {
        CloseHandle(c->rd);
        c->rd = NULL;
    }
    if (c->proc) {
        CloseHandle(c->proc);
        c->proc = NULL;
    }
#else
    if (c->fd >= 0) {
        close(c->fd);
        c->fd = -1;
    }
    c->pid = 0;
#endif
    c->alive = 0;
}

#ifdef _WIN32
static int start_child(const char *key, const char *exe, char *cmdline) {
    Child *c = kid_find(key);
    SECURITY_ATTRIBUTES sa;
    HANDLE rd = NULL, wr = NULL;
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;

    if (c && c->alive) {
        log_add(key, "уже запущен");
        return 0;
    }
    c = kid_slot(key);
    if (!c) {
        log_add(key, "нет слотов");
        return 0;
    }

    sa.nLength = sizeof sa;
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;
    if (!CreatePipe(&rd, &wr, &sa, 0)) return 0;
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);

    memset(&si, 0, sizeof si);
    si.cb = sizeof si;
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = wr;
    si.hStdError = wr;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    memset(&pi, 0, sizeof pi);

    if (!CreateProcessA(exe, cmdline, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, g_workdir, &si, &pi)) {
        CloseHandle(rd);
        CloseHandle(wr);
        log_add(key, "CreateProcess failed");
        return 0;
    }
    CloseHandle(wr);
    CloseHandle(pi.hThread);
    c->proc = pi.hProcess;
    c->rd = rd;
    c->alive = 1;
    {
        char msg[LOG_LINE];
        snprintf(msg, sizeof msg, "▶ %s", cmdline);
        log_add(key, msg);
    }
    snprintf(g_status, sizeof g_status, "Запущено: %s", key);
    return 1;
}
#else
static int start_child(const char *key, char *const argv[]) {
    Child *c = kid_find(key);
    int pfd[2];
    pid_t pid;
    char cmdline[LOG_LINE];
    int i, o = 0;

    if (c && c->alive) {
        log_add(key, "уже запущен");
        return 0;
    }
    c = kid_slot(key);
    if (!c) {
        log_add(key, "нет слотов");
        return 0;
    }

    cmdline[0] = 0;
    for (i = 0; argv[i]; i++) {
        int n = snprintf(cmdline + o, sizeof cmdline - (size_t)o, "%s%s", i ? " " : "", argv[i]);
        if (n > 0) o += n;
    }

    if (pipe(pfd) != 0) return 0;
    pid = fork();
    if (pid < 0) {
        close(pfd[0]);
        close(pfd[1]);
        return 0;
    }
    if (pid == 0) {
        close(pfd[0]);
        dup2(pfd[1], STDOUT_FILENO);
        dup2(pfd[1], STDERR_FILENO);
        close(pfd[1]);
        if (g_workdir[0]) chdir(g_workdir);
        execv(argv[0], argv);
        _exit(127);
    }
    close(pfd[1]);
    fcntl(pfd[0], F_SETFL, O_NONBLOCK);
    c->pid = pid;
    c->fd = pfd[0];
    c->alive = 1;
    {
        char msg[LOG_LINE];
        snprintf(msg, sizeof msg, "▶ %s", cmdline);
        log_add(key, msg);
    }
    snprintf(g_status, sizeof g_status, "Запущено: %s", key);
    return 1;
}
#endif

static void stop_child(const char *key) {
    Child *c = kid_find(key);
    if (!c || !c->alive) return;
#ifdef _WIN32
    TerminateProcess(c->proc, 1);
#else
    kill(c->pid, SIGTERM);
#endif
    log_add(key, "остановлено пользователем");
    kid_reap_slot(c);
}

static void stop_all(void) {
    int i;
    for (i = 0; i < g_nkids; i++)
        if (g_kids[i].alive) stop_child(g_kids[i].key);
}

static void poll_children(void) {
    int i;
    char buf[1024];
    for (i = 0; i < g_nkids; i++) {
        Child *c = &g_kids[i];
        if (!c->alive) continue;
#ifdef _WIN32
        {
            DWORD avail = 0, got = 0;
            if (PeekNamedPipe(c->rd, NULL, 0, NULL, &avail, NULL) && avail > 0) {
                if (avail > sizeof buf) avail = (DWORD)sizeof buf;
                if (ReadFile(c->rd, buf, avail, &got, NULL) && got)
                    kid_feed(c, buf, (size_t)got);
            }
            if (WaitForSingleObject(c->proc, 0) == WAIT_OBJECT_0) {
                DWORD code = 0;
                while (PeekNamedPipe(c->rd, NULL, 0, NULL, &avail, NULL) && avail > 0) {
                    if (avail > sizeof buf) avail = (DWORD)sizeof buf;
                    if (!ReadFile(c->rd, buf, avail, &got, NULL) || !got) break;
                    kid_feed(c, buf, (size_t)got);
                }
                kid_flush_acc(c);
                GetExitCodeProcess(c->proc, &code);
                {
                    char msg[64];
                    snprintf(msg, sizeof msg, "■ завершено, код %lu", (unsigned long)code);
                    log_add(c->key, msg);
                }
                kid_reap_slot(c);
            }
        }
#else
        {
            ssize_t n;
            while ((n = read(c->fd, buf, sizeof buf)) > 0)
                kid_feed(c, buf, (size_t)n);
            {
                int st = 0;
                pid_t r = waitpid(c->pid, &st, WNOHANG);
                if (r == c->pid) {
                    char msg[64];
                    int code = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
                    kid_flush_acc(c);
                    snprintf(msg, sizeof msg, "■ завершено, код %d", code);
                    log_add(c->key, msg);
                    kid_reap_slot(c);
                }
            }
        }
#endif
    }
    {
        int any = 0, j;
        for (j = 0; j < g_nkids; j++)
            if (g_kids[j].alive) any = 1;
        if (!any) snprintf(g_status, sizeof g_status, "Готово");
    }
}

/* ---------- actions ---------- */

static void run_diagnose(void) {
    char exe[PATH_MAX_G];
#ifdef _WIN32
    char cmd[2048];
    int o = 0;
    if (!tool_path("connect-check", exe, sizeof exe)) {
        log_add("connect-check", "не найден");
        return;
    }
    o = snprintf(cmd, sizeof cmd, "\"%s\"", exe);
    if (opt_yes) o += snprintf(cmd + o, sizeof cmd - o, " -y");
    if (opt_skip_dns) o += snprintf(cmd + o, sizeof cmd - o, " --skip-dns-bulk");
    if (opt_skip_video) o += snprintf(cmd + o, sizeof cmd - o, " --skip-video");
    if (opt_dns_bulk) o += snprintf(cmd + o, sizeof cmd - o, " --dns-bulk");
    if (opt_skip_speed) o += snprintf(cmd + o, sizeof cmd - o, " --skip-speed");
    if (opt_no_open) o += snprintf(cmd + o, sizeof cmd - o, " --no-open");
    if (opt_outdir[0])
        o += snprintf(cmd + o, sizeof cmd - o, " -o \"%s\"", opt_outdir);
    (void)o;
    start_child("connect-check", exe, cmd);
#else
    char *argv[ARG_MAX_N];
    int n = 0;
    if (!tool_path("connect-check", exe, sizeof exe)) {
        log_add("connect-check", "не найден — make -f Makefile.package");
        return;
    }
    argv[n++] = exe;
    if (opt_yes) argv[n++] = "-y";
    if (opt_skip_dns) argv[n++] = "--skip-dns-bulk";
    if (opt_skip_video) argv[n++] = "--skip-video";
    if (opt_dns_bulk) argv[n++] = "--dns-bulk";
    if (opt_skip_speed) argv[n++] = "--skip-speed";
    if (opt_no_open) argv[n++] = "--no-open";
    if (opt_outdir[0]) {
        argv[n++] = "-o";
        argv[n++] = opt_outdir;
    }
    argv[n] = NULL;
    start_child("connect-check", argv);
#endif
}

static void run_probes(void) {
    int i, started = 0;
    char iv[16], rn[16];
    snprintf(iv, sizeof iv, "%d", probe_interval);
    snprintf(rn, sizeof rn, "%d", probe_rounds);
    for (i = 0; i < 5; i++) {
        char exe[PATH_MAX_G];
        if (!probe_on[i]) continue;
        if (!tool_path(probe_ids[i], exe, sizeof exe)) {
            log_add(probe_ids[i], "не найден");
            continue;
        }
#ifdef _WIN32
        {
            char cmd[1024];
            snprintf(cmd, sizeof cmd, "\"%s\" -i %s -n %s", exe, iv, rn);
            if (start_child(probe_ids[i], exe, cmd)) started++;
        }
#else
        {
            char *argv[8];
            argv[0] = exe;
            argv[1] = "-i";
            argv[2] = iv;
            argv[3] = "-n";
            argv[4] = rn;
            argv[5] = NULL;
            if (start_child(probe_ids[i], argv)) started++;
        }
#endif
    }
    if (!started) log_add("probes", "ничего не запущено — отметьте пробы");
}

static void run_url(void) {
    char exe[PATH_MAX_G];
    char iv[16], rn[16];
    if (!url_buf[0]) {
        log_add("probe-url", "укажите URL");
        return;
    }
    if (!tool_path("probe-url", exe, sizeof exe)) {
        log_add("probe-url", "не найден");
        return;
    }
    snprintf(iv, sizeof iv, "%d", url_interval);
    snprintf(rn, sizeof rn, "%d", url_rounds);
#ifdef _WIN32
    {
        char cmd[1536];
        if (url_follow)
            snprintf(cmd, sizeof cmd, "\"%s\" -i %s -n %s -f \"%s\"", exe, iv, rn, url_buf);
        else
            snprintf(cmd, sizeof cmd, "\"%s\" -i %s -n %s \"%s\"", exe, iv, rn, url_buf);
        start_child("probe-url", exe, cmd);
    }
#else
    {
        char *argv[10];
        int n = 0;
        argv[n++] = exe;
        argv[n++] = "-i";
        argv[n++] = iv;
        argv[n++] = "-n";
        argv[n++] = rn;
        if (url_follow) argv[n++] = "-f";
        argv[n++] = url_buf;
        argv[n] = NULL;
        start_child("probe-url", argv);
    }
#endif
}

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
    update_detect_install_root(g_bindir[0] ? g_bindir : NULL, root, sizeof root);
    log_add("update", root);
    snprintf(g_status, sizeof g_status, "Обновление до %s…", g_update.tag);

#if defined(__APPLE__)
    {
        char app[PATH_MAX_G];
        path_join(app, sizeof app, root, "ConnectCheck-mac.app");
        if (access(app, F_OK) == 0) {
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
    nk_layout_row_dynamic(ctx, 22, 1);
    nk_label(ctx, "Параметры connect-check", NK_TEXT_LEFT);
    nk_layout_row_dynamic(ctx, 24, 1);
    nk_checkbox_label(ctx, "Без вопросов (-y)", &opt_yes);
    nk_checkbox_label(ctx, "Пропустить DNS-прогон", &opt_skip_dns);
    nk_checkbox_label(ctx, "Пропустить видео", &opt_skip_video);
    nk_checkbox_label(ctx, "DNS-прогон (--dns-bulk)", &opt_dns_bulk);
    nk_checkbox_label(ctx, "Пропустить скорость", &opt_skip_speed);
    nk_checkbox_label(ctx, "Не открывать HTML", &opt_no_open);
    nk_layout_row_begin(ctx, NK_STATIC, 28, 2);
    nk_layout_row_push(ctx, 140);
    nk_label(ctx, "Каталог (-o):", NK_TEXT_LEFT);
    nk_layout_row_push(ctx, 280);
    nk_edit_string_zero_terminated(ctx, NK_EDIT_FIELD, opt_outdir, sizeof opt_outdir, nk_filter_default);
    nk_layout_row_end(ctx);
    nk_layout_row_dynamic(ctx, 34, 3);
    if (nk_button_label(ctx, "Запустить диагностику")) run_diagnose();
    if (nk_button_label(ctx, "Остановить")) stop_child("connect-check");
    (void)i;
}

static void ui_tab_probes(struct nk_context *ctx) {
    int i;
    nk_layout_row_dynamic(ctx, 22, 1);
    nk_label(ctx, "Циклические пробы (параллельно)", NK_TEXT_LEFT);
    for (i = 0; i < 5; i++) {
        char lab[96];
        snprintf(lab, sizeof lab, "%s  (%s)", probe_labels[i], probe_ids[i]);
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
    if (nk_button_label(ctx, "Остановить пробы")) {
        for (i = 0; i < 5; i++) stop_child(probe_ids[i]);
    }
}

static void ui_tab_url(struct nk_context *ctx) {
    nk_layout_row_dynamic(ctx, 22, 1);
    nk_label(ctx, "probe-url", NK_TEXT_LEFT);
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
    nk_checkbox_label(ctx, "Следовать редиректам (-f)", &url_follow);
    nk_layout_row_dynamic(ctx, 34, 2);
    if (nk_button_label(ctx, "Старт probe-url")) run_url();
    if (nk_button_label(ctx, "Остановить")) stop_child("probe-url");
}

static void ui_frame(struct nk_context *ctx, int width, int height) {
    char hdr[PATH_MAX_G + 64];
    int log_h;
    if (nk_begin(ctx, "Connect Check", nk_rect(0, 0, (float)width, (float)height),
                 NK_WINDOW_NO_SCROLLBAR)) {
        if (g_bindir[0])
            snprintf(hdr, sizeof hdr, "Утилиты: %s", g_bindir);
        else
            snprintf(hdr, sizeof hdr,
                     "connect-check не найден рядом с GUI (ожидается папка %s/)",
                     OS_CLI_SUBDIR);
        nk_layout_row_dynamic(ctx, 22, 1);
        nk_label_colored(ctx, hdr, NK_TEXT_LEFT,
                         g_bindir[0] ? nk_rgb(40, 140, 60) : nk_rgb(180, 40, 40));

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
        if (nk_button_label(ctx, g_tab == 2 ? "[ probe-url ]" : "probe-url")) g_tab = 2;

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
        if (log_h < 120) log_h = 120;
        nk_layout_row_dynamic(ctx, (float)log_h, 1);
        if (nk_group_begin(ctx, "log", NK_WINDOW_BORDER)) {
            int i;
            nk_layout_row_dynamic(ctx, 18, 1);
            for (i = 0; i < g_log.n; i++) {
                const char *ln = g_log.lines[i];
                /* progress (\r) — приглушённый; ошибки — краснее */
                if (i == g_log_prog_idx || strstr(ln, " … "))
                    nk_label_colored(ctx, ln, NK_TEXT_LEFT, nk_rgb(140, 150, 160));
                else if (strstr(ln, "fail") || strstr(ln, "ошиб") || strstr(ln, "Error") ||
                         strstr(ln, "не найден"))
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
    static const char *names[] = {
        "Consolas", "Cascadia Mono", "Lucida Console", "Courier New", "Arial", NULL
    };
    char pkg[PATH_MAX_G], ttf[PATH_MAX_G];
    WCHAR wpath[PATH_MAX_G];
    GdipFont *font = NULL;
    int i;

    if (package_root_from_gui(pkg, sizeof pkg)) {
        path_join(ttf, sizeof ttf, pkg, "DejaVuSansMono.ttf");
        if (!file_exists(ttf))
            path_join(ttf, sizeof ttf, pkg, "DejaVuSans.ttf");
        if (file_exists(ttf) &&
            MultiByteToWideChar(CP_UTF8, 0, ttf, -1, wpath, PATH_MAX_G) > 0) {
            font = nk_gdipfont_create_from_file(wpath, 18);
            if (font) {
                log_add("font", ttf);
                return font;
            }
        }
    }
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
    resolve_bindir();
    log_add("", "Connect Check GUI (GDI+) " CONNECT_CHECK_VERSION);
    if (g_workdir[0]) log_add("pkg", g_workdir);
    if (g_bindir[0]) log_add("bin", g_bindir);
    else log_add("", "нет CLI рядом с GUI — положите папку " OS_CLI_SUBDIR "/ рядом с приложением");

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
        poll_children();
        ui_frame(ctx, width, height);
        nk_gdip_render(NK_ANTI_ALIASING_ON, nk_rgb(30, 30, 36));
    }

    stop_all();
    if (font) nk_gdipfont_del(font);
    nk_gdip_shutdown();
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

    resolve_bindir();
    log_add("", "Connect Check GUI (Nuklear) " CONNECT_CHECK_VERSION);
    if (g_workdir[0]) log_add("pkg", g_workdir);
    if (g_bindir[0]) log_add("bin", g_bindir);
    else log_add("", "нет CLI рядом с GUI — положите папку " OS_CLI_SUBDIR "/ рядом с приложением");

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
        poll_children();
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
    nk_glfw3_shutdown();
    glfwTerminate();
    return 0;
}
#endif /* !_WIN32 */

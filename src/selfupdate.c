/*
 * selfupdate.c — check / download / apply updates from GitHub Releases.
 *
 * Env:
 *   CONNECT_CHECK_UPDATE_REPO=owner/name  (default cooler58/connect-check)
 *   CONNECT_CHECK_NO_UPDATE=1            (refuse apply)
 */
#define _CRT_SECURE_NO_WARNINGS
#include "selfupdate.h"
#include "version.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#  include <wininet.h>
#  include <direct.h>
#  include <process.h>
#  define PATH_SEP '\\'
#else
#  include <unistd.h>
#  include <sys/stat.h>
#  include <sys/types.h>
#  include <sys/wait.h>
#  include <fcntl.h>
#  include <limits.h>
#  include <libgen.h>
#  ifdef __APPLE__
#    include <mach-o/dyld.h>
#  endif
#  define PATH_SEP '/'
#endif

#ifndef PATH_MAX
#  define PATH_MAX 1024
#endif

#define SU_STR 512
#define SU_BIG 65536

/* ---------- small helpers ---------- */

static void set_err(char *err, size_t errlen, const char *msg) {
    if (!err || errlen == 0) return;
    snprintf(err, errlen, "%s", msg ? msg : "ошибка");
}

static int file_exists(const char *path) {
#ifdef _WIN32
    DWORD a = GetFileAttributesA(path);
    return a != INVALID_FILE_ATTRIBUTES;
#else
    return access(path, F_OK) == 0;
#endif
}

static int is_dir(const char *path) {
#ifdef _WIN32
    DWORD a = GetFileAttributesA(path);
    return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY);
#else
    struct stat st;
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
#endif
}

static void path_join2(char *out, size_t n, const char *a, const char *b) {
    size_t la = a ? strlen(a) : 0;
    int need = la > 0 && a[la - 1] != '/' && a[la - 1] != '\\';
    if (need)
        snprintf(out, n, "%s%c%s", a, PATH_SEP, b ? b : "");
    else
        snprintf(out, n, "%s%s", a ? a : "", b ? b : "");
}

static const char *path_basename(const char *p) {
    const char *s = strrchr(p, '/');
    const char *b = strrchr(p, '\\');
    if (b && (!s || b > s)) s = b;
    return s ? s + 1 : p;
}

static void path_dirname(const char *path, char *out, size_t n) {
    const char *s = strrchr(path, '/');
    const char *b = strrchr(path, '\\');
    if (b && (!s || b > s)) s = b;
    if (!s) {
        snprintf(out, n, ".");
        return;
    }
    {
        size_t len = (size_t)(s - path);
        if (len == 0) len = 1;
        if (len >= n) len = n - 1;
        memcpy(out, path, len);
        out[len] = 0;
    }
}

static long long file_size(const char *path) {
#ifdef _WIN32
    WIN32_FILE_ATTRIBUTE_DATA fad;
    if (!GetFileAttributesExA(path, GetFileExInfoStandard, &fad)) return -1;
    return ((long long)fad.nFileSizeHigh << 32) | fad.nFileSizeLow;
#else
    struct stat st;
    if (stat(path, &st) != 0) return -1;
    return (long long)st.st_size;
#endif
}

static int run_cmd(const char *cmd) {
#ifdef _WIN32
    return system(cmd);
#else
    return system(cmd);
#endif
}

/* ---------- platform asset id ---------- */

static void asset_needle(char *out, size_t n) {
#if defined(_WIN32)
    snprintf(out, n, "connect-check-win-x86_64-");
#elif defined(__APPLE__)
    snprintf(out, n, "connect-check-mac-arm64-");
#else
    snprintf(out, n, "connect-check-linux-x86_64-");
#endif
}

static const char *os_cli_subdir(void) {
#if defined(_WIN32)
    return "win";
#elif defined(__APPLE__)
    return "mac";
#else
    return "linux";
#endif
}

static const char *gui_marker_name(void) {
#if defined(_WIN32)
    return "connect-check-gui-win.exe";
#elif defined(__APPLE__)
    return "ConnectCheck-mac.app";
#else
    return "connect-check-gui-linux";
#endif
}

static void default_repo(char *out, size_t n) {
    const char *e = getenv("CONNECT_CHECK_UPDATE_REPO");
    if (e && e[0])
        snprintf(out, n, "%s", e);
    else
        snprintf(out, n, "cooler58/connect-check");
}

/* ---------- semver ---------- */

static int parse_semver(const char *s, int *maj, int *min, int *pat) {
    const char *p = s;
    *maj = *min = *pat = 0;
    if (!p || !*p) return -1;
    if (*p == 'v' || *p == 'V') p++;
    if (!isdigit((unsigned char)*p)) return -1;
    *maj = atoi(p);
    p = strchr(p, '.');
    if (!p) return 0;
    p++;
    *min = atoi(p);
    p = strchr(p, '.');
    if (!p) return 0;
    p++;
    *pat = atoi(p);
    return 0;
}

int update_semver_gt(const char *remote, const char *local) {
    int rM, rm, rp, lM, lm, lp;
    if (parse_semver(remote, &rM, &rm, &rp) != 0) return 0;
    if (parse_semver(local, &lM, &lm, &lp) != 0) return 1;
    if (rM != lM) return rM > lM;
    if (rm != lm) return rm > lm;
    return rp > lp;
}

/* ---------- HTTP GET (body or file) ---------- */

#ifdef _WIN32
static int http_get_body(const char *url, char *body, size_t bodylen, char *err, size_t errlen) {
    HINTERNET hNet = NULL, hUrl = NULL;
    DWORD nread = 0;
    size_t off = 0;
    char ua[80];
    snprintf(ua, sizeof ua, "connect-check/%s", CONNECT_CHECK_VERSION);
    hNet = InternetOpenA(ua, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!hNet) {
        set_err(err, errlen, "InternetOpen failed");
        return -1;
    }
    hUrl = InternetOpenUrlA(hNet, url, "Accept: application/vnd.github+json\r\n",
                            (DWORD)-1,
                            INTERNET_FLAG_RELOAD | INTERNET_FLAG_SECURE |
                                INTERNET_FLAG_NO_CACHE_WRITE,
                            0);
    if (!hUrl) {
        set_err(err, errlen, "InternetOpenUrl failed");
        InternetCloseHandle(hNet);
        return -1;
    }
    body[0] = 0;
    while (off + 1 < bodylen) {
        if (!InternetReadFile(hUrl, body + off, (DWORD)(bodylen - off - 1), &nread) || nread == 0)
            break;
        off += nread;
        body[off] = 0;
    }
    InternetCloseHandle(hUrl);
    InternetCloseHandle(hNet);
    if (off == 0) {
        set_err(err, errlen, "пустой ответ GitHub API");
        return -1;
    }
    return 0;
}

static int http_download_file(const char *url, const char *path, char *err, size_t errlen) {
    HINTERNET hNet = NULL, hUrl = NULL;
    FILE *fp;
    DWORD nread;
    char buf[8192];
    char ua[80];
    size_t total = 0;
    snprintf(ua, sizeof ua, "connect-check/%s", CONNECT_CHECK_VERSION);
    hNet = InternetOpenA(ua, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!hNet) {
        set_err(err, errlen, "InternetOpen failed");
        return -1;
    }
    hUrl = InternetOpenUrlA(hNet, url, NULL, 0,
                            INTERNET_FLAG_RELOAD | INTERNET_FLAG_SECURE |
                                INTERNET_FLAG_NO_CACHE_WRITE,
                            0);
    if (!hUrl) {
        set_err(err, errlen, "скачивание: InternetOpenUrl failed");
        InternetCloseHandle(hNet);
        return -1;
    }
    fp = fopen(path, "wb");
    if (!fp) {
        set_err(err, errlen, "не открыть файл для записи");
        InternetCloseHandle(hUrl);
        InternetCloseHandle(hNet);
        return -1;
    }
    while (InternetReadFile(hUrl, buf, sizeof buf, &nread) && nread > 0) {
        if (fwrite(buf, 1, nread, fp) != nread) {
            fclose(fp);
            InternetCloseHandle(hUrl);
            InternetCloseHandle(hNet);
            set_err(err, errlen, "ошибка записи файла");
            return -1;
        }
        total += nread;
    }
    fclose(fp);
    InternetCloseHandle(hUrl);
    InternetCloseHandle(hNet);
    if (total < 1024) {
        set_err(err, errlen, "скачанный файл слишком мал");
        return -1;
    }
    return 0;
}
#else
static int http_get_body(const char *url, char *body, size_t bodylen, char *err, size_t errlen) {
    char cmd[SU_STR * 2];
    FILE *fp;
    size_t n;
#if defined(__APPLE__)
    const char *ssl = "CURL_SSL_BACKEND=secure-transport ";
#else
    const char *ssl = "";
#endif
    snprintf(cmd, sizeof cmd,
             "%scurl -fsSL --max-time 15 -A 'connect-check/%s' "
             "-H 'Accept: application/vnd.github+json' '%s' 2>/dev/null",
             ssl, CONNECT_CHECK_VERSION, url);
    fp = popen(cmd, "r");
    if (!fp) {
        set_err(err, errlen, "curl недоступен");
        return -1;
    }
    n = fread(body, 1, bodylen - 1, fp);
    body[n] = 0;
    pclose(fp);
    if (n == 0) {
        set_err(err, errlen, "пустой ответ GitHub API (сеть/curl?)");
        return -1;
    }
    return 0;
}

static int http_download_file(const char *url, const char *path, char *err, size_t errlen) {
    char cmd[SU_STR * 3];
    int rc;
#if defined(__APPLE__)
    const char *ssl = "CURL_SSL_BACKEND=secure-transport ";
#else
    const char *ssl = "";
#endif
    snprintf(cmd, sizeof cmd,
             "%scurl -fsSL --max-time 600 -A 'connect-check/%s' -o '%s' '%s'",
             ssl, CONNECT_CHECK_VERSION, path, url);
    rc = run_cmd(cmd);
    if (rc != 0 || file_size(path) < 1024) {
        set_err(err, errlen, "ошибка скачивания архива");
        return -1;
    }
    return 0;
}
#endif

/* ---------- JSON helpers (minimal) ---------- */

static const char *json_find_key(const char *json, const char *key) {
    char pat[96];
    const char *p;
    snprintf(pat, sizeof pat, "\"%s\"", key);
    p = json;
    while ((p = strstr(p, pat)) != NULL) {
        const char *q = p + strlen(pat);
        while (*q && isspace((unsigned char)*q)) q++;
        if (*q == ':') return q + 1;
        p++;
    }
    return NULL;
}

static int json_read_string(const char *after_colon, char *out, size_t n) {
    const char *p = after_colon;
    size_t i = 0;
    while (*p && isspace((unsigned char)*p)) p++;
    if (*p != '"') return -1;
    p++;
    while (*p && *p != '"' && i + 1 < n) {
        if (*p == '\\' && p[1]) {
            p++;
            if (*p == 'n') out[i++] = '\n';
            else if (*p == 't') out[i++] = '\t';
            else if (*p == '"') out[i++] = '"';
            else if (*p == '\\') out[i++] = '\\';
            else if (*p == '/') out[i++] = '/';
            else out[i++] = *p;
            p++;
            continue;
        }
        out[i++] = *p++;
    }
    out[i] = 0;
    return 0;
}

static int json_get_string(const char *json, const char *key, char *out, size_t n) {
    const char *p = json_find_key(json, key);
    if (!p) return -1;
    return json_read_string(p, out, n);
}

/* Find asset by name substring; optionally collect SHA256SUMS url. */
static int json_find_asset(const char *json, const char *needle,
                           char *name, size_t namelen,
                           char *url, size_t urllen,
                           char *sums_url, size_t sums_len) {
    const char *p = json;
    name[0] = url[0] = 0;
    if (sums_url && sums_len) sums_url[0] = 0;
    while ((p = strstr(p, "\"name\"")) != NULL) {
        char aname[256], aurl[512];
        const char *colon = strchr(p + 6, ':');
        const char *next_name;
        const char *url_key;
        aname[0] = aurl[0] = 0;
        if (!colon) {
            p++;
            continue;
        }
        if (json_read_string(colon + 1, aname, sizeof aname) != 0) {
            p++;
            continue;
        }
        next_name = strstr(p + 6, "\"name\"");
        url_key = strstr(p, "\"browser_download_url\"");
        if (url_key && (!next_name || url_key < next_name)) {
            const char *uc = strchr(url_key + 20, ':');
            if (uc) json_read_string(uc + 1, aurl, sizeof aurl);
        }
        if (sums_url && sums_len && strcmp(aname, "SHA256SUMS") == 0 && aurl[0])
            snprintf(sums_url, sums_len, "%s", aurl);
        if (strstr(aname, needle) && aurl[0] &&
            (strstr(aname, ".tar.gz") || strstr(aname, ".zip"))) {
            snprintf(name, namelen, "%s", aname);
            snprintf(url, urllen, "%s", aurl);
            /* keep scanning for SHA256SUMS */
            p = next_name ? next_name : p + 6;
            continue;
        }
        p = next_name ? next_name : p + 6;
    }
    return name[0] && url[0] ? 0 : -1;
}

static int parse_sha256sums(const char *text, const char *asset_name, char *hex, size_t hexlen) {
    const char *line = text;
    hex[0] = 0;
    (void)hexlen;
    while (line && *line) {
        const char *nl = strchr(line, '\n');
        char buf[640];
        size_t len = nl ? (size_t)(nl - line) : strlen(line);
        if (len >= sizeof buf) len = sizeof buf - 1;
        memcpy(buf, line, len);
        buf[len] = 0;
        /* format: <hex>  <filename> or <hex> *filename */
        if (len > 66 && strstr(buf, asset_name)) {
            size_t i = 0;
            while (i < 64 && isxdigit((unsigned char)buf[i])) i++;
            if (i == 64) {
                memcpy(hex, buf, 64);
                hex[64] = 0;
                return 0;
            }
        }
        line = nl ? nl + 1 : NULL;
    }
    return -1;
}

/* ---------- SHA256 of local file ---------- */

static int file_sha256_hex(const char *path, char *hex, size_t hexlen, char *err, size_t errlen) {
#ifdef _WIN32
    char cmd[SU_STR * 2];
    char out[512];
    FILE *fp;
    char *p;
    snprintf(cmd, sizeof cmd, "certutil -hashfile \"%s\" SHA256", path);
    fp = _popen(cmd, "r");
    if (!fp) {
        set_err(err, errlen, "certutil недоступен");
        return -1;
    }
    /* skip first line "SHA256 hash of ..." then read hex line */
    if (!fgets(out, sizeof out, fp)) {
        _pclose(fp);
        set_err(err, errlen, "certutil: нет вывода");
        return -1;
    }
    if (!fgets(out, sizeof out, fp)) {
        _pclose(fp);
        set_err(err, errlen, "certutil: нет хеша");
        return -1;
    }
    _pclose(fp);
    p = out;
    while (*p && isspace((unsigned char)*p)) p++;
    {
        size_t i = 0;
        while (*p && i + 1 < hexlen) {
            if (isxdigit((unsigned char)*p)) hex[i++] = (char)tolower((unsigned char)*p);
            p++;
        }
        hex[i] = 0;
        if (i != 64) {
            set_err(err, errlen, "некорректный SHA256");
            return -1;
        }
    }
    return 0;
#else
    char cmd[SU_STR * 2];
    char out[256];
    FILE *fp;
    snprintf(cmd, sizeof cmd,
             "(command -v shasum >/dev/null && shasum -a 256 '%s') || "
             "(command -v sha256sum >/dev/null && sha256sum '%s')",
             path, path);
    fp = popen(cmd, "r");
    if (!fp) {
        set_err(err, errlen, "sha256 недоступен");
        return -1;
    }
    if (!fgets(out, sizeof out, fp)) {
        pclose(fp);
        set_err(err, errlen, "не удалось посчитать SHA256");
        return -1;
    }
    pclose(fp);
    {
        size_t i = 0;
        while (out[i] && isxdigit((unsigned char)out[i]) && i + 1 < hexlen) {
            hex[i] = (char)tolower((unsigned char)out[i]);
            i++;
        }
        hex[i] = 0;
        if (i != 64) {
            set_err(err, errlen, "некорректный SHA256");
            return -1;
        }
    }
    return 0;
#endif
}

static int hex_eq_ci(const char *a, const char *b) {
    size_t i;
    for (i = 0; i < 64; i++) {
        char ca = (char)tolower((unsigned char)a[i]);
        char cb = (char)tolower((unsigned char)b[i]);
        if (!ca || !cb || ca != cb) return 0;
    }
    return 1;
}

/* ---------- install root ---------- */

int update_detect_install_root(const char *argv0_or_bindir, char *out, size_t n) {
    char base[PATH_MAX];
    char parent[PATH_MAX];
    char marker[PATH_MAX];
    const char *sub = os_cli_subdir();
    const char *gui = gui_marker_name();

    out[0] = 0;
    if (argv0_or_bindir && argv0_or_bindir[0]) {
        if (is_dir(argv0_or_bindir))
            snprintf(base, sizeof base, "%s", argv0_or_bindir);
        else
            path_dirname(argv0_or_bindir, base, sizeof base);
    } else {
#ifdef _WIN32
        if (!GetModuleFileNameA(NULL, base, (DWORD)sizeof base)) {
            snprintf(base, sizeof base, ".");
        } else {
            path_dirname(base, base, sizeof base);
        }
#elif defined(__APPLE__)
        {
            char tmp[PATH_MAX];
            uint32_t sz = sizeof tmp;
            if (_NSGetExecutablePath(tmp, &sz) == 0) {
                char real[PATH_MAX];
                if (realpath(tmp, real))
                    path_dirname(real, base, sizeof base);
                else
                    path_dirname(tmp, base, sizeof base);
            } else {
                snprintf(base, sizeof base, ".");
            }
        }
#else
        {
            char tmp[PATH_MAX];
            ssize_t r = readlink("/proc/self/exe", tmp, sizeof tmp - 1);
            if (r > 0) {
                tmp[r] = 0;
                path_dirname(tmp, base, sizeof base);
            } else {
                snprintf(base, sizeof base, ".");
            }
        }
#endif
    }

    /* If base is .../mac|linux|win, parent may be package root */
    if (strcmp(path_basename(base), sub) == 0) {
        path_dirname(base, parent, sizeof parent);
        path_join2(marker, sizeof marker, parent, gui);
        if (file_exists(marker) || is_dir(marker)) {
            snprintf(out, n, "%s", parent);
            return 0;
        }
        /* also: parent/bin layout already is package if VERSION sits next to subdir */
        {
            char ver[PATH_MAX];
            path_join2(ver, sizeof ver, parent, "VERSION");
            if (file_exists(ver)) {
                snprintf(out, n, "%s", parent);
                return 0;
            }
        }
        /* CLI-only */
        snprintf(out, n, "%s", base);
        return 0;
    }

    /* base itself may be package root (has OS subdir + GUI) */
    {
        char subdir[PATH_MAX];
        path_join2(subdir, sizeof subdir, base, sub);
        path_join2(marker, sizeof marker, base, gui);
        if (is_dir(subdir) && (file_exists(marker) || is_dir(marker))) {
            snprintf(out, n, "%s", base);
            return 0;
        }
        if (is_dir(subdir)) {
            /* package-like without GUI */
            char ver[PATH_MAX];
            path_join2(ver, sizeof ver, base, "VERSION");
            if (file_exists(ver)) {
                snprintf(out, n, "%s", base);
                return 0;
            }
        }
    }

    snprintf(out, n, "%s", base);
    return 0;
}

/* ---------- update_check ---------- */

int update_check(UpdateInfo *out, char *err, size_t errlen) {
    char repo[128], url[SU_STR], *body = NULL;
    char needle[80];
    char tag[32], html[256];

    if (!out) {
        set_err(err, errlen, "null UpdateInfo");
        return -1;
    }
    memset(out, 0, sizeof *out);
    default_repo(repo, sizeof repo);
    asset_needle(needle, sizeof needle);
    snprintf(url, sizeof url, "https://api.github.com/repos/%s/releases/latest", repo);

    body = (char *)malloc(SU_BIG);
    if (!body) {
        set_err(err, errlen, "out of memory");
        return -1;
    }
    if (http_get_body(url, body, SU_BIG, err, errlen) != 0) {
        free(body);
        return -1;
    }
    if (json_get_string(body, "tag_name", tag, sizeof tag) != 0) {
        free(body);
        set_err(err, errlen, "нет tag_name в ответе GitHub");
        return -1;
    }
    html[0] = 0;
    json_get_string(body, "html_url", html, sizeof html);

    snprintf(out->tag, sizeof out->tag, "%s", tag);
    {
        const char *v = tag;
        if (v[0] == 'v' || v[0] == 'V') v++;
        snprintf(out->version, sizeof out->version, "%s", v);
    }
    snprintf(out->html_url, sizeof out->html_url, "%s", html[0] ? html : url);

    if (json_find_asset(body, needle, out->asset_name, sizeof out->asset_name,
                        out->asset_url, sizeof out->asset_url,
                        out->sha256sums_url, sizeof out->sha256sums_url) != 0) {
        free(body);
        set_err(err, errlen, "нет ассета для этой ОС в latest release");
        return -1;
    }
    free(body);

    /* optional SHA256SUMS */
    if (out->sha256sums_url[0]) {
        char *sums = (char *)malloc(16384);
        if (sums) {
            char e2[128];
            if (http_get_body(out->sha256sums_url, sums, 16384, e2, sizeof e2) == 0)
                parse_sha256sums(sums, out->asset_name, out->sha256, sizeof out->sha256);
            free(sums);
        }
    }
    return 0;
}

/* ---------- temp dir / extract / helper ---------- */

static int make_temp_dir(char *out, size_t n, char *err, size_t errlen) {
#ifdef _WIN32
    char tmp[MAX_PATH], dir[MAX_PATH + 64];
    DWORD t = GetTickCount();
    if (!GetTempPathA(MAX_PATH, tmp)) {
        set_err(err, errlen, "GetTempPath failed");
        return -1;
    }
    snprintf(dir, sizeof dir, "%sconnect-check-update-%lu", tmp, (unsigned long)t);
    if (_mkdir(dir) != 0 && errno != EEXIST) {
        set_err(err, errlen, "не создать temp dir");
        return -1;
    }
    snprintf(out, n, "%s", dir);
    return 0;
#else
    char tmpl[] = "/tmp/connect-check-update-XXXXXX";
    if (!mkdtemp(tmpl)) {
        set_err(err, errlen, "mkdtemp failed");
        return -1;
    }
    snprintf(out, n, "%s", tmpl);
    return 0;
#endif
}

static int extract_archive(const char *archive, const char *dest, char *err, size_t errlen) {
    char cmd[SU_STR * 3];
#ifdef _WIN32
    /* Prefer tar (Win10+) then PowerShell Expand-Archive */
    if (strstr(archive, ".zip")) {
        snprintf(cmd, sizeof cmd,
                 "tar -xf \"%s\" -C \"%s\" 2>nul || "
                 "powershell -NoProfile -Command \"Expand-Archive -Force -Path '%s' -DestinationPath '%s'\"",
                 archive, dest, archive, dest);
    } else {
        snprintf(cmd, sizeof cmd, "tar -xzf \"%s\" -C \"%s\"", archive, dest);
    }
#else
    if (strstr(archive, ".zip"))
        snprintf(cmd, sizeof cmd, "unzip -qo '%s' -d '%s'", archive, dest);
    else
        snprintf(cmd, sizeof cmd, "tar -xzf '%s' -C '%s'", archive, dest);
#endif
    if (run_cmd(cmd) != 0) {
        set_err(err, errlen, "ошибка распаковки архива");
        return -1;
    }
    return 0;
}

static int verify_staging_layout(const char *staging, int package_root, char *err, size_t errlen) {
    char p[PATH_MAX];
    const char *sub = os_cli_subdir();
    if (package_root) {
        path_join2(p, sizeof p, staging, "VERSION");
        if (!file_exists(p)) {
            /* VERSION may be optional in older packs — check CLI */
        }
        path_join2(p, sizeof p, staging, sub);
        if (!is_dir(p)) {
            set_err(err, errlen, "в архиве нет каталога CLI для этой ОС");
            return -1;
        }
#ifdef _WIN32
        path_join2(p, sizeof p, staging, "win\\connect-check.exe");
#else
        {
            char cli[PATH_MAX];
            path_join2(cli, sizeof cli, staging, sub);
            path_join2(p, sizeof p, cli, "connect-check");
        }
#endif
        if (!file_exists(p)) {
            set_err(err, errlen, "в архиве нет connect-check");
            return -1;
        }
    } else {
        /* CLI-only staging may still have subdir layout from archive */
        char a[PATH_MAX], b[PATH_MAX];
        path_join2(a, sizeof a, staging, sub);
#ifdef _WIN32
        path_join2(b, sizeof b, a, "connect-check.exe");
        path_join2(p, sizeof p, staging, "connect-check.exe");
#else
        path_join2(b, sizeof b, a, "connect-check");
        path_join2(p, sizeof p, staging, "connect-check");
#endif
        if (!file_exists(b) && !file_exists(p)) {
            set_err(err, errlen, "после распаковки нет connect-check");
            return -1;
        }
    }
    return 0;
}

static int is_package_root(const char *root) {
    char sub[PATH_MAX], marker[PATH_MAX], ver[PATH_MAX];
    path_join2(sub, sizeof sub, root, os_cli_subdir());
    path_join2(marker, sizeof marker, root, gui_marker_name());
    path_join2(ver, sizeof ver, root, "VERSION");
    if (!is_dir(sub)) return 0;
    if (file_exists(marker) || is_dir(marker)) return 1;
    if (file_exists(ver)) return 1;
    return 0;
}

#ifdef _WIN32
static int write_helper_win(const char *helper_path, const char *staging,
                            const char *root, int package,
                            const char *relaunch_path, char *const relaunch_argv[],
                            DWORD parent_pid, char *err, size_t errlen) {
    FILE *fp = fopen(helper_path, "wb");
    char src[PATH_MAX];
    int i;
    if (!fp) {
        set_err(err, errlen, "не записать helper.cmd");
        return -1;
    }
    fprintf(fp, "@echo off\r\nsetlocal\r\n");
    fprintf(fp, "set PARENT=%lu\r\n", (unsigned long)parent_pid);
    fprintf(fp, "set STAGING=%s\r\n", staging);
    fprintf(fp, "set ROOT=%s\r\n", root);
    fprintf(fp, ":wait\r\n");
    fprintf(fp, "tasklist /FI \"PID eq %%PARENT%%\" 2>NUL | find \"%%PARENT%%\" >NUL\r\n");
    fprintf(fp, "if not errorlevel 1 (\r\n  timeout /t 1 /nobreak >NUL\r\n  goto wait\r\n)\r\n");
    fprintf(fp, "timeout /t 1 /nobreak >NUL\r\n");
    if (package) {
        /* robocopy: mirror staging into root (exit codes 0-7 = success) */
        fprintf(fp,
                "robocopy \"%%STAGING%%\" \"%%ROOT%%\" /E /R:2 /W:1 /NFL /NDL /NJH /NJS\r\n"
                "if %%ERRORLEVEL%% GEQ 8 exit /b 1\r\n");
    } else {
        path_join2(src, sizeof src, staging, "win");
        if (is_dir(src))
            fprintf(fp,
                    "robocopy \"%%STAGING%%\\win\" \"%%ROOT%%\" /E /R:2 /W:1 /NFL /NDL /NJH /NJS\r\n"
                    "if %%ERRORLEVEL%% GEQ 8 exit /b 1\r\n");
        else
            fprintf(fp,
                    "robocopy \"%%STAGING%%\" \"%%ROOT%%\" /E /R:2 /W:1 /NFL /NDL /NJH /NJS\r\n"
                    "if %%ERRORLEVEL%% GEQ 8 exit /b 1\r\n");
    }
    fprintf(fp, "rmdir /s /q \"%%STAGING%%\" 2>NUL\r\n");
    fprintf(fp, "start \"\" \"%s\"", relaunch_path);
    if (relaunch_argv) {
        for (i = 1; relaunch_argv[i]; i++)
            fprintf(fp, " \"%s\"", relaunch_argv[i]);
    }
    fprintf(fp, "\r\n");
    fprintf(fp, "del \"%%~f0\"\r\n");
    fclose(fp);
    return 0;
}
#else
static int write_helper_unix(const char *helper_path, const char *staging,
                             const char *root, int package,
                             const char *relaunch_path, char *const relaunch_argv[],
                             pid_t parent_pid, char *err, size_t errlen) {
    FILE *fp = fopen(helper_path, "w");
    int i;
    if (!fp) {
        set_err(err, errlen, "не записать helper.sh");
        return -1;
    }
    fprintf(fp, "#!/bin/sh\n");
    fprintf(fp, "PARENT=%d\n", (int)parent_pid);
    fprintf(fp, "STAGING='%s'\n", staging);
    fprintf(fp, "ROOT='%s'\n", root);
    fprintf(fp, "while kill -0 \"$PARENT\" 2>/dev/null; do sleep 0.3; done\n");
    fprintf(fp, "sleep 0.5\n");
    if (package) {
        fprintf(fp,
                "for item in \"$STAGING\"/* \"$STAGING\"/.[!.]*; do\n"
                "  [ -e \"$item\" ] || continue\n"
                "  name=$(basename \"$item\")\n"
                "  if [ -e \"$ROOT/$name\" ]; then\n"
                "    rm -rf \"$ROOT/$name.bak\"\n"
                "    mv \"$ROOT/$name\" \"$ROOT/$name.bak\" || true\n"
                "  fi\n"
                "  cp -R \"$item\" \"$ROOT/$name\"\n"
                "done\n");
#if defined(__APPLE__)
        fprintf(fp, "xattr -dr com.apple.quarantine \"$ROOT\" 2>/dev/null || true\n");
#endif
    } else {
        fprintf(fp,
                "SRC=\"$STAGING/%s\"\n"
                "if [ -d \"$SRC\" ]; then\n"
                "  cp -R \"$SRC\"/* \"$ROOT\"/\n"
                "else\n"
                "  cp -R \"$STAGING\"/* \"$ROOT\"/\n"
                "fi\n",
                os_cli_subdir());
#if defined(__APPLE__)
        fprintf(fp, "xattr -dr com.apple.quarantine \"$ROOT\" 2>/dev/null || true\n");
#endif
    }
    fprintf(fp, "rm -rf \"$STAGING\"\n");
    fprintf(fp, "exec '%s'", relaunch_path);
    if (relaunch_argv) {
        for (i = 1; relaunch_argv[i]; i++)
            fprintf(fp, " '%s'", relaunch_argv[i]);
    }
    fprintf(fp, "\n");
    fclose(fp);
    chmod(helper_path, 0700);
    return 0;
}
#endif

static int spawn_helper_and_exit(const char *helper_path) {
#ifdef _WIN32
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    char cmd[PATH_MAX + 32];
    memset(&si, 0, sizeof si);
    memset(&pi, 0, sizeof pi);
    si.cb = sizeof si;
    snprintf(cmd, sizeof cmd, "cmd.exe /c \"%s\"", helper_path);
    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE,
                        CREATE_NO_WINDOW | DETACHED_PROCESS, NULL, NULL, &si, &pi))
        return -1;
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    ExitProcess(0);
    return 0;
#else
    pid_t p = fork();
    if (p < 0) return -1;
    if (p == 0) {
        /* child: detach and run helper */
        if (setsid() < 0) { /* ignore */ }
        execl("/bin/sh", "sh", helper_path, (char *)NULL);
        _exit(127);
    }
    /* parent exits so helper can replace binaries */
    _exit(0);
    return 0;
#endif
}

int update_apply(const UpdateInfo *info, const char *install_root,
                 const char *relaunch_path, char *const relaunch_argv[],
                 char *err, size_t errlen) {
    char tmp[PATH_MAX + 128], archive[PATH_MAX + 128], staging[PATH_MAX + 128], helper[PATH_MAX + 128];
    char hex[80];
    const char *nou = getenv("CONNECT_CHECK_NO_UPDATE");
    int package;

    if (!info || !install_root || !install_root[0] || !relaunch_path || !relaunch_path[0]) {
        set_err(err, errlen, "некорректные аргументы update_apply");
        return -1;
    }
    if (nou && (nou[0] == '1' || nou[0] == 'y' || nou[0] == 'Y')) {
        set_err(err, errlen, "CONNECT_CHECK_NO_UPDATE=1 — apply отключён");
        return -1;
    }
    if (!info->asset_url[0]) {
        set_err(err, errlen, "нет URL ассета");
        return -1;
    }

    package = is_package_root(install_root);

    if (make_temp_dir(tmp, sizeof tmp, err, errlen) != 0) return -1;
    path_join2(archive, sizeof archive, tmp, info->asset_name[0] ? info->asset_name : "update.bin");
    path_join2(staging, sizeof staging, tmp, "staging");
#ifdef _WIN32
    _mkdir(staging);
#else
    mkdir(staging, 0755);
#endif

    if (http_download_file(info->asset_url, archive, err, errlen) != 0) return -1;

    if (file_size(archive) < 50 * 1024) {
        set_err(err, errlen, "архив слишком мал — возможно битый");
        return -1;
    }

    if (info->sha256[0]) {
        if (file_sha256_hex(archive, hex, sizeof hex, err, errlen) != 0) return -1;
        if (!hex_eq_ci(hex, info->sha256)) {
            set_err(err, errlen, "SHA256 ассета не совпал");
            return -1;
        }
    }

    if (extract_archive(archive, staging, err, errlen) != 0) return -1;
    if (verify_staging_layout(staging, package, err, errlen) != 0) return -1;

#ifdef _WIN32
    path_join2(helper, sizeof helper, tmp, "apply_update.cmd");
    if (write_helper_win(helper, staging, install_root, package,
                         relaunch_path, relaunch_argv, GetCurrentProcessId(),
                         err, errlen) != 0)
        return -1;
#else
    path_join2(helper, sizeof helper, tmp, "apply_update.sh");
    if (write_helper_unix(helper, staging, install_root, package,
                          relaunch_path, relaunch_argv, getpid(),
                          err, errlen) != 0)
        return -1;
#endif

    if (spawn_helper_and_exit(helper) != 0) {
        set_err(err, errlen, "не запустить helper обновления");
        return -1;
    }
    /* not reached */
    return 0;
}

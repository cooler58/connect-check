/*
 * macOS trampoline: CFBundleExecutable для ConnectCheck-mac.app.
 * Снимает com.apple.quarantine с бандла (после первого «Открыть» Gatekeeper)
 * и exec → connect-check-bin рядом. Без Terminal / .command.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <dirent.h>
#include <mach-o/dyld.h>

static void strip_quarantine_file(const char *path) {
    if (!path || !path[0]) return;
    removexattr(path, "com.apple.quarantine", XATTR_NOFOLLOW);
    removexattr(path, "com.apple.quarantine", 0);
}

static void strip_quarantine_tree(const char *root) {
    DIR *d;
    struct dirent *ent;
    struct stat st;
    char child[PATH_MAX];

    strip_quarantine_file(root);
    if (lstat(root, &st) != 0 || !S_ISDIR(st.st_mode))
        return;
    d = opendir(root);
    if (!d) return;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.' &&
            (ent->d_name[1] == 0 ||
             (ent->d_name[1] == '.' && ent->d_name[2] == 0)))
            continue;
        snprintf(child, sizeof child, "%s/%s", root, ent->d_name);
        if (lstat(child, &st) != 0) continue;
        if (S_ISDIR(st.st_mode))
            strip_quarantine_tree(child);
        else
            strip_quarantine_file(child);
    }
    closedir(d);
}

/* …/Contents/MacOS/connect-check-gui → …/ConnectCheck-mac.app */
static int app_bundle_root(const char *macos_exe, char *out, size_t n) {
    char tmp[PATH_MAX], *p;
    snprintf(tmp, sizeof tmp, "%s", macos_exe);
    p = strstr(tmp, "/Contents/MacOS/");
    if (!p) return 0;
    *p = 0;
    snprintf(out, n, "%s", tmp);
    return 1;
}

int main(int argc, char **argv) {
    char exe[PATH_MAX], macos_dir[PATH_MAX], app[PATH_MAX], bin[PATH_MAX];
    char *av[64];
    uint32_t sz = sizeof exe;
    int i;
    char *slash;

    if (_NSGetExecutablePath(exe, &sz) != 0) {
        fprintf(stderr, "connect-check: cannot resolve executable path\n");
        return 1;
    }
    /*
     * Не вызывать realpath(): при App Translocation он уводит на оригинал в Downloads,
     * а рядом с процессом нет connect-check-bin. Берём dirname от пути загрузки.
     */
    snprintf(macos_dir, sizeof macos_dir, "%s", exe);
    slash = strrchr(macos_dir, '/');
    if (!slash) {
        fprintf(stderr, "connect-check: bad path\n");
        return 1;
    }
    *slash = 0;

    if (app_bundle_root(exe, app, sizeof app))
        strip_quarantine_tree(app);
    /* также попробовать снять quarantine с «логического» .app, если путь другой */
    {
        char real[PATH_MAX];
        if (realpath(exe, real) && strcmp(real, exe) != 0) {
            char app2[PATH_MAX];
            if (app_bundle_root(real, app2, sizeof app2))
                strip_quarantine_tree(app2);
        }
    }

    snprintf(bin, sizeof bin, "%s/connect-check-bin", macos_dir);
    if (access(bin, X_OK) != 0) {
        fprintf(stderr, "connect-check: нет %s (%s)\n", bin, strerror(errno));
        return 1;
    }

    if (argc + 1 >= (int)(sizeof av / sizeof av[0]))
        argc = (int)(sizeof av / sizeof av[0]) - 2;
    av[0] = bin;
    for (i = 1; i < argc; i++)
        av[i] = argv[i];
    av[argc] = NULL;
    execv(bin, av);
    fprintf(stderr, "connect-check: exec %s: %s\n", bin, strerror(errno));
    return 1;
}

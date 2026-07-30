/* Self-update from GitHub Releases (cooler58/connect-check). */
#ifndef CONNECT_CHECK_SELFUPDATE_H
#define CONNECT_CHECK_SELFUPDATE_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char tag[32];           /* v1.2.0 */
    char version[32];       /* 1.2.0 */
    char asset_url[512];    /* browser_download_url */
    char asset_name[128];
    char html_url[512];     /* release page */
    char sha256[72];        /* hex or empty if unknown */
    char sha256sums_url[512];
} UpdateInfo;

/* Compare X.Y.Z (optional leading 'v'). Returns 1 if remote > local. */
int update_semver_gt(const char *remote, const char *local);

/* Fetch latest release for current OS/arch. Returns 0 on success. */
int update_check(UpdateInfo *out, char *err, size_t errlen);

/*
 * Detect install root (package dir with mac|linux|win + optional GUI).
 * Prefer argv0_or_bindir if set (CLI exe dir or GUI bindir).
 * Returns 0 on success.
 */
int update_detect_install_root(const char *argv0_or_bindir, char *out, size_t n);

/*
 * Download, verify, stage, write helper that swaps after this process exits,
 * then relaunches relaunch_path with relaunch_argv (NULL-terminated; argv[0]
 * should be the program path). Does not return on success (process exits 0
 * after spawning helper). Returns -1 on failure.
 *
 * Honours CONNECT_CHECK_NO_UPDATE=1 (refuses apply).
 */
int update_apply(const UpdateInfo *info, const char *install_root,
                 const char *relaunch_path, char *const relaunch_argv[],
                 char *err, size_t errlen);

#ifdef __cplusplus
}
#endif

#endif /* CONNECT_CHECK_SELFUPDATE_H */

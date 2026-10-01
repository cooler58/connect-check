/*
 * Скрытый spawn: GUI Windows собран с -mwindows, _popen/system()
 * каждый раз открывают cmd.exe с консолью (curl, ping, nslookup, tracert).
 */
#define _CRT_SECURE_NO_WARNINGS
#include "cc_spawn.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#endif

#ifndef CC_SPAWN_CMDLINE
#define CC_SPAWN_CMDLINE 8192
#endif

#ifdef _WIN32
static HANDLE win_nul(SECURITY_ATTRIBUTES *sa)
{
    HANDLE h = CreateFileA("NUL", GENERIC_READ | GENERIC_WRITE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE,
                           sa, OPEN_EXISTING, 0, NULL);
    return h == INVALID_HANDLE_VALUE ? NULL : h;
}

static int win_start(const char *cmd, HANDLE h_in, HANDLE h_out, HANDLE h_err,
                     PROCESS_INFORMATION *pi)
{
    STARTUPINFOA si;
    char cmdline[CC_SPAWN_CMDLINE];
    const char *comspec;

    memset(&si, 0, sizeof si);
    memset(pi, 0, sizeof *pi);
    si.cb = sizeof si;
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdInput = h_in ? h_in : INVALID_HANDLE_VALUE;
    si.hStdOutput = h_out ? h_out : INVALID_HANDLE_VALUE;
    si.hStdError = h_err ? h_err : INVALID_HANDLE_VALUE;

    comspec = getenv("COMSPEC");
    if (!comspec || !comspec[0]) comspec = "cmd.exe";
    if (snprintf(cmdline, sizeof cmdline, "%s /c %s", comspec, cmd) >= (int)sizeof cmdline)
        return -1;

    if (!CreateProcessA(NULL, cmdline, NULL, NULL, TRUE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, pi))
        return -1;
    return 0;
}

static int win_wait(PROCESS_INFORMATION *pi, DWORD *exit_out)
{
    DWORD exit_code = 1;
    WaitForSingleObject(pi->hProcess, INFINITE);
    GetExitCodeProcess(pi->hProcess, &exit_code);
    CloseHandle(pi->hThread);
    CloseHandle(pi->hProcess);
    if (exit_out) *exit_out = exit_code;
    return 0;
}
#endif

int cc_run_capture(const char *cmd, char *buf, size_t buflen)
{
    size_t n = 0;

    if (!buf || buflen == 0) return -1;
    buf[0] = 0;
    if (!cmd || !cmd[0]) return -1;

#ifdef _WIN32
    {
        SECURITY_ATTRIBUTES sa;
        PROCESS_INFORMATION pi;
        HANDLE rd = NULL, wr = NULL, nul = NULL;
        DWORD nread;
        char chunk[4096];

        sa.nLength = sizeof sa;
        sa.lpSecurityDescriptor = NULL;
        sa.bInheritHandle = TRUE;
        if (!CreatePipe(&rd, &wr, &sa, 0)) return -1;
        if (!SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0)) {
            CloseHandle(rd);
            CloseHandle(wr);
            return -1;
        }
        nul = win_nul(&sa);
        if (win_start(cmd, nul, wr, wr, &pi) != 0) {
            CloseHandle(rd);
            CloseHandle(wr);
            if (nul) CloseHandle(nul);
            return -1;
        }
        CloseHandle(wr);
        if (nul) CloseHandle(nul);
        while (ReadFile(rd, chunk, sizeof chunk, &nread, NULL) && nread > 0) {
            if (n + 1 < buflen) {
                size_t room = buflen - 1 - n;
                size_t take = (size_t)nread < room ? (size_t)nread : room;
                memcpy(buf + n, chunk, take);
                n += take;
            }
        }
        buf[n] = 0;
        CloseHandle(rd);
        win_wait(&pi, NULL);
        return 0;
    }
#else
    {
        FILE *fp = popen(cmd, "r");
        if (!fp) return -1;
        while (n + 1 < buflen) {
            size_t r = fread(buf + n, 1, buflen - 1 - n, fp);
            if (r == 0) break;
            n += r;
        }
        buf[n] = 0;
        pclose(fp);
        return 0;
    }
#endif
}

int cc_run_cmd(const char *cmd)
{
#ifdef _WIN32
    {
        SECURITY_ATTRIBUTES sa;
        PROCESS_INFORMATION pi;
        HANDLE nul;
        DWORD exit_code = 1;

        if (!cmd || !cmd[0]) return -1;
        sa.nLength = sizeof sa;
        sa.lpSecurityDescriptor = NULL;
        sa.bInheritHandle = TRUE;
        nul = win_nul(&sa);
        if (win_start(cmd, nul, nul, nul, &pi) != 0) {
            if (nul) CloseHandle(nul);
            return -1;
        }
        if (nul) CloseHandle(nul);
        win_wait(&pi, &exit_code);
        return exit_code == 0 ? 0 : (int)exit_code;
    }
#else
    return system(cmd);
#endif
}

/* Скрытый запуск внешней команды (без окна консоли на Windows GUI). */
#ifndef CONNECT_CHECK_CC_SPAWN_H
#define CONNECT_CHECK_CC_SPAWN_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* stdout+stderr в buf. 0 = процесс запущен (даже если команда вернула ошибку). */
int cc_run_capture(const char *cmd, char *buf, size_t buflen);

/* Как system(), но без окна консоли на Win32. 0 = успех. */
int cc_run_cmd(const char *cmd);

#ifdef __cplusplus
}
#endif

#endif

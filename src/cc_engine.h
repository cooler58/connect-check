/* connect-check engine — диагностика и пробы in-process (GUI / тесты). */
#ifndef CONNECT_CHECK_CC_ENGINE_H
#define CONNECT_CHECK_CC_ENGINE_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int yes;            /* без интерактива (как -y) */
    int skip_dns_bulk;
    int force_dns_bulk;
    int skip_video;
    int skip_speed;
    int no_open;        /* не открывать HTML в браузере */
    int jobs;           /* 0 = default */
    char outdir[512];
    char resources[1024];
    char workdir[1024]; /* cwd / корень пакета для resources.conf */
} CcOpts;

typedef struct {
    void (*on_log)(void *ud, const char *line);
    void (*on_progress)(void *ud, const char *msg, int cur, int total);
    void (*on_stage)(void *ud, const char *title, const char *desc);
    void (*on_check)(void *ud, const char *cat, const char *name,
                     const char *status, const char *detail);
    void (*on_finding)(void *ud, const char *level, const char *title, const char *text);
    void (*on_done)(void *ud, const char *report_path, int ok_n, int warn_n, int fail_n);
    void *userdata;
} CcCallbacks;

/* Полный прогон диагностики. 0 = без fail, 1 = были fail, <0 = ошибка/отмена. */
int cc_engine_run(const CcOpts *opts, const CcCallbacks *cb);

/*
 * Каталог этапов в порядке прогона (для GUI-чеклиста).
 * titles[i] — заголовок (как в on_stage); skipped[i]=1 если opts отключают этап
 * (видео/скорость/DNS-прогон). skipped может быть NULL.
 * Возвращает число этапов (≤ max).
 */
#define CC_STAGE_TITLE_LEN 96
int cc_engine_stages(const CcOpts *opts, char titles[][CC_STAGE_TITLE_LEN],
                     int *skipped, int max);

/* Запросить остановку (из UI-потока). */
void cc_engine_request_cancel(void);

/* Сброс флага отмены перед новым прогоном. */
void cc_engine_clear_cancel(void);

int cc_engine_cancel_requested(void);

/* ---- циклические пробы (бывшие probe-*) ---- */
typedef enum {
    CC_PROBE_CAPTIVE = 0,
    CC_PROBE_QUIC,
    CC_PROBE_BATTLENET,
    CC_PROBE_MQTT,
    CC_PROBE_VIDEO,
    CC_PROBE_URL,
    CC_PROBE_COUNT
} CcProbeKind;

typedef struct {
    int interval_sec;   /* >=1 */
    int rounds;         /* 0 = бесконечно */
    int follow;         /* только URL */
    char url[512];      /* только URL */
} CcProbeOpts;

/*
 * Блокирующий цикл пробы (вызывать из worker-thread).
 * log_line — каждая строка вывода; cancel — volatile флаг остановки.
 * Возврат: 0 ок, 1 были сбои, <0 ошибка аргументов.
 */
int cc_probe_run(CcProbeKind kind, const CcProbeOpts *opts,
                 void (*log_line)(void *ud, const char *line), void *ud,
                 volatile int *cancel);

const char *cc_probe_kind_name(CcProbeKind kind);

#ifdef __cplusplus
}
#endif

#endif /* CONNECT_CHECK_CC_ENGINE_H */

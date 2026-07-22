/* Единая версия connect-check. Переопределяется сборкой: -DCONNECT_CHECK_VERSION=\"…\" */
#ifndef CONNECT_CHECK_VERSION_H
#define CONNECT_CHECK_VERSION_H

#ifndef CONNECT_CHECK_VERSION
#define CONNECT_CHECK_VERSION "0.0.0-dev"
#endif

/* Формат resources.conf (секции [significant]/…). */
#ifndef CONNECT_CHECK_RESOURCES_FORMAT
#define CONNECT_CHECK_RESOURCES_FORMAT 1
#endif

#endif /* CONNECT_CHECK_VERSION_H */

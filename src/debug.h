#ifndef _DEBUG_H
#define _DEBUG_H

#ifdef DEBUG

#ifndef _LOG
#define _LOG(fmt, ...)              \
    do {                            \
        printf("debug: ");          \
        printf(fmt, ##__VA_ARGS__); \
        printf("\n");               \
    } while (0)
#endif

#endif

#endif /* DEBUG_H */

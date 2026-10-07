/*
 * can_log_fmt.h - tiny allocation-free CSV formatter for CAN frames.
 * Replaces snprintf(): much faster, no stdio/newlib overhead in the hot path.
 * Pure C with no hardware dependencies, so it can be unit-tested on a PC.
 *
 * Line format:   timestamp_ms,can_id,flags,dlc,data_hex\r\n
 *   can_id : hex, "0x" + 3 digits (11-bit id) or 8 digits (29-bit id)
 *   flags  : bit0 = extended (29-bit) id, bit1 = remote-transmission-request
 *   data   : payload bytes as hex, no separators ("" for RTR / dlc 0)
 *   e.g.   1523,0x101,0,8,E803D2040000FFFF
 */
#ifndef CAN_LOG_FMT_H
#define CAN_LOG_FMT_H

#include <stddef.h>
#include <stdint.h>

#define CAN_LOG_FLAG_EXT  0x01u
#define CAN_LOG_FLAG_RTR  0x02u
#define CAN_LOG_LINE_MAX  64u    /* longest possible line is 44 bytes */

#define CAN_LOG_HEADER "timestamp_ms,can_id,flags,dlc,data_hex\r\n"

static inline char *fmt_u32(char *p, uint32_t v)
{
    char tmp[10];
    int n = 0;
    do { tmp[n++] = (char)('0' + (v % 10u)); v /= 10u; } while (v);
    while (n) *p++ = tmp[--n];
    return p;
}

static inline char *fmt_hex(char *p, uint32_t v, int digits)
{
    static const char hex[] = "0123456789ABCDEF";
    for (int i = digits - 1; i >= 0; i--) *p++ = hex[(v >> (4 * i)) & 0xFu];
    return p;
}

/* Writes one CSV line into buf (>= CAN_LOG_LINE_MAX bytes). Returns its length. */
static inline size_t fmt_can_frame(char *buf, uint32_t t_ms, uint32_t id,
                                   uint8_t flags, uint8_t dlc, const uint8_t *data)
{
    char *p = buf;
    if (dlc > 8) dlc = 8;                      /* never trust the wire */

    p = fmt_u32(p, t_ms);
    *p++ = ',';
    *p++ = '0'; *p++ = 'x';
    p = (flags & CAN_LOG_FLAG_EXT) ? fmt_hex(p, id & 0x1FFFFFFFu, 8)
                                   : fmt_hex(p, id & 0x7FFu, 3);
    *p++ = ',';
    p = fmt_u32(p, flags);
    *p++ = ',';
    p = fmt_u32(p, dlc);
    *p++ = ',';
    if (!(flags & CAN_LOG_FLAG_RTR)) {
        for (uint8_t i = 0; i < dlc; i++) p = fmt_hex(p, data[i], 2);
    }
    *p++ = '\r';
    *p++ = '\n';
    return (size_t)(p - buf);
}

#endif /* CAN_LOG_FMT_H */

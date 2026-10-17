/* Small utilities shared by every layer: clocks, randomness, logging, hex.
 *
 * Nothing Matter-specific lives here. The one design point worth noting is
 * that all protocol timers (retransmissions, fail-safe, subscriptions) use a
 * MONOTONIC clock, so changing the wall-clock time can't fire or stall them.
 */
#include "matter.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/rand.h>

int g_verbose;   /* set by -v; gates DBG() and hexdump() */

/* Milliseconds since an arbitrary point (boot). Only differences matter. */
uint64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* Cryptographic randomness (OpenSSL's CSPRNG). Used for keys, nonces, salts,
 * session/exchange ids and message counters. Failing here would make every
 * key predictable, so we abort rather than continue. */
void rand_bytes(void *p, size_t n)
{
    if (RAND_bytes(p, (int)n) != 1)
        abort();
}

uint32_t rand_u32(void)
{
    uint32_t v;
    rand_bytes(&v, sizeof v);
    return v;
}

/* Wall-clock timestamp printed before each log line (for humans only). */
void log_prefix(void)
{
    struct timespec ts;
    struct tm tm;
    clock_gettime(CLOCK_REALTIME, &ts);
    localtime_r(&ts.tv_sec, &tm);
    printf("%02d:%02d:%02d.%03ld ", tm.tm_hour, tm.tm_min, tm.tm_sec, ts.tv_nsec / 1000000);
}

/* Debug helper: dump bytes as hex, 32 per line (only with -v). */
void hexdump(const char *label, const void *p, size_t n)
{
    if (!g_verbose)
        return;
    const uint8_t *b = p;
    log_prefix();
    printf("%s (%zu):", label, n);
    for (size_t i = 0; i < n; i++)
        printf("%s%02x", (i % 32) ? "" : "\n    ", b[i]);
    printf("\n");
}

/* Decode a hex string of exactly 2*outlen characters. Used for the SPAKE2+
 * constant points M and N, which are easier to audit as hex literals. */
int hex2bin(const char *hex, uint8_t *out, size_t outlen)
{
    size_t n = strlen(hex);
    if (n != outlen * 2)
        return -1;
    for (size_t i = 0; i < outlen; i++) {
        unsigned v;
        if (sscanf(hex + 2 * i, "%2x", &v) != 1)
            return -1;
        out[i] = (uint8_t)v;
    }
    return 0;
}

/* Minimal hand-written Matter accessory (On/Off Light) — shared declarations.
 *
 * =====================================================================
 *  BIG PICTURE
 * =====================================================================
 *
 * Matter is an application-layer smart-home protocol that runs over IPv6
 * (UDP port 5540 here). A Matter *node* — this program — exposes a
 * *data model*:
 *
 *      node
 *       └─ endpoints (0 = "root node" utilities, 1 = our light)
 *           └─ clusters (e.g. On/Off = 0x0006)
 *               ├─ attributes (e.g. OnOff = 0x0000, a bool)
 *               └─ commands   (e.g. Off = 0, On = 1, Toggle = 2)
 *
 * Controllers (Apple Home on an iPhone, a HomePod acting as hub, Google,
 * Home Assistant...) read/write attributes and invoke commands over
 * encrypted sessions.
 *
 * The stack, bottom to top, and the file implementing each layer:
 *
 *   +---------------------------------------------------------------+
 *   | Data model: clusters on endpoints                  clusters.c |
 *   +---------------------------------------------------------------+
 *   | Interaction Model: Read/Subscribe/Write/Invoke           im.c |
 *   +---------------------------------------------------------------+
 *   | Secure Channel: PASE + CASE handshakes       secure_channel.c |
 *   +---------------------------------------------------------------+
 *   | Message layer: headers, AES-CCM, acks/retries    transport.c |
 *   +---------------------------------------------------------------+
 *   | UDP / IPv6 (port 5540)                                        |
 *   +---------------------------------------------------------------+
 *
 *   Side services:
 *     mdns.c          — DNS-SD so controllers can *find* us
 *     fabric.c        — trust domains ("fabrics") + on-disk state
 *     tlv.c           — the binary encoding every payload uses
 *     crypto.c        — OpenSSL wrappers + the SPAKE2+ math
 *     setup_payload.c — the QR / 11-digit pairing code
 *     creds.c         — the (public, test) factory certificates
 *     main.c          — event loop, commissioning window, fail-safe
 *
 * =====================================================================
 *  LIFE OF THE DEVICE
 * =====================================================================
 *
 *  1. Boot with no fabrics -> open a "commissioning window": advertise
 *     _matterc._udp over mDNS and print the setup code.
 *  2. A commissioner (e.g. iPhone) finds us and runs PASE: a password-
 *     authenticated key exchange keyed by the setup passcode. Result: an
 *     encrypted session, without any certificates.
 *  3. Over that PASE session it: arms the fail-safe timer, checks our
 *     device attestation (DAC -> PAI -> PAA chain + Certification
 *     Declaration), asks us to generate a key pair and CSR, then installs
 *     a root CA certificate and our Node Operational Certificate (NOC).
 *     That set of credentials is a *fabric*.
 *  4. We now advertise _matter._tcp (operational discovery). The
 *     controller connects with CASE (a certificate-based handshake, like a
 *     tiny TLS) and sends CommissioningComplete. Fabric committed.
 *  5. From then on controllers open CASE sessions, subscribe to
 *     attributes and invoke commands (On/Off/Toggle).
 *
 *  Suggested reading order: util -> tlv -> crypto -> setup_payload ->
 *  fabric -> transport -> secure_channel -> mdns -> im -> clusters -> main.
 *
 *  All multi-byte integers on the Matter wire are LITTLE-endian, except
 *  where noted (a few key-derivation inputs use big-endian).
 */
#ifndef MATTER_H
#define MATTER_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <netinet/in.h>

/* ------------------------------------------------------------------ util */
/* Small helpers used everywhere: time, randomness, logging, byte packing. */

extern int g_verbose;                 /* -v flag: enables DBG() and hexdump() */
uint64_t now_ms(void);                /* monotonic milliseconds; all timers use this */
void rand_bytes(void *p, size_t n);   /* cryptographically secure random bytes */
uint32_t rand_u32(void);
void log_prefix(void);                /* prints "HH:MM:SS.mmm " */
void hexdump(const char *label, const void *p, size_t n);
int hex2bin(const char *hex, uint8_t *out, size_t outlen);

/* LOG always prints; DBG only with -v. Both append a newline. */
#define LOG(...) do { log_prefix(); printf(__VA_ARGS__); printf("\n"); fflush(stdout); } while (0)
#define DBG(...) do { if (g_verbose) LOG(__VA_ARGS__); } while (0)

/* Byte-order helpers. Matter is little-endian on the wire, so these are used
 * for every header field. put_be64 exists for the few big-endian KDF inputs. */
static inline void put_le16(uint8_t *p, uint16_t v) { p[0] = v; p[1] = v >> 8; }
static inline void put_le32(uint8_t *p, uint32_t v) { for (int i = 0; i < 4; i++) p[i] = v >> (8 * i); }
static inline void put_le64(uint8_t *p, uint64_t v) { for (int i = 0; i < 8; i++) p[i] = v >> (8 * i); }
static inline void put_be64(uint8_t *p, uint64_t v) { for (int i = 0; i < 8; i++) p[i] = v >> (8 * (7 - i)); }
static inline uint16_t get_le16(const uint8_t *p) { return p[0] | (p[1] << 8); }
static inline uint32_t get_le32(const uint8_t *p) { return p[0] | (p[1] << 8) | (p[2] << 16) | ((uint32_t)p[3] << 24); }
static inline uint64_t get_le64(const uint8_t *p) { return get_le32(p) | ((uint64_t)get_le32(p + 4) << 32); }

#endif

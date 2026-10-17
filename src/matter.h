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

/* ------------------------------------------------------------------- TLV */
/* TLV (Tag-Length-Value) is Matter's binary serialization, a bit like a
 * compact CBOR. Every Interaction Model message, every handshake message and
 * even Matter certificates are TLV. Each element = control byte (tag form +
 * type), optional tag bytes, optional length, value. See tlv.c for details.
 *
 * Tags: in Matter payloads you almost only see two kinds:
 *   - anonymous   (no tag)   — top-level structs, array items
 *   - context tag (0..255)   — struct fields, meaning depends on the schema
 * We represent "anonymous" as TLV_ANON and any profile tag as TLV_OTHER. */

#define TLV_ANON  0xFFFFFFFFu   /* anonymous tag */
#define TLV_OTHER 0xFFFFFFFEu   /* profile tag (unsupported, parsed and ignored) */

/* Normalised element types (the wire has several widths per type). */
enum { TLV_T_INT, TLV_T_UINT, TLV_T_BOOL, TLV_T_FLOAT, TLV_T_UTF8, TLV_T_BYTES,
       TLV_T_NULL, TLV_T_STRUCT, TLV_T_ARRAY, TLV_T_LIST, TLV_T_END };

/* Writer: appends into a caller-provided buffer. On overflow it sets err and
 * stops writing, so callers can emit a whole message and check err once. */
typedef struct { uint8_t *buf; size_t cap, len; int err; } tlv_w;

/* A parsed element. Parsing is zero-copy: p/raw point into the input. */
typedef struct {
    int type;
    uint32_t tag;
    uint64_t u;              /* unsigned / bool value */
    int64_t i;               /* signed value */
    const uint8_t *p;        /* string data, or container contents (without end marker) */
    size_t n;
    const uint8_t *raw;      /* the whole encoded element */
    size_t rawlen;
} tlv_el;

/* Iterator over the direct children of a container element. */
typedef struct { const uint8_t *p, *end; } tlv_it;

void tlv_w_init(tlv_w *w, uint8_t *buf, size_t cap);
void tlv_put_uint(tlv_w *w, uint32_t tag, uint64_t v);
void tlv_put_int(tlv_w *w, uint32_t tag, int64_t v);
void tlv_put_bool(tlv_w *w, uint32_t tag, int v);
void tlv_put_null(tlv_w *w, uint32_t tag);
void tlv_put_bytes(tlv_w *w, uint32_t tag, const void *p, size_t n);
void tlv_put_str(tlv_w *w, uint32_t tag, const char *s);
void tlv_start(tlv_w *w, uint32_t tag, int type);   /* open struct/array/list ... */
void tlv_end(tlv_w *w);                              /* ... and close it */
void tlv_put_raw(tlv_w *w, const void *p, size_t n); /* splice pre-encoded TLV */
/* copy an element, replacing its tag (only for elements whose tag is anonymous or context) */
void tlv_put_retag(tlv_w *w, uint32_t tag, const tlv_el *e);

int tlv_parse(const uint8_t *p, size_t n, tlv_el *out);       /* parse one element; 0 = ok */
void tlv_iter(tlv_it *it, const tlv_el *container);
int tlv_next(tlv_it *it, tlv_el *out);                         /* 1 = got a child, 0 = done */
int tlv_get(const tlv_el *container, uint32_t tag, tlv_el *out); /* find child by context tag */
uint64_t tlv_get_u(const tlv_el *container, uint32_t tag, uint64_t def); /* int field or default */

/* ---------------------------------------------------------------- crypto */
/* Matter fixes one cipher suite: P-256 ECC, SHA-256, HMAC/HKDF/PBKDF2 over
 * SHA-256 and AES-128-CCM with a 16-byte tag. OpenSSL does the primitives;
 * SPAKE2+ (used by PASE) is assembled here from raw EC point math. */

/* A P-256 key pair in raw form: 32-byte scalar + 65-byte uncompressed point
 * (0x04 || X || Y). Matter puts public keys on the wire in this format. */
typedef struct { uint8_t priv[32]; uint8_t pub[65]; } p256_key;

void crypto_init(void);
void sha256(const void *d, size_t n, uint8_t out[32]);
void hmac_sha256(const uint8_t *key, size_t kl, const void *d, size_t n, uint8_t out[32]);
/* HKDF (RFC 5869). Matter uses this for nearly every key derivation; 'info'
 * is a short ASCII label such as "SessionKeys" or "Sigma2". */
int hkdf_sha256(const uint8_t *salt, size_t sl, const uint8_t *ikm, size_t il,
                const char *info, uint8_t *out, size_t outl);
/* AES-128-CCM, 13-byte nonce, 16-byte tag (Matter's only AEAD). */
int aes_ccm_encrypt(const uint8_t key[16], const uint8_t nonce[13], const uint8_t *aad, size_t al,
                    const uint8_t *pt, size_t n, uint8_t *ct, uint8_t tag[16]);
int aes_ccm_decrypt(const uint8_t key[16], const uint8_t nonce[13], const uint8_t *aad, size_t al,
                    const uint8_t *ct, size_t n, uint8_t *pt, const uint8_t tag[16]);
int p256_keygen(p256_key *k);
int p256_from_priv(p256_key *k);                 /* fills k->pub from k->priv */
int p256_from_der(const uint8_t *der, size_t n, p256_key *k);
/* ECDSA over SHA-256(msg). Signatures are raw 64 bytes r||s (not DER). */
int p256_sign(const p256_key *k, const void *msg, size_t n, uint8_t sig[64]);
int p256_verify(const uint8_t pub[65], const void *msg, size_t n, const uint8_t sig[64]);
int p256_ecdh(const p256_key *k, const uint8_t peer[65], uint8_t secret[32]);
int p256_csr(const p256_key *k, uint8_t *out, size_t *outlen);  /* PKCS#10, DER */

/* SPAKE2+ (verifier side only)
 * The device is the "verifier": it never needs the passcode itself, only the
 * verifier (w0, L) derived from it. See crypto.c for the full math. */
int spake_verifier(uint32_t passcode, const uint8_t *salt, size_t sl, uint32_t iters,
                   uint8_t w0[32], uint8_t L[65]);
int spake_respond(const uint8_t w0[32], const uint8_t L[65], const uint8_t context[32],
                  const uint8_t X[65], uint8_t Y[65], uint8_t cB[32], uint8_t cA_expected[32],
                  uint8_t Ke[16]);

#endif

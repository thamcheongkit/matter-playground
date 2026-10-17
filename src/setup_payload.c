/* Onboarding payloads: QR code string ("MT:...") and 11-digit manual pairing code.
 *
 * These are what the user scans or types. Both encode, at minimum:
 *   - the discriminator (12 bits): which advertising device to talk to
 *   - the passcode (27 bits):      the shared secret for PASE/SPAKE2+
 * The QR code additionally carries vendor/product id and how to discover the
 * device ("rendezvous" capabilities: bit1 BLE, bit2 on-network, ...).
 */
#include "matter.h"

#include <string.h>

/* QR payload = "MT:" + Base38(88-bit packed record).
 *
 * The record is packed LSB-first: each field's least significant bit goes at
 * the current bit offset, then the offset advances by the field width.
 *
 *   bits  0..2   version (0)
 *   bits  3..18  vendor id
 *   bits 19..34  product id
 *   bits 35..36  commissioning flow (0 = standard)
 *   bits 37..44  discovery capabilities (0x04 = already on the IP network)
 *   bits 45..56  discriminator (all 12 bits)
 *   bits 57..83  passcode
 *   bits 84..87  padding
 *
 * Base38 uses digits, A-Z, '-' and '.', which are all QR "alphanumeric"
 * characters (denser QR codes than binary mode). Every 3 bytes, read as a
 * little-endian integer, become 5 characters (least significant first); a
 * trailing 2-byte chunk becomes 4 characters, a 1-byte chunk 2. */
void setup_qr(char out[32], uint16_t vid, uint16_t pid, uint8_t caps, uint16_t disc, uint32_t pin)
{
    static const char b38[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-.";
    uint8_t b[11] = { 0 };
    int off = 0;
    /* fields are packed LSB-first: version(3) vid(16) pid(16) flow(2) caps(8) disc(12) pin(27) pad(4) */
    const struct { uint32_t v; int bits; } f[] = {
        { 0, 3 }, { vid, 16 }, { pid, 16 }, { 0, 2 }, { caps, 8 }, { disc, 12 }, { pin, 27 }, { 0, 4 },
    };
    for (size_t i = 0; i < sizeof f / sizeof f[0]; i++)
        for (int k = 0; k < f[i].bits; k++, off++)
            if ((f[i].v >> k) & 1)
                b[off / 8] |= 1 << (off % 8);

    char *o = out + 3;
    memcpy(out, "MT:", 3);
    for (int i = 0; i < 11; i += 3) {          /* chunks of 3, 3, 3, 2 bytes */
        int n = 11 - i < 3 ? 11 - i : 3;
        uint32_t v = 0;
        for (int j = 0; j < n; j++)
            v |= (uint32_t)b[i + j] << (8 * j);
        for (int c = 0; c < (n == 3 ? 5 : n == 2 ? 4 : 2); c++) {
            *o++ = b38[v % 38];
            v /= 38;
        }
    }
    *o = 0;
}

/* Verhoeff check digit: detects every single-digit error and every swap of
 * adjacent digits, which are the typical typing mistakes. 'd' is the
 * multiplication table of the dihedral group D5, 'p' a position permutation
 * and 'inv' the group inverse. */
static int verhoeff(const char *s)
{
    static const uint8_t d[10][10] = {
        { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 }, { 1, 2, 3, 4, 0, 6, 7, 8, 9, 5 },
        { 2, 3, 4, 0, 1, 7, 8, 9, 5, 6 }, { 3, 4, 0, 1, 2, 8, 9, 5, 6, 7 },
        { 4, 0, 1, 2, 3, 9, 5, 6, 7, 8 }, { 5, 9, 8, 7, 6, 0, 4, 3, 2, 1 },
        { 6, 5, 9, 8, 7, 1, 0, 4, 3, 2 }, { 7, 6, 5, 9, 8, 2, 1, 0, 4, 3 },
        { 8, 7, 6, 5, 9, 3, 2, 1, 0, 4 }, { 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 },
    };
    static const uint8_t p[8][10] = {
        { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 }, { 1, 5, 7, 6, 2, 8, 3, 0, 9, 4 },
        { 5, 8, 0, 3, 7, 9, 6, 1, 4, 2 }, { 8, 9, 1, 6, 0, 4, 3, 5, 2, 7 },
        { 9, 4, 5, 3, 1, 2, 6, 8, 7, 0 }, { 4, 2, 8, 6, 5, 7, 3, 9, 0, 1 },
        { 2, 7, 9, 3, 8, 0, 6, 4, 1, 5 }, { 7, 0, 4, 6, 9, 1, 3, 2, 5, 8 },
    };
    static const uint8_t inv[10] = { 0, 4, 3, 2, 1, 5, 6, 7, 8, 9 };
    int c = 0, len = (int)strlen(s);
    for (int i = 0; i < len; i++)
        c = d[c][p[(i + 1) % 8][s[len - 1 - i] - '0']];
    return inv[c];
}

/* 11-digit manual code (the "3497-011-2332" printed under the QR):
 *
 *   digit  1      : bit2 = "vid/pid present" (0 here), bits1..0 = top 2 bits
 *                   of the 4-bit *short* discriminator (disc >> 8)
 *   digits 2..6   : low 2 bits of short discriminator << 14 | passcode[13:0]
 *   digits 7..10  : passcode[26:14]
 *   digit  11     : Verhoeff check digit
 *
 * Only the short (4-bit) discriminator fits, so a commissioner using this
 * code may find several candidates and tries PASE with each.
 * Example: passcode 20202021, discriminator 3840 -> 34970112332. */
void setup_manual(char out[12], uint16_t disc, uint32_t pin)
{
    unsigned sd = (disc >> 8) & 0xF;
    unsigned c1 = (sd >> 2) & 0x3;
    unsigned c2 = ((sd & 0x3) << 14) | (pin & 0x3FFF);
    unsigned c3 = pin >> 14;
    char tmp[32];
    snprintf(tmp, sizeof tmp, "%01u%05u%04u", c1, c2 % 100000, c3 % 10000);
    memcpy(out, tmp, 10);
    out[10] = 0;
    out[10] = (char)('0' + verhoeff(out));
    out[11] = 0;
}

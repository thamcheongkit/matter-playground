/* Matter TLV encoder / decoder (anonymous and context tags only).
 *
 * WIRE FORMAT
 * ===========
 * Every element starts with a control byte:
 *
 *     bit  7 6 5 | 4 3 2 1 0
 *         tag    | element
 *         control| type
 *
 * Tag control (bits 7..5) says how many tag bytes follow:
 *     0 = anonymous (0 bytes)          1 = context tag (1 byte, 0..255)
 *     2/3 = common profile (2/4 bytes) 4/5 = implicit profile (2/4)
 *     6/7 = fully qualified (6/8)
 * Matter messages use only 0 and 1, so the writer only produces those.
 *
 * Element type (bits 4..0):
 *     0x00-0x03  signed int,   1/2/4/8 bytes
 *     0x04-0x07  unsigned int, 1/2/4/8 bytes
 *     0x08/0x09  false / true (no value bytes)
 *     0x0A/0x0B  float / double
 *     0x0C-0x0F  UTF-8 string, length field 1/2/4/8 bytes, then data
 *     0x10-0x13  octet string, length field 1/2/4/8 bytes, then data
 *     0x14       null
 *     0x15       structure  (children have unique tags, usually context)
 *     0x16       array      (children are anonymous, ordered)
 *     0x17       list       (ordered, tags allowed - used for "paths")
 *     0x18       end of container
 *
 * EXAMPLE: { 1: true, 2: 300 } as an anonymous struct:
 *     15             start anonymous struct
 *     29 01          context tag 1, true            (0x20 | 0x09)
 *     25 02 2c 01    context tag 2, uint16 = 300    (0x20 | 0x05)
 *     18             end of container
 *
 * Integers may use any width; we always pick the smallest that fits.
 * Everything is little-endian.
 */
#include "matter.h"

#include <string.h>

/* ============================================================== writer */

void tlv_w_init(tlv_w *w, uint8_t *buf, size_t cap)
{
    w->buf = buf;
    w->cap = cap;
    w->len = 0;
    w->err = 0;
}

/* Append bytes. Once err is set, all further writes are ignored ("sticky
 * error"), so callers can build a whole message and check err once. */
static void wr(tlv_w *w, const void *p, size_t n)
{
    if (w->err || w->len + n > w->cap) {
        w->err = 1;
        return;
    }
    if (n)
        memcpy(w->buf + w->len, p, n);
    w->len += n;
}

/* Write the control byte (+ tag byte for context tags). 'type' is the raw
 * 5-bit element type from the table above. */
static void wr_ctl(tlv_w *w, uint32_t tag, uint8_t type)
{
    if (tag == TLV_ANON) {
        wr(w, &type, 1);
    } else {
        uint8_t c[2] = { (uint8_t)(0x20 | type), (uint8_t)tag };
        wr(w, c, 2);
    }
}

/* Unsigned integer in the smallest width: types 0x04 (u8) .. 0x07 (u64). */
void tlv_put_uint(tlv_w *w, uint32_t tag, uint64_t v)
{
    uint8_t b[8];
    if (v <= 0xFF) {
        wr_ctl(w, tag, 0x04); b[0] = (uint8_t)v; wr(w, b, 1);
    } else if (v <= 0xFFFF) {
        wr_ctl(w, tag, 0x05); put_le16(b, (uint16_t)v); wr(w, b, 2);
    } else if (v <= 0xFFFFFFFFu) {
        wr_ctl(w, tag, 0x06); put_le32(b, (uint32_t)v); wr(w, b, 4);
    } else {
        wr_ctl(w, tag, 0x07); put_le64(b, v); wr(w, b, 8);
    }
}

/* Signed integer in the smallest width: types 0x00 (i8) .. 0x03 (i64). */
void tlv_put_int(tlv_w *w, uint32_t tag, int64_t v)
{
    uint8_t b[8];
    if (v >= INT8_MIN && v <= INT8_MAX) {
        wr_ctl(w, tag, 0x00); b[0] = (uint8_t)v; wr(w, b, 1);
    } else if (v >= INT16_MIN && v <= INT16_MAX) {
        wr_ctl(w, tag, 0x01); put_le16(b, (uint16_t)v); wr(w, b, 2);
    } else if (v >= INT32_MIN && v <= INT32_MAX) {
        wr_ctl(w, tag, 0x02); put_le32(b, (uint32_t)v); wr(w, b, 4);
    } else {
        wr_ctl(w, tag, 0x03); put_le64(b, (uint64_t)v); wr(w, b, 8);
    }
}

/* Booleans and null carry their value in the type field itself. */
void tlv_put_bool(tlv_w *w, uint32_t tag, int v) { wr_ctl(w, tag, v ? 0x09 : 0x08); }
void tlv_put_null(tlv_w *w, uint32_t tag) { wr_ctl(w, tag, 0x14); }

/* Strings: 'base' is 0x0C (UTF-8) or 0x10 (bytes); +0/+1/+2 selects a
 * 1/2/4-byte length prefix. */
static void put_lenstr(tlv_w *w, uint32_t tag, uint8_t base, const void *p, size_t n)
{
    uint8_t b[4];
    if (n <= 0xFF) {
        wr_ctl(w, tag, base); b[0] = (uint8_t)n; wr(w, b, 1);
    } else if (n <= 0xFFFF) {
        wr_ctl(w, tag, base + 1); put_le16(b, (uint16_t)n); wr(w, b, 2);
    } else {
        wr_ctl(w, tag, base + 2); put_le32(b, (uint32_t)n); wr(w, b, 4);
    }
    wr(w, p, n);
}

void tlv_put_bytes(tlv_w *w, uint32_t tag, const void *p, size_t n) { put_lenstr(w, tag, 0x10, p, n); }
void tlv_put_str(tlv_w *w, uint32_t tag, const char *s) { put_lenstr(w, tag, 0x0C, s, strlen(s)); }

/* Containers have no length prefix: they open with 0x15/0x16/0x17 and close
 * with 0x18. Callers must balance every tlv_start() with a tlv_end(). */
void tlv_start(tlv_w *w, uint32_t tag, int type)
{
    wr_ctl(w, tag, type == TLV_T_STRUCT ? 0x15 : type == TLV_T_ARRAY ? 0x16 : 0x17);
}

void tlv_end(tlv_w *w)
{
    uint8_t c = 0x18;
    wr(w, &c, 1);
}

/* Splice in bytes that are already valid TLV (e.g. a stored certificate
 * struct or a child element copied verbatim from a request). */
void tlv_put_raw(tlv_w *w, const void *p, size_t n) { wr(w, p, n); }

/* Copy an element but give it a new tag. Used to move an anonymous array
 * item into a context-tagged field (e.g. list chunking in im.c puts each
 * item under tag 2 = "Data"). Only works for anonymous/context sources
 * because only those have a tag we know how to strip. */
void tlv_put_retag(tlv_w *w, uint32_t tag, const tlv_el *e)
{
    uint8_t ctl = e->raw[0];
    size_t skip = (ctl >> 5) == 0 ? 1 : (ctl >> 5) == 1 ? 2 : 0;
    if (!skip) {
        w->err = 1;
        return;
    }
    wr_ctl(w, tag, ctl & 0x1F);
    wr(w, e->raw + skip, e->rawlen - skip);
}

/* ============================================================== reader */

/* Parse the element at p (not past end) into *e. For containers we walk all
 * children (recursively) just to find the matching end marker, so that
 * e->p/e->n cover exactly the contents and e->rawlen covers the whole thing.
 * This makes the reader stateless: to look inside a container you iterate
 * over e->p .. e->p+e->n. 'depth' bounds recursion on hostile input. */
static int parse_at(const uint8_t *p, const uint8_t *end, tlv_el *e, int depth)
{
    static const uint8_t taglen[8] = { 0, 1, 2, 4, 2, 4, 6, 8 };
    const uint8_t *start = p;
    if (p >= end)
        return -1;
    uint8_t ctl = *p++;
    int tc = ctl >> 5, et = ctl & 0x1F;
    if ((size_t)(end - p) < taglen[tc])
        return -1;
    memset(e, 0, sizeof *e);
    e->tag = tc == 0 ? TLV_ANON : tc == 1 ? p[0] : TLV_OTHER;
    p += taglen[tc];
    e->raw = start;

    if (et <= 0x07) {                         /* integers */
        size_t n = (size_t)1 << (et & 3);    /* low 2 bits = log2(width) */
        if ((size_t)(end - p) < n)
            return -1;
        uint64_t v = n == 1 ? p[0] : n == 2 ? get_le16(p) : n == 4 ? get_le32(p) : get_le64(p);
        if (et <= 0x03) {
            /* sign-extend from the encoded width */
            e->type = TLV_T_INT;
            e->i = n == 1 ? (int8_t)v : n == 2 ? (int16_t)v : n == 4 ? (int32_t)v : (int64_t)v;
            e->u = (uint64_t)e->i;
        } else {
            e->type = TLV_T_UINT;
            e->u = v;
            e->i = (int64_t)v;
        }
        p += n;
    } else if (et == 0x08 || et == 0x09) {
        e->type = TLV_T_BOOL;
        e->u = et & 1;
    } else if (et == 0x0A || et == 0x0B) {
        /* floats are skipped over; nothing in this device needs their value */
        size_t n = et == 0x0A ? 4 : 8;
        if ((size_t)(end - p) < n)
            return -1;
        e->type = TLV_T_FLOAT;
        p += n;
    } else if (et >= 0x0C && et <= 0x13) {   /* strings */
        size_t lw = (size_t)1 << (et & 3);   /* width of the length field */
        if ((size_t)(end - p) < lw)
            return -1;
        uint64_t len = lw == 1 ? p[0] : lw == 2 ? get_le16(p) : lw == 4 ? get_le32(p) : get_le64(p);
        p += lw;
        if (len > (uint64_t)(end - p))
            return -1;
        e->type = et < 0x10 ? TLV_T_UTF8 : TLV_T_BYTES;
        e->p = p;                            /* zero-copy: points into the input */
        e->n = (size_t)len;
        p += len;
    } else if (et == 0x14) {
        e->type = TLV_T_NULL;
    } else if (et >= 0x15 && et <= 0x17) {   /* containers */
        if (depth > 24)
            return -1;
        e->type = et == 0x15 ? TLV_T_STRUCT : et == 0x16 ? TLV_T_ARRAY : TLV_T_LIST;
        e->p = p;
        for (;;) {
            if (p >= end)
                return -1;                   /* unterminated container */
            if (*p == 0x18) {
                e->n = p - e->p;             /* contents exclude the end marker */
                p++;
                break;
            }
            tlv_el c;
            if (parse_at(p, end, &c, depth + 1) < 0)
                return -1;
            p = c.raw + c.rawlen;
        }
    } else if (et == 0x18) {
        e->type = TLV_T_END;
    } else {
        return -1;
    }
    e->rawlen = p - start;
    return 0;
}

int tlv_parse(const uint8_t *p, size_t n, tlv_el *out)
{
    return parse_at(p, p + n, out, 0);
}

/* Iterate the direct children of a container:
 *     tlv_it it; tlv_el child;
 *     tlv_iter(&it, &container);
 *     while (tlv_next(&it, &child)) { ... }
 */
void tlv_iter(tlv_it *it, const tlv_el *c)
{
    it->p = c->p;
    it->end = c->p + c->n;
}

int tlv_next(tlv_it *it, tlv_el *out)
{
    if (it->p >= it->end)
        return 0;
    if (parse_at(it->p, it->end, out, 1) < 0 || out->type == TLV_T_END) {
        it->p = it->end;
        return 0;
    }
    it->p = out->raw + out->rawlen;
    return 1;
}

/* Find a struct field by context tag (linear scan; structs are small). */
int tlv_get(const tlv_el *c, uint32_t tag, tlv_el *out)
{
    tlv_it it;
    tlv_iter(&it, c);
    while (tlv_next(&it, out))
        if (out->tag == tag)
            return 1;
    return 0;
}

/* Convenience: integer/bool field, or 'def' if missing or of another type.
 * Handy because many Matter fields are optional with a documented default. */
uint64_t tlv_get_u(const tlv_el *c, uint32_t tag, uint64_t def)
{
    tlv_el e;
    if (tlv_get(c, tag, &e) && (e.type == TLV_T_UINT || e.type == TLV_T_INT || e.type == TLV_T_BOOL))
        return e.u;
    return def;
}

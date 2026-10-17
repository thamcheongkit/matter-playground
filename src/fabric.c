/* Fabric table, Matter TLV certificate parsing and on-disk persistence.
 *
 * WHAT IS A FABRIC?
 * A fabric is one controller ecosystem's PKI and namespace: "Apple Home",
 * "Google Home", a Home Assistant install... It consists of:
 *   - RCAC: Root CA Certificate (the trust anchor; its public key + the
 *           64-bit fabric id identify the fabric)
 *   - ICAC: optional Intermediate CA Certificate
 *   - NOC:  our Node Operational Certificate, issued by RCAC/ICAC, binding
 *           our operational public key to (fabric id, node id)
 *   - IPK:  Identity Protection Key, a fabric-wide symmetric secret used in
 *           CASE (to hide which fabric/node a handshake targets, and as a
 *           second factor: you need it to complete CASE at all)
 *
 * A device may belong to several fabrics at once (multi-admin), each with
 * its own node id and keys. Locally each is referred to by a fabric index.
 *
 * MATTER CERTIFICATES are not X.509 on the wire: they are a compact TLV
 * re-encoding of an X.509 certificate (about half the size). Layout:
 *     struct {
 *       1: serial number          2: signature algorithm
 *       3: issuer  (list of DN attributes)
 *       4: not-before             5: not-after
 *       6: subject (list of DN attributes)
 *       7: public key algorithm   8: EC curve id
 *       9: EC public key (65 bytes, uncompressed)
 *      10: extensions (list)      11: signature (64 bytes r||s)
 *     }
 * DN attributes are context-tagged; the Matter-specific ones we need:
 *     17 = matter-node-id   21 = matter-fabric-id   22 = matter-noc-cat
 */
#include "matter.h"

#include <stdlib.h>
#include <string.h>

/* Extract the public key and the Matter-specific subject fields from a
 * Matter TLV certificate. We don't verify the signature or validity period
 * (see the CASE note in secure_channel.c). */
int cert_parse(const uint8_t *c, size_t n, uint8_t pub[65], uint64_t *node_id,
               uint64_t *fabric_id, uint32_t cats[3])
{
    tlv_el m, e, subj;
    tlv_it it;
    int ncat = 0;
    if (tlv_parse(c, n, &m) || m.type != TLV_T_STRUCT)
        return -1;
    if (!tlv_get(&m, 9, &e) || e.type != TLV_T_BYTES || e.n != 65)
        return -1;
    memcpy(pub, e.p, 65);
    if (node_id) *node_id = 0;
    if (fabric_id) *fabric_id = 0;
    if (cats) memset(cats, 0, 3 * sizeof *cats);
    if (tlv_get(&m, 6, &subj) && subj.type == TLV_T_LIST) {
        tlv_iter(&it, &subj);
        while (tlv_next(&it, &e)) {
            if (e.tag == 17 && node_id) *node_id = e.u;          /* matter-node-id */
            if (e.tag == 21 && fabric_id) *fabric_id = e.u;      /* matter-fabric-id */
            if (e.tag == 22 && cats && ncat < 3) cats[ncat++] = (uint32_t)e.u;  /* CAT */
        }
    }
    return 0;
}

/* Fill in everything that is *derived* from the stored certs and IPK.
 *
 *  Compressed Fabric ID (8 bytes) — a short, globally unique-ish fabric
 *  identifier used in mDNS operational names:
 *     CFID = HKDF(ikm  = root public key without the 0x04 prefix (64 bytes),
 *                 salt = fabric id as 8-byte BIG-endian,
 *                 info = "CompressedFabric")
 *
 *  Operational IPK (16 bytes) — what CASE actually uses:
 *     IPK  = HKDF(ikm = epoch key from AddNOC, salt = CFID,
 *                 info = "GroupKey v1.0")
 */
int fabric_derive(fabric_t *f)
{
    uint8_t pub[65], salt[8];
    if (cert_parse(f->rcac, f->rcac_len, f->root_pub, NULL, NULL, NULL))
        return -1;
    if (cert_parse(f->noc, f->noc_len, pub, &f->node_id, &f->fabric_id, NULL))
        return -1;
    put_be64(salt, f->fabric_id);
    if (hkdf_sha256(salt, 8, f->root_pub + 1, 64, "CompressedFabric", f->cfid, 8))
        return -1;
    return hkdf_sha256(f->cfid, 8, f->ipk_epoch, 16, "GroupKey v1.0", f->ipk, 16);
}

/* Index 0 means "no fabric" (e.g. a PASE session before AddNOC). */
fabric_t *fabric_by_index(uint8_t idx)
{
    for (int i = 0; i < MAX_FABRICS && idx; i++)
        if (g_node.fabrics[i].in_use && g_node.fabrics[i].index == idx)
            return &g_node.fabrics[i];
    return NULL;
}

int fabric_count(int committed_only)
{
    int n = 0;
    for (int i = 0; i < MAX_FABRICS; i++)
        if (g_node.fabrics[i].in_use && (!committed_only || g_node.fabrics[i].committed))
            n++;
    return n;
}

void fabric_remove(uint8_t idx)
{
    fabric_t *f = fabric_by_index(idx);
    if (f)
        memset(f, 0, sizeof *f);   /* also wipes the operational private key */
}

/* ---------------------------------------------------------- persistence */
/* The state file is itself TLV (we already have an encoder/decoder):
 *
 *   struct {
 *     1: on/off (bool)              2: next fabric index
 *     3: NodeLabel                  4: Location
 *     5: reboot count
 *     6: array of fabrics: struct {
 *          0: index   1: RCAC   2: ICAC   3: NOC   4: IPK epoch key
 *          5: operational private key   6: admin vendor id
 *          7: label   8: ACL entries (raw TLV)
 *        }
 *   }
 *
 * Only committed fabrics are saved: a fabric that is still inside its
 * fail-safe must disappear if we crash/restart before CommissioningComplete.
 * Keys are stored in plaintext - fine for a demo, not for a product. */

#define STATE_MAX 32768

int state_save(void)
{
    static uint8_t buf[STATE_MAX];
    tlv_w w;
    tlv_w_init(&w, buf, sizeof buf);
    tlv_start(&w, TLV_ANON, TLV_T_STRUCT);
    tlv_put_bool(&w, 1, g_node.onoff);
    tlv_put_uint(&w, 2, g_node.next_fabric_index);
    tlv_put_str(&w, 3, g_node.node_label);
    tlv_put_str(&w, 4, g_node.location);
    tlv_put_uint(&w, 5, g_node.reboot_count);
    tlv_start(&w, 6, TLV_T_ARRAY);
    for (int i = 0; i < MAX_FABRICS; i++) {
        fabric_t *f = &g_node.fabrics[i];
        if (!f->in_use || !f->committed)
            continue;
        tlv_start(&w, TLV_ANON, TLV_T_STRUCT);
        tlv_put_uint(&w, 0, f->index);
        tlv_put_bytes(&w, 1, f->rcac, f->rcac_len);
        tlv_put_bytes(&w, 2, f->icac, f->icac_len);
        tlv_put_bytes(&w, 3, f->noc, f->noc_len);
        tlv_put_bytes(&w, 4, f->ipk_epoch, 16);
        tlv_put_bytes(&w, 5, f->opkey.priv, 32);
        tlv_put_uint(&w, 6, f->vendor_id);
        tlv_put_str(&w, 7, f->label);
        tlv_put_bytes(&w, 8, f->acl, f->acl_len);
        tlv_end(&w);
    }
    tlv_end(&w);
    tlv_end(&w);
    if (w.err)
        return -1;

    /* write to a temp file then rename(): atomic, so a crash mid-write
     * never leaves a truncated state file behind */
    char tmp[300];
    snprintf(tmp, sizeof tmp, "%s.tmp", g_node.state_path);
    FILE *fp = fopen(tmp, "wb");
    if (!fp)
        return -1;
    int ok = fwrite(buf, 1, w.len, fp) == w.len;
    ok &= fclose(fp) == 0;
    return ok && rename(tmp, g_node.state_path) == 0 ? 0 : -1;
}

/* copy a TLV string into a fixed C buffer, truncating and NUL-terminating */
static void copy_str(char *dst, size_t cap, const tlv_el *e)
{
    size_t n = e->n < cap - 1 ? e->n : cap - 1;
    memcpy(dst, e->p, n);
    dst[n] = 0;
}

static int copy_bytes(uint8_t *dst, size_t cap, size_t *len, const tlv_el *e)
{
    if (e->type != TLV_T_BYTES || e->n > cap)
        return -1;
    memcpy(dst, e->p, e->n);
    *len = e->n;
    return 0;
}

/* Load the state file (missing file = fresh device). Malformed fabric
 * entries are skipped rather than aborting the whole load. */
int state_load(void)
{
    static uint8_t buf[STATE_MAX];
    FILE *fp = fopen(g_node.state_path, "rb");
    if (!fp)
        return -1;
    size_t n = fread(buf, 1, sizeof buf, fp);
    fclose(fp);

    tlv_el m, e, arr, fe;
    tlv_it it;
    if (tlv_parse(buf, n, &m) || m.type != TLV_T_STRUCT) {
        LOG("state file %s is corrupt, ignoring", g_node.state_path);
        return -1;
    }
    g_node.onoff = (int)tlv_get_u(&m, 1, 0);
    g_node.next_fabric_index = (uint8_t)tlv_get_u(&m, 2, 1);
    g_node.reboot_count = (uint32_t)tlv_get_u(&m, 5, 0);
    if (tlv_get(&m, 3, &e) && e.type == TLV_T_UTF8)
        copy_str(g_node.node_label, sizeof g_node.node_label, &e);
    if (tlv_get(&m, 4, &e) && e.type == TLV_T_UTF8)
        copy_str(g_node.location, sizeof g_node.location, &e);
    if (tlv_get(&m, 6, &arr) && arr.type == TLV_T_ARRAY) {
        int i = 0;
        tlv_iter(&it, &arr);
        while (i < MAX_FABRICS && tlv_next(&it, &fe)) {
            fabric_t *f = &g_node.fabrics[i];
            size_t l;
            memset(f, 0, sizeof *f);
            f->index = (uint8_t)tlv_get_u(&fe, 0, 0);
            f->vendor_id = (uint16_t)tlv_get_u(&fe, 6, 0);
            if (!tlv_get(&fe, 1, &e) || copy_bytes(f->rcac, MAX_CERT, &f->rcac_len, &e)) continue;
            if (!tlv_get(&fe, 2, &e) || copy_bytes(f->icac, MAX_CERT, &f->icac_len, &e)) continue;
            if (!tlv_get(&fe, 3, &e) || copy_bytes(f->noc, MAX_CERT, &f->noc_len, &e)) continue;
            if (!tlv_get(&fe, 4, &e) || copy_bytes(f->ipk_epoch, 16, &l, &e)) continue;
            if (!tlv_get(&fe, 5, &e) || copy_bytes(f->opkey.priv, 32, &l, &e)) continue;
            if (tlv_get(&fe, 7, &e) && e.type == TLV_T_UTF8)
                copy_str(f->label, sizeof f->label, &e);
            if (tlv_get(&fe, 8, &e))
                copy_bytes(f->acl, MAX_ACL_BYTES, &f->acl_len, &e);
            /* recompute public key, ids, CFID and operational IPK */
            if (p256_from_priv(&f->opkey) || fabric_derive(f))
                continue;
            f->in_use = f->committed = 1;
            i++;
        }
    }
    return 0;
}

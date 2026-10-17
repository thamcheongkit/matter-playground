/* Secure Channel protocol: PASE (SPAKE2+) and CASE (Sigma) responders, StatusReport.
 *
 * Both handshakes run over the *unsecured* session (session id 0) and end
 * with a new secure session in transport.c's table. We only ever play the
 * responder role: controllers always initiate.
 *
 * PASE — Passcode-Authenticated Session Establishment (commissioning only)
 * ------------------------------------------------------------------------
 *   controller                                   device (us)
 *   PBKDFParamRequest  {random, session id}  ->
 *                      <-  PBKDFParamResponse {random, session id,
 *                                              PBKDF2 iterations + salt}
 *   Pake1  {X}                               ->
 *                      <-  Pake2  {Y, cB}
 *   Pake3  {cA}                              ->
 *                      <-  StatusReport(success)
 *   => session keys from SPAKE2+ Ke. Allowed only while the commissioning
 *      window is open.
 *
 * CASE — Certificate-Authenticated Session Establishment (daily use)
 * ------------------------------------------------------------------
 * A SIGMA-I style signed Diffie-Hellman (similar in spirit to TLS 1.3):
 *   Sigma1 {initiator random, session id, destination id, ephemeral pubkey}
 *   Sigma2 {responder random, session id, ephemeral pubkey,
 *           Enc_S2K(our NOC, ICAC, Sign_opkey(NOCs + both ephemeral keys))}
 *   Sigma3 {Enc_S3K(their NOC, ICAC, Sign(...))}
 *   StatusReport(success)
 *   => session keys from the ECDH secret + transcript hash.
 * The "destination id" is an HMAC under the fabric IPK, so an observer can't
 * tell which fabric/node is being contacted, and only fabric members can
 * produce a matching one.
 *
 * Note on structure: the handshake transcripts are hashed over the exact
 * TLV payload bytes, so we keep copies of the messages we sent/received.
 */
#include "matter.h"

#include <string.h>

/* Secure Channel opcodes */
enum {
    SC_STANDALONE_ACK = 0x10,
    SC_PBKDF_REQ = 0x20, SC_PBKDF_RESP = 0x21, SC_PAKE1 = 0x22, SC_PAKE2 = 0x23, SC_PAKE3 = 0x24,
    SC_SIGMA1 = 0x30, SC_SIGMA2 = 0x31, SC_SIGMA3 = 0x32, SC_SIGMA2_RESUME = 0x33,
    SC_STATUS_REPORT = 0x40,
};
/* StatusReport general codes and Secure Channel protocol-specific codes */
enum { GC_SUCCESS = 0, GC_FAILURE = 1 };
enum { PC_SUCCESS = 0, PC_NO_SHARED_ROOT = 1, PC_INVALID_PARAM = 2, PC_CLOSE_SESSION = 3, PC_BUSY = 4 };

/* StatusReport is not TLV, it's a fixed binary layout:
 *   general code (u16) | protocol id (u32: vendor<<16 | protocol) | protocol code (u16) */
void send_status_report(rx_ctx *rx, uint16_t general, uint16_t code)
{
    uint8_t b[8];
    put_le16(b, general);
    put_le32(b + 2, PROTO_SECURE_CHANNEL);
    put_le16(b + 6, code);
    reply(rx, PROTO_SECURE_CHANNEL, SC_STATUS_REPORT, b, sizeof b, 1);
}

/* Optional "session parameters" we advertise in PASE/CASE: our MRP timing
 * (how long we may sleep / how quickly we retransmit) and protocol revisions.
 * A sleepy battery device would advertise a long idle interval here. */
static void put_session_params(tlv_w *w, uint32_t tag)
{
    tlv_start(w, tag, TLV_T_STRUCT);
    tlv_put_uint(w, 1, 500);          /* SESSION_IDLE_INTERVAL ms */
    tlv_put_uint(w, 2, 300);          /* SESSION_ACTIVE_INTERVAL ms */
    tlv_put_uint(w, 3, 4000);         /* SESSION_ACTIVE_THRESHOLD ms */
    tlv_put_uint(w, 4, 17);           /* DataModelRevision */
    tlv_put_uint(w, 5, 11);           /* InteractionModelRevision */
    tlv_put_uint(w, 6, 0x01030000);   /* SpecificationVersion 1.3 */
    tlv_put_uint(w, 7, 1);            /* MaxPathsPerInvoke */
    tlv_end(w);
}

/* constant-time compare, so timing doesn't reveal how many bytes matched */
static int ct_equal(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t d = 0;
    for (size_t i = 0; i < n; i++)
        d |= a[i] ^ b[i];
    return d == 0;
}

/* fetch an octet-string field, optionally requiring an exact length */
static int get_bytes(const tlv_el *m, uint32_t tag, size_t len, const uint8_t **out)
{
    tlv_el e;
    if (!tlv_get(m, tag, &e) || e.type != TLV_T_BYTES || (len && e.n != len))
        return -1;
    *out = e.p;
    return 0;
}

/* ================================================================= PASE */

/* Only one PASE attempt at a time (there's only one commissioner anyway). */
static struct {
    int stage;                /* 0 idle, 1 sent PBKDFParamResponse, 2 sent Pake2 */
    uint16_t exch;
    uint64_t peer_node;
    uint16_t peer_sid, local_sid;
    uint8_t context[32];      /* hash binding SPAKE2+ to this exact exchange */
    uint8_t cA[32], Ke[16];   /* expected confirmation, and the key material */
} pase;

/* Step 1: PBKDFParamRequest -> PBKDFParamResponse.
 * Request:  { 1: initiatorRandom(32), 2: initiatorSessionId,
 *             3: passcodeId (0), 4: hasPBKDFParameters, 5: session params }
 * Response: { 1: initiatorRandom (echo), 2: responderRandom(32),
 *             3: responderSessionId, 4: { 1: iterations, 2: salt }, 5: params }
 * The commissioner needs iterations+salt to run PBKDF2 on the passcode and
 * get the same w0/w1 we derived (unless it already has them: field 4). */
static void pase_pbkdf_request(rx_ctx *rx)
{
    tlv_el m;
    const uint8_t *irand;
    if (!g_node.cw_open) {
        LOG("PASE rejected: commissioning window is closed");
        send_status_report(rx, GC_FAILURE, PC_INVALID_PARAM);
        return;
    }
    if (tlv_parse(rx->payload, rx->len, &m) || m.type != TLV_T_STRUCT || get_bytes(&m, 1, 32, &irand)) {
        send_status_report(rx, GC_FAILURE, PC_INVALID_PARAM);
        return;
    }
    int has_params = (int)tlv_get_u(&m, 4, 0);

    memset(&pase, 0, sizeof pase);
    pase.exch = rx->exchange_id;
    pase.peer_node = rx->src_node;
    pase.peer_sid = (uint16_t)tlv_get_u(&m, 2, 0);
    pase.local_sid = new_session_id();   /* where the peer must send once secure */

    uint8_t resp[256], rrand[32];
    tlv_w w;
    rand_bytes(rrand, 32);
    tlv_w_init(&w, resp, sizeof resp);
    tlv_start(&w, TLV_ANON, TLV_T_STRUCT);
    tlv_put_bytes(&w, 1, irand, 32);
    tlv_put_bytes(&w, 2, rrand, 32);
    tlv_put_uint(&w, 3, pase.local_sid);
    if (!has_params) {
        tlv_start(&w, 4, TLV_T_STRUCT);
        tlv_put_uint(&w, 1, g_node.cw_iters);
        tlv_put_bytes(&w, 2, g_node.cw_salt, g_node.cw_salt_len);
        tlv_end(&w);
    }
    put_session_params(&w, 5);
    tlv_end(&w);

    /* Context = SHA256("CHIP PAKE V1 Commissioning" || PBKDFParamRequest || PBKDFParamResponse)
     * It goes into the SPAKE2+ transcript, so a man-in-the-middle who
     * tampers with these two messages makes the confirmations fail. */
    static const char prefix[] = "CHIP PAKE V1 Commissioning";
    uint8_t ctx[sizeof prefix - 1 + 2 * MAX_UDP];
    size_t cl = 0;
    memcpy(ctx, prefix, sizeof prefix - 1); cl += sizeof prefix - 1;
    memcpy(ctx + cl, rx->payload, rx->len); cl += rx->len;
    memcpy(ctx + cl, resp, w.len); cl += w.len;
    sha256(ctx, cl, pase.context);

    LOG("PASE: PBKDFParamRequest received, responding");
    reply(rx, PROTO_SECURE_CHANNEL, SC_PBKDF_RESP, resp, w.len, 1);
    pase.stage = 1;
}

/* Step 2: Pake1 {1: X} -> Pake2 {1: Y, 2: cB}. All the SPAKE2+ math happens
 * in spake_respond(); we remember the cA we expect and Ke for later. */
static void pase_pake1(rx_ctx *rx)
{
    tlv_el m;
    const uint8_t *X;
    if (pase.stage != 1 || rx->exchange_id != pase.exch || tlv_parse(rx->payload, rx->len, &m) ||
        get_bytes(&m, 1, 65, &X)) {
        send_status_report(rx, GC_FAILURE, PC_INVALID_PARAM);
        return;
    }
    uint8_t Y[65], cB[32];
    if (spake_respond(g_node.cw_w0, g_node.cw_L, pase.context, X, Y, cB, pase.cA, pase.Ke)) {
        send_status_report(rx, GC_FAILURE, PC_INVALID_PARAM);
        pase.stage = 0;
        return;
    }
    uint8_t resp[160];
    tlv_w w;
    tlv_w_init(&w, resp, sizeof resp);
    tlv_start(&w, TLV_ANON, TLV_T_STRUCT);
    tlv_put_bytes(&w, 1, Y, 65);
    tlv_put_bytes(&w, 2, cB, 32);
    tlv_end(&w);
    reply(rx, PROTO_SECURE_CHANNEL, SC_PAKE2, resp, w.len, 1);
    pase.stage = 2;
}

/* Step 3: Pake3 {1: cA}. If cA matches, the commissioner provably knows the
 * passcode. Derive session keys:
 *     I2R || R2I || AttestationChallenge = HKDF(Ke, info="SessionKeys", 48)
 * I2R = initiator->responder (we decrypt with it), R2I = we encrypt with it.
 * The attestation challenge is a per-session value that the device signs
 * during attestation and CSR, binding those signatures to this session. */
static void pase_pake3(rx_ctx *rx)
{
    tlv_el m;
    const uint8_t *cA;
    if (pase.stage != 2 || rx->exchange_id != pase.exch || tlv_parse(rx->payload, rx->len, &m) ||
        get_bytes(&m, 1, 32, &cA)) {
        send_status_report(rx, GC_FAILURE, PC_INVALID_PARAM);
        return;
    }
    pase.stage = 0;
    if (!ct_equal(cA, pase.cA, 32)) {
        LOG("PASE failed: confirmation mismatch (wrong setup code?)");
        send_status_report(rx, GC_FAILURE, PC_INVALID_PARAM);
        return;
    }
    uint8_t keys[48];
    hkdf_sha256(NULL, 0, pase.Ke, 16, "SessionKeys", keys, sizeof keys);
    session_t *s = session_new(SESS_PASE);
    s->local_id = pase.local_sid;
    s->peer_id = pase.peer_sid;
    memcpy(s->dec_key, keys, 16);          /* I2R */
    memcpy(s->enc_key, keys + 16, 16);     /* R2I */
    memcpy(s->att_challenge, keys + 32, 16);
    s->peer = rx->from;
    send_status_report(rx, GC_SUCCESS, PC_SUCCESS);
    LOG("PASE session established (local session %u)", s->local_id);
}

/* ================================================================= CASE */

#define MAX_CASE_HS 4   /* a few concurrent handshakes (several controllers) */

typedef struct {
    int active;
    uint16_t exch;
    uint64_t peer_node, started;
    uint16_t peer_sid, local_sid;
    uint8_t fabric_idx;
    p256_key eph;                     /* our ephemeral ECDH key for this handshake */
    uint8_t peer_eph[65], shared[32]; /* their ephemeral key, ECDH shared secret */
    uint8_t s1[MAX_UDP]; size_t s1len;   /* Sigma1 bytes, for transcript hashes */
    uint8_t s2[MAX_UDP]; size_t s2len;   /* Sigma2 bytes */
} case_hs_t;

static case_hs_t chs[MAX_CASE_HS];

static case_hs_t *case_find(rx_ctx *rx)
{
    for (int i = 0; i < MAX_CASE_HS; i++)
        if (chs[i].active && chs[i].exch == rx->exchange_id && chs[i].peer_node == rx->src_node)
            return &chs[i];
    return NULL;
}

static case_hs_t *case_alloc(void)
{
    case_hs_t *h = &chs[0];
    for (int i = 0; i < MAX_CASE_HS; i++) {
        if (!chs[i].active)
            return &chs[i];
        if (chs[i].started < h->started)
            h = &chs[i];
    }
    return h;   /* all busy: recycle the oldest */
}

/* Sigma1 -> Sigma2.
 * Sigma1: { 1: initiatorRandom(32), 2: initiatorSessionId,
 *           3: destinationId(32), 4: initiatorEphPubKey(65),
 *           5: session params, 6/7: resumption id/MIC (ignored: we always
 *           do the full handshake, which the spec allows) } */
static void case_sigma1(rx_ctx *rx)
{
    tlv_el m;
    const uint8_t *irand, *dest, *ieph;
    if (tlv_parse(rx->payload, rx->len, &m) || m.type != TLV_T_STRUCT || get_bytes(&m, 1, 32, &irand) ||
        get_bytes(&m, 3, 32, &dest) || get_bytes(&m, 4, 65, &ieph) || rx->len > MAX_UDP) {
        send_status_report(rx, GC_FAILURE, PC_INVALID_PARAM);
        return;
    }

    /* Which of our fabrics/identities is the initiator trying to reach?
     * Destination ID = HMAC(IPK, initiatorRandom || rootPubKey || fabricId || nodeId)
     * We recompute it for each fabric and look for a match. */
    fabric_t *f = NULL;
    for (int i = 0; i < MAX_FABRICS && !f; i++) {
        fabric_t *c = &g_node.fabrics[i];
        uint8_t msg[32 + 65 + 8 + 8], cand[32];
        if (!c->in_use)
            continue;
        memcpy(msg, irand, 32);
        memcpy(msg + 32, c->root_pub, 65);
        put_le64(msg + 97, c->fabric_id);
        put_le64(msg + 105, c->node_id);
        hmac_sha256(c->ipk, 16, msg, sizeof msg, cand);
        if (ct_equal(cand, dest, 32))
            f = c;
    }
    if (!f) {
        LOG("CASE: Sigma1 destination does not match any fabric");
        send_status_report(rx, GC_FAILURE, PC_NO_SHARED_ROOT);
        return;
    }

    case_hs_t *h = case_alloc();
    memset(h, 0, sizeof *h);
    h->active = 1;
    h->exch = rx->exchange_id;
    h->peer_node = rx->src_node;
    h->started = now_ms();
    h->peer_sid = (uint16_t)tlv_get_u(&m, 2, 0);
    h->local_sid = new_session_id();
    h->fabric_idx = f->index;
    memcpy(h->peer_eph, ieph, 65);
    memcpy(h->s1, rx->payload, rx->len);
    h->s1len = rx->len;
    /* fresh ephemeral key + ECDH = forward secrecy for this session */
    if (p256_keygen(&h->eph) || p256_ecdh(&h->eph, ieph, h->shared)) {
        h->active = 0;
        send_status_report(rx, GC_FAILURE, PC_INVALID_PARAM);
        return;
    }

    /* S2K, the key that encrypts the Sigma2 payload:
     *   HKDF(ikm = ECDH secret,
     *        salt = IPK || responderRandom || responderEphPubKey || SHA256(Sigma1),
     *        info = "Sigma2") */
    uint8_t rrand[32], h1[32], salt[16 + 32 + 65 + 32], s2k[16];
    rand_bytes(rrand, 32);
    sha256(h->s1, h->s1len, h1);
    memcpy(salt, f->ipk, 16);
    memcpy(salt + 16, rrand, 32);
    memcpy(salt + 48, h->eph.pub, 65);
    memcpy(salt + 113, h1, 32);
    hkdf_sha256(salt, sizeof salt, h->shared, 32, "Sigma2", s2k, 16);

    /* TBSData2 ("to be signed"): proves we own the NOC's key AND binds it to
     * both ephemeral keys of this handshake (so it can't be replayed).
     *   { 1: responderNOC, 2: responderICAC?, 3: responderEphPub, 4: initiatorEphPub } */
    uint8_t tbs[1024], sig[64];
    tlv_w w;
    tlv_w_init(&w, tbs, sizeof tbs);
    tlv_start(&w, TLV_ANON, TLV_T_STRUCT);
    tlv_put_bytes(&w, 1, f->noc, f->noc_len);
    if (f->icac_len)
        tlv_put_bytes(&w, 2, f->icac, f->icac_len);
    tlv_put_bytes(&w, 3, h->eph.pub, 65);
    tlv_put_bytes(&w, 4, ieph, 65);
    tlv_end(&w);
    p256_sign(&f->opkey, tbs, w.len, sig);

    /* TBEData2 ("to be encrypted"): our certificates + the signature +
     * a resumption id (would allow a shortcut handshake next time).
     *   { 1: NOC, 2: ICAC?, 3: signature, 4: resumptionId(16) }
     * Encrypting it hides our identity (certificates) from eavesdroppers. */
    uint8_t tbe[1024], enc[1024 + 16], resumption[16];
    rand_bytes(resumption, 16);
    tlv_w_init(&w, tbe, sizeof tbe);
    tlv_start(&w, TLV_ANON, TLV_T_STRUCT);
    tlv_put_bytes(&w, 1, f->noc, f->noc_len);
    if (f->icac_len)
        tlv_put_bytes(&w, 2, f->icac, f->icac_len);
    tlv_put_bytes(&w, 3, sig, 64);
    tlv_put_bytes(&w, 4, resumption, 16);
    tlv_end(&w);
    size_t tbelen = w.len;
    /* fixed nonce is fine: S2K is single-use */
    aes_ccm_encrypt(s2k, (const uint8_t *)"NCASE_Sigma2N", NULL, 0, tbe, tbelen, enc, enc + tbelen);

    /* Sigma2: { 1: responderRandom, 2: responderSessionId,
     *           3: responderEphPubKey, 4: encrypted2 (ciphertext || tag), 5: params } */
    tlv_w_init(&w, h->s2, sizeof h->s2);
    tlv_start(&w, TLV_ANON, TLV_T_STRUCT);
    tlv_put_bytes(&w, 1, rrand, 32);
    tlv_put_uint(&w, 2, h->local_sid);
    tlv_put_bytes(&w, 3, h->eph.pub, 65);
    tlv_put_bytes(&w, 4, enc, tbelen + 16);
    put_session_params(&w, 5);
    tlv_end(&w);
    if (w.err) {
        h->active = 0;
        send_status_report(rx, GC_FAILURE, PC_INVALID_PARAM);
        return;
    }
    h->s2len = w.len;
    LOG("CASE: Sigma1 matched fabric %u, sending Sigma2", f->index);
    reply(rx, PROTO_SECURE_CHANNEL, SC_SIGMA2, h->s2, h->s2len, 1);
}

/* Sigma3 -> StatusReport. Sigma3: { 1: encrypted3 }.
 * Decrypt with S3K, check the initiator's NOC is on our fabric and that it
 * signed this handshake, then derive the session keys. */
static void case_sigma3(rx_ctx *rx)
{
    case_hs_t *h = case_find(rx);
    fabric_t *f = h ? fabric_by_index(h->fabric_idx) : NULL;
    tlv_el m, e, t, noc, icac;
    if (!h || !f) {
        send_status_report(rx, GC_FAILURE, PC_INVALID_PARAM);
        return;
    }
    h->active = 0;
    if (tlv_parse(rx->payload, rx->len, &m) || !tlv_get(&m, 1, &e) || e.type != TLV_T_BYTES ||
        e.n <= 16 || e.n > 1100)
        goto fail;

    /* S3K = HKDF(ECDH secret, salt = IPK || SHA256(Sigma1 || Sigma2), "Sigma3") */
    uint8_t buf[3 * MAX_UDP], h12[32], salt[48], s3k[16], tbe[1100];
    memcpy(buf, h->s1, h->s1len);
    memcpy(buf + h->s1len, h->s2, h->s2len);
    sha256(buf, h->s1len + h->s2len, h12);
    memcpy(salt, f->ipk, 16);
    memcpy(salt + 16, h12, 32);
    hkdf_sha256(salt, sizeof salt, h->shared, 32, "Sigma3", s3k, 16);
    size_t tl = e.n - 16;   /* last 16 bytes are the CCM tag */
    if (aes_ccm_decrypt(s3k, (const uint8_t *)"NCASE_Sigma3N", NULL, 0, e.p, tl, tbe, e.p + tl)) {
        LOG("CASE: Sigma3 decryption failed");
        goto fail;
    }
    /* TBEData3: { 1: initiatorNOC, 2: initiatorICAC?, 3: signature } */
    const uint8_t *sig;
    if (tlv_parse(tbe, tl, &t) || !tlv_get(&t, 1, &noc) || noc.type != TLV_T_BYTES ||
        get_bytes(&t, 3, 64, &sig))
        goto fail;
    int has_icac = tlv_get(&t, 2, &icac) && icac.type == TLV_T_BYTES;

    uint8_t pub[65];
    uint64_t node, fab;
    uint32_t cats[3];
    if (cert_parse(noc.p, noc.n, pub, &node, &fab, cats) || fab != f->fabric_id) {
        LOG("CASE: initiator NOC is not on our fabric");
        goto fail;
    }
    /* NOTE: demo shortcut — the NOC/ICAC chain is not validated against the root.
     * Completing CASE still requires knowledge of the fabric IPK. */

    /* TBSData3 mirrors TBSData2 with roles swapped:
     *   { 1: initiatorNOC, 2: initiatorICAC?, 3: initiatorEphPub, 4: responderEphPub } */
    uint8_t tbs[1100];
    tlv_w w;
    tlv_w_init(&w, tbs, sizeof tbs);
    tlv_start(&w, TLV_ANON, TLV_T_STRUCT);
    tlv_put_bytes(&w, 1, noc.p, noc.n);
    if (has_icac)
        tlv_put_bytes(&w, 2, icac.p, icac.n);
    tlv_put_bytes(&w, 3, h->peer_eph, 65);
    tlv_put_bytes(&w, 4, h->eph.pub, 65);
    tlv_end(&w);
    if (w.err || p256_verify(pub, tbs, w.len, sig)) {
        LOG("CASE: Sigma3 signature invalid");
        goto fail;
    }

    /* Session keys:
     *   I2R || R2I || AttestationChallenge =
     *     HKDF(ECDH secret, salt = IPK || SHA256(Sigma1 || Sigma2 || Sigma3), "SessionKeys") */
    uint8_t h123[32], keys[48];
    memcpy(buf + h->s1len + h->s2len, rx->payload, rx->len);
    sha256(buf, h->s1len + h->s2len + rx->len, h123);
    memcpy(salt + 16, h123, 32);
    hkdf_sha256(salt, sizeof salt, h->shared, 32, "SessionKeys", keys, sizeof keys);

    session_t *s = session_new(SESS_CASE);
    s->local_id = h->local_sid;
    s->peer_id = h->peer_sid;
    memcpy(s->dec_key, keys, 16);
    memcpy(s->enc_key, keys + 16, 16);
    memcpy(s->att_challenge, keys + 32, 16);
    s->local_node = f->node_id;       /* used in our nonces */
    s->peer_node = node;              /* used in their nonces */
    s->fabric_idx = f->index;
    memcpy(s->peer_cats, cats, sizeof cats);
    s->peer = rx->from;
    send_status_report(rx, GC_SUCCESS, PC_SUCCESS);
    LOG("CASE session established with node %016llX on fabric %u (local session %u)",
        (unsigned long long)node, f->index, s->local_id);
    return;
fail:
    send_status_report(rx, GC_FAILURE, PC_INVALID_PARAM);
}

/* ============================================================= dispatch */

void secure_channel_rx(rx_ctx *rx)
{
    if (rx->sess) {
        /* on an established session we only expect StatusReport(CloseSession) */
        if (rx->opcode == SC_STATUS_REPORT && rx->len >= 8 && get_le16(rx->payload + 6) == PC_CLOSE_SESSION) {
            LOG("peer closed session %u", rx->sess->local_id);
            session_free(rx->sess);
        }
        return;
    }
    switch (rx->opcode) {
    case SC_PBKDF_REQ: pase_pbkdf_request(rx); break;
    case SC_PAKE1:     pase_pake1(rx); break;
    case SC_PAKE3:     pase_pake3(rx); break;
    case SC_SIGMA1:    case_sigma1(rx); break;
    case SC_SIGMA3:    case_sigma3(rx); break;
    case SC_STATUS_REPORT:
        if (rx->len >= 8)
            LOG("peer StatusReport: general=%u code=%u", get_le16(rx->payload), get_le16(rx->payload + 6));
        break;
    default:
        DBG("unhandled secure channel opcode 0x%02x", rx->opcode);
    }
}

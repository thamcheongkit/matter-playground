/* Matter message layer: UDP, message/protocol headers, AES-CCM session crypto,
 * duplicate detection and MRP (reliable messaging with acks + retransmits).
 *
 * MESSAGE FORMAT (everything little-endian)
 * =========================================
 *
 *  Message header (always plaintext; authenticated as AAD when secured)
 *  ┌────────────┬────────────┬────────────┬──────────────┬───────────┬───────────┐
 *  │ msg flags  │ session id │ sec. flags │ msg counter  │ [src node]│ [dst node]│
 *  │ 1 byte     │ 2 bytes    │ 1 byte     │ 4 bytes      │ 8 bytes   │ 8 / 2     │
 *  └────────────┴────────────┴────────────┴──────────────┴───────────┴───────────┘
 *    msg flags:  bits 7..4 version (0), bit 2 S = source node id present,
 *                bits 1..0 DSIZ: 1 = 64-bit dest node id, 2 = 16-bit group id
 *    sec flags:  bit 7 P (privacy), bit 6 C (control), bit 5 MX (extensions),
 *                bits 1..0 session type (0 unicast, 1 group)
 *
 *  Protocol header (encrypted in secure sessions)
 *  ┌──────────┬────────┬─────────────┬───────────┬─────────────┬───────────────┐
 *  │ exch flg │ opcode │ exchange id │ [vendor]  │ protocol id │ [ack counter] │
 *  │ 1 byte   │ 1 byte │ 2 bytes     │ 2 bytes   │ 2 bytes     │ 4 bytes       │
 *  └──────────┴────────┴─────────────┴───────────┴─────────────┴───────────────┘
 *    exchange flags: 0x01 I = sender is the exchange initiator
 *                    0x02 A = ack counter present (acknowledges a message)
 *                    0x04 R = reliable: please ack this message
 *                    0x08 SX = secured extensions, 0x10 V = vendor id present
 *
 *  Then the payload (TLV for almost everything), then for secure sessions
 *  a 16-byte AES-CCM tag ("MIC").
 *
 * ENCRYPTION
 *  key   = session key for this direction (from PASE/CASE)
 *  nonce = security flags (1) || message counter (4) || sender node id (8)
 *  AAD   = the message header bytes
 *  Because the counter is in the nonce, a counter must never repeat within a
 *  session; it starts at a random value and increments per message.
 *
 * RELIABILITY (MRP — Message Reliability Protocol)
 *  UDP can drop packets, so a message sent with R must be acknowledged:
 *   - "piggybacked": the A flag + ack counter in our next message on the same
 *     exchange (usually the response), or
 *   - "standalone ack": an empty Secure Channel message, opcode 0x10.
 *  Unacknowledged messages are re-sent (same bytes, same counter) with
 *  exponential backoff; after MRP_MAX_TX attempts we give up.
 *  Receivers detect retransmissions as duplicates via the message counter:
 *  they re-ack them but don't process them twice.
 */
#include "matter.h"

#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define MAX_SESSIONS 16
#define MAX_RETX     24
#define MRP_BASE_MS  500       /* first retransmission after 500 ms ... */
#define MRP_MAX_TX   5         /* ... then x1.6 each time, 5 transmissions total */

#define XF_INITIATOR 0x01
#define XF_ACK       0x02
#define XF_RELIABLE  0x04
#define XF_SX        0x08
#define XF_VENDOR    0x10

/* One message waiting for its ack. We keep the exact encrypted datagram so a
 * retransmission is byte-identical (same counter), as MRP requires. */
typedef struct {
    int in_use;
    session_t *sess;          /* NULL = unsecured */
    uint32_t counter;
    uint16_t exch;
    struct sockaddr_in6 to;
    uint8_t buf[MAX_UDP];
    size_t len;
    int tx;                   /* how many times it has been sent */
    uint64_t next;            /* when to resend */
} retx_t;

/* Duplicate detection for the unsecured session: remember the last few
 * counters per ephemeral peer node id. (Unsecured counters have no
 * cryptographic meaning; this only stops us re-processing retransmitted
 * handshake messages.) */
typedef struct { int in_use; uint64_t node; uint32_t ctr[8]; int pos; uint64_t used; } unsec_peer_t;

static int fd = -1;
static session_t sessions[MAX_SESSIONS];
static retx_t retx[MAX_RETX];
static unsec_peer_t upeers[8];
static uint32_t unsec_counter;          /* our counter for unsecured messages */
static uint16_t next_exch, next_sid;

/* One dual-stack UDP socket on port 5540 (IPv4 peers show up as
 * ::ffff:a.b.c.d). Matter itself is IPv6-first. */
int transport_init(void)
{
    struct sockaddr_in6 a = { .sin6_family = AF_INET6, .sin6_port = htons(MATTER_PORT) };
    int off = 0, on = 1;
    fd = socket(AF_INET6, SOCK_DGRAM, 0);
    if (fd < 0)
        return -1;
    setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof off);
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
    if (bind(fd, (struct sockaddr *)&a, sizeof a) < 0) {
        LOG("bind udp/%d: %s", MATTER_PORT, strerror(errno));
        return -1;
    }
    /* random starting points make stale packets from a previous run unlikely
     * to collide with fresh ones */
    unsec_counter = (rand_u32() & 0x0FFFFFFF) + 1;
    next_exch = (uint16_t)rand_u32();
    next_sid = (uint16_t)rand_u32();
    return 0;
}

int transport_fd(void) { return fd; }

uint16_t new_exchange_id(void) { return next_exch++; }

/* Session ids are chosen by the *receiver*: we tell the peer "send to me
 * using session id X" during PASE/CASE. 0 is reserved for unsecured. */
uint16_t new_session_id(void)
{
    for (;;) {
        uint16_t id = ++next_sid;
        int used = id == 0;
        for (int i = 0; i < MAX_SESSIONS && !used; i++)
            used = sessions[i].in_use && sessions[i].local_id == id;
        if (!used)
            return id;
    }
}

/* Allocate a session slot; if the table is full, evict the least recently
 * used one (controllers happily open many sessions over time). */
session_t *session_new(int type)
{
    session_t *s = NULL;
    for (int i = 0; i < MAX_SESSIONS && !s; i++)
        if (!sessions[i].in_use)
            s = &sessions[i];
    if (!s) {   /* evict least recently used */
        s = &sessions[0];
        for (int i = 1; i < MAX_SESSIONS; i++)
            if (sessions[i].last_used < s->last_used)
                s = &sessions[i];
        LOG("evicting session %u", s->local_id);
        session_free(s);
    }
    memset(s, 0, sizeof *s);
    s->in_use = 1;
    s->type = type;
    s->local_id = new_session_id();
    s->tx_counter = (rand_u32() & 0x0FFFFFFF) + 1;
    s->last_used = now_ms();
    return s;
}

/* Free a session and everything hanging off it (subscriptions, pending
 * IM exchanges, queued retransmissions). Keys are wiped by the memset. */
void session_free(session_t *s)
{
    if (!s->in_use)
        return;
    im_drop_session(s);
    for (int i = 0; i < MAX_RETX; i++)
        if (retx[i].in_use && retx[i].sess == s)
            retx[i].in_use = 0;
    memset(s, 0, sizeof *s);
}

void sessions_drop_fabric(uint8_t idx)
{
    for (int i = 0; i < MAX_SESSIONS; i++)
        if (sessions[i].in_use && sessions[i].fabric_idx == idx)
            session_free(&sessions[i]);
}

static session_t *find_session(uint16_t id)
{
    for (int i = 0; i < MAX_SESSIONS; i++)
        if (sessions[i].in_use && sessions[i].local_id == id)
            return &sessions[i];
    return NULL;
}

/* ------------------------------------------------------------- sending */

/* Build, (optionally) encrypt, send, and (optionally) queue for
 * retransmission one message. 's' NULL = unsecured session. For unsecured
 * replies we address the initiator's ephemeral node id as destination. */
static int encode_and_send(session_t *s, const struct sockaddr_in6 *to, int has_dst, uint64_t dst,
                           uint8_t xflags, uint8_t opcode, uint16_t exch, uint16_t proto,
                           uint32_t ack, const uint8_t *payload, size_t n, int reliable)
{
    uint8_t pkt[MAX_UDP + 64], pt[MAX_UDP + 64];
    size_t hdr = 0, po = 0;
    uint32_t ctr = s ? s->tx_counter++ : unsec_counter++;

    /* --- message header (plaintext) --- */
    pkt[hdr++] = has_dst ? 0x01 : 0x00;          /* version 0, DSIZ = 64-bit node id */
    put_le16(pkt + hdr, s ? s->peer_id : 0); hdr += 2;
    pkt[hdr++] = 0x00;                           /* security flags: unicast */
    put_le32(pkt + hdr, ctr); hdr += 4;
    if (has_dst) {
        put_le64(pkt + hdr, dst);
        hdr += 8;
    }

    /* --- protocol header + payload (built separately: it gets encrypted) --- */
    if (reliable)
        xflags |= XF_RELIABLE;
    pt[po++] = xflags;
    pt[po++] = opcode;
    put_le16(pt + po, exch); po += 2;
    put_le16(pt + po, proto); po += 2;
    if (xflags & XF_ACK) {
        put_le32(pt + po, ack);
        po += 4;
    }
    if (hdr + po + n + 16 > MAX_UDP) {
        LOG("message too large (%zu bytes payload), dropped", n);
        return -1;
    }
    if (n)
        memcpy(pt + po, payload, n);
    po += n;

    size_t total;
    if (s) {
        /* nonce = security flags || counter || OUR node id (0 for PASE) */
        uint8_t nonce[13];
        nonce[0] = pkt[3];
        put_le32(nonce + 1, ctr);
        put_le64(nonce + 5, s->local_node);
        if (aes_ccm_encrypt(s->enc_key, nonce, pkt, hdr, pt, po, pkt + hdr, pkt + hdr + po))
            return -1;
        total = hdr + po + 16;
    } else {
        memcpy(pkt + hdr, pt, po);
        total = hdr + po;
    }

    DBG("tx proto=%u op=0x%02x exch=%u ctr=%u len=%zu%s%s", proto, opcode, exch, ctr, total,
        reliable ? " R" : "", (xflags & XF_ACK) ? " A" : "");
    if (sendto(fd, pkt, total, 0, (const struct sockaddr *)to, sizeof *to) < 0)
        LOG("sendto: %s", strerror(errno));

    if (reliable) {
        /* remember it until acked (process_ack) or given up (transport_tick) */
        retx_t *r = NULL;
        for (int i = 0; i < MAX_RETX && !r; i++)
            if (!retx[i].in_use)
                r = &retx[i];
        if (!r) {
            LOG("MRP table full; message %u will not be retransmitted", ctr);
            return 0;
        }
        r->in_use = 1;
        r->sess = s;
        r->counter = ctr;
        r->exch = exch;
        r->to = *to;
        memcpy(r->buf, pkt, total);
        r->len = total;
        r->tx = 1;
        r->next = now_ms() + MRP_BASE_MS;
    }
    return 0;
}

/* Respond on the same exchange as the received message. Our I flag is the
 * opposite of the peer's. If the received message still needs an ack, we
 * piggyback it here instead of sending a separate standalone ack. */
int reply(rx_ctx *rx, uint16_t proto, uint8_t opcode, const uint8_t *p, size_t n, int reliable)
{
    uint8_t xf = rx->peer_is_initiator ? 0 : XF_INITIATOR;
    uint32_t ack = 0;
    if (rx->needs_ack && !rx->acked) {
        xf |= XF_ACK;
        ack = rx->counter;
        rx->acked = 1;
    }
    session_t *s = rx->sess;
    return encode_and_send(s, s ? &s->peer : &rx->from, !s && rx->has_src, rx->src_node, xf, opcode,
                           rx->exchange_id, proto, ack, p, n, reliable);
}

/* Start a brand new exchange where *we* are the initiator. Only used for
 * subscription reports, which the device pushes unprompted. */
int send_initiate(session_t *s, uint16_t exch, uint16_t proto, uint8_t opcode,
                  const uint8_t *p, size_t n)
{
    return encode_and_send(s, &s->peer, 0, 0, XF_INITIATOR, opcode, exch, proto, 0, p, n, 1);
}

/* ----------------------------------------------------------- receiving */

/* Replay / duplicate detection for secure sessions, using a sliding window:
 * rx_max is the highest counter seen; bit i of rx_bitmap means counter
 * rx_max-(i+1) was seen. Anything older than 32 behind is treated as a
 * duplicate. Returns 1 if this counter was already received. */
static int counter_dup(session_t *s, uint32_t c)
{
    if (!s->rx_init) {
        s->rx_init = 1;
        s->rx_max = c;
        s->rx_bitmap = 0;
        return 0;
    }
    if (c > s->rx_max) {
        /* new highest: slide the window forward by d and mark the old max */
        uint32_t d = c - s->rx_max;
        s->rx_bitmap = d > 32 ? 0 : d == 32 ? (1u << 31) : (s->rx_bitmap << d) | (1u << (d - 1));
        s->rx_max = c;
        return 0;
    }
    if (c == s->rx_max)
        return 1;
    uint32_t d = s->rx_max - c;
    if (d > 32)
        return 1;
    uint32_t bit = 1u << (d - 1);
    if (s->rx_bitmap & bit)
        return 1;
    s->rx_bitmap |= bit;
    return 0;
}

static int unsec_dup(uint64_t node, uint32_t c)
{
    unsec_peer_t *p = NULL, *lru = &upeers[0];
    for (int i = 0; i < 8; i++) {
        if (upeers[i].in_use && upeers[i].node == node)
            p = &upeers[i];
        if (upeers[i].used < lru->used)
            lru = &upeers[i];
    }
    if (!p) {
        p = lru;
        memset(p, 0, sizeof *p);
        p->in_use = 1;
        p->node = node;
    }
    p->used = now_ms();
    for (int i = 0; i < 8; i++)
        if (p->ctr[i] == c && c != 0)
            return 1;
    p->ctr[p->pos++ % 8] = c;
    return 0;
}

/* The peer acknowledged our message 'ctr' on session 's': stop resending it. */
static void process_ack(session_t *s, uint32_t ctr)
{
    for (int i = 0; i < MAX_RETX; i++)
        if (retx[i].in_use && retx[i].sess == s && retx[i].counter == ctr) {
            retx[i].in_use = 0;
            DBG("acked ctr=%u", ctr);
        }
}

/* Read one datagram and push it up the stack:
 *   parse message header -> find session -> decrypt -> replay check ->
 *   parse protocol header -> handle ack -> dispatch by protocol id ->
 *   send a standalone ack if the handler didn't reply. */
void transport_rx(void)
{
    uint8_t buf[2048], pt[2048];
    struct sockaddr_in6 from;
    socklen_t fl = sizeof from;
    ssize_t n = recvfrom(fd, buf, sizeof buf, 0, (struct sockaddr *)&from, &fl);
    if (n < 8)
        return;

    /* --- message header --- */
    rx_ctx rx;
    memset(&rx, 0, sizeof rx);
    rx.from = from;
    uint8_t mflags = buf[0], sflags = buf[3];
    uint16_t sid = get_le16(buf + 1);
    rx.counter = get_le32(buf + 4);
    size_t off = 8;
    if ((mflags >> 4) != 0 || (sflags & 0x80) || (sflags & 0x03))
        return;   /* unknown version, privacy, or group session: unsupported */
    if (mflags & 0x04) {
        if ((size_t)n < off + 8)
            return;
        rx.has_src = 1;
        rx.src_node = get_le64(buf + off);
        off += 8;
    }
    off += (mflags & 3) == 1 ? 8 : (mflags & 3) == 2 ? 2 : 0;   /* skip dest node/group */
    if (sflags & 0x20) {                                        /* skip message extensions */
        if ((size_t)n < off + 2)
            return;
        off += 2 + get_le16(buf + off);
    }
    if (off > (size_t)n)
        return;

    /* --- session lookup + decryption --- */
    const uint8_t *p;
    size_t plen;
    int dup;
    if (sid == 0) {
        /* unsecured: only handshakes (PASE/CASE) travel here */
        p = buf + off;
        plen = n - off;
        dup = unsec_dup(rx.src_node, rx.counter);
    } else {
        session_t *s = find_session(sid);
        if (!s) {
            DBG("message for unknown session %u", sid);
            return;
        }
        if ((size_t)n < off + 16)
            return;
        plen = n - off - 16;
        /* nonce uses the SENDER's node id, i.e. the peer's */
        uint8_t nonce[13];
        nonce[0] = sflags;
        put_le32(nonce + 1, rx.counter);
        put_le64(nonce + 5, s->peer_node);
        if (aes_ccm_decrypt(s->dec_key, nonce, buf, off, buf + off, plen, pt, buf + off + plen)) {
            DBG("decrypt failed on session %u", sid);
            return;
        }
        p = pt;
        /* only check replays *after* authentication, so forged packets
         * can't poison the window */
        dup = counter_dup(s, rx.counter);
        rx.sess = s;
        s->peer = from;              /* follow the peer if its address changed */
        s->last_used = now_ms();
    }

    /* --- protocol header --- */
    if (plen < 6)
        return;
    uint8_t xf = p[0];
    size_t po = 4;
    rx.opcode = p[1];
    rx.exchange_id = get_le16(p + 2);
    if (xf & XF_VENDOR)
        po += 2;
    if (plen < po + 2)
        return;
    rx.protocol = (xf & XF_VENDOR) ? 0xFFFF : get_le16(p + po);   /* vendor protocols: ignored */
    po += 2;
    uint32_t ackc = 0;
    if (xf & XF_ACK) {
        if (plen < po + 4)
            return;
        ackc = get_le32(p + po);
        po += 4;
    }
    if (xf & XF_SX) {
        if (plen < po + 2)
            return;
        po += 2 + get_le16(p + po);
    }
    if (po > plen)
        return;
    rx.peer_is_initiator = xf & XF_INITIATOR;
    rx.needs_ack = (xf & XF_RELIABLE) != 0;
    rx.payload = p + po;
    rx.len = plen - po;

    DBG("rx sess=%u proto=%u op=0x%02x exch=%u ctr=%u%s%s%s", sid, rx.protocol, rx.opcode,
        rx.exchange_id, rx.counter, rx.needs_ack ? " R" : "", (xf & XF_ACK) ? " A" : "",
        dup ? " DUP" : "");

    /* --- MRP --- */
    if (xf & XF_ACK)
        process_ack(rx.sess, ackc);
    if (dup) {
        /* a retransmission: our earlier ack was probably lost, so re-ack,
         * but never process the message twice */
        if (rx.needs_ack)
            reply(&rx, PROTO_SECURE_CHANNEL, 0x10, NULL, 0, 0);
        return;
    }
    if (rx.protocol == PROTO_SECURE_CHANNEL && rx.opcode == 0x10)
        return;   /* standalone ack */

    /* --- dispatch to the protocol handler --- */
    if (rx.protocol == PROTO_SECURE_CHANNEL)
        secure_channel_rx(&rx);
    else if (rx.protocol == PROTO_IM && rx.sess)
        im_rx(&rx);                  /* IM is only allowed on secure sessions */
    else
        DBG("ignoring protocol %u", rx.protocol);

    /* handler didn't send anything on this exchange: ack it standalone
     * (unless the handler just closed the session) */
    if (rx.needs_ack && !rx.acked && (!rx.sess || rx.sess->in_use))
        reply(&rx, PROTO_SECURE_CHANNEL, 0x10, NULL, 0, 0);
}

/* Called every loop iteration: resend overdue unacked messages with
 * exponential backoff (500, 800, 1280, 2048 ms ...), or give up and let
 * the IM layer clean up (e.g. drop a subscription whose peer vanished). */
void transport_tick(uint64_t now)
{
    for (int i = 0; i < MAX_RETX; i++) {
        retx_t *r = &retx[i];
        if (!r->in_use || r->next > now)
            continue;
        if (r->tx >= MRP_MAX_TX) {
            session_t *s = r->sess;
            uint16_t exch = r->exch;
            LOG("MRP: no ack for message %u after %d attempts, giving up", r->counter, r->tx);
            r->in_use = 0;
            if (s)
                im_on_send_failed(s, exch);
            continue;
        }
        sendto(fd, r->buf, r->len, 0, (struct sockaddr *)&r->to, sizeof r->to);
        DBG("retransmit ctr=%u (attempt %d)", r->counter, r->tx + 1);
        uint64_t backoff = MRP_BASE_MS;
        for (int k = 0; k < r->tx; k++)
            backoff = backoff * 8 / 5;
        r->tx++;
        r->next = now + backoff;
    }
}

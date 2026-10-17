/* Minimal mDNS / DNS-SD responder for Matter commissionable (_matterc._udp)
 * and operational (_matter._tcp) discovery. No probing / known-answer suppression.
 *
 * HOW DISCOVERY WORKS
 * ===================
 * mDNS (RFC 6762) is DNS without a server: queries are multicast to
 * 224.0.0.251 / ff02::fb on UDP port 5353, and whoever owns a name answers.
 * DNS-SD (RFC 6763) layers service discovery on top using three record types:
 *
 *   PTR  _service._proto.local      -> "<instance>._service._proto.local"
 *        ("who offers this service?" -> list of instances)
 *   SRV  <instance>._service...      -> host name + port
 *   TXT  <instance>._service...      -> key=value metadata
 *   AAAA / A  <host>.local           -> IP addresses
 *
 * Matter advertises two services:
 *
 * 1. COMMISSIONABLE  (only while the commissioning window is open)
 *      _matterc._udp.local  PTR  <random 64-bit hex>._matterc._udp.local
 *    plus "subtype" PTRs so a commissioner can query for exactly the device
 *    it wants without listing everything:
 *      _L<discriminator>   long (12-bit) discriminator, from the QR code
 *      _S<short disc>      top 4 bits, from the manual code
 *      _V<vendor id>, _T<device type>, _CM (currently in commissioning mode)
 *    TXT: D=discriminator, CM=1 (basic window) / 2 (enhanced), VP=vid+pid,
 *         DT=device type, DN=device name, SII/SAI/SAT=MRP timing, PH=hint
 *
 * 2. OPERATIONAL  (once we have a fabric; one instance per fabric)
 *      _matter._tcp.local  PTR  <CompressedFabricId>-<NodeId>._matter._tcp.local
 *      subtype _I<CompressedFabricId> = "nodes of this fabric"
 *    (It says _tcp for historical reasons; the transport is still UDP.)
 *    Controllers resolve this name before CASE, so we must advertise it
 *    right after AddNOC, before commissioning completes.
 *
 * Simplifications vs. a full responder: we don't probe for name conflicts,
 * don't do known-answer suppression, and always answer via multicast
 * (except for "legacy" unicast queries from a non-5353 port).
 */
#include "matter.h"

#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>

#define MDNS_PORT 5353
#define T_A    1           /* DNS record types */
#define T_PTR  12
#define T_TXT  16
#define T_AAAA 28
#define T_SRV  33
#define T_ANY  255
#define TTL    120         /* seconds peers may cache our records */
#define MAXRR  64

enum { RR_COMM = 1, RR_OPER = 2, RR_HOST = 4, RR_ALL = 7 };   /* record groups */

/* One resource record, in an easy-to-build form (encoded later by p_rr). */
typedef struct {
    char name[128];
    uint16_t type;
    int unique;            /* SRV/TXT/A/AAAA are "unique" (cache-flush bit); PTRs are shared */
    char target[128];      /* PTR target or SRV host */
    uint16_t port;
    char txt[12][48];
    int ntxt;
    uint8_t addr[16];
    int alen;
} rr_t;

static int fd4 = -1, fd6 = -1;
static unsigned ifidx;
static char ifname[32];
static int announce_left;       /* repeat announcements a couple of times (packet loss) */
static uint64_t announce_next;

int mdns_fd4(void) { return fd4; }
int mdns_fd6(void) { return fd6; }

/* the interface's IPv4 address, needed to join the IPv4 multicast group */
static int if_ipv4(struct in_addr *out)
{
    struct ifaddrs *ifa, *i;
    int found = 0;
    if (getifaddrs(&ifa))
        return 0;
    for (i = ifa; i && !found; i = i->ifa_next)
        if (i->ifa_addr && i->ifa_addr->sa_family == AF_INET && !strcmp(i->ifa_name, ifname)) {
            *out = ((struct sockaddr_in *)i->ifa_addr)->sin_addr;
            found = 1;
        }
    freeifaddrs(ifa);
    return found;
}

/* Open one IPv6 and one IPv4 socket on port 5353 and join the mDNS groups
 * on the chosen interface. SO_REUSEPORT lets us share 5353 with a system
 * responder (Avahi / macOS mDNSResponder): multicast is delivered to all. */
int mdns_init(const char *name)
{
    int on = 1, ttl = 255;   /* mDNS requires hop limit / TTL 255 */
    snprintf(ifname, sizeof ifname, "%s", name);
    ifidx = if_nametoindex(name);
    if (!ifidx) {
        LOG("mdns: unknown interface %s", name);
        return -1;
    }

    struct sockaddr_in6 a6 = { .sin6_family = AF_INET6, .sin6_port = htons(MDNS_PORT) };
    struct ipv6_mreq mr6 = { .ipv6mr_interface = ifidx };
    inet_pton(AF_INET6, "ff02::fb", &mr6.ipv6mr_multiaddr);
    fd6 = socket(AF_INET6, SOCK_DGRAM, 0);
    setsockopt(fd6, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
    setsockopt(fd6, SOL_SOCKET, SO_REUSEPORT, &on, sizeof on);
    setsockopt(fd6, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof on);
    if (bind(fd6, (struct sockaddr *)&a6, sizeof a6) < 0 ||
        setsockopt(fd6, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mr6, sizeof mr6) < 0) {
        LOG("mdns: IPv6 socket setup failed: %s", strerror(errno));
        return -1;
    }
    setsockopt(fd6, IPPROTO_IPV6, IPV6_MULTICAST_IF, &ifidx, sizeof ifidx);
    setsockopt(fd6, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &ttl, sizeof ttl);
    setsockopt(fd6, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &on, sizeof on);   /* lets local controllers see us */

    /* IPv4 is optional (Matter is IPv6), but many queriers ask on both */
    struct in_addr if4;
    if (if_ipv4(&if4)) {
        struct sockaddr_in a4 = { .sin_family = AF_INET, .sin_port = htons(MDNS_PORT) };
        struct ip_mreq mr4 = { .imr_interface = if4 };
        unsigned char ttl4 = 255, loop4 = 1;
        inet_pton(AF_INET, "224.0.0.251", &mr4.imr_multiaddr);
        fd4 = socket(AF_INET, SOCK_DGRAM, 0);
        setsockopt(fd4, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
        setsockopt(fd4, SOL_SOCKET, SO_REUSEPORT, &on, sizeof on);
        if (bind(fd4, (struct sockaddr *)&a4, sizeof a4) < 0 ||
            setsockopt(fd4, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mr4, sizeof mr4) < 0) {
            LOG("mdns: IPv4 socket setup failed: %s (continuing with IPv6 only)", strerror(errno));
            close(fd4);
            fd4 = -1;
        } else {
            setsockopt(fd4, IPPROTO_IP, IP_MULTICAST_IF, &if4, sizeof if4);
            setsockopt(fd4, IPPROTO_IP, IP_MULTICAST_TTL, &ttl4, sizeof ttl4);
            setsockopt(fd4, IPPROTO_IP, IP_MULTICAST_LOOP, &loop4, sizeof loop4);
        }
    }
    return 0;
}

/* ------------------------------------------------------------- records */

static int add_rr(rr_t *rr, int n, const char *name, uint16_t type, const char *target)
{
    if (n >= MAXRR)
        return n;
    memset(&rr[n], 0, sizeof rr[n]);
    snprintf(rr[n].name, sizeof rr[n].name, "%s", name);
    rr[n].type = type;
    rr[n].unique = type != T_PTR;
    if (target)
        snprintf(rr[n].target, sizeof rr[n].target, "%s", target);
    return n + 1;
}

/* Build the full set of records we currently own, from live node state.
 * Rebuilding on every query/announcement means there's no cache to keep in
 * sync: open/close the window or add a fabric and the next answer reflects it. */
static int build_records(rr_t *rr, int which)
{
    int n = 0;
    char host[64], name[128], inst[128];
    snprintf(host, sizeof host, "%s.local", g_node.host);

    if ((which & RR_COMM) && g_node.cw_open) {
        snprintf(inst, sizeof inst, "%s._matterc._udp.local", g_node.instance);
        n = add_rr(rr, n, "_matterc._udp.local", T_PTR, inst);
        snprintf(name, sizeof name, "_L%u._sub._matterc._udp.local", g_node.cw_disc);
        n = add_rr(rr, n, name, T_PTR, inst);
        snprintf(name, sizeof name, "_S%u._sub._matterc._udp.local", g_node.cw_disc >> 8);
        n = add_rr(rr, n, name, T_PTR, inst);
        snprintf(name, sizeof name, "_V%u._sub._matterc._udp.local", g_node.vid);
        n = add_rr(rr, n, name, T_PTR, inst);
        n = add_rr(rr, n, "_T256._sub._matterc._udp.local", T_PTR, inst);   /* 256 = On/Off Light */
        n = add_rr(rr, n, "_CM._sub._matterc._udp.local", T_PTR, inst);
        n = add_rr(rr, n, "_services._dns-sd._udp.local", T_PTR, "_matterc._udp.local");
        n = add_rr(rr, n, inst, T_SRV, host);
        rr[n - 1].port = MATTER_PORT;
        n = add_rr(rr, n, inst, T_TXT, NULL);
        rr_t *t = &rr[n - 1];
        snprintf(t->txt[t->ntxt++], 48, "D=%u", g_node.cw_disc);
        snprintf(t->txt[t->ntxt++], 48, "CM=%d", g_node.cw_enhanced ? 2 : 1);
        snprintf(t->txt[t->ntxt++], 48, "VP=%u+%u", g_node.vid, g_node.pid);
        snprintf(t->txt[t->ntxt++], 48, "DT=256");
        snprintf(t->txt[t->ntxt++], 48, "DN=C Matter Light");
        snprintf(t->txt[t->ntxt++], 48, "SII=500");
        snprintf(t->txt[t->ntxt++], 48, "SAI=300");
        snprintf(t->txt[t->ntxt++], 48, "SAT=4000");
        snprintf(t->txt[t->ntxt++], 48, "PH=33");
    }

    if (which & RR_OPER) {
        int any = 0;
        for (int i = 0; i < MAX_FABRICS; i++) {
            fabric_t *f = &g_node.fabrics[i];
            char cf[17];
            if (!f->in_use)
                continue;
            for (int k = 0; k < 8; k++)
                sprintf(cf + 2 * k, "%02X", f->cfid[k]);
            snprintf(inst, sizeof inst, "%s-%016llX._matter._tcp.local", cf, (unsigned long long)f->node_id);
            n = add_rr(rr, n, "_matter._tcp.local", T_PTR, inst);
            snprintf(name, sizeof name, "_I%s._sub._matter._tcp.local", cf);
            n = add_rr(rr, n, name, T_PTR, inst);
            n = add_rr(rr, n, inst, T_SRV, host);
            rr[n - 1].port = MATTER_PORT;
            n = add_rr(rr, n, inst, T_TXT, NULL);
            rr_t *t = &rr[n - 1];
            snprintf(t->txt[t->ntxt++], 48, "SII=500");
            snprintf(t->txt[t->ntxt++], 48, "SAI=300");
            snprintf(t->txt[t->ntxt++], 48, "SAT=4000");
            any = 1;
        }
        if (any)
            n = add_rr(rr, n, "_services._dns-sd._udp.local", T_PTR, "_matter._tcp.local");
    }

    if (which & RR_HOST) {
        /* one AAAA/A per address on the interface (link-local, ULA, global...) */
        struct ifaddrs *ifa, *i;
        if (!getifaddrs(&ifa)) {
            for (i = ifa; i; i = i->ifa_next) {
                if (!i->ifa_addr || strcmp(i->ifa_name, ifname))
                    continue;
                if (i->ifa_addr->sa_family == AF_INET6 && n < MAXRR) {
                    n = add_rr(rr, n, host, T_AAAA, NULL);
                    memcpy(rr[n - 1].addr, &((struct sockaddr_in6 *)i->ifa_addr)->sin6_addr, 16);
                    rr[n - 1].alen = 16;
                } else if (i->ifa_addr->sa_family == AF_INET && n < MAXRR) {
                    n = add_rr(rr, n, host, T_A, NULL);
                    memcpy(rr[n - 1].addr, &((struct sockaddr_in *)i->ifa_addr)->sin_addr, 4);
                    rr[n - 1].alen = 4;
                }
            }
            freeifaddrs(ifa);
        }
    }
    return n;
}

/* ------------------------------------------------------------ encoding */
/* Standard DNS wire format (big-endian!). We never compress names on
 * output - simpler, and our packets are small enough. */

typedef struct { uint8_t b[1500]; size_t len; int err; } pkt_t;

static void p_put(pkt_t *p, const void *d, size_t n)
{
    if (p->err || p->len + n > sizeof p->b) {
        p->err = 1;
        return;
    }
    memcpy(p->b + p->len, d, n);
    p->len += n;
}

static void p_u16(pkt_t *p, uint16_t v) { uint8_t b[2] = { v >> 8, v & 0xFF }; p_put(p, b, 2); }
static void p_u32(pkt_t *p, uint32_t v) { p_u16(p, v >> 16); p_u16(p, v & 0xFFFF); }

/* "a.b.local" -> \x01a\x01b\x05local\x00 */
static void p_name(pkt_t *p, const char *name)
{
    while (*name) {
        const char *dot = strchr(name, '.');
        size_t l = dot ? (size_t)(dot - name) : strlen(name);
        uint8_t lb = (uint8_t)l;
        p_put(p, &lb, 1);
        p_put(p, name, l);
        name += l;
        if (*name == '.')
            name++;
    }
    uint8_t z = 0;
    p_put(p, &z, 1);
}

/* Resource record: name, type, class (IN, with the cache-flush bit 0x8000
 * for unique records = "replace what you cached"), TTL, rdlength, rdata. */
static void p_rr(pkt_t *p, const rr_t *r, uint32_t ttl, int flush)
{
    p_name(p, r->name);
    p_u16(p, r->type);
    p_u16(p, 1 | (flush && r->unique ? 0x8000 : 0));
    p_u32(p, ttl);
    size_t lenpos = p->len;
    p_u16(p, 0);                       /* rdlength placeholder, patched below */
    size_t start = p->len;
    switch (r->type) {
    case T_PTR: p_name(p, r->target); break;
    case T_SRV: p_u16(p, 0); p_u16(p, 0); p_u16(p, r->port); p_name(p, r->target); break;  /* prio, weight, port, host */
    case T_TXT:
        /* each "key=value" is a length-prefixed string */
        for (int i = 0; i < r->ntxt; i++) {
            uint8_t l = (uint8_t)strlen(r->txt[i]);
            p_put(p, &l, 1);
            p_put(p, r->txt[i], l);
        }
        if (!r->ntxt) {
            uint8_t z = 0;
            p_put(p, &z, 1);
        }
        break;
    default: p_put(p, r->addr, r->alen); break;   /* A / AAAA */
    }
    if (!p->err) {
        size_t rdlen = p->len - start;
        p->b[lenpos] = rdlen >> 8;
        p->b[lenpos + 1] = rdlen & 0xFF;
    }
}

static void send_multicast(const pkt_t *p)
{
    struct sockaddr_in6 d6 = { .sin6_family = AF_INET6, .sin6_port = htons(MDNS_PORT), .sin6_scope_id = ifidx };
    inet_pton(AF_INET6, "ff02::fb", &d6.sin6_addr);
    if (sendto(fd6, p->b, p->len, 0, (struct sockaddr *)&d6, sizeof d6) < 0)
        DBG("mdns send v6: %s", strerror(errno));
    if (fd4 >= 0) {
        struct sockaddr_in d4 = { .sin_family = AF_INET, .sin_port = htons(MDNS_PORT) };
        inet_pton(AF_INET, "224.0.0.251", &d4.sin_addr);
        if (sendto(fd4, p->b, p->len, 0, (struct sockaddr *)&d4, sizeof d4) < 0)
            DBG("mdns send v4: %s", strerror(errno));
    }
}

/* send all records as unsolicited responses, split over as many packets as needed */
static void send_all(int which, uint32_t ttl)
{
    static rr_t rr[MAXRR];
    /* DNS header: id 0, flags 0x8400 (response + authoritative), all counts
     * 0; the answer count (bytes 6..7) is patched before each send */
    static const uint8_t hdr[12] = { 0, 0, 0x84, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    pkt_t p = { .len = 0 };
    int n = build_records(rr, which), count = 0;
    p_put(&p, hdr, sizeof hdr);
    for (int i = 0; i < n; i++) {
        size_t mark = p.len;
        p_rr(&p, &rr[i], ttl, 1);
        if (p.err && count) {     /* packet full: send what we have and retry this record */
            p.len = mark;
            p.err = 0;
            p.b[6] = count >> 8;
            p.b[7] = count & 0xFF;
            send_multicast(&p);
            p.len = sizeof hdr;
            count = 0;
            i--;
            continue;
        }
        count++;
    }
    if (count && !p.err) {
        p.b[6] = count >> 8;
        p.b[7] = count & 0xFF;
        send_multicast(&p);
    }
}

/* Unsolicited announcement: tell everyone our current records now, then
 * twice more (mdns_tick) in case a packet is lost. */
void mdns_announce(void)
{
    send_all(RR_ALL, TTL);
    announce_left = 2;
    announce_next = now_ms() + 1000;
}

/* "Goodbye" = the same records with TTL 0, which tells caches to drop them
 * immediately (e.g. the commissioning window just closed). */
void mdns_goodbye_commissionable(void) { send_all(RR_COMM, 0); }
void mdns_goodbye_all(void) { send_all(RR_COMM | RR_OPER, 0); }

void mdns_tick(uint64_t now)
{
    if (announce_left && now >= announce_next) {
        send_all(RR_ALL, TTL);
        announce_left--;
        announce_next = now + 2000;
    }
}

/* ------------------------------------------------------------- queries */

/* Read a possibly-compressed DNS name. Compression: a byte 0b11xxxxxx means
 * "the rest of the name is at offset xxxxxx..." (14-bit pointer). *off is
 * advanced past the name as it appears at the original position. The hop
 * limit stops pointer loops in malicious packets. */
static int read_name(const uint8_t *pkt, size_t n, size_t *off, char *out, size_t cap)
{
    size_t o = *off, olen = 0;
    int jumped = 0, hops = 0;
    for (;;) {
        if (o >= n)
            return -1;
        uint8_t l = pkt[o];
        if (l == 0) {
            o++;
            break;
        }
        if ((l & 0xC0) == 0xC0) {
            if (o + 1 >= n || ++hops > 16)
                return -1;
            if (!jumped)
                *off = o + 2;
            jumped = 1;
            o = ((l & 0x3F) << 8) | pkt[o + 1];
            continue;
        }
        if (l > 63 || o + 1 + l > n || olen + l + 2 > cap)
            return -1;
        if (olen)
            out[olen++] = '.';
        memcpy(out + olen, pkt + o + 1, l);
        olen += l;
        o += 1 + l;
    }
    out[olen] = 0;
    if (!jumped)
        *off = o;
    return 0;
}

/* Handle one incoming mDNS packet: if it is a query for any of our names,
 * answer it. Answers go in the answer section; helpful related records
 * (SRV+TXT for a PTR, addresses for an SRV) go in the additional section so
 * the querier can resolve everything in one round trip. */
void mdns_rx(int fd)
{
    static rr_t rr[MAXRR];
    uint8_t q[1500];
    struct sockaddr_storage from;
    socklen_t fl = sizeof from;
    ssize_t n = recvfrom(fd, q, sizeof q, 0, (struct sockaddr *)&from, &fl);
    if (n < 12)
        return;
    /* DNS header: id, flags, qdcount, ancount, nscount, arcount */
    uint16_t id = (q[0] << 8) | q[1], flags = (q[2] << 8) | q[3], qd = (q[4] << 8) | q[5];
    if (flags & 0x8000)
        return;   /* a response, not a query */

    /* "legacy unicast": a plain DNS client querying from a random port; it
     * expects a normal unicast reply that echoes id and questions */
    uint16_t sport = from.ss_family == AF_INET6 ? ntohs(((struct sockaddr_in6 *)&from)->sin6_port)
                                                : ntohs(((struct sockaddr_in *)&from)->sin_port);
    int legacy = sport != MDNS_PORT;
    int nrr = build_records(rr, RR_ALL);
    int ans[MAXRR] = { 0 }, add[MAXRR] = { 0 };
    char qnames[8][256];
    uint16_t qtypes[8];
    int nq = 0;
    size_t off = 12;

    /* question section: name, type, class. Match names case-insensitively. */
    for (int i = 0; i < qd; i++) {
        char name[256];
        if (read_name(q, n, &off, name, sizeof name) || off + 4 > (size_t)n)
            return;
        uint16_t qt = (q[off] << 8) | q[off + 1];
        off += 4;
        if (nq < 8) {
            snprintf(qnames[nq], sizeof qnames[nq], "%s", name);
            qtypes[nq++] = qt;
        }
        for (int r = 0; r < nrr; r++)
            if (!strcasecmp(rr[r].name, name) && (qt == T_ANY || qt == rr[r].type))
                ans[r] = 1;
    }

    int nans = 0;
    for (int r = 0; r < nrr; r++)
        nans += ans[r];
    if (!nans)
        return;   /* not about us: stay silent */

    /* additional records: SRV/TXT for answered PTRs, then addresses for SRVs */
    for (int r = 0; r < nrr; r++)
        if (ans[r] && rr[r].type == T_PTR)
            for (int k = 0; k < nrr; k++)
                if ((rr[k].type == T_SRV || rr[k].type == T_TXT) && !strcasecmp(rr[k].name, rr[r].target))
                    add[k] = 1;
    for (int r = 0; r < nrr; r++)
        if ((ans[r] || add[r]) && rr[r].type == T_SRV)
            for (int k = 0; k < nrr; k++)
                if ((rr[k].type == T_A || rr[k].type == T_AAAA) && !strcasecmp(rr[k].name, rr[r].target))
                    add[k] = 1;
    int nadd = 0;
    for (int r = 0; r < nrr; r++) {
        add[r] &= !ans[r];
        nadd += add[r];
    }

    pkt_t p = { .len = 0 };
    p_u16(&p, legacy ? id : 0);
    p_u16(&p, 0x8400);
    p_u16(&p, legacy ? (uint16_t)nq : 0);
    p_u16(&p, (uint16_t)nans);
    p_u16(&p, 0);
    p_u16(&p, (uint16_t)nadd);
    if (legacy)
        for (int i = 0; i < nq; i++) {
            p_name(&p, qnames[i]);
            p_u16(&p, qtypes[i]);
            p_u16(&p, 1);
        }
    for (int r = 0; r < nrr; r++)
        if (ans[r])
            p_rr(&p, &rr[r], legacy ? 10 : TTL, !legacy);
    for (int r = 0; r < nrr; r++)
        if (add[r])
            p_rr(&p, &rr[r], legacy ? 10 : TTL, !legacy);
    if (p.err)
        return;

    DBG("mdns: answering query (%d answers, %d additional)%s", nans, nadd, legacy ? " [unicast]" : "");
    if (legacy)
        sendto(fd, p.b, p.len, 0, (struct sockaddr *)&from, fl);
    else
        send_multicast(&p);
}

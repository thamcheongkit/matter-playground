/* Interaction Model: Read, Subscribe (+ reports), Write, Invoke, Timed.
 *
 * The Interaction Model (IM, protocol id 1) is how controllers use the data
 * model. All IM messages are TLV structs, and every one ends with tag 0xFF =
 * InteractionModelRevision.
 *
 * PATHS
 *   An attribute is addressed by (endpoint, cluster, attribute). Any part
 *   may be omitted = wildcard, e.g. "all attributes of all clusters on all
 *   endpoints" is an empty path - which is exactly what controllers send
 *   right after commissioning to learn the whole device. Paths are TLV
 *   *lists* (AttributePathIB): {2: endpoint, 3: cluster, 4: attribute,
 *   5: list index}.
 *
 * INTERACTIONS
 *   Read:       ReadRequest -> ReportData (possibly several chunks)
 *   Subscribe:  SubscribeRequest -> ReportData chunks ("priming") ->
 *               SubscribeResponse; afterwards WE initiate ReportData on
 *               every change, plus empty keep-alive reports before
 *               MaxInterval runs out, so the controller knows we're alive.
 *   Write:      WriteRequest -> WriteResponse (one status per attribute)
 *   Invoke:     InvokeRequest -> InvokeResponse (a response command, or a
 *               status per command)
 *   Timed:      TimedRequest -> StatusResponse, then the actual Write/Invoke
 *               (an anti-replay measure for doors/locks; we just accept it)
 *
 * CHUNKING
 *   A message must fit in one IPv6 minimum-MTU UDP packet (~1.2 KB), but a
 *   wildcard read of this device is ~119 attributes. So ReportData is sent
 *   in chunks with MoreChunkedMessages=true; the client answers each with a
 *   StatusResponse(Success) before we send the next. A single list attribute
 *   too big for one message is split: first "replace the whole list with
 *   []", then one "append item" report per element.
 *
 * DATA VERSIONS
 *   Each cluster instance has a 32-bit DataVersion that changes whenever
 *   any of its attributes changes. Clients send DataVersionFilters ("I
 *   already have version V of cluster C") to skip unchanged clusters.
 */
#include "matter.h"

#include <stdlib.h>
#include <string.h>

#define IM_REV 11

enum {
    IM_STATUS_RESPONSE = 0x01, IM_READ_REQUEST = 0x02, IM_SUBSCRIBE_REQUEST = 0x03,
    IM_SUBSCRIBE_RESPONSE = 0x04, IM_REPORT_DATA = 0x05, IM_WRITE_REQUEST = 0x06,
    IM_WRITE_RESPONSE = 0x07, IM_INVOKE_REQUEST = 0x08, IM_INVOKE_RESPONSE = 0x09,
    IM_TIMED_REQUEST = 0x0A,
};

#define MAX_PATHS      512
#define MAX_REQ_PATHS  16
#define MAX_DV_FILTERS 16
#define MAX_SUBS       8
#define MAX_EXCH       8
#define MAX_DIRTY      16
#define REPORT_BUDGET  1100     /* TLV bytes of AttributeReportIBs per ReportData chunk */
#define EXCH_TIMEOUT_MS 30000

/* A path as requested (each component may be a wildcard). */
typedef struct { int has_ep, has_cl, has_at; uint16_t ep; uint32_t cl, at; } req_path;
/* A concrete attribute after wildcard expansion. status != 0 means "report
 * this error for this path" (e.g. UNSUPPORTED_ATTRIBUTE). */
typedef struct { uint16_t ep; uint32_t cl, at; uint8_t status; } apath;
typedef struct { uint16_t ep; uint32_t cl; uint32_t ver; } dv_filter;
typedef struct { uint16_t ep; uint32_t cl; } cpath;   /* a cluster instance */

/* Progress of a (possibly multi-chunk) report: which path is next, and if
 * we are in the middle of splitting a list, which list item is next. */
typedef struct {
    apath *paths;
    int npaths, next;
    int list_item;            /* -1: whole attribute, -2: emit ReplaceAll, >=0: next list item */
    int is_sub, is_read;
    uint32_t sub_id;
    im_ctx ctx;
} report_state;

/* An active subscription: what the client asked for, timing limits, and the
 * clusters that changed since the last report. */
typedef struct {
    int in_use;
    uint32_t id;
    session_t *sess;
    int fabric_filtered;
    req_path paths[MAX_REQ_PATHS]; int npaths;
    uint16_t min_iv, max_iv;  /* seconds: no reports faster than min; at least one per max */
    int active, busy;         /* active = SubscribeResponse sent; busy = report in flight */
    uint64_t last_report;
    cpath dirty[MAX_DIRTY]; int ndirty;
} sub_t;

enum { EX_READ = 1, EX_SUB_PRIMING, EX_SUB_REPORT };

/* An IM exchange that spans several messages (chunked reports). Single-shot
 * interactions (write, invoke) don't need one of these. */
typedef struct {
    int in_use, kind, we_initiated;
    session_t *sess;
    uint16_t exch;
    report_state rs;
    sub_t *sub;
    uint64_t created;
} im_exch;

static sub_t subs[MAX_SUBS];
static im_exch exchs[MAX_EXCH];

/* ------------------------------------------------------- data model helpers */

/* Look up a cluster instance. On failure *status tells which level was
 * missing, so errors can be precise (UNSUPPORTED_ENDPOINT vs _CLUSTER). */
const cluster_def *find_cluster(uint16_t ep, uint32_t cl, int *status)
{
    for (int e = 0; e < g_nendpoints; e++) {
        if (g_endpoints[e].id != ep)
            continue;
        for (int c = 0; c < g_endpoints[e].nclusters; c++)
            if (g_endpoints[e].clusters[c]->id == cl)
                return g_endpoints[e].clusters[c];
        if (status)
            *status = ST_UNSUPPORTED_CLUSTER;
        return NULL;
    }
    if (status)
        *status = ST_UNSUPPORTED_ENDPOINT;
    return NULL;
}

/* Per-cluster-instance DataVersion, indexed by position in g_endpoints.
 * Initialised randomly so a restarted device doesn't accidentally match a
 * version a client cached before the restart. */
uint32_t *data_version(uint16_t ep, uint32_t cl)
{
    static uint32_t dv[4][16];
    static int init;
    if (!init) {
        for (int i = 0; i < 4; i++)
            for (int j = 0; j < 16; j++)
                dv[i][j] = rand_u32();
        init = 1;
    }
    static uint32_t dummy;
    for (int e = 0; e < g_nendpoints && e < 4; e++)
        if (g_endpoints[e].id == ep)
            for (int c = 0; c < g_endpoints[e].nclusters && c < 16; c++)
                if (g_endpoints[e].clusters[c]->id == cl)
                    return &dv[e][c];
    return &dummy;
}

/* "Global" attributes every cluster has, served by the engine itself:
 *   0xFFF8 GeneratedCommandList   0xFFF9 AcceptedCommandList
 *   0xFFFB AttributeList          0xFFFC FeatureMap
 *   0xFFFD ClusterRevision */
static const uint32_t global_attrs[] = { 0xFFF8, 0xFFF9, 0xFFFB, 0xFFFC, 0xFFFD };
#define NGLOBAL ((int)(sizeof global_attrs / sizeof global_attrs[0]))

/* i-th attribute id of a cluster: its own list first, then the globals */
static uint32_t attr_at(const cluster_def *cd, int i)
{
    return i < cd->nattrs ? cd->attrs[i] : global_attrs[i - cd->nattrs];
}

static int has_attr(const cluster_def *cd, uint32_t at)
{
    for (int i = 0; i < cd->nattrs + NGLOBAL; i++)
        if (attr_at(cd, i) == at)
            return 1;
    return 0;
}

static void put_u32_array(tlv_w *w, uint32_t tag, const uint32_t *v, int n)
{
    tlv_start(w, tag, TLV_T_ARRAY);
    for (int i = 0; i < n; i++)
        tlv_put_uint(w, TLV_ANON, v[i]);
    tlv_end(w);
}

/* Read one attribute value into w (with the given tag). Global attributes
 * are answered here from the cluster_def tables; the rest go to the cluster.
 * Returns an IM status (0 = success). */
static int read_attr(const im_ctx *c, uint16_t ep, const cluster_def *cd, uint32_t at, tlv_w *w, uint32_t tag)
{
    switch (at) {
    case 0xFFFD: tlv_put_uint(w, tag, cd->rev); return 0;
    case 0xFFFC: tlv_put_uint(w, tag, cd->features); return 0;
    case 0xFFF9: put_u32_array(w, tag, cd->acmds, cd->nacmds); return 0;
    case 0xFFF8: put_u32_array(w, tag, cd->gcmds, cd->ngcmds); return 0;
    case 0xFFFB:
        tlv_start(w, tag, TLV_T_ARRAY);
        for (int i = 0; i < cd->nattrs + NGLOBAL; i++)
            tlv_put_uint(w, TLV_ANON, attr_at(cd, i));
        tlv_end(w);
        return 0;
    }
    return cd->read ? cd->read(c, ep, at, w, tag) : ST_UNSUPPORTED_ATTRIBUTE;
}

/* ---------------------------------------------------------------- paths */

/* AttributePathIB (a TLV list): 1 node (ignored), 2 endpoint, 3 cluster,
 * 4 attribute, 5 list index. In writes, "list index = null" means "append
 * this item to the list" rather than replacing the whole attribute. */
static void parse_attr_path(const tlv_el *p, req_path *rp, int *list_append)
{
    tlv_it it;
    tlv_el e;
    memset(rp, 0, sizeof *rp);
    if (list_append)
        *list_append = 0;
    tlv_iter(&it, p);
    while (tlv_next(&it, &e)) {
        switch (e.tag) {
        case 2: if (e.type == TLV_T_UINT) { rp->has_ep = 1; rp->ep = (uint16_t)e.u; } break;
        case 3: if (e.type == TLV_T_UINT) { rp->has_cl = 1; rp->cl = (uint32_t)e.u; } break;
        case 4: if (e.type == TLV_T_UINT) { rp->has_at = 1; rp->at = (uint32_t)e.u; } break;
        case 5: if (e.type == TLV_T_NULL && list_append) *list_append = 1; break;
        }
    }
}

static int parse_req_paths(const tlv_el *arr, req_path *out, int max)
{
    tlv_it it;
    tlv_el e;
    int n = 0;
    tlv_iter(&it, arr);
    while (tlv_next(&it, &e)) {
        if (n >= max)
            return -1;
        parse_attr_path(&e, &out[n++], NULL);
    }
    return n;
}

/* DataVersionFilterIB: { 0: ClusterPathIB {1: endpoint, 2: cluster}, 1: version } */
static int parse_dv_filters(const tlv_el *arr, dv_filter *out, int max)
{
    tlv_it it;
    tlv_el e, p;
    int n = 0;
    tlv_iter(&it, arr);
    while (n < max && tlv_next(&it, &e)) {
        if (!tlv_get(&e, 0, &p))
            continue;
        out[n].ep = (uint16_t)tlv_get_u(&p, 1, 0);
        out[n].cl = (uint32_t)tlv_get_u(&p, 2, 0);
        out[n].ver = (uint32_t)tlv_get_u(&e, 1, 0);
        n++;
    }
    return n;
}

static int path_matches(const req_path *r, uint16_t ep, uint32_t cl)
{
    return (!r->has_ep || r->ep == ep) && (!r->has_cl || r->cl == cl);
}

/* Expand (possibly wildcard) request paths into concrete attribute paths.
 * If 'only' is given, restrict to those clusters (used for change reports).
 *
 * Rules: wildcards silently skip what doesn't exist; a fully concrete path
 * that matches nothing produces an explicit error entry. Clusters whose
 * DataVersion matches a client filter are skipped entirely. */
static int expand(const req_path *rp, int nrp, const dv_filter *dvf, int ndvf,
                  const cpath *only, int nonly, apath *out, int max)
{
    int n = 0;
    for (int i = 0; i < nrp; i++) {
        const req_path *r = &rp[i];
        int matched = 0;
        for (int e = 0; e < g_nendpoints; e++) {
            const endpoint_def *ed = &g_endpoints[e];
            if (r->has_ep && r->ep != ed->id)
                continue;
            for (int c = 0; c < ed->nclusters; c++) {
                const cluster_def *cd = ed->clusters[c];
                if (r->has_cl && r->cl != cd->id)
                    continue;
                if (only) {
                    int ok = 0;
                    for (int k = 0; k < nonly; k++)
                        ok |= only[k].ep == ed->id && only[k].cl == cd->id;
                    if (!ok)
                        continue;
                }
                int skip = 0;
                for (int k = 0; k < ndvf; k++)
                    skip |= dvf[k].ep == ed->id && dvf[k].cl == cd->id &&
                            dvf[k].ver == *data_version(ed->id, cd->id);
                for (int a = 0; a < cd->nattrs + NGLOBAL; a++) {
                    uint32_t at = attr_at(cd, a);
                    if (r->has_at && r->at != at)
                        continue;
                    matched = 1;
                    if (!skip && n < max)
                        out[n++] = (apath){ ed->id, cd->id, at, 0 };
                }
            }
        }
        if (!matched && !only && r->has_ep && r->has_cl && r->has_at && n < max) {
            int st = ST_UNSUPPORTED_ATTRIBUTE;
            find_cluster(r->ep, r->cl, &st);
            out[n++] = (apath){ r->ep, r->cl, r->at, (uint8_t)st };
        }
    }
    return n;
}

/* --------------------------------------------------------------- reports */
/*
 * ReportDataMessage:
 *   { 0: SubscriptionId (subscriptions only),
 *     1: AttributeReports [ AttributeReportIB ... ],
 *     3: MoreChunkedMessages (bool), 4: SuppressResponse (bool), 0xFF: rev }
 *
 * AttributeReportIB is one of:
 *   { 1: AttributeDataIB   { 0: DataVersion, 1: Path, 2: Data } }
 *   { 0: AttributeStatusIB { 0: Path, 1: StatusIB { 0: status } } }
 */

static void put_path(tlv_w *w, uint32_t tag, uint16_t ep, uint32_t cl, uint32_t at, int list_null)
{
    tlv_start(w, tag, TLV_T_LIST);
    tlv_put_uint(w, 2, ep);
    tlv_put_uint(w, 3, cl);
    tlv_put_uint(w, 4, at);
    if (list_null)
        tlv_put_null(w, 5);           /* "this is one appended list item" */
    tlv_end(w);
}

static void put_attr_status(tlv_w *w, const apath *p, int status)
{
    tlv_start(w, TLV_ANON, TLV_T_STRUCT);   /* AttributeReportIB */
    tlv_start(w, 0, TLV_T_STRUCT);          /* AttributeStatusIB */
    put_path(w, 0, p->ep, p->cl, p->at, 0);
    tlv_start(w, 1, TLV_T_STRUCT);          /* StatusIB */
    tlv_put_uint(w, 0, status);
    tlv_end(w);
    tlv_end(w);
    tlv_end(w);
}

/* Opens AttributeReportIB + AttributeDataIB and writes version + path; the
 * caller writes the Data (tag 2) and closes the two containers. */
static void put_data_header(tlv_w *w, const apath *p, int list_null)
{
    tlv_start(w, TLV_ANON, TLV_T_STRUCT);   /* AttributeReportIB */
    tlv_start(w, 1, TLV_T_STRUCT);          /* AttributeDataIB */
    tlv_put_uint(w, 0, *data_version(p->ep, p->cl));
    put_path(w, 1, p->ep, p->cl, p->at, list_null);
}

/* Build the next ReportData chunk from rs into out. Sets *more if paths
 * remain. Strategy: encode each attribute report into a scratch buffer
 * first, then copy it in only if it fits the chunk budget. An attribute
 * that doesn't fit even into an empty chunk must be a big list, so it
 * switches to list-splitting mode (list_item = -2, then 0, 1, 2, ...). */
static size_t build_report(report_state *rs, uint8_t *out, size_t cap, int *more)
{
    static uint8_t body[REPORT_BUDGET], tmp[8192], ib[REPORT_BUDGET];
    tlv_w b, t, iw;
    tlv_w_init(&b, body, sizeof body);

    while (rs->next < rs->npaths) {
        apath *p = &rs->paths[rs->next];
        const cluster_def *cd = find_cluster(p->ep, p->cl, NULL);

        if (rs->list_item == -1) {
            /* normal case: the whole attribute in one AttributeReportIB */
            tlv_w_init(&t, tmp, sizeof tmp);
            int st = p->status;
            if (!st) {
                put_data_header(&t, p, 0);
                st = read_attr(&rs->ctx, p->ep, cd, p->at, &t, 2);
                tlv_end(&t);
                tlv_end(&t);
                if (t.err && !st)
                    st = ST_RESOURCE_EXHAUSTED;
            }
            if (st) {
                tlv_w_init(&t, tmp, sizeof tmp);
                put_attr_status(&t, p, st);
            }
            if (b.len + t.len <= sizeof body) {
                tlv_put_raw(&b, tmp, t.len);
                rs->next++;
                continue;
            }
            if (b.len)
                break;              /* start a new chunk */
            rs->list_item = -2;     /* does not fit alone: split the list across chunks */
        }

        /* list chunking: ReplaceAll with an empty list, then append items one by one */
        tlv_el arr, item;
        tlv_it it;
        tlv_w_init(&t, tmp, sizeof tmp);
        if (read_attr(&rs->ctx, p->ep, cd, p->at, &t, TLV_ANON) || t.err ||
            tlv_parse(tmp, t.len, &arr) || arr.type != TLV_T_ARRAY) {
            LOG("attribute %u/0x%x/0x%x too large to report, skipped", p->ep, p->cl, p->at);
            rs->list_item = -1;
            rs->next++;
            continue;
        }
        if (rs->list_item == -2) {
            tlv_w_init(&iw, ib, sizeof ib);
            put_data_header(&iw, p, 0);
            tlv_start(&iw, 2, TLV_T_ARRAY);
            tlv_end(&iw);
            tlv_end(&iw);
            tlv_end(&iw);
            if (b.len + iw.len > sizeof body)
                break;
            tlv_put_raw(&b, ib, iw.len);
            rs->list_item = 0;
        }
        /* re-read and skip items already sent in earlier chunks */
        int idx = 0, full = 0;
        tlv_iter(&it, &arr);
        while (tlv_next(&it, &item)) {
            if (idx++ < rs->list_item)
                continue;
            tlv_w_init(&iw, ib, sizeof ib);
            put_data_header(&iw, p, 1);
            tlv_put_retag(&iw, 2, &item);
            tlv_end(&iw);
            tlv_end(&iw);
            if (iw.err) {
                LOG("list item of 0x%x/0x%x too large, skipped", p->cl, p->at);
                rs->list_item++;
                continue;
            }
            if (b.len + iw.len > sizeof body) {
                full = 1;
                break;
            }
            tlv_put_raw(&b, ib, iw.len);
            rs->list_item++;
        }
        if (full)
            break;
        rs->list_item = -1;
        rs->next++;
    }

    /* wrap the collected AttributeReportIBs into the ReportData message */
    tlv_w w;
    tlv_w_init(&w, out, cap);
    tlv_start(&w, TLV_ANON, TLV_T_STRUCT);
    if (rs->is_sub)
        tlv_put_uint(&w, 0, rs->sub_id);
    if (b.len) {
        tlv_start(&w, 1, TLV_T_ARRAY);
        tlv_put_raw(&w, body, b.len);
        tlv_end(&w);
    }
    *more = rs->next < rs->npaths;
    if (*more)
        tlv_put_bool(&w, 3, 1);           /* MoreChunkedMessages */
    else if (rs->is_read)
        tlv_put_bool(&w, 4, 1);           /* SuppressResponse: last chunk of a read needs no StatusResponse */
    tlv_put_uint(&w, 0xFF, IM_REV);
    tlv_end(&w);
    return w.len;
}

/* ------------------------------------------------------------- exchanges */

static im_exch *exch_find(session_t *s, uint16_t id, int we_initiated)
{
    for (int i = 0; i < MAX_EXCH; i++)
        if (exchs[i].in_use && exchs[i].sess == s && exchs[i].exch == id &&
            exchs[i].we_initiated == we_initiated)
            return &exchs[i];
    return NULL;
}

static void exch_free(im_exch *x)
{
    free(x->rs.paths);
    memset(x, 0, sizeof *x);
}

static im_exch *exch_alloc(session_t *s, uint16_t id, int we_initiated, int kind)
{
    im_exch *x = NULL;
    for (int i = 0; i < MAX_EXCH && !x; i++)
        if (!exchs[i].in_use)
            x = &exchs[i];
    if (!x)
        return NULL;
    memset(x, 0, sizeof *x);
    x->in_use = 1;
    x->sess = s;
    x->exch = id;
    x->we_initiated = we_initiated;
    x->kind = kind;
    x->created = now_ms();
    x->rs.list_item = -1;
    x->rs.paths = calloc(MAX_PATHS, sizeof(apath));
    return x;
}

static void sub_free(sub_t *s)
{
    for (int i = 0; i < MAX_EXCH; i++)
        if (exchs[i].in_use && exchs[i].sub == s)
            exch_free(&exchs[i]);
    if (s->in_use)
        LOG("subscription 0x%08x ended", s->id);
    memset(s, 0, sizeof *s);
}

/* session going away: everything that depended on it goes too */
void im_drop_session(session_t *s)
{
    for (int i = 0; i < MAX_SUBS; i++)
        if (subs[i].in_use && subs[i].sess == s)
            sub_free(&subs[i]);
    for (int i = 0; i < MAX_EXCH; i++)
        if (exchs[i].in_use && exchs[i].sess == s)
            exch_free(&exchs[i]);
}

/* MRP gave up delivering a message on this exchange: the peer is gone, so
 * tear down the exchange (and its subscription, if any). The controller
 * will notice the missing reports and resubscribe when it comes back. */
void im_on_send_failed(session_t *s, uint16_t exch)
{
    for (int i = 0; i < MAX_EXCH; i++) {
        im_exch *x = &exchs[i];
        if (x->in_use && x->sess == s && x->exch == exch) {
            if (x->sub)
                sub_free(x->sub);
            else
                exch_free(x);
        }
    }
}

/* StatusResponseMessage: { 0: status, 0xFF: rev } */
static void send_status(rx_ctx *rx, int status)
{
    uint8_t b[16];
    tlv_w w;
    tlv_w_init(&w, b, sizeof b);
    tlv_start(&w, TLV_ANON, TLV_T_STRUCT);
    tlv_put_uint(&w, 0, status);
    tlv_put_uint(&w, 0xFF, IM_REV);
    tlv_end(&w);
    reply(rx, PROTO_IM, IM_STATUS_RESPONSE, b, w.len, 1);
}

/* send the next report chunk on an exchange; returns 'more'.
 * rx != NULL: continue an exchange (reply); rx == NULL: start a new one. */
static int send_chunk(im_exch *x, rx_ctx *rx)
{
    uint8_t buf[MAX_UDP];
    int more;
    size_t n = build_report(&x->rs, buf, sizeof buf, &more);
    if (rx)
        reply(rx, PROTO_IM, IM_REPORT_DATA, buf, n, 1);
    else
        send_initiate(x->sess, x->exch, PROTO_IM, IM_REPORT_DATA, buf, n);
    return more;
}

/* ------------------------------------------------------- read/subscribe */

/* ReadRequest and SubscribeRequest share most of their handling; only the
 * field tags differ:
 *   ReadRequest:      { 0: AttributeRequests, 1: EventRequests, 2: EventFilters,
 *                       3: FabricFiltered, 4: DataVersionFilters }
 *   SubscribeRequest: { 0: KeepSubscriptions, 1: MinIntervalFloor,
 *                       2: MaxIntervalCeiling, 3: AttributeRequests,
 *                       4: EventRequests, 5: EventFilters,
 *                       7: FabricFiltered, 8: DataVersionFilters }
 * Event requests are ignored: this device has no events. */
static void handle_read(rx_ctx *rx, int subscribe)
{
    tlv_el m, e;
    req_path rp[MAX_REQ_PATHS];
    dv_filter dvf[MAX_DV_FILTERS];
    int nrp = 0, ndvf = 0;
    if (tlv_parse(rx->payload, rx->len, &m) || m.type != TLV_T_STRUCT) {
        send_status(rx, ST_INVALID_ACTION);
        return;
    }
    uint32_t t_attrs = subscribe ? 3 : 0, t_filtered = subscribe ? 7 : 3, t_dv = subscribe ? 8 : 4;
    if (tlv_get(&m, t_attrs, &e) && (nrp = parse_req_paths(&e, rp, MAX_REQ_PATHS)) < 0) {
        send_status(rx, ST_RESOURCE_EXHAUSTED);
        return;
    }
    if (tlv_get(&m, t_dv, &e))
        ndvf = parse_dv_filters(&e, dvf, MAX_DV_FILTERS);

    im_exch *x = exch_alloc(rx->sess, rx->exchange_id, 0, subscribe ? EX_SUB_PRIMING : EX_READ);
    if (!x || !x->rs.paths) {
        if (x)
            exch_free(x);
        send_status(rx, ST_BUSY);
        return;
    }
    x->rs.ctx.sess = rx->sess;
    x->rs.ctx.fabric_idx = rx->sess->fabric_idx;
    x->rs.ctx.fabric_filtered = (int)tlv_get_u(&m, t_filtered, 1);
    x->rs.is_read = !subscribe;
    x->rs.npaths = expand(rp, nrp, dvf, ndvf, NULL, 0, x->rs.paths, MAX_PATHS);

    if (subscribe) {
        sub_t *s = NULL;
        if (!tlv_get_u(&m, 0, 0)) {   /* KeepSubscriptions == false: drop this peer's others */
            for (int i = 0; i < MAX_SUBS; i++)
                if (subs[i].in_use && subs[i].sess->fabric_idx == rx->sess->fabric_idx &&
                    subs[i].sess->peer_node == rx->sess->peer_node)
                    sub_free(&subs[i]);
        }
        for (int i = 0; i < MAX_SUBS && !s; i++)
            if (!subs[i].in_use)
                s = &subs[i];
        if (!s) {
            exch_free(x);
            send_status(rx, ST_RESOURCE_EXHAUSTED);
            return;
        }
        memset(s, 0, sizeof *s);
        s->in_use = 1;
        s->id = rand_u32();
        s->sess = rx->sess;
        s->fabric_filtered = x->rs.ctx.fabric_filtered;
        /* keep the *unexpanded* paths: change reports re-expand them later */
        memcpy(s->paths, rp, sizeof(req_path) * nrp);
        s->npaths = nrp;
        /* we pick MaxInterval = the client's ceiling (allowed by the spec) */
        s->min_iv = (uint16_t)tlv_get_u(&m, 1, 0);
        s->max_iv = (uint16_t)tlv_get_u(&m, 2, 60);
        if (s->max_iv < s->min_iv)
            s->max_iv = s->min_iv;
        if (s->max_iv < 2)
            s->max_iv = 2;
        x->sub = s;
        x->rs.is_sub = 1;
        x->rs.sub_id = s->id;
        LOG("subscribe: %d attribute paths -> %d attributes, interval %u..%us",
            nrp, x->rs.npaths, s->min_iv, s->max_iv);
    } else {
        DBG("read: %d paths -> %d attributes", nrp, x->rs.npaths);
    }

    /* first chunk now; later chunks are sent from handle_status_response() */
    int more = send_chunk(x, rx);
    if (!more && !subscribe)
        exch_free(x);
}

/* Priming done: SubscribeResponse { 0: SubscriptionId, 2: MaxInterval }.
 * From here on the subscription lives on its own, driven by im_tick(). */
static void subscribe_finish(im_exch *x, rx_ctx *rx)
{
    uint8_t b[32];
    tlv_w w;
    sub_t *s = x->sub;
    tlv_w_init(&w, b, sizeof b);
    tlv_start(&w, TLV_ANON, TLV_T_STRUCT);
    tlv_put_uint(&w, 0, s->id);
    tlv_put_uint(&w, 2, s->max_iv);
    tlv_put_uint(&w, 0xFF, IM_REV);
    tlv_end(&w);
    reply(rx, PROTO_IM, IM_SUBSCRIBE_RESPONSE, b, w.len, 1);
    s->active = 1;
    s->last_report = now_ms();
    LOG("subscription 0x%08x active (max interval %us)", s->id, s->max_iv);
    exch_free(x);
}

/* The client acknowledged a report chunk at the IM level. Depending on the
 * exchange's state: send the next chunk, finish the subscription
 * handshake, or mark a change report as delivered. A non-success status
 * (e.g. INVALID_SUBSCRIPTION after the client restarted) kills the
 * exchange and its subscription. */
static void handle_status_response(rx_ctx *rx, im_exch *x)
{
    tlv_el m;
    int st = ST_FAILURE;
    if (!tlv_parse(rx->payload, rx->len, &m))
        st = (int)tlv_get_u(&m, 0, ST_FAILURE);
    if (st != ST_SUCCESS) {
        DBG("peer StatusResponse 0x%02x, aborting exchange", st);
        if (x->sub)
            sub_free(x->sub);
        else
            exch_free(x);
        return;
    }
    if (x->rs.next < x->rs.npaths) {   /* more chunks to send */
        send_chunk(x, rx);
        return;
    }
    if (x->kind == EX_SUB_PRIMING) {
        subscribe_finish(x, rx);
    } else if (x->kind == EX_SUB_REPORT) {
        x->sub->busy = 0;
        x->sub->last_report = now_ms();
        exch_free(x);
    } else {
        exch_free(x);
    }
}

/* Push a report for a subscription on a NEW exchange we initiate. With
 * dirty clusters it contains their attributes (re-expanded from the
 * subscription's paths); with none it is an empty keep-alive. */
static void sub_send_report(sub_t *s)
{
    im_exch *x = exch_alloc(s->sess, new_exchange_id(), 1, EX_SUB_REPORT);
    if (!x || !x->rs.paths) {
        if (x)
            exch_free(x);
        return;
    }
    x->sub = s;
    x->rs.is_sub = 1;
    x->rs.sub_id = s->id;
    x->rs.ctx.sess = s->sess;
    x->rs.ctx.fabric_idx = s->sess->fabric_idx;
    x->rs.ctx.fabric_filtered = s->fabric_filtered;
    if (s->ndirty)
        x->rs.npaths = expand(s->paths, s->npaths, NULL, 0, s->dirty, s->ndirty, x->rs.paths, MAX_PATHS);
    s->ndirty = 0;
    s->busy = 1;
    DBG("subscription 0x%08x: sending report (%d attributes)", s->id, x->rs.npaths);
    send_chunk(x, NULL);
}

/* Called by clusters whenever an attribute value changes. We don't send
 * anything here; im_tick() does, respecting each subscription's
 * MinInterval and one-report-in-flight limit. */
void im_mark_dirty(uint16_t ep, uint32_t cl)
{
    (*data_version(ep, cl))++;
    for (int i = 0; i < MAX_SUBS; i++) {
        sub_t *s = &subs[i];
        int match = 0, present = 0;
        if (!s->in_use)
            continue;
        for (int k = 0; k < s->npaths; k++)
            match |= path_matches(&s->paths[k], ep, cl);
        for (int k = 0; k < s->ndirty; k++)
            present |= s->dirty[k].ep == ep && s->dirty[k].cl == cl;
        if (match && !present && s->ndirty < MAX_DIRTY)
            s->dirty[s->ndirty++] = (cpath){ ep, cl };
    }
}

/* ------------------------------------------------------------------ write */

/* WriteRequest:  { 0: SuppressResponse, 1: TimedRequest,
 *                  2: WriteRequests [ AttributeDataIB {0: DataVersion?, 1: Path, 2: Data} ],
 *                  3: MoreChunkedMessages }
 * WriteResponse: { 0: WriteResponses [ AttributeStatusIB ] }
 * Chunked writes need no extra state: each chunk is answered on its own. */
static void handle_write(rx_ctx *rx)
{
    tlv_el m, reqs, ib, path, data, dv;
    tlv_it it;
    uint8_t out[MAX_UDP];
    tlv_w w;
    if (tlv_parse(rx->payload, rx->len, &m) || !tlv_get(&m, 2, &reqs)) {
        send_status(rx, ST_INVALID_ACTION);
        return;
    }
    im_ctx ctx = { rx->sess, rx->sess->fabric_idx, 1 };
    tlv_w_init(&w, out, sizeof out);
    tlv_start(&w, TLV_ANON, TLV_T_STRUCT);
    tlv_start(&w, 0, TLV_T_ARRAY);
    tlv_iter(&it, &reqs);
    while (tlv_next(&it, &ib)) {
        req_path rp;
        int append = 0, st;
        const cluster_def *cd = NULL;
        if (!tlv_get(&ib, 1, &path) || !tlv_get(&ib, 2, &data)) {
            st = ST_INVALID_ACTION;
            memset(&rp, 0, sizeof rp);
        } else {
            parse_attr_path(&path, &rp, &append);
            st = ST_UNSUPPORTED_ATTRIBUTE;
            if (!rp.has_ep || !rp.has_cl || !rp.has_at)
                st = ST_INVALID_ACTION;                 /* no wildcard writes */
            else if (!(cd = find_cluster(rp.ep, rp.cl, &st)))
                ;
            else if (!has_attr(cd, rp.at))
                st = ST_UNSUPPORTED_ATTRIBUTE;
            else if (tlv_get(&ib, 0, &dv) && dv.u != *data_version(rp.ep, rp.cl))
                st = ST_DATA_VERSION_MISMATCH;          /* optimistic concurrency check */
            else if (!cd->write)
                st = ST_UNSUPPORTED_WRITE;
            else if ((st = cd->write(&ctx, rp.ep, rp.at, &data, append)) == ST_SUCCESS)
                im_mark_dirty(rp.ep, rp.cl);
        }
        LOG("write %u/0x%04x/0x%04x%s -> 0x%02x", rp.ep, rp.cl, rp.at, append ? " (append)" : "", st);
        tlv_start(&w, TLV_ANON, TLV_T_STRUCT);
        put_path(&w, 0, rp.ep, rp.cl, rp.at, 0);
        tlv_start(&w, 1, TLV_T_STRUCT);
        tlv_put_uint(&w, 0, st);
        tlv_end(&w);
        tlv_end(&w);
    }
    tlv_end(&w);
    tlv_put_uint(&w, 0xFF, IM_REV);
    tlv_end(&w);
    if (!tlv_get_u(&m, 0, 0))
        reply(rx, PROTO_IM, IM_WRITE_RESPONSE, out, w.len, 1);
}

/* ----------------------------------------------------------------- invoke */
/*
 * InvokeRequest:  { 0: SuppressResponse, 1: TimedRequest,
 *                   2: InvokeRequests [ CommandDataIB ] }
 *   CommandDataIB: { 0: CommandPathIB (list: 0 endpoint, 1 cluster, 2 command),
 *                    1: CommandFields (struct), 2: Ref (batch correlation) }
 * InvokeResponse: { 0: SuppressResponse, 1: InvokeResponses [ InvokeResponseIB ] }
 *   InvokeResponseIB: { 0: CommandDataIB (a response command) }
 *                  or { 1: CommandStatusIB { 0: path, 1: StatusIB, 2: Ref } }
 */

/* For handlers that answer with a response command (e.g. CSRResponse):
 * opens the containers; the handler writes fields with context tags, then
 * calls cmd_resp_end(). */
tlv_w *cmd_resp_begin(cmd_ctx *c, uint32_t resp_cmd)
{
    tlv_w *w = c->w;
    tlv_start(w, TLV_ANON, TLV_T_STRUCT);   /* InvokeResponseIB */
    tlv_start(w, 0, TLV_T_STRUCT);          /* CommandDataIB */
    tlv_start(w, 0, TLV_T_LIST);
    tlv_put_uint(w, 0, c->ep);
    tlv_put_uint(w, 1, c->cl);
    tlv_put_uint(w, 2, resp_cmd);
    tlv_end(w);
    tlv_start(w, 1, TLV_T_STRUCT);          /* CommandFields */
    c->responded = 1;
    return w;
}

void cmd_resp_end(cmd_ctx *c)
{
    tlv_end(c->w);
    if (c->has_ref)
        tlv_put_uint(c->w, 2, c->ref);
    tlv_end(c->w);
    tlv_end(c->w);
}

static void handle_invoke(rx_ctx *rx)
{
    static const uint8_t empty_struct[] = { 0x15, 0x18 };   /* {} for commands without fields */
    tlv_el m, reqs, cd_ib, path, fields, ref;
    tlv_it it;
    uint8_t out[MAX_UDP];
    tlv_w w;
    if (tlv_parse(rx->payload, rx->len, &m) || !tlv_get(&m, 2, &reqs)) {
        send_status(rx, ST_INVALID_ACTION);
        return;
    }
    tlv_w_init(&w, out, sizeof out);
    tlv_start(&w, TLV_ANON, TLV_T_STRUCT);
    tlv_put_bool(&w, 0, 0);
    tlv_start(&w, 1, TLV_T_ARRAY);
    tlv_iter(&it, &reqs);
    while (tlv_next(&it, &cd_ib)) {
        cmd_ctx c;
        memset(&c, 0, sizeof c);
        c.im = (im_ctx){ rx->sess, rx->sess->fabric_idx, 1 };
        c.w = &w;
        c.cluster_status = -1;
        int st = ST_INVALID_ACTION;
        if (tlv_get(&cd_ib, 0, &path)) {
            c.ep = (uint16_t)tlv_get_u(&path, 0, 0);
            c.cl = (uint32_t)tlv_get_u(&path, 1, 0);
            c.cmd = (uint32_t)tlv_get_u(&path, 2, 0);
            if (tlv_get(&cd_ib, 2, &ref)) {
                c.has_ref = 1;
                c.ref = (uint16_t)ref.u;
            }
            if (!tlv_get(&cd_ib, 1, &fields))
                tlv_parse(empty_struct, sizeof empty_struct, &fields);
            const cluster_def *cd = find_cluster(c.ep, c.cl, &st);
            if (cd) {
                st = ST_UNSUPPORTED_COMMAND;
                for (int i = 0; i < cd->nacmds; i++)
                    if (cd->acmds[i] == c.cmd && cd->invoke)
                        st = cd->invoke(&c, &fields);
            }
        }
        LOG("invoke %u/0x%04x/0x%02x -> %s0x%02x", c.ep, c.cl, c.cmd,
            c.responded ? "response, " : "status ", c.responded ? 0 : st);
        if (!c.responded) {
            /* no response command: report a status for this command instead */
            tlv_start(&w, TLV_ANON, TLV_T_STRUCT);   /* InvokeResponseIB */
            tlv_start(&w, 1, TLV_T_STRUCT);          /* CommandStatusIB */
            tlv_start(&w, 0, TLV_T_LIST);
            tlv_put_uint(&w, 0, c.ep);
            tlv_put_uint(&w, 1, c.cl);
            tlv_put_uint(&w, 2, c.cmd);
            tlv_end(&w);
            tlv_start(&w, 1, TLV_T_STRUCT);
            tlv_put_uint(&w, 0, st);
            if (c.cluster_status >= 0)
                tlv_put_uint(&w, 1, c.cluster_status);   /* cluster-specific detail */
            tlv_end(&w);
            if (c.has_ref)
                tlv_put_uint(&w, 2, c.ref);
            tlv_end(&w);
            tlv_end(&w);
        }
    }
    tlv_end(&w);
    tlv_put_uint(&w, 0xFF, IM_REV);
    tlv_end(&w);
    if (w.err) {
        LOG("invoke response too large");
        send_status(rx, ST_RESOURCE_EXHAUSTED);
        return;
    }
    if (!tlv_get_u(&m, 0, 0))
        reply(rx, PROTO_IM, IM_INVOKE_RESPONSE, out, w.len, 1);
}

/* --------------------------------------------------------------- dispatch */

void im_rx(rx_ctx *rx)
{
    /* a StatusResponse continuing one of our multi-message exchanges? */
    im_exch *x = exch_find(rx->sess, rx->exchange_id, !rx->peer_is_initiator);
    if (x && rx->opcode == IM_STATUS_RESPONSE) {
        handle_status_response(rx, x);
        return;
    }
    switch (rx->opcode) {
    case IM_READ_REQUEST:      handle_read(rx, 0); break;
    case IM_SUBSCRIBE_REQUEST: handle_read(rx, 1); break;
    case IM_WRITE_REQUEST:     handle_write(rx); break;
    case IM_INVOKE_REQUEST:    handle_invoke(rx); break;
    case IM_TIMED_REQUEST:     send_status(rx, ST_SUCCESS); break;
    case IM_STATUS_RESPONSE:   break;
    default:
        DBG("unhandled IM opcode 0x%02x", rx->opcode);
        send_status(rx, ST_INVALID_ACTION);
    }
}

/* Periodic work: expire stuck exchanges, then for each idle subscription
 * send a change report (if something is dirty and MinInterval has passed)
 * or a keep-alive (shortly before MaxInterval would expire). */
void im_tick(uint64_t now)
{
    for (int i = 0; i < MAX_EXCH; i++) {
        im_exch *x = &exchs[i];
        if (x->in_use && now - x->created > EXCH_TIMEOUT_MS) {
            DBG("IM exchange %u timed out", x->exch);
            if (x->sub)
                sub_free(x->sub);
            else
                exch_free(x);
        }
    }
    for (int i = 0; i < MAX_SUBS; i++) {
        sub_t *s = &subs[i];
        if (!s->in_use || !s->active || s->busy)
            continue;
        uint64_t since = now - s->last_report;
        uint64_t keepalive = (uint64_t)s->max_iv * 1000;
        if (keepalive > 2000)
            keepalive -= 1000;   /* a little early, so it arrives in time */
        if ((s->ndirty && since >= (uint64_t)s->min_iv * 1000) || since >= keepalive)
            sub_send_report(s);
    }
}

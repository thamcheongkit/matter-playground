/* Data model: endpoint 0 (Root Node) and endpoint 1 (On/Off Light) clusters.
 *
 * Endpoint 0 is the "utility" endpoint every Matter node has. Its clusters
 * are about the node itself: identity, commissioning, credentials, access
 * control. Endpoint 1 is the actual product: a light.
 *
 *   endpoint 0 (device type 0x0016 Root Node)
 *     0x001D Descriptor               what's on this endpoint
 *     0x001F Access Control           who may do what (ACL)
 *     0x0028 Basic Information        vendor, product, versions, labels
 *     0x0030 General Commissioning    fail-safe, regulatory, CommissioningComplete
 *     0x0031 Network Commissioning    how we're connected (Ethernet: nothing to configure)
 *     0x0033 General Diagnostics      uptime, reboot count
 *     0x003C Administrator Commissioning   open a window for another ecosystem
 *     0x003E Operational Credentials  attestation, CSR, certificates, fabrics
 *     0x003F Group Key Management     group keys (unused, attributes only)
 *   endpoint 1 (device type 0x0100 On/Off Light)
 *     0x0003 Identify                 "blink so I can find you"
 *     0x001D Descriptor
 *     0x0006 On/Off                   the light itself
 *
 * Each cluster is a cluster_def: id, revision, feature map, the attribute
 * and command ids it supports, and read/write/invoke callbacks. The IM
 * engine (im.c) does all the protocol work; callbacks only deal with values.
 * Callback conventions:
 *   read:   write the value with 'tag'; return 0 or an IM status
 *   write:  'v' is the new value; 'append' = add one list item; return status
 *   invoke: 'f' is the CommandFields struct; return a status, or send a
 *           response command via cmd_resp_begin()/cmd_resp_end()
 */
#include "matter.h"

#include <string.h>

/* LIST(1, 2, 3) expands to two initializers: a compound-literal array and
 * its length, filling the (pointer, count) pairs of cluster_def. */
#define LIST(...) (const uint32_t[]){ __VA_ARGS__ }, (int)(sizeof((const uint32_t[]){ __VA_ARGS__ }) / sizeof(uint32_t))
#define NONE NULL, 0

/* copy a TLV string into a fixed C buffer, truncating and NUL-terminating */
static void copy_str(char *dst, size_t cap, const tlv_el *e)
{
    size_t n = e->n < cap - 1 ? e->n : cap - 1;
    memcpy(dst, e->p, n);
    dst[n] = 0;
}

/* ============================================================ Descriptor */
/* Lets a controller discover the node's structure: which device type each
 * endpoint is, which server/client clusters it has, and (on endpoint 0)
 * which other endpoints exist. */

static int descriptor_read(const im_ctx *c, uint16_t ep, uint32_t at, tlv_w *w, uint32_t tag)
{
    (void)c;
    switch (at) {
    case 0:   /* DeviceTypeList: [ {0: device type, 1: revision} ] */
        tlv_start(w, tag, TLV_T_ARRAY);
        tlv_start(w, TLV_ANON, TLV_T_STRUCT);
        tlv_put_uint(w, 0, ep == 0 ? 0x0016 : 0x0100);   /* Root Node / On/Off Light */
        tlv_put_uint(w, 1, ep == 0 ? 1 : 2);
        tlv_end(w);
        tlv_end(w);
        return 0;
    case 1:   /* ServerList: cluster ids we implement on this endpoint */
        tlv_start(w, tag, TLV_T_ARRAY);
        for (int e = 0; e < g_nendpoints; e++)
            if (g_endpoints[e].id == ep)
                for (int i = 0; i < g_endpoints[e].nclusters; i++)
                    tlv_put_uint(w, TLV_ANON, g_endpoints[e].clusters[i]->id);
        tlv_end(w);
        return 0;
    case 2:   /* ClientList: clusters we *use* on other devices (none) */
        tlv_start(w, tag, TLV_T_ARRAY);
        tlv_end(w);
        return 0;
    case 3:   /* PartsList: endpoint 0 lists all other endpoints */
        tlv_start(w, tag, TLV_T_ARRAY);
        if (ep == 0)
            for (int e = 0; e < g_nendpoints; e++)
                if (g_endpoints[e].id != 0)
                    tlv_put_uint(w, TLV_ANON, g_endpoints[e].id);
        tlv_end(w);
        return 0;
    }
    return ST_UNSUPPORTED_ATTRIBUTE;
}

static const cluster_def cl_descriptor = {
    0x001D, 1, 0, LIST(0, 1, 2, 3), NONE, NONE, descriptor_read, NULL, NULL
};

/* ======================================================== Access Control */
/* The ACL says which subjects (node ids / CATs) get which privilege
 * (View=1, ProxyView=2, Operate=3, Manage=4, Administer=5), by which auth
 * mode (PASE=1, CASE=2, Group=3), optionally limited to targets.
 *   AccessControlEntryStruct:
 *     { 1: Privilege, 2: AuthMode, 3: Subjects [u64] | null,
 *       4: Targets [ {0 cluster, 1 endpoint, 2 device type} ] | null,
 *       0xFE: FabricIndex }
 * The ACL is *fabric-scoped*: each fabric only sees and edits its own
 * entries. We store entries per fabric (fields 1..4, raw TLV) and add
 * FabricIndex when reading.
 * NOTE: demo shortcut — entries are stored and reported but NOT enforced. */

/* iterate the ACL entries stored back-to-back in f->acl */
static int acl_next(const fabric_t *f, size_t *off, tlv_el *e)
{
    if (*off >= f->acl_len || tlv_parse(f->acl + *off, f->acl_len - *off, e))
        return 0;
    *off += e->rawlen;
    return 1;
}

static int acl_read(const im_ctx *c, uint16_t ep, uint32_t at, tlv_w *w, uint32_t tag)
{
    (void)ep;
    switch (at) {
    case 0:   /* ACL */
        tlv_start(w, tag, TLV_T_ARRAY);
        for (int i = 0; i < MAX_FABRICS; i++) {
            fabric_t *f = &g_node.fabrics[i];
            tlv_el e, fld;
            tlv_it it;
            size_t off = 0;
            if (!f->in_use || (c->fabric_filtered && f->index != c->fabric_idx))
                continue;
            while (acl_next(f, &off, &e)) {
                tlv_start(w, TLV_ANON, TLV_T_STRUCT);
                if (f->index == c->fabric_idx) {   /* fabric-sensitive fields */
                    tlv_iter(&it, &e);
                    while (tlv_next(&it, &fld))
                        tlv_put_raw(w, fld.raw, fld.rawlen);
                }
                tlv_put_uint(w, 0xFE, f->index);
                tlv_end(w);
            }
        }
        tlv_end(w);
        return 0;
    case 2: tlv_put_uint(w, tag, 4); return 0;               /* SubjectsPerAccessControlEntry */
    case 3: tlv_put_uint(w, tag, 3); return 0;               /* TargetsPerAccessControlEntry */
    case 4: tlv_put_uint(w, tag, MAX_ACL_ENTRIES); return 0; /* AccessControlEntriesPerFabric */
    }
    return ST_UNSUPPORTED_ATTRIBUTE;
}

/* validate one entry and append it (fields 1..4 only) to the fabric's ACL */
static int acl_append(fabric_t *f, const tlv_el *e)
{
    uint8_t buf[MAX_ACL_BYTES];
    tlv_w w;
    tlv_el fld, x;
    tlv_it it;
    size_t off = 0;
    int count = 0;
    if (e->type != TLV_T_STRUCT)
        return ST_INVALID_DATA_TYPE;
    while (acl_next(f, &off, &x))
        count++;
    if (count >= MAX_ACL_ENTRIES)
        return ST_RESOURCE_EXHAUSTED;
    uint64_t priv = tlv_get_u(e, 1, 0), auth = tlv_get_u(e, 2, 0);
    if (priv < 1 || priv > 5 || auth < 1 || auth > 3)
        return ST_CONSTRAINT_ERROR;
    tlv_w_init(&w, buf, sizeof buf);
    tlv_start(&w, TLV_ANON, TLV_T_STRUCT);
    tlv_iter(&it, e);
    while (tlv_next(&it, &fld))
        if (fld.tag >= 1 && fld.tag <= 4)
            tlv_put_raw(&w, fld.raw, fld.rawlen);
    tlv_end(&w);
    if (w.err || f->acl_len + w.len > MAX_ACL_BYTES)
        return ST_RESOURCE_EXHAUSTED;
    memcpy(f->acl + f->acl_len, buf, w.len);
    f->acl_len += w.len;
    return ST_SUCCESS;
}

/* Two write forms: the whole list (replace; all-or-nothing, so we keep a
 * backup) or a single appended item (list index = null). Big lists arrive
 * as "replace with []" followed by appends. */
static int acl_write(const im_ctx *c, uint16_t ep, uint32_t at, const tlv_el *v, int append)
{
    (void)ep;
    fabric_t *f = fabric_by_index(c->fabric_idx);
    int st = ST_SUCCESS;
    if (at != 0)
        return ST_UNSUPPORTED_WRITE;
    if (!f)
        return ST_UNSUPPORTED_ACCESS;
    if (append) {
        st = acl_append(f, v);
    } else if (v->type != TLV_T_ARRAY) {
        st = ST_INVALID_DATA_TYPE;
    } else {
        uint8_t backup[MAX_ACL_BYTES];
        size_t blen = f->acl_len;
        tlv_el item;
        tlv_it it;
        memcpy(backup, f->acl, blen);
        f->acl_len = 0;
        tlv_iter(&it, v);
        while (st == ST_SUCCESS && tlv_next(&it, &item))
            st = acl_append(f, &item);
        if (st != ST_SUCCESS) {
            memcpy(f->acl, backup, blen);
            f->acl_len = blen;
        }
    }
    if (st == ST_SUCCESS && f->committed)
        state_save();
    return st;
}

static const cluster_def cl_acl = {
    0x001F, 1, 0, LIST(0, 2, 3, 4), NONE, NONE, acl_read, acl_write, NULL
};

/* ===================================================== Basic Information */
/* Static identity of the node. Commissioners check that VendorID/ProductID
 * here match the DAC certificate. NodeLabel/Location are user-writable. */

static int basic_read(const im_ctx *c, uint16_t ep, uint32_t at, tlv_w *w, uint32_t tag)
{
    (void)c; (void)ep;
    switch (at) {
    case 0x00: tlv_put_uint(w, tag, 17); return 0;                    /* DataModelRevision */
    case 0x01: tlv_put_str(w, tag, "Matter Playground"); return 0;    /* VendorName */
    case 0x02: tlv_put_uint(w, tag, g_node.vid); return 0;
    case 0x03: tlv_put_str(w, tag, "C Matter Light"); return 0;       /* ProductName */
    case 0x04: tlv_put_uint(w, tag, g_node.pid); return 0;
    case 0x05: tlv_put_str(w, tag, g_node.node_label); return 0;
    case 0x06: tlv_put_str(w, tag, g_node.location); return 0;
    case 0x07: tlv_put_uint(w, tag, 1); return 0;                     /* HardwareVersion */
    case 0x08: tlv_put_str(w, tag, "1.0"); return 0;
    case 0x09: tlv_put_uint(w, tag, 1); return 0;                     /* SoftwareVersion */
    case 0x0A: tlv_put_str(w, tag, "1.0"); return 0;
    case 0x0F: tlv_put_str(w, tag, "CML-0001"); return 0;             /* SerialNumber */
    case 0x12: tlv_put_str(w, tag, g_node.host); return 0;            /* UniqueID */
    case 0x13:                                                        /* CapabilityMinima */
        tlv_start(w, tag, TLV_T_STRUCT);
        tlv_put_uint(w, 0, 3);
        tlv_put_uint(w, 1, 3);
        tlv_end(w);
        return 0;
    case 0x15: tlv_put_uint(w, tag, 0x01030000); return 0;            /* SpecificationVersion */
    case 0x16: tlv_put_uint(w, tag, 1); return 0;                     /* MaxPathsPerInvoke */
    }
    return ST_UNSUPPORTED_ATTRIBUTE;
}

static int basic_write(const im_ctx *c, uint16_t ep, uint32_t at, const tlv_el *v, int append)
{
    (void)c; (void)ep; (void)append;
    if (at == 0x05) {
        if (v->type != TLV_T_UTF8 || v->n > 32)
            return ST_CONSTRAINT_ERROR;
        copy_str(g_node.node_label, sizeof g_node.node_label, v);
    } else if (at == 0x06) {
        if (v->type != TLV_T_UTF8 || v->n != 2)   /* ISO country code */
            return ST_CONSTRAINT_ERROR;
        copy_str(g_node.location, sizeof g_node.location, v);
    } else {
        return ST_UNSUPPORTED_WRITE;
    }
    state_save();
    return ST_SUCCESS;
}

static const cluster_def cl_basic = {
    0x0028, 3, 0, LIST(0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0F, 0x12, 0x13, 0x15, 0x16),
    NONE, NONE, basic_read, basic_write, NULL
};

/* ================================================== General Commissioning */
/* The commissioning "transaction":
 *   ArmFailSafe(N s)  -> start a timer; changes made from now on are
 *                        provisional (certificates, new fabric, ...)
 *   ... commissioning steps ...
 *   CommissioningComplete (over CASE!) -> commit everything, stop timer
 * If the timer expires first, failsafe_expire() (main.c) rolls back. This
 * keeps a half-commissioned device from ending up in a broken state. */

static int gc_read(const im_ctx *c, uint16_t ep, uint32_t at, tlv_w *w, uint32_t tag)
{
    (void)c; (void)ep;
    switch (at) {
    case 0: tlv_put_uint(w, tag, g_node.breadcrumb); return 0;
    case 1:   /* BasicCommissioningInfo */
        tlv_start(w, tag, TLV_T_STRUCT);
        tlv_put_uint(w, 0, 60);    /* FailSafeExpiryLengthSeconds */
        tlv_put_uint(w, 1, 900);   /* MaxCumulativeFailsafeSeconds */
        tlv_end(w);
        return 0;
    case 2: tlv_put_uint(w, tag, g_node.regulatory); return 0;
    case 3: tlv_put_uint(w, tag, 2); return 0;      /* LocationCapability: IndoorOutdoor */
    case 4: tlv_put_bool(w, tag, 1); return 0;      /* SupportsConcurrentConnection */
    }
    return ST_UNSUPPORTED_ATTRIBUTE;
}

static int gc_write(const im_ctx *c, uint16_t ep, uint32_t at, const tlv_el *v, int append)
{
    (void)c; (void)ep; (void)append;
    if (at != 0)
        return ST_UNSUPPORTED_WRITE;
    if (v->type != TLV_T_UINT)
        return ST_INVALID_DATA_TYPE;
    g_node.breadcrumb = v->u;
    return ST_SUCCESS;
}

/* All three commands answer with { 0: ErrorCode, 1: DebugText } */
static int gc_respond(cmd_ctx *c, uint32_t resp, int err)
{
    tlv_w *w = cmd_resp_begin(c, resp);
    tlv_put_uint(w, 0, err);      /* ErrorCode: 0 OK, 2 InvalidAuthentication, 3 NoFailSafe, 4 BusyWithOtherAdmin */
    tlv_put_str(w, 1, "");
    cmd_resp_end(c);
    return ST_SUCCESS;
}

static int gc_invoke(cmd_ctx *c, const tlv_el *f)
{
    switch (c->cmd) {
    case 0x00: {   /* ArmFailSafe { 0: ExpiryLengthSeconds, 1: Breadcrumb } */
        uint64_t secs = tlv_get_u(f, 0, 0);
        /* only the admin that armed it may extend/disarm it */
        if (g_node.fs_armed && g_node.fs_armed_by != c->im.fabric_idx)
            return gc_respond(c, 0x01, 4);
        if (secs == 0) {
            if (g_node.fs_armed)
                failsafe_expire();
        } else {
            g_node.fs_armed = 1;
            g_node.fs_armed_by = c->im.fabric_idx;
            g_node.fs_deadline = now_ms() + secs * 1000;
            g_node.breadcrumb = tlv_get_u(f, 1, 0);
        }
        LOG("fail-safe %s (%llus)", secs ? "armed" : "disarmed", (unsigned long long)secs);
        return gc_respond(c, 0x01, 0);
    }
    case 0x02:     /* SetRegulatoryConfig { 0: config, 1: country code, 2: breadcrumb } */
        g_node.regulatory = (uint8_t)tlv_get_u(f, 0, 0);
        g_node.breadcrumb = tlv_get_u(f, 2, 0);
        return gc_respond(c, 0x03, 0);
    case 0x04: {   /* CommissioningComplete */
        if (!g_node.fs_armed)
            return gc_respond(c, 0x05, 3);
        /* must arrive over CASE on the new fabric: proves the controller
         * can reach us operationally with the credentials it just installed */
        if (c->im.sess->type != SESS_CASE ||
            (g_node.fs_added_fabric && c->im.fabric_idx != g_node.fs_added_fabric))
            return gc_respond(c, 0x05, 2);
        fabric_t *fab = fabric_by_index(g_node.fs_added_fabric);
        if (fab)
            fab->committed = 1;
        g_node.fs_armed = 0;
        g_node.fs_added_fabric = 0;
        g_node.fs_have_root = g_node.fs_have_csr = 0;
        g_node.breadcrumb = 0;
        cw_close();
        state_save();
        im_mark_dirty(0, 0x003E);
        mdns_announce();
        LOG("*** COMMISSIONING COMPLETE (fabric %u) ***", c->im.fabric_idx);
        return gc_respond(c, 0x05, 0);
    }
    }
    return ST_UNSUPPORTED_COMMAND;
}

static const cluster_def cl_gencomm = {
    0x0030, 1, 0, LIST(0, 1, 2, 3, 4), LIST(0x00, 0x02, 0x04), LIST(0x01, 0x03, 0x05),
    gc_read, gc_write, gc_invoke
};

/* =================================================== Network Commissioning */
/* For Wi-Fi/Thread devices this is where the commissioner hands over network
 * credentials. With the Ethernet feature (we're already on the IP network)
 * there's nothing to configure: we just describe the one interface. */

static int nc_read(const im_ctx *c, uint16_t ep, uint32_t at, tlv_w *w, uint32_t tag)
{
    (void)c; (void)ep;
    switch (at) {
    case 0: tlv_put_uint(w, tag, 1); return 0;     /* MaxNetworks */
    case 1:                                        /* Networks: [ {0: NetworkID, 1: Connected} ] */
        tlv_start(w, tag, TLV_T_ARRAY);
        tlv_start(w, TLV_ANON, TLV_T_STRUCT);
        tlv_put_bytes(w, 0, g_node.ifname, strlen(g_node.ifname));
        tlv_put_bool(w, 1, 1);
        tlv_end(w);
        tlv_end(w);
        return 0;
    case 4: tlv_put_bool(w, tag, 1); return 0;     /* InterfaceEnabled */
    case 5: case 6: case 7: tlv_put_null(w, tag); return 0;   /* last connect status/id/error */
    }
    return ST_UNSUPPORTED_ATTRIBUTE;
}

static int nc_write(const im_ctx *c, uint16_t ep, uint32_t at, const tlv_el *v, int append)
{
    (void)c; (void)ep; (void)append;
    return at == 4 && v->type == TLV_T_BOOL ? ST_SUCCESS : ST_UNSUPPORTED_WRITE;
}

static const cluster_def cl_netcomm = {
    0x0031, 1, 0x04 /* Ethernet */, LIST(0, 1, 4, 5, 6, 7), NONE, NONE, nc_read, nc_write, NULL
};

/* ==================================================== General Diagnostics */

static int gd_read(const im_ctx *c, uint16_t ep, uint32_t at, tlv_w *w, uint32_t tag)
{
    (void)c; (void)ep;
    switch (at) {
    case 0: tlv_start(w, tag, TLV_T_ARRAY); tlv_end(w); return 0;   /* NetworkInterfaces */
    case 1: tlv_put_uint(w, tag, g_node.reboot_count); return 0;
    case 2: tlv_put_uint(w, tag, (now_ms() - g_node.boot_ms) / 1000); return 0;   /* UpTime (s) */
    case 8: tlv_put_bool(w, tag, 0); return 0;                       /* TestEventTriggersEnabled */
    }
    return ST_UNSUPPORTED_ATTRIBUTE;
}

static const cluster_def cl_gendiag = {
    0x0033, 1, 0, LIST(0, 1, 2, 8), NONE, NONE, gd_read, NULL, NULL
};

/* ============================================= Administrator Commissioning */
/* Multi-admin: an existing admin (e.g. Apple Home) opens an *enhanced*
 * commissioning window so a second ecosystem can join. It gives us a PAKE
 * verifier (w0 || L) for a one-time passcode it generated and shows the
 * user; we never learn that passcode. PASE then runs against this verifier
 * instead of our printed setup code. */

static int ac_read(const im_ctx *c, uint16_t ep, uint32_t at, tlv_w *w, uint32_t tag)
{
    (void)c; (void)ep;
    switch (at) {
    case 0: tlv_put_uint(w, tag, !g_node.cw_open ? 0 : g_node.cw_enhanced ? 1 : 2); return 0;  /* WindowStatus */
    case 1:   /* AdminFabricIndex: who opened the window */
        if (g_node.cw_open && g_node.cw_admin_fabric) tlv_put_uint(w, tag, g_node.cw_admin_fabric);
        else tlv_put_null(w, tag);
        return 0;
    case 2:   /* AdminVendorId */
        if (g_node.cw_open && g_node.cw_admin_fabric) tlv_put_uint(w, tag, g_node.cw_admin_vid);
        else tlv_put_null(w, tag);
        return 0;
    }
    return ST_UNSUPPORTED_ATTRIBUTE;
}

static int ac_invoke(cmd_ctx *c, const tlv_el *f)
{
    tlv_el v, s;
    if (c->cmd == 0x00) {   /* OpenCommissioningWindow (enhanced) */
        /* { 0: CommissioningTimeout, 1: PAKEPasscodeVerifier (w0 32 || L 65),
         *   2: Discriminator, 3: Iterations, 4: Salt } */
        uint64_t timeout = tlv_get_u(f, 0, 0), iters = tlv_get_u(f, 3, 0), disc = tlv_get_u(f, 2, 0xFFFF);
        if (g_node.cw_open || g_node.fs_armed) {
            c->cluster_status = 2;   /* Busy */
            return ST_FAILURE;
        }
        if (!tlv_get(f, 1, &v) || v.type != TLV_T_BYTES || v.n != 97 || !tlv_get(f, 4, &s) ||
            s.type != TLV_T_BYTES || s.n < 16 || s.n > 32 || iters < 1000 || iters > 100000 || disc > 0xFFF) {
            c->cluster_status = 3;   /* PAKEParameterError */
            return ST_FAILURE;
        }
        if (timeout < 180 || timeout > 900)
            return ST_INVALID_COMMAND;
        fabric_t *fab = fabric_by_index(c->im.fabric_idx);
        memcpy(g_node.cw_w0, v.p, 32);
        memcpy(g_node.cw_L, v.p + 32, 65);
        memcpy(g_node.cw_salt, s.p, s.n);
        g_node.cw_salt_len = s.n;
        g_node.cw_iters = (uint32_t)iters;
        g_node.cw_disc = (uint16_t)disc;
        g_node.cw_open = g_node.cw_enhanced = 1;
        g_node.cw_deadline = now_ms() + timeout * 1000;
        g_node.cw_admin_fabric = c->im.fabric_idx;
        g_node.cw_admin_vid = fab ? fab->vendor_id : 0;
        LOG("enhanced commissioning window opened for %llus (discriminator %llu)",
            (unsigned long long)timeout, (unsigned long long)disc);
        mdns_announce();
        im_mark_dirty(0, 0x003C);
        return ST_SUCCESS;
    }
    if (c->cmd == 0x02) {   /* RevokeCommissioning */
        if (!g_node.cw_open) {
            c->cluster_status = 4;   /* WindowNotOpen */
            return ST_FAILURE;
        }
        if (g_node.fs_armed)
            failsafe_expire();
        cw_close();
        return ST_SUCCESS;
    }
    return ST_UNSUPPORTED_COMMAND;
}

static const cluster_def cl_admincomm = {
    0x003C, 1, 0, LIST(0, 1, 2), LIST(0x00, 0x02), NONE, ac_read, NULL, ac_invoke
};

/* ================================================ Operational Credentials */
/* The heart of commissioning. Typical command sequence over PASE:
 *
 *   CertificateChainRequest(PAI), CertificateChainRequest(DAC)
 *   AttestationRequest(nonce)      -> signed CD + nonce        "are you genuine?"
 *   CSRRequest(nonce)              -> new key pair, signed CSR "give me a key to certify"
 *   AddTrustedRootCertificate(RCAC)                            "trust this root"
 *   AddNOC(NOC, ICAC, IPK, CaseAdminSubject, AdminVendorId)    "here is your identity"
 *
 * After AddNOC we're on a new (uncommitted) fabric and advertise it over
 * mDNS; the commissioner then switches to CASE for CommissioningComplete.
 *
 * Attestation and CSR responses are signed with the DAC key over
 * (elements || session attestation challenge), which ties them to the
 * current PASE session so they can't be replayed elsewhere. */

static int oc_read(const im_ctx *c, uint16_t ep, uint32_t at, tlv_w *w, uint32_t tag)
{
    (void)ep;
    switch (at) {
    case 0:   /* NOCs:    [ {1: NOC, 2: ICAC|null, 0xFE: FabricIndex} ] */
    case 1:   /* Fabrics: [ {1: RootPublicKey, 2: VendorID, 3: FabricID,
               *             4: NodeID, 5: Label, 0xFE: FabricIndex} ] */
        tlv_start(w, tag, TLV_T_ARRAY);
        for (int i = 0; i < MAX_FABRICS; i++) {
            fabric_t *f = &g_node.fabrics[i];
            if (!f->in_use || (c->fabric_filtered && f->index != c->fabric_idx))
                continue;
            tlv_start(w, TLV_ANON, TLV_T_STRUCT);
            if (at == 0 && f->index == c->fabric_idx) {   /* certs are fabric-sensitive */
                tlv_put_bytes(w, 1, f->noc, f->noc_len);
                if (f->icac_len)
                    tlv_put_bytes(w, 2, f->icac, f->icac_len);
                else
                    tlv_put_null(w, 2);
            } else if (at == 1) {
                tlv_put_bytes(w, 1, f->root_pub, 65);
                tlv_put_uint(w, 2, f->vendor_id);
                tlv_put_uint(w, 3, f->fabric_id);
                tlv_put_uint(w, 4, f->node_id);
                tlv_put_str(w, 5, f->label);
            }
            tlv_put_uint(w, 0xFE, f->index);
            tlv_end(w);
        }
        tlv_end(w);
        return 0;
    case 2: tlv_put_uint(w, tag, MAX_FABRICS); return 0;      /* SupportedFabrics */
    case 3: tlv_put_uint(w, tag, fabric_count(1)); return 0;  /* CommissionedFabrics */
    case 4:   /* TrustedRootCertificates (including one pending in the fail-safe) */
        tlv_start(w, tag, TLV_T_ARRAY);
        for (int i = 0; i < MAX_FABRICS; i++)
            if (g_node.fabrics[i].in_use)
                tlv_put_bytes(w, TLV_ANON, g_node.fabrics[i].rcac, g_node.fabrics[i].rcac_len);
        if (g_node.fs_have_root && !g_node.fs_added_fabric)
            tlv_put_bytes(w, TLV_ANON, g_node.fs_root, g_node.fs_root_len);
        tlv_end(w);
        return 0;
    case 5: tlv_put_uint(w, tag, c->fabric_idx); return 0;    /* CurrentFabricIndex */
    }
    return ST_UNSUPPORTED_ATTRIBUTE;
}

/* NOCResponse { 0: StatusCode, 1: FabricIndex, 2: DebugText } answers
 * AddNOC, UpdateFabricLabel and RemoveFabric. */
static int noc_respond(cmd_ctx *c, int status, uint8_t idx)
{
    tlv_w *w = cmd_resp_begin(c, 0x08);   /* NOCResponse */
    tlv_put_uint(w, 0, status);
    if (idx)
        tlv_put_uint(w, 1, idx);
    cmd_resp_end(c);
    if (status)
        LOG("NOCResponse status %d", status);
    return ST_SUCCESS;
}

/* sign (elements || attestation challenge) with the DAC key */
static void dac_sign(const session_t *s, const uint8_t *el, size_t n, uint8_t sig[64])
{
    uint8_t tbs[1024];
    memcpy(tbs, el, n);
    memcpy(tbs + n, s->att_challenge, 16);
    p256_sign(&g_node.dac_key, tbs, n + 16, sig);
}

/* AddNOC { 0: NOCValue, 1: ICACValue?, 2: IPKValue, 3: CaseAdminSubject,
 *          4: AdminVendorId }
 * Creates the new fabric from the pending root + the key pair generated at
 * CSRRequest, and installs an initial ACL entry granting Administer to
 * CaseAdminSubject (the commissioner's node id or CAT) so it can manage us. */
static int oc_add_noc(cmd_ctx *c, const tlv_el *f)
{
    tlv_el noc, icac, ipk;
    uint8_t pub[65];
    if (!g_node.fs_armed)
        return ST_FAILSAFE_REQUIRED;
    if (g_node.fs_added_fabric)
        return ST_CONSTRAINT_ERROR;                        /* one AddNOC per fail-safe */
    if (!tlv_get(f, 0, &noc) || noc.type != TLV_T_BYTES || noc.n > MAX_CERT ||
        !tlv_get(f, 2, &ipk) || ipk.type != TLV_T_BYTES || ipk.n != 16)
        return ST_INVALID_COMMAND;
    int has_icac = tlv_get(f, 1, &icac) && icac.type == TLV_T_BYTES;
    if (has_icac && icac.n > MAX_CERT)
        return ST_INVALID_COMMAND;
    if (!g_node.fs_have_csr)
        return noc_respond(c, 4, 0);                       /* MissingCsr */
    if (!g_node.fs_have_root || cert_parse(noc.p, noc.n, pub, NULL, NULL, NULL))
        return noc_respond(c, 3, 0);                       /* InvalidNOC */
    /* the NOC must certify the key we generated at CSRRequest */
    if (memcmp(pub, g_node.fs_csr_key.pub, 65))
        return noc_respond(c, 1, 0);                       /* InvalidPublicKey */

    fabric_t *fab = NULL;
    for (int i = 0; i < MAX_FABRICS && !fab; i++)
        if (!g_node.fabrics[i].in_use)
            fab = &g_node.fabrics[i];
    if (!fab)
        return noc_respond(c, 5, 0);                       /* TableFull */

    memset(fab, 0, sizeof *fab);
    memcpy(fab->rcac, g_node.fs_root, g_node.fs_root_len);
    fab->rcac_len = g_node.fs_root_len;
    memcpy(fab->noc, noc.p, noc.n);
    fab->noc_len = noc.n;
    if (has_icac) {
        memcpy(fab->icac, icac.p, icac.n);
        fab->icac_len = icac.n;
    }
    memcpy(fab->ipk_epoch, ipk.p, 16);
    fab->opkey = g_node.fs_csr_key;
    fab->vendor_id = (uint16_t)tlv_get_u(f, 4, 0);
    if (fabric_derive(fab)) {
        memset(fab, 0, sizeof *fab);
        return noc_respond(c, 3, 0);
    }
    /* the same fabric (root key + fabric id) can't be added twice */
    for (int i = 0; i < MAX_FABRICS; i++) {
        fabric_t *o = &g_node.fabrics[i];
        if (o != fab && o->in_use && o->fabric_id == fab->fabric_id && !memcmp(o->root_pub, fab->root_pub, 65)) {
            memset(fab, 0, sizeof *fab);
            return noc_respond(c, 9, 0);                   /* FabricConflict */
        }
    }
    fab->index = g_node.next_fabric_index++;
    if (g_node.next_fabric_index == 0 || g_node.next_fabric_index == 255)
        g_node.next_fabric_index = 1;
    fab->in_use = 1;

    /* implicit admin ACL entry for CaseAdminSubject */
    uint8_t acl[64];
    tlv_w w;
    tlv_w_init(&w, acl, sizeof acl);
    tlv_start(&w, TLV_ANON, TLV_T_STRUCT);
    tlv_put_uint(&w, 1, 5);     /* Privilege: Administer */
    tlv_put_uint(&w, 2, 2);     /* AuthMode: CASE */
    tlv_start(&w, 3, TLV_T_ARRAY);
    tlv_put_uint(&w, TLV_ANON, tlv_get_u(f, 3, 0));
    tlv_end(&w);
    tlv_put_null(&w, 4);        /* Targets: null = everything */
    tlv_end(&w);
    memcpy(fab->acl, acl, w.len);
    fab->acl_len = w.len;

    g_node.fs_added_fabric = fab->index;
    g_node.fs_have_csr = 0;
    /* from now on the PASE session acts on behalf of the new fabric */
    if (c->im.sess->type == SESS_PASE)
        c->im.sess->fabric_idx = fab->index;
    LOG("AddNOC: fabric %u added (fabric id %016llX, node id %016llX, vendor 0x%04X)", fab->index,
        (unsigned long long)fab->fabric_id, (unsigned long long)fab->node_id, fab->vendor_id);
    im_mark_dirty(0, 0x003E);
    mdns_announce();   /* start operational advertising so CASE can find us */
    return noc_respond(c, 0, fab->index);
}

static int oc_invoke(cmd_ctx *c, const tlv_el *f)
{
    tlv_el e;
    uint8_t el[1024], sig[64];
    tlv_w w, *r;
    switch (c->cmd) {
    case 0x00:   /* AttestationRequest { 0: AttestationNonce(32) } */
        if (!tlv_get(f, 0, &e) || e.type != TLV_T_BYTES || e.n != 32)
            return ST_INVALID_COMMAND;
        /* AttestationElements { 1: CertificationDeclaration, 2: nonce, 3: timestamp } */
        tlv_w_init(&w, el, sizeof el);
        tlv_start(&w, TLV_ANON, TLV_T_STRUCT);
        tlv_put_bytes(&w, 1, creds_cd, creds_cd_len);
        tlv_put_bytes(&w, 2, e.p, 32);
        tlv_put_uint(&w, 3, 0);
        tlv_end(&w);
        dac_sign(c->im.sess, el, w.len, sig);
        r = cmd_resp_begin(c, 0x01);   /* AttestationResponse { 0: elements, 1: signature } */
        tlv_put_bytes(r, 0, el, w.len);
        tlv_put_bytes(r, 1, sig, 64);
        cmd_resp_end(c);
        return ST_SUCCESS;
    case 0x02: { /* CertificateChainRequest { 0: type (1 = DAC, 2 = PAI) } */
        uint64_t type = tlv_get_u(f, 0, 0);
        if (type != 1 && type != 2)
            return ST_INVALID_COMMAND;
        r = cmd_resp_begin(c, 0x03);
        if (type == 1)
            tlv_put_bytes(r, 0, creds_dac_cert, creds_dac_cert_len);
        else
            tlv_put_bytes(r, 0, creds_pai_cert, creds_pai_cert_len);
        cmd_resp_end(c);
        return ST_SUCCESS;
    }
    case 0x04: { /* CSRRequest { 0: CSRNonce(32), 1: IsForUpdateNOC } */
        uint8_t csr[512];
        size_t csrlen = sizeof csr;
        if (!tlv_get(f, 0, &e) || e.type != TLV_T_BYTES || e.n != 32)
            return ST_INVALID_COMMAND;
        if (!g_node.fs_armed)
            return ST_FAILSAFE_REQUIRED;
        /* the operational key is generated on-device and never leaves it */
        if (p256_keygen(&g_node.fs_csr_key) || p256_csr(&g_node.fs_csr_key, csr, &csrlen))
            return ST_FAILURE;
        g_node.fs_have_csr = 1;
        /* NOCSRElements { 1: CSR (DER), 2: nonce } */
        tlv_w_init(&w, el, sizeof el);
        tlv_start(&w, TLV_ANON, TLV_T_STRUCT);
        tlv_put_bytes(&w, 1, csr, csrlen);
        tlv_put_bytes(&w, 2, e.p, 32);
        tlv_end(&w);
        dac_sign(c->im.sess, el, w.len, sig);
        r = cmd_resp_begin(c, 0x05);   /* CSRResponse { 0: NOCSRElements, 1: AttestationSignature } */
        tlv_put_bytes(r, 0, el, w.len);
        tlv_put_bytes(r, 1, sig, 64);
        cmd_resp_end(c);
        return ST_SUCCESS;
    }
    case 0x0B: { /* AddTrustedRootCertificate { 0: RCAC } — held until AddNOC */
        uint8_t pub[65];
        if (!g_node.fs_armed)
            return ST_FAILSAFE_REQUIRED;
        if (!tlv_get(f, 0, &e) || e.type != TLV_T_BYTES || e.n > MAX_CERT ||
            cert_parse(e.p, e.n, pub, NULL, NULL, NULL))
            return ST_INVALID_COMMAND;
        memcpy(g_node.fs_root, e.p, e.n);
        g_node.fs_root_len = e.n;
        g_node.fs_have_root = 1;
        LOG("AddTrustedRootCertificate: root stored");
        return ST_SUCCESS;
    }
    case 0x06:   /* AddNOC */
        return oc_add_noc(c, f);
    case 0x09: { /* UpdateFabricLabel { 0: label } — e.g. "Apple Home" */
        fabric_t *fab = fabric_by_index(c->im.fabric_idx);
        if (!fab)
            return ST_UNSUPPORTED_ACCESS;
        if (!tlv_get(f, 0, &e) || e.type != TLV_T_UTF8 || e.n > 32)
            return ST_CONSTRAINT_ERROR;
        copy_str(fab->label, sizeof fab->label, &e);
        if (fab->committed)
            state_save();
        im_mark_dirty(0, 0x003E);
        return noc_respond(c, 0, fab->index);
    }
    case 0x0A: { /* RemoveFabric { 0: FabricIndex } — "remove from Home" */
        uint8_t idx = (uint8_t)tlv_get_u(f, 0, 0);
        if (!fabric_by_index(idx))
            return noc_respond(c, 11, 0);                  /* InvalidFabricIndex */
        /* deferred: removing now would also free the session we must
         * still send this response on */
        g_node.pending_remove = idx;                       /* done after the response is sent */
        return noc_respond(c, 0, idx);
    }
    }
    return ST_UNSUPPORTED_COMMAND;
}

static const cluster_def cl_opcreds = {
    0x003E, 1, 0, LIST(0, 1, 2, 3, 4, 5), LIST(0x00, 0x02, 0x04, 0x06, 0x09, 0x0A, 0x0B),
    LIST(0x01, 0x03, 0x05, 0x08), oc_read, NULL, oc_invoke
};

/* ================================================== Group Key Management */
/* Mandatory on the root node. We don't support groups (multicast commands),
 * so the tables are empty and no commands are offered. */

static int gk_read(const im_ctx *c, uint16_t ep, uint32_t at, tlv_w *w, uint32_t tag)
{
    (void)c; (void)ep;
    switch (at) {
    case 0: case 1: tlv_start(w, tag, TLV_T_ARRAY); tlv_end(w); return 0;   /* GroupKeyMap, GroupTable */
    case 2: case 3: tlv_put_uint(w, tag, 1); return 0;   /* MaxGroupsPerFabric, MaxGroupKeysPerFabric */
    }
    return ST_UNSUPPORTED_ATTRIBUTE;
}

static const cluster_def cl_groupkeys = {
    0x003F, 1, 0, LIST(0, 1, 2, 3), NONE, NONE, gk_read, NULL, NULL
};

/* ============================================================== Identify */
/* "Show yourself for N seconds" — a real light would blink; we log. */

static int id_read(const im_ctx *c, uint16_t ep, uint32_t at, tlv_w *w, uint32_t tag)
{
    (void)c; (void)ep;
    uint64_t now = now_ms();
    switch (at) {
    case 0: tlv_put_uint(w, tag, g_node.identify_end > now ? (g_node.identify_end - now + 999) / 1000 : 0); return 0;
    case 1: tlv_put_uint(w, tag, 2); return 0;   /* IdentifyType: VisibleIndicator */
    }
    return ST_UNSUPPORTED_ATTRIBUTE;
}

static void identify_start(uint64_t secs)
{
    g_node.identify_end = secs ? now_ms() + secs * 1000 : 0;
    LOG(secs ? ">>> IDENTIFY for %llu s <<<" : "identify stopped", (unsigned long long)secs);
}

static int id_write(const im_ctx *c, uint16_t ep, uint32_t at, const tlv_el *v, int append)
{
    (void)c; (void)ep; (void)append;
    if (at != 0)
        return ST_UNSUPPORTED_WRITE;
    if (v->type != TLV_T_UINT)
        return ST_INVALID_DATA_TYPE;
    identify_start(v->u);
    return ST_SUCCESS;
}

static int id_invoke(cmd_ctx *c, const tlv_el *f)
{
    if (c->cmd != 0x00)   /* Identify { 0: IdentifyTime } */
        return ST_UNSUPPORTED_COMMAND;
    identify_start(tlv_get_u(f, 0, 0));
    im_mark_dirty(c->ep, c->cl);
    return ST_SUCCESS;
}

static const cluster_def cl_identify = {
    0x0003, 4, 0, LIST(0, 1), LIST(0x00), NONE, id_read, id_write, id_invoke
};

/* ================================================================ On/Off */
/* The whole point of the device. One bool attribute, three commands.
 * light_set() (main.c) logs, persists and marks the cluster dirty so that
 * subscribed controllers (e.g. the HomePod) get a report. */

static int onoff_read(const im_ctx *c, uint16_t ep, uint32_t at, tlv_w *w, uint32_t tag)
{
    (void)c; (void)ep;
    if (at == 0) {
        tlv_put_bool(w, tag, g_node.onoff);
        return 0;
    }
    return ST_UNSUPPORTED_ATTRIBUTE;
}

static int onoff_invoke(cmd_ctx *c, const tlv_el *f)
{
    (void)f;
    switch (c->cmd) {
    case 0x00: light_set(0, "controller"); return ST_SUCCESS;              /* Off */
    case 0x01: light_set(1, "controller"); return ST_SUCCESS;              /* On */
    case 0x02: light_set(!g_node.onoff, "controller"); return ST_SUCCESS;  /* Toggle */
    }
    return ST_UNSUPPORTED_COMMAND;
}

static const cluster_def cl_onoff = {
    0x0006, 5, 0, LIST(0), LIST(0x00, 0x01, 0x02), NONE, onoff_read, NULL, onoff_invoke
};

/* ============================================================= endpoints */
/* The node's composition. To add a feature (say, brightness), write a
 * cluster_def for Level Control (0x0008) and list it on endpoint 1. */

static const cluster_def *const ep0[] = {
    &cl_descriptor, &cl_acl, &cl_basic, &cl_gencomm, &cl_netcomm,
    &cl_gendiag, &cl_admincomm, &cl_opcreds, &cl_groupkeys,
};
static const cluster_def *const ep1[] = { &cl_identify, &cl_descriptor, &cl_onoff };

const endpoint_def g_endpoints[] = {
    { 0, ep0, (int)(sizeof ep0 / sizeof ep0[0]) },
    { 1, ep1, (int)(sizeof ep1 / sizeof ep1[0]) },
};
const int g_nendpoints = 2;

/* C Matter Light: a Matter On/Off Light accessory written without the Matter SDK.
 *
 * This file owns:
 *   - startup: options, credentials, state file, PASE verifier, sockets
 *   - the commissioning window (open/close) and fail-safe rollback
 *   - deferred actions (RemoveFabric) and timers (node_tick)
 *   - the single-threaded event loop
 *
 * EVENT LOOP
 * Everything runs on one thread. poll() waits up to 50 ms for:
 *     the Matter UDP socket  -> transport_rx() -> secure channel / IM
 *     the two mDNS sockets   -> mdns_rx()
 *     stdin                  -> 't' toggle, 's' status, 'q' quit
 * then every iteration runs the timer functions (retransmissions,
 * subscription reports, fail-safe, mDNS re-announcements). No locks are
 * needed because nothing is concurrent; the 50 ms tick bounds timer jitter.
 */
#include "matter.h"

#include <getopt.h>
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef __APPLE__
#define DEFAULT_IFACE "en0"
#else
#define DEFAULT_IFACE "eth0"
#endif

node_t g_node;                       /* all device state, see matter.h */
static volatile sig_atomic_t quit;   /* set by Ctrl-C / SIGTERM */

static void print_setup_codes(void)
{
    char qr[32], manual[12];
    setup_qr(qr, g_node.vid, g_node.pid, 0x04 /* on-network */, g_node.discriminator, g_node.passcode);
    setup_manual(manual, g_node.discriminator, g_node.passcode);
    printf("\n  ┌──────────────────────────────────────────────────────────────┐\n");
    printf("  │  Commissioning window OPEN                                     \n");
    printf("  │  Manual pairing code : %.4s-%.3s-%.4s                            \n", manual, manual + 4, manual + 7);
    printf("  │  QR payload          : %s                          \n", qr);
    printf("  │  QR image            : https://project-chip.github.io/connectedhomeip/qrcode.html?data=%s\n", qr);
    printf("  │  Discriminator %u, passcode %u                       \n", g_node.discriminator, g_node.passcode);
    printf("  └──────────────────────────────────────────────────────────────┘\n\n");
    fflush(stdout);
}

/* Open the *basic* commissioning window: PASE uses our own setup passcode
 * (via the verifier computed at startup). Opened automatically whenever the
 * device has no fabrics, and never times out in this demo. */
void cw_open_basic(void)
{
    g_node.cw_open = 1;
    g_node.cw_enhanced = 0;
    g_node.cw_deadline = 0;
    memcpy(g_node.cw_w0, g_node.def_w0, 32);
    memcpy(g_node.cw_L, g_node.def_L, 65);
    memcpy(g_node.cw_salt, g_node.def_salt, 32);
    g_node.cw_salt_len = 32;
    g_node.cw_iters = g_node.def_iters;
    g_node.cw_disc = g_node.discriminator;
    g_node.cw_admin_fabric = 0;
    g_node.cw_admin_vid = 0;
    im_mark_dirty(0, 0x003C);
    mdns_announce();
    print_setup_codes();
}

/* Close the window: withdraw the _matterc._udp advertisement (goodbye
 * packet) and refuse further PASE attempts. */
void cw_close(void)
{
    if (!g_node.cw_open)
        return;
    mdns_goodbye_commissionable();
    g_node.cw_open = 0;
    g_node.cw_admin_fabric = 0;
    im_mark_dirty(0, 0x003C);
    LOG("commissioning window closed");
}

/* Fail-safe expired (or was disarmed with ArmFailSafe(0)): undo everything
 * provisional. In particular a fabric added by AddNOC but never confirmed by
 * CommissioningComplete is removed along with its sessions. If we end up
 * with no fabrics, become commissionable again. */
void failsafe_expire(void)
{
    if (g_node.fs_added_fabric) {
        LOG("fail-safe: rolling back uncommitted fabric %u", g_node.fs_added_fabric);
        sessions_drop_fabric(g_node.fs_added_fabric);
        fabric_remove(g_node.fs_added_fabric);
        im_mark_dirty(0, 0x003E);
        mdns_announce();
    }
    g_node.fs_armed = 0;
    g_node.fs_added_fabric = 0;
    g_node.fs_have_root = g_node.fs_have_csr = 0;
    g_node.breadcrumb = 0;
    if (!fabric_count(1) && !g_node.cw_open)
        cw_open_basic();
}

/* The single place the light changes state - whether from a controller
 * command or the local "button" (stdin). Marking On/Off dirty is what makes
 * the HomePod's subscription receive a report and update the Home app. */
void light_set(int on, const char *why)
{
    if (g_node.onoff == on)
        return;
    g_node.onoff = on;
    LOG("💡 LIGHT %s  (%s)", on ? "ON " : "OFF", why);
    im_mark_dirty(1, 0x0006);
    state_save();
}

/* Node-level timers and deferred work, run every loop iteration. */
void node_tick(uint64_t now)
{
    if (g_node.fs_armed && now >= g_node.fs_deadline) {
        LOG("fail-safe timer expired");
        failsafe_expire();
    }
    if (g_node.cw_open && g_node.cw_deadline && now >= g_node.cw_deadline) {
        LOG("commissioning window timed out");
        cw_close();
        if (!fabric_count(1))
            cw_open_basic();
    }
    if (g_node.identify_end && now >= g_node.identify_end) {
        g_node.identify_end = 0;
        LOG("identify finished");
        im_mark_dirty(1, 0x0003);
    }
    /* RemoveFabric was answered last iteration; now it's safe to drop the
     * fabric and its sessions (including the one the command came on) */
    if (g_node.pending_remove) {
        uint8_t idx = g_node.pending_remove;
        g_node.pending_remove = 0;
        mdns_goodbye_all();
        sessions_drop_fabric(idx);
        fabric_remove(idx);
        state_save();
        LOG("fabric %u removed", idx);
        im_mark_dirty(0, 0x003E);
        mdns_announce();
        if (!fabric_count(1))
            cw_open_basic();
    }
}

static void print_status(void)
{
    LOG("light is %s; %d fabric(s); commissioning window %s", g_node.onoff ? "ON" : "OFF",
        fabric_count(1), g_node.cw_open ? "open" : "closed");
    for (int i = 0; i < MAX_FABRICS; i++) {
        fabric_t *f = &g_node.fabrics[i];
        if (f->in_use)
            LOG("  fabric %u: vendor 0x%04X fabric %016llX node %016llX label '%s'%s", f->index,
                f->vendor_id, (unsigned long long)f->fabric_id, (unsigned long long)f->node_id, f->label,
                f->committed ? "" : " (uncommitted)");
    }
}

static void on_signal(int sig)
{
    (void)sig;
    quit = 1;
}

static void usage(const char *argv0)
{
    fprintf(stderr,
            "usage: %s [-i iface] [-p passcode] [-d discriminator] [-s statefile] [-r] [-v]\n"
            "  -i  network interface to advertise on (default " DEFAULT_IFACE ")\n"
            "  -p  setup passcode (default 20202021)\n"
            "  -d  discriminator 0..4095 (default 3840)\n"
            "  -s  state file (default matter-light.state)\n"
            "  -r  factory reset (delete state file) before starting\n"
            "  -v  verbose protocol logging\n",
            argv0);
}

int main(int argc, char **argv)
{
    int opt, reset = 0;
    setvbuf(stdout, NULL, _IOLBF, 0);
    /* defaults: test vendor/product (must match the test DAC) and the
     * well-known test passcode/discriminator used across the Matter SDK */
    g_node.vid = 0xFFF1;
    g_node.pid = 0x8000;
    g_node.passcode = 20202021;
    g_node.discriminator = 3840;
    g_node.next_fabric_index = 1;
    snprintf(g_node.ifname, sizeof g_node.ifname, DEFAULT_IFACE);
    snprintf(g_node.state_path, sizeof g_node.state_path, "matter-light.state");
    snprintf(g_node.location, sizeof g_node.location, "XX");

    while ((opt = getopt(argc, argv, "i:p:d:s:rvh")) != -1) {
        switch (opt) {
        case 'i': snprintf(g_node.ifname, sizeof g_node.ifname, "%s", optarg); break;
        case 'p': g_node.passcode = (uint32_t)strtoul(optarg, NULL, 10); break;
        case 'd': g_node.discriminator = (uint16_t)(strtoul(optarg, NULL, 10) & 0xFFF); break;
        case 's': snprintf(g_node.state_path, sizeof g_node.state_path, "%s", optarg); break;
        case 'r': reset = 1; break;
        case 'v': g_verbose = 1; break;
        default: usage(argv[0]); return 1;
        }
    }
    if (g_node.passcode < 1 || g_node.passcode > 99999998) {
        fprintf(stderr, "invalid passcode\n");
        return 1;
    }

    /* --- credentials and persistent state --- */
    crypto_init();
    if (p256_from_der(creds_dac_key, creds_dac_key_len, &g_node.dac_key)) {
        fprintf(stderr, "failed to load DAC key\n");
        return 1;
    }
    if (reset) {
        unlink(g_node.state_path);
        LOG("factory reset: %s removed", g_node.state_path);
    }
    if (state_load() == 0)
        LOG("loaded state from %s (%d fabric(s))", g_node.state_path, fabric_count(1));
    g_node.reboot_count++;
    g_node.boot_ms = now_ms();
    state_save();

    /* random mDNS host and commissionable instance names (fresh each boot;
     * controllers find us by service, not by these names) */
    uint8_t r[8];
    rand_bytes(r, 8);
    snprintf(g_node.host, sizeof g_node.host, "%02X%02X%02X%02X%02X%02X", r[0], r[1], r[2], r[3], r[4], r[5]);
    rand_bytes(r, 8);
    for (int i = 0; i < 8; i++)
        sprintf(g_node.instance + 2 * i, "%02X", r[i]);

    /* Precompute the SPAKE2+ verifier (w0, L) for our passcode with a fresh
     * random salt. PBKDF2 is deliberately slow, so do it once here. */
    g_node.def_iters = 1000;
    rand_bytes(g_node.def_salt, 32);
    if (spake_verifier(g_node.passcode, g_node.def_salt, 32, g_node.def_iters, g_node.def_w0, g_node.def_L)) {
        fprintf(stderr, "failed to compute PASE verifier\n");
        return 1;
    }

    /* --- network --- */
    if (transport_init() || mdns_init(g_node.ifname)) {
        fprintf(stderr, "network setup failed (try -i <iface>)\n");
        return 1;
    }
    LOG("C Matter Light up: udp/%d, mDNS host %s.local on %s, light is %s", MATTER_PORT, g_node.host,
        g_node.ifname, g_node.onoff ? "ON" : "OFF");

    /* uncommissioned -> become commissionable; otherwise just advertise
     * our operational identities so controllers can reconnect via CASE */
    if (!fabric_count(1))
        cw_open_basic();
    else
        mdns_announce();
    print_status();
    printf("keys: [t]oggle light, [s]tatus, [q]uit\n");

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    /* --- event loop --- */
    while (!quit) {
        struct pollfd p[4] = {
            { transport_fd(), POLLIN, 0 },
            { mdns_fd6(), POLLIN, 0 },
            { mdns_fd4(), POLLIN, 0 },   /* -1 if no IPv4: poll ignores it */
            { STDIN_FILENO, POLLIN, 0 },
        };
        int n = poll(p, 4, 50);
        if (n > 0) {
            if (p[0].revents & POLLIN)
                transport_rx();
            if (p[1].revents & POLLIN)
                mdns_rx(p[1].fd);
            if (p[2].fd >= 0 && (p[2].revents & POLLIN))
                mdns_rx(p[2].fd);
            if (p[3].revents & (POLLIN | POLLHUP)) {
                char line[64];
                if (!fgets(line, sizeof line, stdin)) {
                    p[3].fd = -1;   /* stdin closed: keep running headless */
                    close(STDIN_FILENO);
                } else if (line[0] == 't') {
                    light_set(!g_node.onoff, "local button");
                } else if (line[0] == 's') {
                    print_status();
                } else if (line[0] == 'q') {
                    quit = 1;
                }
            }
        }
        uint64_t now = now_ms();
        transport_tick(now);   /* MRP retransmissions */
        im_tick(now);          /* subscription reports / keep-alives */
        node_tick(now);        /* fail-safe, window timeout, deferred removal */
        mdns_tick(now);        /* repeated announcements */
    }

    /* tell the network we're gone so controllers don't wait on stale records */
    LOG("shutting down");
    mdns_goodbye_all();
    return 0;
}

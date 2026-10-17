# C Matter Light

A Matter **On/Off Light** accessory written in plain C, **without the Matter SDK**.
OpenSSL's libcrypto is used only for the crypto primitives (SHA-256, HMAC, HKDF,
PBKDF2, AES-CCM, P-256 ECDSA/ECDH, CSR encoding). Everything Matter-specific is
implemented here, in about 4,400 lines.

A HomePod mini is a Matter *controller* (and Thread border router), so "talking to it"
means being an accessory that Apple Home commissions and controls. Once the light is
paired, "Hey Siri, turn on C Matter Light" reaches this program through the HomePod.

## What's implemented

| File | What |
|---|---|
| `src/tlv.c` | Matter TLV encoder/decoder |
| `src/crypto.c` | OpenSSL wrappers + SPAKE2+ verifier (P-256, Matter M/N points) |
| `src/transport.c` | UDP/5540, message & protocol headers, AES-CCM sessions, replay window, MRP acks/retransmits |
| `src/secure_channel.c` | PASE (PBKDFParam, Pake1/2/3) and CASE (Sigma1/2/3) responders |
| `src/im.c` | Interaction Model: Read, Subscribe (+ chunked reports, keep-alives), Write, Invoke, Timed |
| `src/clusters.c` | Descriptor, Access Control, Basic Information, General Commissioning, Network Commissioning (Ethernet), General Diagnostics, Administrator Commissioning, Operational Credentials, Group Key Management, Identify, On/Off |
| `src/mdns.c` | mDNS/DNS-SD responder for `_matterc._udp` (commissionable) and `_matter._tcp` (operational) |
| `src/fabric.c` | Fabric table, Matter TLV certificate parsing, persistence |
| `src/setup_payload.c` | QR (`MT:…`) and 11-digit manual pairing codes |
| `src/creds.c` | **Public test** DAC/PAI/Certification Declaration (VID 0xFFF1, PID 0x8000) |

## Build & run

```sh
# Linux:  sudo apt install libssl-dev
# macOS:  brew install openssl@3
make
./matter-light            # -i <iface> to choose the interface, -r to factory reset, -v for protocol logs
```

When it starts with no fabrics, it opens a commissioning window and prints:

- Manual pairing code: **3497-011-2332**
- QR: `MT:Y.K90AFN00KA0648G00`, with a link that renders it as an image

While it runs, type `t` + Enter to toggle the light locally (the change is reported to
subscribed controllers), `s` for status, and `q` to quit. Fabrics and the light state persist in
`matter-light.state`.

## Pairing with Apple Home

1. Run it on a machine on the **same LAN (with IPv6) as your iPhone and HomePod**.
2. In the Home app, go to **+ → Add Accessory → More options…**. The light should appear;
   otherwise, enter the code `3497-011-2332`.
3. iOS warns about an **uncertified accessory**, because it uses public test certificates.
   Choose *Add Anyway*.

> ⚠️ **OrbStack:** the OrbStack Linux VM sits behind NAT, and in testing it received
> no mDNS traffic from the LAN. The iPhone/HomePod therefore can't discover it there.
> Run the binary natively on the Mac (`make && ./matter-light -i en0`) or on a Linux box
> on the LAN. The macOS build hasn't been tested yet.

## Testing without Apple

Verified against the official Matter SDK controller via python-matter-server:
commissioning, On/Off/Toggle, Identify, wildcard subscription with live reports, restart
plus CASE reconnect, multi-admin (enhanced commissioning window → second fabric), and RemoveFabric.

```sh
docker run -d --name mserver --network host -v $PWD/mserver:/data \
  ghcr.io/home-assistant-libs/python-matter-server:stable --storage-path /data
# then send websocket commands to ws://127.0.0.1:5580/ws, e.g.
#   {"message_id":"1","command":"commission_with_code","args":{"code":"34970112332","network_only":true}}
#   {"message_id":"2","command":"device_command","args":{"node_id":1,"endpoint_id":1,"cluster_id":6,"command_name":"Toggle","payload":{}}}
```

## Deliberate shortcuts (this is a demo, not a product)

- **No access-control enforcement.** The ACL is stored and reported but not checked; any
  established session may read, write and invoke anything.
- **CASE does not validate the peer's NOC→ICAC→RCAC chain.** It checks the fabric ID and the
  Sigma3 signature. Completing CASE still requires the fabric's IPK.
- No CASE session resumption (it falls back to a full handshake), no events, and no Groups/Scenes
  clusters. Strictly, the On/Off Light device type also requires Groups.
- mDNS has no probing or conflict resolution and advertises on one interface.
- The DAC private key is public test material, and operational private keys are stored in
  plaintext in the state file.

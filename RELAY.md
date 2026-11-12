# Scaleway WSS / WireGuard relay

This is a targeted Rust fork of Shoes v0.3.7, upstream commit
`ee44a397e6850193e86a1ae66639f037f963822d`.

The relay keeps a Trojan-over-WebSocket interface and routes authenticated TCP,
UDP and DNS through a user-space WireGuard connection. TLS is terminated by the
hosting platform. It requires neither a host TUN interface nor a Go runtime.

## Delivery status

This repository is an artifact delivery. It does **not** deploy itself or change
any existing server, client profile, password or WireGuard key. A successful
offline acceptance run is not proof of public-network throughput, latency,
Scaleway sandbox compatibility or long-term stability.

## Building

Use Rust 1.99.1 and the committed lockfile:

```sh
cargo build --locked --release --no-default-features --features relay-minimal --bin shoes --bin relay-config
docker buildx build --platform linux/amd64 --file Dockerfile.relay --target runtime --tag scaleway-wss-wg-relay:local --load .
```

`relay-minimal` removes unused protocol implementations and their heavyweight
dependencies. The runtime defaults to one Tokio execution thread and no hot
reload. WireGuard still has its event-driven network-stack thread; this is not a
claim that the entire process has only one OS thread.

The GNU/Linux build uses portable x86-64 instructions, LTO and one codegen unit.
The Docker build embeds jemalloc settings for one arena and bounded idle-page
retention. Crypto remains in the pinned upstream implementations, including
their existing native optimizations.

## Private configuration

The `relay-config` executable strictly converts the supported sing-box relay
configuration into native Shoes JSON. Unsupported fields or changed policies
are errors. Read `relay-config --help` for the command contract. Converted output
must stay outside this repository with mode `0600`; do not add it to images,
build arguments, Actions secrets, examples, logs or release assets.

The program reads its configuration directly from the named environment
variable:

```text
shoes -t 1 --no-reload --config-env RELAY_CONFIG
```

Use the program's `--check` mode to parse and validate configuration without
starting WireGuard. The environment-variable **name** is compatible with the
existing deployment; its **payload format changes**. Old sing-box JSON must not
be passed directly to this Rust program.

## Resource model

TCP begins with four 32 KiB buffers per flow, with a maximum of 4 MiB per buffer.
A 48 MiB aggregate capacity budget preserves 10 MiB of base admission for
80 flows. Growth is tiered: buffers below 512 KiB quadruple per round, larger
ones double, so a slow-start flow reaches the 4 MiB maximum in five
reallocations instead of eight. Growth accounts for both old and replacement
allocations, preserves window scaling and out-of-order data, and never shrinks
a live receive window.

UDP allocations share an 8 MiB budget. IPv4 reassembly is further limited to
32 incomplete datagrams, 2 MiB and 15 seconds. GotaTun packet pools and internal
channels are set to 64 entries. The WireGuard carrier requests 4 MiB kernel
socket buffers and coalesces its traffic: up to 64 encrypted packets leave in
one `sendmmsg` syscall with a readiness-managed per-packet fallback, and a
receive takes one readiness-managed datagram plus a synchronous `recvmmsg`
drain of at most 64 packets per call into eight reusable 64 KiB scratch slots,
so large datagrams are never truncated at the 4 KiB packet pool. The detour
(proxy-chain) transport intentionally stays on the single-packet path. These
limits describe controlled allocations, not a hard bound on total process RSS
or a throughput guarantee.

The 100 mVCPU CFS quota can stall any single task for tens of milliseconds at
a time; the carrier batch sizes and 4 MiB socket buffers absorb such stalls
instead of dropping authenticated traffic while the CPU budget is exhausted.

Packets reaching the IP-stack classifier have already been authenticated by
WireGuard's AEAD layer, so that path skips the IP/TCP checksum verification.
Checksums are still checked where integrity is not yet established (IPv4
fragment reassembly), and the stack's TCP sockets keep validating according to
their checksum capabilities. The IP-stack device additionally advertises
receive-side checksum offload to smoltcp: every packet entering the device has
already been AEAD-authenticated and was checksum-validated by the peer's
kernel before entering the tunnel, so the software RX add-loops are skipped in
both directions of a flow. Transmit-side computation stays enabled because
emitted packets leave the tunnel to real hosts and no hardware computes them.

TCP congestion control and retransmission behavior carry three deliberate fork
deviations in the vendored smoltcp, each documented at its constant: the
initial congestion window is ten segments (RFC 6928) instead of two, applied
when the real MSS becomes known at handshake time and never reducing a
post-loss window; the retransmission timeout floor is 300 ms instead of the
RFC 6298 1 second, because the tunnel's roughly 300 ms RTT made every loss
wait at least three RTTs before recovering; and socket egress drains until
smoltcp reports quiescence instead of a fixed eight rounds, so a burst fills
the output channel in one wake. Socket egress packet coalescing stops at the
output channel's backpressure exactly as before.

Outbound UDP flows are reaped by the stack thread after 120 idle seconds with
no pending datagrams, so abandoned DNS or UDP sessions cannot accumulate for
the process lifetime on the 128 MB host; a reaped flow surfaces as the usual
BrokenPipe on next use, and pooled DNS connections re-establish transparently.

The WireGuard endpoint completes one peer handshake at startup before serving
(capped at ten seconds, best effort), so a cold start or scale-up no longer
pays the handshake round trip on the first user connection; the on-demand
handshake remains the fallback when the warm-up fails.

Relay chunk buffers are 32 KiB per direction and the WebSocket packing buffer
is 64 KiB, so bulk flows emit one 32 KiB frame per write instead of 16 KiB
frames, halving frame and downstream write syscall counts; interactive traffic
still flushes as soon as both sides are pending.

DNS response caches survive idle-transport rebuilds for up to one hour
(previously sixty seconds), and a UDP upstream whose exchange times out or
fails at the transport level retries the same endpoint over its configured TCP
companion within the same slot before the overall deadline: over the tunnel a
silently dropped UDP datagram is the normal failure mode, and no ICMP feedback
ever reaches the container. Definitive DNS answers are never retried over TCP;
they are handled by the exchange-level partial logic.

The expected host resource specification remains 100 mVCPU / 128 MB with
minimum replicas 0 and maximum replicas 1. Language changes do not alter the
provider's billing allowances or remove geographic propagation delay.

## Offline acceptance

All fixtures use test keys and loopback or in-memory transports. No test may
load the production WireGuard configuration or contact a public test target.
The dedicated CI workflow runs test containers with `--network none`, and runs
the compiled release binary's limited acceptance suite under a 128 MiB cap.
There is no public speed test, benchmark or stress test.

## Future migration and rollback

Online migration is deliberately outside this delivery. Before a future switch,
save the old image digest, command, environment, full secret configuration and
client settings in a private location. Keep the hostname, WS path and client
passwords unchanged. Do not start two instances with the same real WireGuard
key: a rolling update can cause peer endpoint roaming even with max replicas 1.

Use a controlled maintenance window and verify that the old WG instance has
stopped before starting the new one. Rollback requires restoring the **matching
old image and old secret payload**, not just one of them. Do not use an unrelated
direct-egress configuration as a rollback.

All upstream and vendored license notices are retained in the source tree and
included in the runtime image.

## Explicit direct egress

Set `global_settings.relay_egress` to `direct` and use `client_chain: "direct"`
for the allowed ingress routes and DNS servers to send traffic directly from
Scaleway. Remove all WireGuard client/server definitions. Direct mode rejects
WireGuard definitions, including unused ones; an omitted mode retains the
WireGuard-only ingress policy for existing configurations.

Keep authentication, the WebSocket path, and private/reserved/IPv6 destination
blocks when changing egress. The platform's region becomes the egress location;
the former WireGuard exit IP no longer applies. Direct UDP replies are accepted
only from the selected destination address and port.

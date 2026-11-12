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

TCP begins with four 32 KiB buffers per flow, with a maximum of 1 MiB per buffer.
A 32 MiB aggregate capacity budget preserves 10 MiB of base admission for
80 flows. Growth accounts for both old and replacement allocations, preserves
window scaling and out-of-order data, and never shrinks a live receive window.

UDP allocations share an 8 MiB budget. IPv4 reassembly is further limited to
32 incomplete datagrams, 2 MiB and 15 seconds. GotaTun packet pools and internal
channels are set to 64 entries. These limits describe controlled allocations,
not a hard bound on total process RSS or a throughput guarantee.

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

---
title: "Trojan"
description: shoes trojan configuration.
---

**Complete example:** [trojan_basic.yaml](/examples/trojan_basic/). Adapt addresses and secrets before deployment.

The field sketches below contain placeholders, not runnable values. Use a complete example when configuring a deployment.

## Server

```yaml
protocol:
  type: trojan
  password: string            # Or a nonempty list of accepted server passwords
  shadowsocks:                 # Optional encryption layer
    cipher: string
    password: string
```

This relay fork supports both TCP CONNECT and UDP ASSOCIATE on the server, including
Trojan over WebSocket. UDP frames are routed independently by destination. The IPv4
payload limit is 65507 bytes; zero-length datagrams are preserved. Reply addresses
identify the resolved remote IP.

Multiple server credentials can share one listener and WebSocket path:

```yaml
protocol:
  type: trojan
  password: [first-password, second-password]
```

The `relay-minimal` build rejects IPv6 destinations (including IPv4-mapped IPv6),
Trojan multiplexing, and the optional Shadowsocks wrapper. Its deployment rules
provide the private-address checks and WireGuard-only routing. The client-side
Trojan implementation still uses one password and does not implement outbound UDP.


## Client

```yaml
protocol:
  type: trojan
  password: string
  shadowsocks:                 # Optional
    cipher: string
    password: string
  h2mux:                         # Optional multiplexing; see H2MUX
    max_connections: 4
    min_streams: 4
    max_streams: 0
    padding: false
```

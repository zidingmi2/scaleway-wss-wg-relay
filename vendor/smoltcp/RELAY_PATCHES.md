Upstream: https://github.com/cfal/smoltcp
Commit: 7ef43e497f575cb0340a43e4f414f0f0b8760bf6

Local relay patch: fallible, growth-only TCP buffers with a receive-window
scale negotiated from a configured maximum before connection establishment.
No upstream license changes.

Added APIs (with `alloc`, including `std` builds):
- `storage::RingBuffer::try_grow(capacity)` replaces owned storage only,
  preserving the full logical ring including out-of-order data beyond `len()`.
- `socket::tcp::Socket::set_recv_max_capacity(capacity)` is valid only before
  opening the socket; it sets the SYN window scale without advertising or
  allocating the maximum receive window.
- `Socket::try_grow_recv_buffer` and `Socket::try_grow_send_buffer` preserve
  sequence numbers, timers, retransmission cursors, and reassembly state.

Growth never shrinks a buffer. Callers must reserve the entire new allocation
while the old allocation still exists, then release the old reservation after
success. An allocation failure or invalid request leaves existing storage and
TCP state intact. Interface polling after receive growth uses the existing
window-update mechanism. No new unsafe code is introduced.

Offline unit-test filters: `dynamic_` (TCP) and `grow_` (ring storage).

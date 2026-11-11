//! shoes - A high-performance multi-protocol proxy server.
//!
//! This library provides the core functionality for shoes, enabling it to be
//! embedded in mobile applications (Android/iOS) as a VPN backend.
//!
//! # Features
//!
//! - **Multi-protocol support**: VLESS, VMess, Trojan, Shadowsocks, and more
//! - **TUN device support**: Virtual network interface for VPN mode
//! - **Proxy chaining**: Connect through multiple proxies
//! - **Flexible routing**: Rule-based traffic routing
//!
//! # Mobile Integration
//!
//! Android apps supply their own JNI declarations matching `src/ffi/android.rs`
//! and manage the VPN service and socket-protection callback. See the README's
//! Mobile Embedding section for the native build and integration contract.
//!
//! For iOS, use the C FFI module from Swift:
//!
//! ```swift
//! // Initialize
//! shoes_init("info")
//!
//! // Start VPN with packet tunnel fd
//! let handle = shoes_start(configYaml, protectCallback)
//!
//! // Stop VPN
//! shoes_stop(handle)
//! ```
//!
//! # Platform Support
//!
//! - Linux (x86_64, aarch64)
//! - Android (arm64-v8a, armeabi-v7a, x86_64)
//! - iOS (arm64)

// This module tree backs both the shoes binary, through `cli`, and FFI/mobile
// integration.
mod address;
#[cfg(not(feature = "relay-minimal"))]
mod anytls;
mod async_stream;
mod atomic;
#[cfg(not(feature = "relay-minimal"))]
mod buf_reader;
#[cfg_attr(feature = "relay-minimal", path = "minimal/certificates.rs")]
mod certificates;
#[cfg(not(feature = "relay-minimal"))]
mod clash_api;
mod client_proxy_chain;
mod client_proxy_selector;
mod clock;
mod control;
mod copy_bidirectional;
mod copy_bidirectional_message;
#[cfg(not(feature = "relay-minimal"))]
mod crypto;
#[cfg_attr(feature = "relay-minimal", path = "minimal/desktop.rs")]
mod desktop;
pub mod dns;
#[cfg(not(feature = "relay-minimal"))]
mod file_watcher;
#[cfg(not(feature = "relay-minimal"))]
mod h2mux;
#[cfg(not(feature = "relay-minimal"))]
mod http2;
#[cfg(not(feature = "relay-minimal"))]
mod http_handler;
#[cfg(not(feature = "relay-minimal"))]
mod hysteria2_server;
mod listener_tasks;
#[cfg(not(feature = "relay-minimal"))]
mod mixed_handler;
#[cfg(not(feature = "relay-minimal"))]
mod naiveproxy;
#[cfg(not(feature = "relay-minimal"))]
mod ntp;
mod option_util;
#[cfg(not(feature = "relay-minimal"))]
mod port_forward_handler;
mod prepend_stream;
#[cfg(not(feature = "relay-minimal"))]
mod process;
#[cfg(not(feature = "relay-minimal"))]
mod quic_client;
#[cfg(not(feature = "relay-minimal"))]
mod quic_endpoint;
#[cfg(not(feature = "relay-minimal"))]
mod quic_server;
#[cfg(not(feature = "relay-minimal"))]
mod quic_stream;
#[cfg_attr(feature = "relay-minimal", path = "minimal/reality.rs")]
mod reality;
pub mod resolver;
pub mod resources;
mod routing;
pub mod rule_set;
#[cfg(unix)]
#[cfg(not(feature = "relay-minimal"))]
mod rule_updater;
pub mod rules;
mod rustls_config_util;
#[cfg(not(feature = "relay-minimal"))]
mod rustls_connection_util;
#[cfg(not(feature = "relay-minimal"))]
mod shadow_tls;
#[cfg_attr(feature = "relay-minimal", path = "minimal/shadowsocks.rs")]
mod shadowsocks;
#[cfg(not(feature = "relay-minimal"))]
mod slide_buffer;
#[cfg(not(feature = "relay-minimal"))]
mod snell;
mod sniff;
mod socket_policy;
mod socket_util;
#[cfg(not(feature = "relay-minimal"))]
mod socks5_udp_relay;
#[cfg_attr(feature = "relay-minimal", path = "minimal/socks_handler.rs")]
mod socks_handler;
#[cfg(target_os = "linux")]
mod splice;
mod stream_reader;
#[cfg_attr(feature = "relay-minimal", path = "minimal/sudoku_mask.rs")]
mod sudoku_mask;
#[cfg(not(feature = "relay-minimal"))]
mod sync_adapter;
mod tcp;
mod thread_util;
#[cfg(not(feature = "relay-minimal"))]
mod tls_client_handler;
#[cfg(not(feature = "relay-minimal"))]
mod tls_server_handler;
mod trojan_handler;
mod trojan_udp_stream;
#[cfg(not(feature = "relay-minimal"))]
mod tuic_server;
mod udp_budget;
#[cfg_attr(feature = "relay-minimal", path = "minimal/udp_fragments.rs")]
mod udp_fragments;
mod uot;
mod util;
mod uuid_util;
#[cfg(not(feature = "relay-minimal"))]
mod vless;
#[cfg(not(feature = "relay-minimal"))]
mod vmess;
mod websocket;
#[cfg(not(feature = "relay-minimal"))]
mod xudp;

/// Command-line entry point of the `shoes` binary.
#[cfg_attr(feature = "relay-minimal", path = "minimal/cli.rs")]
pub mod cli;

/// Configuration types.
pub mod config;

/// Multi-output logging infrastructure.
pub mod logging;

/// TUN device support for VPN mode.
#[cfg(unix)]
#[cfg_attr(feature = "relay-minimal", path = "minimal/tun.rs")]
pub mod tun;

#[cfg(unix)]
pub(crate) mod ip_stack;
#[cfg(unix)]
pub(crate) mod wireguard;

/// FFI bindings for mobile platforms.
#[cfg(any(target_os = "android", target_os = "ios", feature = "ffi"))]
pub mod ffi;
#[cfg(not(feature = "relay-minimal"))]
mod xhttp;

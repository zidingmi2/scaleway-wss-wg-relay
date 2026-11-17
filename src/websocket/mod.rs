use futures::task::{ArcWake, AtomicWaker};
use std::sync::Arc;

mod early_data;
mod early_stream;
mod websocket_handler;
mod websocket_stream;

pub(crate) use early_data::{EarlyData, validate_early_data};

pub(crate) fn is_zero(value: &usize) -> bool {
    *value == 0
}

pub use websocket_handler::{
    WebsocketServerTarget, WebsocketTcpClientHandler, WebsocketTcpServerHandler,
};

// Either half may drive a shared transport operation after tokio::io::split.
#[derive(Default)]
struct DuplexWake {
    reader: AtomicWaker,
    writer: AtomicWaker,
}

impl ArcWake for DuplexWake {
    fn wake_by_ref(this: &Arc<Self>) {
        this.reader.wake();
        this.writer.wake();
    }
}

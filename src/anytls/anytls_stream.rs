//! AnyTLS Stream implementation
//!
//! A Stream represents a single multiplexed connection within an AnyTLS Session.

use crate::async_stream::{AsyncPing, AsyncStream};
use bytes::Bytes;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tokio_util::sync::PollSender;

/// Per-stream bounded message queue depth.
///
/// This is message-count based, not byte-based.
/// A slightly larger value helps reduce artificial stalls for bursty
/// QUIC/UoT traffic without making memory usage explode.
pub const STREAM_CHANNEL_BUFFER: usize = 64;

/// Maximum payload per AnyTLS PSH frame.
const MAX_FRAME_DATA_SIZE: usize = 65535;

pub struct AnyTlsStream {
    id: u32,
    data_rx: mpsc::Receiver<Bytes>,
    read_buffer: Bytes,
    read_offset: usize,
    data_tx: PollSender<(u32, Bytes)>,
    session_closed: Arc<AtomicBool>,
    stream_closed: bool,
    shutdown_in_progress: bool,
    eof: bool,
    _session_keepalive: Option<Arc<dyn std::any::Any + Send + Sync>>,
}

impl AnyTlsStream {
    pub fn new(
        id: u32,
        data_rx: mpsc::Receiver<Bytes>,
        data_tx: mpsc::Sender<(u32, Bytes)>,
        session_closed: Arc<AtomicBool>,
    ) -> Self {
        Self {
            id,
            data_rx,
            read_buffer: Bytes::new(),
            read_offset: 0,
            data_tx: PollSender::new(data_tx),
            session_closed,
            stream_closed: false,
            shutdown_in_progress: false,
            eof: false,
            _session_keepalive: None,
        }
    }

    pub fn with_keepalive<S: Send + Sync + 'static>(
        id: u32,
        data_rx: mpsc::Receiver<Bytes>,
        data_tx: mpsc::Sender<(u32, Bytes)>,
        session_closed: Arc<AtomicBool>,
        session: Arc<S>,
    ) -> Self {
        Self {
            id,
            data_rx,
            read_buffer: Bytes::new(),
            read_offset: 0,
            data_tx: PollSender::new(data_tx),
            session_closed,
            stream_closed: false,
            shutdown_in_progress: false,
            eof: false,
            _session_keepalive: Some(session),
        }
    }

    pub fn id(&self) -> u32 {
        self.id
    }

    fn send_fin_best_effort(&mut self) {
        if let Some(sender) = self.data_tx.get_ref() {
            let _ = sender.try_send((self.id, Bytes::new()));
        }
    }
}

impl AsyncRead for AnyTlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.stream_closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "stream closed",
            )));
        }

        let remaining_in_buffer = self.read_buffer.len().saturating_sub(self.read_offset);
        if self.eof && remaining_in_buffer == 0 {
            return Poll::Ready(Ok(()));
        }

        if remaining_in_buffer > 0 {
            let n = remaining_in_buffer.min(buf.remaining());
            buf.put_slice(&self.read_buffer[self.read_offset..self.read_offset + n]);
            self.read_offset += n;

            if self.read_offset >= self.read_buffer.len() {
                self.read_buffer = Bytes::new();
                self.read_offset = 0;
            }

            return Poll::Ready(Ok(()));
        }

        match Pin::new(&mut self.data_rx).poll_recv(cx) {
            Poll::Ready(Some(data)) => {
                if data.is_empty() {
                    self.eof = true;
                    return Poll::Ready(Ok(()));
                }

                let n = data.len().min(buf.remaining());
                buf.put_slice(&data[..n]);

                if n < data.len() {
                    self.read_buffer = data;
                    self.read_offset = n;
                }

                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => {
                self.eof = true;
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for AnyTlsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.stream_closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "stream closed",
            )));
        }

        if self.shutdown_in_progress {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "stream is shutting down",
            )));
        }

        if self.session_closed.load(Ordering::Relaxed) {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "session closed",
            )));
        }

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        match self.data_tx.poll_reserve(cx) {
            Poll::Ready(Ok(())) => {
                let write_len = buf.len().min(MAX_FRAME_DATA_SIZE);
                let data = Bytes::copy_from_slice(&buf[..write_len]);
                let id = self.id;
                match self.data_tx.send_item((id, data)) {
                    Ok(()) => Poll::Ready(Ok(write_len)),
                    Err(_) => Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "session channel closed",
                    ))),
                }
            }
            Poll::Ready(Err(_)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "session channel closed",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.stream_closed {
            return Poll::Ready(Ok(()));
        }

        if self.session_closed.load(Ordering::Relaxed) {
            self.stream_closed = true;
            return Poll::Ready(Ok(()));
        }

        self.shutdown_in_progress = true;

        match self.data_tx.poll_reserve(cx) {
            Poll::Ready(Ok(())) => {
                let id = self.id;
                match self.data_tx.send_item((id, Bytes::new())) {
                    Ok(()) => {
                        self.stream_closed = true;
                        Poll::Ready(Ok(()))
                    }
                    Err(_) => {
                        self.stream_closed = true;
                        Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "session channel closed during shutdown",
                        )))
                    }
                }
            }
            Poll::Ready(Err(_)) => {
                self.stream_closed = true;
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "session channel closed",
                )))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Drop for AnyTlsStream {
    fn drop(&mut self) {
        if !self.stream_closed {
            self.stream_closed = true;
            self.send_fin_best_effort();
        }
    }
}

impl AsyncPing for AnyTlsStream {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl AsyncStream for AnyTlsStream {}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn test_stream_write() {
        let (data_tx, mut data_rx) = mpsc::channel(STREAM_CHANNEL_BUFFER);
        let (_incoming_tx, incoming_rx) = mpsc::channel(STREAM_CHANNEL_BUFFER);
        let session_closed = Arc::new(AtomicBool::new(false));

        let mut stream = AnyTlsStream::new(1, incoming_rx, data_tx, session_closed);

        stream.write_all(b"hello").await.unwrap();

        let (stream_id, data) = data_rx.recv().await.unwrap();
        assert_eq!(stream_id, 1);
        assert_eq!(data.as_ref(), b"hello");
    }

    #[tokio::test]
    async fn test_stream_read() {
        let (data_tx, _data_rx) = mpsc::channel(STREAM_CHANNEL_BUFFER);
        let (incoming_tx, incoming_rx) = mpsc::channel(STREAM_CHANNEL_BUFFER);
        let session_closed = Arc::new(AtomicBool::new(false));

        let mut stream = AnyTlsStream::new(1, incoming_rx, data_tx, session_closed);

        incoming_tx.send(Bytes::from("world")).await.unwrap();

        let mut buf = vec![0u8; 10];
        let n = stream.read(&mut buf).await.unwrap();

        assert_eq!(n, 5);
        assert_eq!(&buf[..n], b"world");
    }

    #[tokio::test]
    async fn test_stream_read_buffering() {
        let (data_tx, _data_rx) = mpsc::channel(STREAM_CHANNEL_BUFFER);
        let (incoming_tx, incoming_rx) = mpsc::channel(STREAM_CHANNEL_BUFFER);
        let session_closed = Arc::new(AtomicBool::new(false));

        let mut stream = AnyTlsStream::new(1, incoming_rx, data_tx, session_closed);

        incoming_tx.send(Bytes::from("hello world")).await.unwrap();

        let mut buf = vec![0u8; 5];

        let n1 = stream.read(&mut buf).await.unwrap();
        assert_eq!(n1, 5);
        assert_eq!(&buf[..n1], b"hello");

        let n2 = stream.read(&mut buf).await.unwrap();
        assert_eq!(n2, 5);
        assert_eq!(&buf[..n2], b" worl");

        let n3 = stream.read(&mut buf).await.unwrap();
        assert_eq!(n3, 1);
        assert_eq!(&buf[..n3], b"d");
    }

    #[tokio::test]
    async fn test_stream_eof() {
        let (data_tx, _data_rx) = mpsc::channel(STREAM_CHANNEL_BUFFER);
        let (incoming_tx, incoming_rx) = mpsc::channel(STREAM_CHANNEL_BUFFER);
        let session_closed = Arc::new(AtomicBool::new(false));

        let mut stream = AnyTlsStream::new(1, incoming_rx, data_tx, session_closed);

        drop(incoming_tx);

        let mut buf = vec![0u8; 10];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(n, 0);
    }

    #[tokio::test]
    async fn test_stream_shutdown_sends_fin() {
        let (data_tx, mut data_rx) = mpsc::channel(STREAM_CHANNEL_BUFFER);
        let (_incoming_tx, incoming_rx) = mpsc::channel(STREAM_CHANNEL_BUFFER);
        let session_closed = Arc::new(AtomicBool::new(false));

        let mut stream = AnyTlsStream::new(42, incoming_rx, data_tx, session_closed);

        stream.shutdown().await.unwrap();

        let (stream_id, data) = data_rx.recv().await.unwrap();
        assert_eq!(stream_id, 42);
        assert!(data.is_empty());
    }

    #[tokio::test]
    async fn test_stream_backpressure() {
        let (data_tx, mut data_rx) = mpsc::channel(2);
        let (_incoming_tx, incoming_rx) = mpsc::channel(STREAM_CHANNEL_BUFFER);
        let session_closed = Arc::new(AtomicBool::new(false));

        let mut stream = AnyTlsStream::new(1, incoming_rx, data_tx, session_closed);

        stream.write_all(b"msg1").await.unwrap();
        stream.write_all(b"msg2").await.unwrap();

        let write_future = stream.write_all(b"msg3");

        let _ = data_rx.recv().await.unwrap();

        write_future.await.unwrap();

        let (_, data) = data_rx.recv().await.unwrap();
        assert_eq!(data.as_ref(), b"msg2");
        let (_, data) = data_rx.recv().await.unwrap();
        assert_eq!(data.as_ref(), b"msg3");
    }

    #[tokio::test]
    async fn test_shutdown_blocks_when_channel_full() {
        let (data_tx, mut data_rx) = mpsc::channel(2);
        let (_incoming_tx, incoming_rx) = mpsc::channel(STREAM_CHANNEL_BUFFER);
        let session_closed = Arc::new(AtomicBool::new(false));

        let mut stream = AnyTlsStream::new(1, incoming_rx, data_tx, session_closed);

        stream.write_all(b"msg1").await.unwrap();
        stream.write_all(b"msg2").await.unwrap();

        let shutdown_future = stream.shutdown();

        let (_, data1) = data_rx.recv().await.unwrap();
        assert_eq!(data1.as_ref(), b"msg1");

        shutdown_future.await.unwrap();

        let (_, data2) = data_rx.recv().await.unwrap();
        assert_eq!(data2.as_ref(), b"msg2");

        let (stream_id, fin) = data_rx.recv().await.unwrap();
        assert_eq!(stream_id, 1);
        assert!(fin.is_empty());
    }

    #[tokio::test]
    async fn test_shutdown_preserves_data_order() {
        let (data_tx, mut data_rx) = mpsc::channel(STREAM_CHANNEL_BUFFER);
        let (_incoming_tx, incoming_rx) = mpsc::channel(STREAM_CHANNEL_BUFFER);
        let session_closed = Arc::new(AtomicBool::new(false));

        let mut stream = AnyTlsStream::new(1, incoming_rx, data_tx, session_closed);

        stream.write_all(b"data1").await.unwrap();
        stream.write_all(b"data2").await.unwrap();
        stream.write_all(b"data3").await.unwrap();

        stream.shutdown().await.unwrap();

        let (_, d1) = data_rx.recv().await.unwrap();
        assert_eq!(d1.as_ref(), b"data1");

        let (_, d2) = data_rx.recv().await.unwrap();
        assert_eq!(d2.as_ref(), b"data2");

        let (_, d3) = data_rx.recv().await.unwrap();
        assert_eq!(d3.as_ref(), b"data3");

        let (_, fin) = data_rx.recv().await.unwrap();
        assert!(fin.is_empty());
    }

    #[tokio::test]
    async fn test_write_after_shutdown_fails() {
        let (data_tx, _data_rx) = mpsc::channel(STREAM_CHANNEL_BUFFER);
        let (_incoming_tx, incoming_rx) = mpsc::channel(STREAM_CHANNEL_BUFFER);
        let session_closed = Arc::new(AtomicBool::new(false));

        let mut stream = AnyTlsStream::new(1, incoming_rx, data_tx, session_closed);

        stream.shutdown().await.unwrap();

        let result = stream.write_all(b"should fail").await;
        assert!(result.is_err());
    }
}

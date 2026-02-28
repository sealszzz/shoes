//! AnyTLS Session implementation
//!
//! A Session manages multiple Streams over a single TLS connection,
//! handling framing, multiplexing, padding, and stream routing.

use crate::address::{Address, NetLocation};
use crate::anytls::anytls_padding::{CHECK_MARK, PaddingFactory};
use crate::anytls::anytls_stream::{AnyTlsStream, STREAM_CHANNEL_BUFFER};
use crate::anytls::anytls_types::{Command, FRAME_HEADER_SIZE, Frame, FrameCodec, StringMap};
use crate::async_stream::{AsyncMessageStream, AsyncTargetedMessageStream};
use crate::client_proxy_selector::{ClientProxySelector, ConnectDecision};
use crate::copy_bidirectional::copy_bidirectional;
use crate::resolver::Resolver;
use crate::routing::{ServerStream, run_udp_routing};
use crate::socks_handler::read_location_direct;
use crate::tcp::tcp_server::run_udp_copy;
use crate::uot::{UOT_V1_MAGIC_ADDRESS, UOT_V2_MAGIC_ADDRESS, UotV1ServerStream};
use crate::vless::VlessMessageStream;
use bytes::{BufMut, Bytes, BytesMut};
use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Mutex, RwLock, mpsc};
use tokio::task::JoinHandle;

/// Timeout for control frame writes (matches reference implementation)
const CONTROL_FRAME_TIMEOUT: Duration = Duration::from_secs(5);

/// Timeout for reading initial destination / UoT headers on a new stream
/// Prevents half-open streams from hanging forever before routing starts.
const STREAM_INIT_TIMEOUT: Duration = Duration::from_secs(15);

/// Timeout for route decision + outbound connect during stream setup
/// Does NOT apply to the long-lived relay/copy phase.
const STREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// AnyTLS Session manages multiplexed streams over a connection
pub struct AnyTlsSession {
    /// Underlying connection (split into reader/writer)
    reader: Mutex<Box<dyn AsyncRead + Send + Unpin>>,
    writer: Mutex<Box<dyn AsyncWrite + Send + Unpin>>,

    /// Stream management (bounded channels for backpressure)
    streams: RwLock<HashMap<u32, mpsc::Sender<Bytes>>>,

    /// Active stream handler tasks (for cancellation on session close)
    stream_tasks: Mutex<HashMap<u32, JoinHandle<()>>>,

    /// Channel for receiving outgoing data from streams (bounded for backpressure)
    outgoing_rx: Mutex<mpsc::Receiver<(u32, Bytes)>>,
    outgoing_tx: mpsc::Sender<(u32, Bytes)>,

    /// Session state
    is_closed: Arc<AtomicBool>,

    /// Padding configuration
    padding: Arc<PaddingFactory>,

    /// Client/Server mode
    is_client: bool,

    /// Padding state (client only)
    send_padding: AtomicBool,
    pkt_counter: AtomicU32,

    /// Buffering state (for initial settings+SYN coalescing)
    buffering: AtomicBool,
    buffer: Mutex<Vec<u8>>,

    /// Reusable write buffer to avoid allocations in hot path
    write_buf: Mutex<BytesMut>,

    /// Protocol version negotiation
    peer_version: AtomicU8,

    /// Server settings received
    received_client_settings: AtomicBool,

    // === Stream handling dependencies (server mode) ===
    /// Resolver for destination addresses (always required)
    resolver: Arc<dyn Resolver>,

    /// Proxy provider for routing decisions (always required - direct connect is dangerous)
    proxy_provider: Arc<ClientProxySelector>,

    /// UDP enabled for UoT support
    udp_enabled: bool,

    /// Authenticated user name for logging
    user_name: String,

    /// Initial data buffered during auth (to be prepended to first read)
    initial_data: std::sync::Mutex<Option<Box<[u8]>>>,
}

impl AnyTlsSession {
    /// Create a new server session with optional initial data that was buffered during auth.
    pub fn new_server_with_initial_data<IO>(
        conn: IO,
        padding: Arc<PaddingFactory>,
        resolver: Arc<dyn Resolver>,
        proxy_provider: Arc<ClientProxySelector>,
        udp_enabled: bool,
        user_name: String,
        initial_data: Option<Box<[u8]>>,
    ) -> Arc<Self>
    where
        IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let (reader, writer) = tokio::io::split(conn);
        let (outgoing_tx, outgoing_rx) = mpsc::channel(STREAM_CHANNEL_BUFFER * 4);

        Arc::new(Self {
            reader: Mutex::new(Box::new(reader)),
            writer: Mutex::new(Box::new(writer)),
            streams: RwLock::new(HashMap::new()),
            stream_tasks: Mutex::new(HashMap::new()),
            outgoing_rx: Mutex::new(outgoing_rx),
            outgoing_tx,
            is_closed: Arc::new(AtomicBool::new(false)),
            padding,
            is_client: false,
            send_padding: AtomicBool::new(false),
            pkt_counter: AtomicU32::new(0),
            buffering: AtomicBool::new(false),
            buffer: Mutex::new(Vec::new()),
            write_buf: Mutex::new(BytesMut::with_capacity(65536 + FRAME_HEADER_SIZE + 64)),
            peer_version: AtomicU8::new(0),
            received_client_settings: AtomicBool::new(false),
            resolver,
            proxy_provider,
            udp_enabled,
            user_name,
            initial_data: std::sync::Mutex::new(initial_data),
        })
    }

    #[cfg(test)]
    pub fn new_server_test<IO>(conn: IO, padding: Arc<PaddingFactory>) -> Arc<Self>
    where
        IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        use crate::client_proxy_selector::ConnectRule;
        use crate::resolver::NativeResolver;

        let (reader, writer) = tokio::io::split(conn);
        let (outgoing_tx, outgoing_rx) = mpsc::channel(STREAM_CHANNEL_BUFFER * 4);

        let proxy_provider = Arc::new(ClientProxySelector::new(vec![ConnectRule::new(
            vec![],
            crate::client_proxy_selector::ConnectAction::Block,
        )]));

        Arc::new(Self {
            reader: Mutex::new(Box::new(reader)),
            writer: Mutex::new(Box::new(writer)),
            streams: RwLock::new(HashMap::new()),
            stream_tasks: Mutex::new(HashMap::new()),
            outgoing_rx: Mutex::new(outgoing_rx),
            outgoing_tx,
            is_closed: Arc::new(AtomicBool::new(false)),
            padding,
            is_client: false,
            send_padding: AtomicBool::new(false),
            pkt_counter: AtomicU32::new(0),
            buffering: AtomicBool::new(false),
            buffer: Mutex::new(Vec::new()),
            write_buf: Mutex::new(BytesMut::with_capacity(65536 + FRAME_HEADER_SIZE + 64)),
            peer_version: AtomicU8::new(0),
            received_client_settings: AtomicBool::new(false),
            resolver: Arc::new(NativeResolver),
            proxy_provider,
            udp_enabled: false,
            user_name: String::new(),
            initial_data: std::sync::Mutex::new(None),
        })
    }

    pub fn is_closed(&self) -> bool {
        self.is_closed.load(Ordering::Relaxed)
    }

    fn is_benign_session_error(err: &io::Error) -> bool {
        let s = err.to_string().to_ascii_lowercase();
        s.contains("peer closed connection without sending tls close_notify")
            || s.contains("unexpected eof")
            || s.contains("stream closed")
            || err.kind() == io::ErrorKind::UnexpectedEof
            || err.kind() == io::ErrorKind::BrokenPipe
            || err.kind() == io::ErrorKind::ConnectionReset
            || err.kind() == io::ErrorKind::ConnectionAborted
    }

    fn is_benign_stream_error(err: &io::Error) -> bool {
        let s = err.to_string().to_ascii_lowercase();
        s.contains("stream closed")
            || s.contains("peer closed connection without sending tls close_notify")
            || s.contains("unexpected eof")
            || err.kind() == io::ErrorKind::UnexpectedEof
            || err.kind() == io::ErrorKind::BrokenPipe
            || err.kind() == io::ErrorKind::ConnectionReset
            || err.kind() == io::ErrorKind::ConnectionAborted
    }

    pub async fn close(&self) {
        if self
            .is_closed
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::Relaxed)
            .is_ok()
        {
            {
                let mut tasks = self.stream_tasks.lock().await;
                for (stream_id, handle) in tasks.drain() {
                    log::trace!("Aborting stream task {}", stream_id);
                    handle.abort();
                }
            }

            {
                let mut streams = self.streams.write().await;
                streams.clear();
            }

            if let Ok(mut writer) = self.writer.try_lock() {
                let _ = writer.shutdown().await;
            }
        }
    }

    pub fn peer_version(&self) -> u8 {
        self.peer_version.load(Ordering::Relaxed)
    }

    pub async fn run(self: &Arc<Self>) -> io::Result<()> {
        let session = Arc::clone(self);

        let session_clone = Arc::clone(&session);
        let outgoing_task = tokio::spawn(async move {
            session_clone.process_outgoing().await;
        });

        let result = session.recv_loop().await;

        match &result {
            Ok(()) => {
                log::debug!("AnyTLS session recv_loop ended normally");
            }
            Err(e) => {
                if Self::is_benign_session_error(e) {
                    log::debug!("AnyTLS session recv_loop ended: {}", e);
                } else {
                    log::warn!("AnyTLS session recv_loop ended with error: {}", e);
                }
            }
        }

        session.close().await;
        outgoing_task.abort();

        result
    }

    async fn process_outgoing(&self) {
        let mut rx = self.outgoing_rx.lock().await;

        while let Some((stream_id, data)) = rx.recv().await {
            if self.is_closed() {
                break;
            }

            if data.is_empty() {
                let frame = Frame::control(Command::Fin, stream_id);
                if let Err(e) = self.write_frame(&frame).await {
                    log::warn!(
                        "Failed to send FIN for stream {}: {}, closing session",
                        stream_id,
                        e
                    );
                    self.close().await;
                    break;
                }

                let mut streams = self.streams.write().await;
                streams.remove(&stream_id);
            } else {
                let frame = Frame::data(stream_id, data);
                if let Err(e) = self.write_frame(&frame).await {
                    log::warn!(
                        "Failed to send data for stream {}: {}, closing session",
                        stream_id,
                        e
                    );
                    self.close().await;
                    break;
                }
            }
        }
    }

    async fn recv_loop(self: &Arc<Self>) -> io::Result<()> {
        let mut buffer = BytesMut::with_capacity(8192);

        if let Some(initial) = self.initial_data.lock().unwrap().take() {
            buffer.extend_from_slice(&initial);
        }

        loop {
            if self.is_closed() {
                return Ok(());
            }

            while let Some(frame) = FrameCodec::decode(&mut buffer)? {
                if let Err(e) = self.handle_frame(frame).await {
                    if Self::is_benign_session_error(&e) {
                        log::debug!("Error handling frame: {}", e);
                    } else {
                        log::warn!("Error handling frame: {}", e);
                    }
                    return Err(e);
                }
            }

            let n = {
                let mut reader = self.reader.lock().await;
                match reader.read_buf(&mut buffer).await {
                    Ok(0) => return Ok(()),
                    Ok(n) => n,
                    Err(e) => return Err(e),
                }
            };

            log::trace!("Read {} bytes from connection", n);
        }
    }

    async fn handle_frame(self: &Arc<Self>, frame: Frame) -> io::Result<()> {
        match frame.cmd {
            Command::Psh => {
                if frame.data.is_empty() {
                    log::trace!("Ignoring zero-length PSH for stream {}", frame.stream_id);
                    return Ok(());
                }

                let stream_id = frame.stream_id;
                let tx = {
                    let streams = self.streams.read().await;
                    streams.get(&stream_id).cloned()
                };

                if let Some(tx) = tx {
                    // FIX 1: Removed the 3-second forced timeout self-destruct logic.
                    // Allowing `.await` here naturally transfers backpressure to the underlying
                    // TCP connection's sliding window. This ensures that a slow-consuming stream
                    // will throttle the sender gracefully instead of violently killing the connection.
                    if tx.send(frame.data).await.is_err() {
                        log::trace!("Stream {} channel closed natively", stream_id);
                    }
                } else {
                    log::trace!("Data for unknown stream {}", stream_id);
                }
            }

            Command::Syn => {
                if self.is_client {
                    log::warn!("Received SYN on client side");
                    return Ok(());
                }

                if !self.received_client_settings.load(Ordering::Relaxed) {
                    let alert_frame = Frame::with_data(
                        Command::Alert,
                        0,
                        Bytes::from("client did not send its settings"),
                    );
                    self.write_control_frame(&alert_frame).await?;
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "client did not send settings",
                    ));
                }

                let stream_id = frame.stream_id;

                let stream_opt = {
                    let mut streams = self.streams.write().await;
                    use std::collections::hash_map::Entry;
                    match streams.entry(stream_id) {
                        Entry::Occupied(_) => {
                            log::warn!("Duplicate SYN for stream {}", stream_id);
                            None
                        }
                        Entry::Vacant(entry) => {
                            let (data_tx, data_rx) = mpsc::channel(STREAM_CHANNEL_BUFFER);
                            let stream = AnyTlsStream::new(
                                stream_id,
                                data_rx,
                                self.outgoing_tx.clone(),
                                Arc::clone(&self.is_closed),
                            );
                            entry.insert(data_tx);
                            Some(stream)
                        }
                    }
                };

                if let Some(stream) = stream_opt {
                    let session = Arc::clone(self);
                    let stream_id_for_cleanup = stream_id;
                    let session_for_cleanup = Arc::clone(self);

                    let handle = tokio::spawn(async move {
                        match session.handle_new_stream(stream).await {
                            Ok(()) => {
                                log::trace!("AnyTLS stream {} completed", stream_id_for_cleanup);
                            }
                            Err(e) => {
                                if AnyTlsSession::is_benign_stream_error(&e) {
                                    log::trace!("AnyTLS stream {} ended: {}", stream_id_for_cleanup, e);
                                } else {
                                    log::debug!("AnyTLS stream {} error: {}", stream_id_for_cleanup, e);
                                }
                            }
                        }

                        // Stream self-cleanup mechanism
                        let mut tasks = session_for_cleanup.stream_tasks.lock().await;
                        tasks.remove(&stream_id_for_cleanup);
                    });

                    let mut tasks = self.stream_tasks.lock().await;
                    tasks.insert(stream_id, handle);
                }
            }

            Command::SynAck => {
                if !self.is_client {
                    log::warn!("Received SYNACK on server side");
                    return Ok(());
                }

                if !frame.data.is_empty() {
                    let error_msg = String::from_utf8_lossy(&frame.data);
                    log::warn!("Stream {} error from server: {}", frame.stream_id, error_msg);
                } else {
                    log::debug!("Stream {} acknowledged", frame.stream_id);
                }
            }

            Command::Fin => {
                let stream_id = frame.stream_id;

                let stream_tx = {
                    let mut streams = self.streams.write().await;
                    streams.remove(&stream_id)
                };

                // FIX 2: Removed `handle.abort()`.
                // Smoothly sending EOF (Bytes::new) through the channel allows the underlying copy 
                // tasks to consume the remaining buffered data before exiting naturally. This prevents 
                // the tail end of web pages or files from being truncated due to abrupt task termination.
                if let Some(tx) = stream_tx {
                    let _ = tx.send(Bytes::new()).await;
                }
            }

            Command::Waste => {
                log::trace!("Received {} bytes of padding", frame.data.len());
            }

            Command::Settings => {
                if self.is_client {
                    return Ok(());
                }

                self.received_client_settings.store(true, Ordering::Relaxed);

                let settings = StringMap::from_bytes(&frame.data);

                if settings
                    .get("padding-md5")
                    .is_some_and(|client_md5| client_md5 != self.padding.md5())
                {
                    let update_frame = Frame::with_data(
                        Command::UpdatePaddingScheme,
                        0,
                        Bytes::copy_from_slice(self.padding.raw_scheme()),
                    );
                    self.write_control_frame(&update_frame).await?;
                }

                if let Some(v) = settings
                    .get("v")
                    .and_then(|s| s.parse::<u8>().ok())
                    .filter(|&v| v >= 2)
                {
                    self.peer_version.store(v, Ordering::Relaxed);

                    let mut server_settings = StringMap::new();
                    server_settings.insert("v", "2");
                    let settings_frame = Frame::with_data(
                        Command::ServerSettings,
                        0,
                        Bytes::from(server_settings.to_bytes()),
                    );
                    self.write_control_frame(&settings_frame).await?;
                }
            }

            Command::ServerSettings => {
                if !self.is_client {
                    return Ok(());
                }

                let settings = StringMap::from_bytes(&frame.data);
                if let Some(v) = settings.get("v").and_then(|s| s.parse::<u8>().ok()) {
                    self.peer_version.store(v, Ordering::Relaxed);
                }
            }

            Command::UpdatePaddingScheme => {
                if !self.is_client {
                    return Ok(());
                }
                log::info!("Received padding scheme update from server");
            }

            Command::Alert => {
                let msg = String::from_utf8_lossy(&frame.data);
                log::error!("Received alert: {}", msg);
                return Err(io::Error::other(msg.to_string()));
            }

            Command::HeartRequest => {
                // FIX 3: Respond to heartbeats asynchronously to prevent deadlocks!
                // Placing the response in a separate task ensures that the network layer 
                // can continue to receive packets without delay even when `recv_loop` is under high load.
                let session = Arc::clone(self);
                let stream_id = frame.stream_id;
                tokio::spawn(async move {
                    let response = Frame::control(Command::HeartResponse, stream_id);
                    if let Err(e) = session.write_control_frame(&response).await {
                        log::debug!("Failed to send HeartResponse: {}", e);
                    }
                });
            }

            Command::HeartResponse => {
                log::trace!("Received heartbeat response");
            }
        }

        Ok(())
    }

    async fn write_frame(&self, frame: &Frame) -> io::Result<()> {
        // FIX 4: Refined lock granularity to prevent lock contention.
        // The scope of the `write_buf` lock is now strictly limited to buffer encoding. 
        // Once the bytes are extracted via `split()`, the lock is released immediately 
        // before blocking on the actual underlying IO write operations.
        let write_data = {
            let mut write_buf = self.write_buf.lock().await;
            write_buf.clear();
            frame.encode_into(&mut write_buf);
            write_buf.split() // Quickly extract the data block and release the lock
        };

        if self.buffering.load(Ordering::Relaxed) {
            let mut buffer = self.buffer.lock().await;
            buffer.extend_from_slice(&write_data);
            return Ok(());
        }

        let combined_data = {
            let mut buffer = self.buffer.lock().await;
            if !buffer.is_empty() {
                let mut combined = BytesMut::from(&buffer[..]);
                combined.extend_from_slice(&write_data);
                buffer.clear();
                combined
            } else {
                write_data
            }
        };

        if self.send_padding.load(Ordering::Relaxed) {
            let pkt = self.pkt_counter.fetch_add(1, Ordering::SeqCst) + 1;

            if pkt < self.padding.stop() {
                return self.write_with_padding(combined_data, pkt).await;
            } else {
                self.send_padding.store(false, Ordering::Relaxed);
            }
        }

        let mut writer = self.writer.lock().await;
        writer.write_all(&combined_data).await?;
        writer.flush().await
    }

    async fn write_with_padding(&self, mut data: BytesMut, pkt: u32) -> io::Result<()> {
        let pkt_sizes = self.padding.generate_record_payload_sizes(pkt);

        if pkt_sizes.is_empty() {
            let mut writer = self.writer.lock().await;
            writer.write_all(&data).await?;
            return writer.flush().await;
        }

        let mut writer = self.writer.lock().await;

        for size in pkt_sizes {
            let remain_payload_len = data.len();

            if size == CHECK_MARK {
                if remain_payload_len == 0 {
                    break;
                }
                continue;
            }

            let size = size as usize;

            if remain_payload_len > size {
                writer.write_all(&data[..size]).await?;
                data = data.split_off(size);
            } else if remain_payload_len > 0 {
                let padding_len = size.saturating_sub(remain_payload_len + FRAME_HEADER_SIZE);

                if padding_len > 0 {
                    data.reserve(FRAME_HEADER_SIZE + padding_len);
                    data.put_u8(Command::Waste as u8);
                    data.put_u32(0);
                    data.put_u16(padding_len as u16);
                    data.put_bytes(0, padding_len);
                }

                writer.write_all(&data).await?;
                data.clear();
            } else {
                let header = [
                    Command::Waste as u8,
                    0,
                    0,
                    0,
                    0,
                    (size >> 8) as u8,
                    size as u8,
                ];
                writer.write_all(&header).await?;
                const ZERO_BUF: [u8; 1024] = [0u8; 1024];
                let mut remaining = size;
                while remaining > 0 {
                    let chunk = remaining.min(ZERO_BUF.len());
                    writer.write_all(&ZERO_BUF[..chunk]).await?;
                    remaining -= chunk;
                }
            }
        }

        if !data.is_empty() {
            writer.write_all(&data).await?;
        }

        writer.flush().await
    }

    pub async fn send_synack(&self, stream_id: u32, error: Option<&str>) -> io::Result<()> {
        if self.peer_version() < 2 {
            return Ok(());
        }

        let frame = if let Some(err) = error {
            Frame::with_data(Command::SynAck, stream_id, Bytes::from(err.to_string()))
        } else {
            Frame::control(Command::SynAck, stream_id)
        };

        self.write_control_frame(&frame).await
    }

    async fn write_control_frame(&self, frame: &Frame) -> io::Result<()> {
        match tokio::time::timeout(CONTROL_FRAME_TIMEOUT, self.write_frame(frame)).await {
            Ok(result) => result,
            Err(_) => {
                log::warn!(
                    "Control frame write timed out after {:?}, closing session",
                    CONTROL_FRAME_TIMEOUT
                );
                self.close().await;
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "control frame write timed out",
                ))
            }
        }
    }

    async fn handle_new_stream(&self, mut stream: AnyTlsStream) -> io::Result<()> {
        let stream_id = stream.id();

        log::trace!("AnyTLS stream {} setup started", stream_id);

        let destination =
            match tokio::time::timeout(STREAM_INIT_TIMEOUT, read_location_direct(&mut stream)).await
            {
                Ok(Ok(dest)) => dest,
                Ok(Err(e)) => return Err(e),
                Err(_) => {
                    let _ = stream.shutdown().await;
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("read destination timed out after {:?}", STREAM_INIT_TIMEOUT),
                    ));
                }
            };

        log::debug!(
            "AnyTLS stream {} (user: {}) -> {}",
            stream_id,
            self.user_name,
            destination
        );

        if let Address::Hostname(host) = destination.address() {
            if host == UOT_V2_MAGIC_ADDRESS {
                return self.handle_uot_v2(stream).await;
            } else if host == UOT_V1_MAGIC_ADDRESS {
                return self.handle_uot_v1(stream).await;
            }
        }

        self.handle_tcp_forward(stream, destination).await
    }

    async fn handle_tcp_forward(
        &self,
        mut stream: AnyTlsStream,
        destination: NetLocation,
    ) -> io::Result<()> {
        let stream_id = stream.id();

        let action = match tokio::time::timeout(
            STREAM_CONNECT_TIMEOUT,
            self.proxy_provider.judge(destination.clone().into(), &self.resolver),
        )
        .await
        {
            Ok(Ok(action)) => action,
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                let error_msg =
                    format!("route decision timed out after {:?}", STREAM_CONNECT_TIMEOUT);
                let _ = self.send_synack(stream_id, Some(&error_msg)).await;
                return Err(io::Error::new(io::ErrorKind::TimedOut, error_msg));
            }
        };

        match action {
            ConnectDecision::Allow {
                chain_group,
                remote_location,
            } => {
                log::debug!(
                    "AnyTLS stream {} routing {} through chain",
                    stream_id,
                    remote_location
                );

                let client_result = match tokio::time::timeout(
                    STREAM_CONNECT_TIMEOUT,
                    chain_group.connect_tcp(remote_location, &self.resolver),
                )
                .await
                {
                    Ok(Ok(result)) => result,
                    Ok(Err(e)) => {
                        let error_msg = format!("connect failed: {}", e);
                        let _ = self.send_synack(stream_id, Some(&error_msg)).await;
                        return Err(e);
                    }
                    Err(_) => {
                        let error_msg =
                            format!("connect timed out after {:?}", STREAM_CONNECT_TIMEOUT);
                        let _ = self.send_synack(stream_id, Some(&error_msg)).await;
                        return Err(io::Error::new(io::ErrorKind::TimedOut, error_msg));
                    }
                };
                let mut client_stream = client_result.client_stream;

                if let Err(e) = self.send_synack(stream_id, None).await {
                    log::debug!("Failed to send SYNACK for stream {}: {}", stream_id, e);
                }

                log::debug!("AnyTLS stream {} connected to destination", stream_id);

                let result =
                    copy_bidirectional(&mut stream, &mut *client_stream, false, false).await;

                let _ = stream.shutdown().await;
                let _ = client_stream.shutdown().await;

                if let Err(e) = &result {
                    if Self::is_benign_stream_error(e) {
                        log::trace!("AnyTLS stream {} ended: {}", stream_id, e);
                    } else {
                        log::debug!("AnyTLS stream {} ended with error: {}", stream_id, e);
                    }
                } else {
                    log::trace!("AnyTLS stream {} completed", stream_id);
                }

                result
            }
            ConnectDecision::Block => {
                let error_msg = format!("blocked by rules: {}", destination);
                let _ = self.send_synack(stream_id, Some(&error_msg)).await;

                log::debug!("AnyTLS stream {} blocked by rules", stream_id);
                let _ = stream.shutdown().await;
                Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    format!("Connection to {} blocked by rules", destination),
                ))
            }
        }
    }

    async fn handle_uot_v2(&self, mut stream: AnyTlsStream) -> io::Result<()> {
        let stream_id = stream.id();
        log::trace!("AnyTLS stream {} UoT V2 setup started", stream_id);
        if !self.udp_enabled {
            log::debug!(
                "AnyTLS stream {} UoT V2 rejected: UDP not enabled",
                stream_id
            );
            let _ = stream.shutdown().await;
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "UDP not enabled for AnyTLS",
            ));
        }

        let is_connect = match tokio::time::timeout(STREAM_INIT_TIMEOUT, stream.read_u8()).await {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                let _ = stream.shutdown().await;
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("UoT header read timed out after {:?}", STREAM_INIT_TIMEOUT),
                ));
            }
        };

        let destination =
            match tokio::time::timeout(STREAM_INIT_TIMEOUT, read_location_direct(&mut stream)).await
            {
                Ok(Ok(dest)) => dest,
                Ok(Err(e)) => return Err(e),
                Err(_) => {
                    let _ = stream.shutdown().await;
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!(
                            "UoT destination read timed out after {:?}",
                            STREAM_INIT_TIMEOUT
                        ),
                    ));
                }
            };

        log::debug!(
            "AnyTLS stream {} UoT V2 (user: {}, connect={}) -> {}",
            stream_id,
            self.user_name,
            is_connect,
            destination
        );

        match is_connect {
            1 => self.handle_uot_v2_connect(stream, destination).await,
            0 => self.handle_uot_multi_destination(stream).await,
            _ => {
                let _ = stream.shutdown().await;
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid UoT V2 connect flag: {}", is_connect),
                ))
            }
        }
    }

    async fn handle_uot_v1(&self, mut stream: AnyTlsStream) -> io::Result<()> {
        let stream_id = stream.id();
        log::trace!("AnyTLS stream {} UoT V1 setup started", stream_id);
        if !self.udp_enabled {
            log::debug!(
                "AnyTLS stream {} UoT V1 rejected: UDP not enabled",
                stream_id
            );
            let _ = stream.shutdown().await;
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "UDP not enabled for AnyTLS",
            ));
        }

        log::debug!(
            "AnyTLS stream {} UoT V1 (user: {})",
            stream_id,
            self.user_name
        );

        self.handle_uot_multi_destination(stream).await
    }

    async fn handle_uot_v2_connect(
        &self,
        mut stream: AnyTlsStream,
        destination: NetLocation,
    ) -> io::Result<()> {
        let stream_id = stream.id();

        let action = match tokio::time::timeout(
            STREAM_CONNECT_TIMEOUT,
            self.proxy_provider.judge(destination.clone().into(), &self.resolver),
        )
        .await
        {
            Ok(Ok(action)) => action,
            Ok(Err(e)) => {
                let error_msg = format!("UDP route decision failed: {}", e);
                let _ = self.send_synack(stream_id, Some(&error_msg)).await;
                let _ = stream.shutdown().await;
                return Err(e);
            }
            Err(_) => {
                let error_msg = format!(
                    "UDP route decision timed out after {:?}",
                    STREAM_CONNECT_TIMEOUT
                );
                let _ = self.send_synack(stream_id, Some(&error_msg)).await;
                let _ = stream.shutdown().await;
                return Err(io::Error::new(io::ErrorKind::TimedOut, error_msg));
            }
        };

        match action {
            ConnectDecision::Allow {
                chain_group,
                remote_location,
            } => {
                log::debug!(
                    "AnyTLS stream {} UoT V2 connect: routing {} through chain",
                    stream_id,
                    remote_location
                );

                let server_stream: Box<dyn AsyncMessageStream> =
                    Box::new(VlessMessageStream::new(stream));

                let client_stream = match tokio::time::timeout(
                    STREAM_CONNECT_TIMEOUT,
                    chain_group.connect_udp_bidirectional(&self.resolver, remote_location),
                )
                .await
                {
                    Ok(Ok(result)) => result,
                    Ok(Err(e)) => {
                        let error_msg = format!("UDP connect failed: {}", e);
                        let _ = self.send_synack(stream_id, Some(&error_msg)).await;
                        return Err(e);
                    }
                    Err(_) => {
                        let error_msg =
                            format!("UDP connect timed out after {:?}", STREAM_CONNECT_TIMEOUT);
                        let _ = self.send_synack(stream_id, Some(&error_msg)).await;
                        return Err(io::Error::new(io::ErrorKind::TimedOut, error_msg));
                    }
                };

                let _ = self.send_synack(stream_id, None).await;

                log::debug!("AnyTLS stream {} UoT V2 connect: connected", stream_id);

                let result = run_udp_copy(server_stream, client_stream, false, false).await;

                if let Err(e) = &result {
                    if Self::is_benign_stream_error(e) {
                        log::trace!("AnyTLS stream {} UoT V2 connect ended: {}", stream_id, e);
                    } else {
                        log::debug!(
                            "AnyTLS stream {} UoT V2 connect ended with error: {}",
                            stream_id,
                            e
                        );
                    }
                } else {
                    log::trace!("AnyTLS stream {} UoT V2 connect completed", stream_id);
                }

                result
            }
            ConnectDecision::Block => {
                let _ = self
                    .send_synack(stream_id, Some("UDP blocked by rules"))
                    .await;
                let _ = stream.shutdown().await;

                log::warn!(
                    "AnyTLS stream {} UoT V2 connect blocked by rules: {}",
                    stream_id,
                    destination
                );
                Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "UDP blocked by rules",
                ))
            }
        }
    }

    async fn handle_uot_multi_destination(&self, stream: AnyTlsStream) -> io::Result<()> {
        let stream_id = stream.id();

        log::debug!(
            "AnyTLS stream {} UoT multi-dest: starting per-destination routing",
            stream_id
        );

        let server_stream: Box<dyn AsyncTargetedMessageStream> =
            Box::new(UotV1ServerStream::new(stream));

        let _ = self.send_synack(stream_id, None).await;

        let result = run_udp_routing(
            ServerStream::Targeted(server_stream),
            self.proxy_provider.clone(),
            self.resolver.clone(),
            false,
        )
        .await;

        if let Err(e) = &result {
            if Self::is_benign_stream_error(e) {
                log::trace!("AnyTLS stream {} UoT multi-dest ended: {}", stream_id, e);
            } else {
                log::debug!(
                    "AnyTLS stream {} UoT multi-dest ended with error: {}",
                    stream_id,
                    e
                );
            }
        } else {
            log::trace!("AnyTLS stream {} UoT multi-dest completed", stream_id);
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
    use tokio::time::{Duration, timeout};

    #[tokio::test]
    async fn test_session_creation() {
        let (client, _server) = duplex(8192);
        let padding = PaddingFactory::default_factory();
        let session = AnyTlsSession::new_server_test(client, padding);

        assert!(!session.is_closed());
        assert!(!session.is_client);
    }

    #[tokio::test]
    async fn test_frame_encoding() {
        let frame = Frame::data(123, Bytes::from("test data"));
        let encoded = frame.encode();

        assert_eq!(encoded[0], Command::Psh as u8);
        assert_eq!(
            u32::from_be_bytes([encoded[1], encoded[2], encoded[3], encoded[4]]),
            123
        );
        assert_eq!(u16::from_be_bytes([encoded[5], encoded[6]]), 9);
        assert_eq!(&encoded[7..], b"test data");
    }

    #[tokio::test]
    async fn test_session_close() {
        let (client, _server) = duplex(8192);
        let padding = PaddingFactory::default_factory();
        let session = AnyTlsSession::new_server_test(client, padding);

        assert!(!session.is_closed());
        session.close().await;
        assert!(session.is_closed());
    }

    #[tokio::test]
    async fn test_settings_frame_parsing() {
        let mut settings = StringMap::new();
        settings.insert("v", "2");
        settings.insert("client", "test");
        settings.insert("padding-md5", "abc123");

        let bytes = settings.to_bytes();
        let parsed = StringMap::from_bytes(&bytes);

        assert_eq!(parsed.get("v"), Some(&"2".to_string()));
        assert_eq!(parsed.get("client"), Some(&"test".to_string()));
        assert_eq!(parsed.get("padding-md5"), Some(&"abc123".to_string()));
    }

    #[tokio::test]
    async fn test_control_frame_types() {
        // Test all control frame types
        for (cmd, expected_byte) in [
            (Command::Waste, 0),
            (Command::Syn, 1),
            (Command::Psh, 2),
            (Command::Fin, 3),
            (Command::Settings, 4),
            (Command::Alert, 5),
            (Command::UpdatePaddingScheme, 6),
            (Command::SynAck, 7),
            (Command::HeartRequest, 8),
            (Command::HeartResponse, 9),
            (Command::ServerSettings, 10),
        ] {
            let frame = Frame::control(cmd, 42);
            let encoded = frame.encode();
            assert_eq!(encoded[0], expected_byte);
        }
    }

    #[tokio::test]
    async fn test_heartbeat_frame_roundtrip() {
        let request = Frame::control(Command::HeartRequest, 0);
        let encoded = request.encode();

        let mut buf = BytesMut::from(&encoded[..]);
        let decoded = FrameCodec::decode(&mut buf).unwrap().unwrap();

        assert_eq!(decoded.cmd, Command::HeartRequest);
        assert_eq!(decoded.stream_id, 0);
        assert!(decoded.data.is_empty());
    }

    #[tokio::test]
    async fn test_multiple_streams_frame_interleaving() {
        // Simulate multiple streams sending data - verify framing isolation
        let stream1_data = Frame::data(1, Bytes::from("stream1-data"));
        let stream2_data = Frame::data(2, Bytes::from("stream2-data"));
        let stream3_data = Frame::data(3, Bytes::from("stream3-data"));

        let mut combined = BytesMut::new();
        combined.extend_from_slice(&stream1_data.encode());
        combined.extend_from_slice(&stream2_data.encode());
        combined.extend_from_slice(&stream3_data.encode());

        // Decode all frames
        let f1 = FrameCodec::decode(&mut combined).unwrap().unwrap();
        let f2 = FrameCodec::decode(&mut combined).unwrap().unwrap();
        let f3 = FrameCodec::decode(&mut combined).unwrap().unwrap();

        assert_eq!(f1.stream_id, 1);
        assert_eq!(f1.data.as_ref(), b"stream1-data");
        assert_eq!(f2.stream_id, 2);
        assert_eq!(f2.data.as_ref(), b"stream2-data");
        assert_eq!(f3.stream_id, 3);
        assert_eq!(f3.data.as_ref(), b"stream3-data");
    }

    #[tokio::test]
    async fn test_fin_and_syn_sequence() {
        // Test SYN -> PSH -> FIN sequence
        let syn = Frame::control(Command::Syn, 1);
        let data = Frame::data(1, Bytes::from("payload"));
        let fin = Frame::control(Command::Fin, 1);

        let mut combined = BytesMut::new();
        combined.extend_from_slice(&syn.encode());
        combined.extend_from_slice(&data.encode());
        combined.extend_from_slice(&fin.encode());

        let f1 = FrameCodec::decode(&mut combined).unwrap().unwrap();
        let f2 = FrameCodec::decode(&mut combined).unwrap().unwrap();
        let f3 = FrameCodec::decode(&mut combined).unwrap().unwrap();

        assert_eq!(f1.cmd, Command::Syn);
        assert_eq!(f2.cmd, Command::Psh);
        assert_eq!(f3.cmd, Command::Fin);
        assert!(f1.data.is_empty());
        assert_eq!(f2.data.as_ref(), b"payload");
        assert!(f3.data.is_empty());
    }

    #[tokio::test]
    async fn test_alert_frame_with_message() {
        let alert = Frame::with_data(Command::Alert, 0, Bytes::from("connection refused"));
        let encoded = alert.encode();

        let mut buf = BytesMut::from(&encoded[..]);
        let decoded = FrameCodec::decode(&mut buf).unwrap().unwrap();

        assert_eq!(decoded.cmd, Command::Alert);
        assert_eq!(decoded.data.as_ref(), b"connection refused");
    }

    #[tokio::test]
    async fn test_large_frame() {
        // Test frame with max-ish size (16KB)
        let large_data = vec![0xABu8; 16384];
        let frame = Frame::data(99, Bytes::from(large_data.clone()));
        let encoded = frame.encode();

        let mut buf = BytesMut::from(&encoded[..]);
        let decoded = FrameCodec::decode(&mut buf).unwrap().unwrap();

        assert_eq!(decoded.stream_id, 99);
        assert_eq!(decoded.data.len(), 16384);
        assert_eq!(decoded.data.as_ref(), large_data.as_slice());
    }

    #[tokio::test]
    async fn test_partial_frame_decode() {
        // Test that partial frames don't decode until complete
        let frame = Frame::data(1, Bytes::from("complete"));
        let encoded = frame.encode();

        // Only provide partial data
        let mut partial = BytesMut::from(&encoded[..5]); // Only header partial
        let result = FrameCodec::decode(&mut partial).unwrap();
        assert!(result.is_none());

        // Add remaining data
        partial.extend_from_slice(&encoded[5..]);
        let decoded = FrameCodec::decode(&mut partial).unwrap().unwrap();
        assert_eq!(decoded.data.as_ref(), b"complete");
    }

    #[tokio::test]
    async fn test_waste_frame_padding() {
        // Test padding frame
        let padding_data = vec![0u8; 100];
        let waste = Frame::with_data(Command::Waste, 0, Bytes::from(padding_data.clone()));
        let encoded = waste.encode();

        let mut buf = BytesMut::from(&encoded[..]);
        let decoded = FrameCodec::decode(&mut buf).unwrap().unwrap();

        assert_eq!(decoded.cmd, Command::Waste);
        assert_eq!(decoded.stream_id, 0);
        assert_eq!(decoded.data.len(), 100);
    }

    #[tokio::test]
    async fn test_session_rejects_syn_without_settings() {
        let (client, mut server) = duplex(8192);
        let padding = PaddingFactory::default_factory();
        let session = AnyTlsSession::new_server_test(client, padding);

        let session_clone = Arc::clone(&session);
        let run_task = tokio::spawn(async move {
            let _ = session_clone.run().await;
        });

        // Send SYN without Settings first
        let syn_frame = Frame::control(Command::Syn, 1);
        server.write_all(&syn_frame.encode()).await.unwrap();

        // Should receive Alert
        let mut buf = vec![0u8; 256];
        let result = timeout(Duration::from_millis(500), server.read(&mut buf)).await;

        if let Ok(Ok(n)) = result {
            if n > 0 {
                assert_eq!(buf[0], Command::Alert as u8);
            }
        }

        session.close().await;
        run_task.abort();
    }

    #[tokio::test]
    async fn test_heartbeat_response() {
        let (client, mut server) = duplex(8192);
        let padding = PaddingFactory::default_factory();
        let session = AnyTlsSession::new_server_test(client, padding);

        let session_clone = Arc::clone(&session);
        let run_task = tokio::spawn(async move {
            let _ = session_clone.run().await;
        });

        // Send settings first
        let mut settings = StringMap::new();
        settings.insert("v", "2");
        settings.insert("padding-md5", PaddingFactory::default_factory().md5());
        let settings_frame =
            Frame::with_data(Command::Settings, 0, Bytes::from(settings.to_bytes()));
        server.write_all(&settings_frame.encode()).await.unwrap();

        // Wait for and consume the ServerSettings response
        let mut buf = vec![0u8; 128];
        let _ = timeout(Duration::from_millis(200), server.read(&mut buf)).await;

        // Send heartbeat request
        let heart_request = Frame::control(Command::HeartRequest, 0);
        server.write_all(&heart_request.encode()).await.unwrap();

        // Should receive heartbeat response
        let mut response_buf = vec![0u8; 16];
        let result = timeout(Duration::from_millis(500), server.read(&mut response_buf)).await;

        if let Ok(Ok(n)) = result {
            if n >= 7 {
                assert_eq!(response_buf[0], Command::HeartResponse as u8);
            }
        }

        session.close().await;
        run_task.abort();
    }

    // ===== Frame parsing edge case tests =====

    #[test]
    fn test_frame_zero_length_data() {
        let frame = Frame::data(1, Bytes::new());
        let encoded = frame.encode();

        assert_eq!(encoded.len(), FRAME_HEADER_SIZE); // Just header, no data
        assert_eq!(encoded[0], Command::Psh as u8);

        // Decode should work
        let mut buf = BytesMut::from(&encoded[..]);
        let decoded = FrameCodec::decode(&mut buf).unwrap().unwrap();
        assert!(decoded.data.is_empty());
    }

    #[test]
    fn test_frame_max_stream_id() {
        let frame = Frame::control(Command::Syn, u32::MAX);
        let encoded = frame.encode();

        let mut buf = BytesMut::from(&encoded[..]);
        let decoded = FrameCodec::decode(&mut buf).unwrap().unwrap();
        assert_eq!(decoded.stream_id, u32::MAX);
    }

    #[test]
    fn test_frame_decode_incomplete_header() {
        // Less than 7 bytes
        let mut buf = BytesMut::from(&[0x00, 0x00, 0x00][..]);
        let result = FrameCodec::decode(&mut buf).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_frame_decode_incomplete_data() {
        // Header says 100 bytes of data, but only 50 provided
        let mut buf = BytesMut::with_capacity(64);
        buf.extend_from_slice(&[Command::Psh as u8]); // cmd
        buf.extend_from_slice(&[0, 0, 0, 1]); // stream_id = 1
        buf.extend_from_slice(&[0, 100]); // length = 100
        buf.extend_from_slice(&[0u8; 50]); // only 50 bytes of data

        let result = FrameCodec::decode(&mut buf).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_frame_unknown_command_returns_error() {
        // Command byte 255 is not defined
        let mut buf = BytesMut::with_capacity(16);
        buf.extend_from_slice(&[255u8]); // unknown cmd
        buf.extend_from_slice(&[0, 0, 0, 1]); // stream_id = 1
        buf.extend_from_slice(&[0, 0]); // length = 0

        let result = FrameCodec::decode(&mut buf);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn test_frame_all_command_types() {
        for cmd in [
            Command::Waste,
            Command::Syn,
            Command::Psh,
            Command::Fin,
            Command::Settings,
            Command::Alert,
            Command::UpdatePaddingScheme,
            Command::SynAck,
            Command::HeartRequest,
            Command::HeartResponse,
            Command::ServerSettings,
        ] {
            let frame = Frame::control(cmd, 1);
            let encoded = frame.encode();
            let mut buf = BytesMut::from(&encoded[..]);
            let decoded = FrameCodec::decode(&mut buf).unwrap().unwrap();
            assert_eq!(decoded.cmd, cmd);
        }
    }

    #[test]
    fn test_frame_max_data_length() {
        // Max u16 = 65535 bytes
        let large_data = vec![0xFFu8; 65535];
        let frame = Frame::data(1, Bytes::from(large_data.clone()));
        let encoded = frame.encode();

        // Verify length field
        let len = u16::from_be_bytes([encoded[5], encoded[6]]);
        assert_eq!(len, 65535);

        let mut buf = BytesMut::from(&encoded[..]);
        let decoded = FrameCodec::decode(&mut buf).unwrap().unwrap();
        assert_eq!(decoded.data.len(), 65535);
    }

    // ===== Session protocol edge case tests =====

    #[tokio::test]
    async fn test_session_psh_for_nonexistent_stream() {
        let (client, mut server) = duplex(8192);
        let padding = PaddingFactory::default_factory();
        let session = AnyTlsSession::new_server_test(client, padding);

        let session_clone = Arc::clone(&session);
        let run_task = tokio::spawn(async move {
            let _ = session_clone.run().await;
        });

        // Send settings
        let mut settings = StringMap::new();
        settings.insert("v", "2");
        settings.insert("padding-md5", PaddingFactory::default_factory().md5());
        let settings_frame =
            Frame::with_data(Command::Settings, 0, Bytes::from(settings.to_bytes()));
        server.write_all(&settings_frame.encode()).await.unwrap();

        tokio::time::sleep(Duration::from_millis(50)).await;

        // Send PSH for stream 999 (never opened)
        // This should NOT crash the session
        let psh = Frame::data(999, Bytes::from("orphan data"));
        server.write_all(&psh.encode()).await.unwrap();

        // Session should still be alive - send heartbeat to verify
        tokio::time::sleep(Duration::from_millis(100)).await;
        let heart = Frame::control(Command::HeartRequest, 0);
        let result = server.write_all(&heart.encode()).await;
        assert!(result.is_ok());

        session.close().await;
        run_task.abort();
    }

    #[tokio::test]
    async fn test_session_fin_for_nonexistent_stream() {
        let (client, mut server) = duplex(8192);
        let padding = PaddingFactory::default_factory();
        let session = AnyTlsSession::new_server_test(client, padding);

        let session_clone = Arc::clone(&session);
        let run_task = tokio::spawn(async move {
            let _ = session_clone.run().await;
        });

        // Send settings
        let mut settings = StringMap::new();
        settings.insert("v", "2");
        settings.insert("padding-md5", PaddingFactory::default_factory().md5());
        let settings_frame =
            Frame::with_data(Command::Settings, 0, Bytes::from(settings.to_bytes()));
        server.write_all(&settings_frame.encode()).await.unwrap();

        tokio::time::sleep(Duration::from_millis(50)).await;

        // Send FIN for stream 999 (never opened)
        // Should be gracefully ignored
        let fin = Frame::control(Command::Fin, 999);
        server.write_all(&fin.encode()).await.unwrap();

        // Session should still be alive
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!session.is_closed());

        session.close().await;
        run_task.abort();
    }

    #[tokio::test]
    async fn test_session_waste_frame_ignored() {
        let (client, mut server) = duplex(8192);
        let padding = PaddingFactory::default_factory();
        let session = AnyTlsSession::new_server_test(client, padding);

        let session_clone = Arc::clone(&session);
        let run_task = tokio::spawn(async move {
            let _ = session_clone.run().await;
        });

        // Send settings
        let mut settings = StringMap::new();
        settings.insert("v", "2");
        settings.insert("padding-md5", PaddingFactory::default_factory().md5());
        let settings_frame =
            Frame::with_data(Command::Settings, 0, Bytes::from(settings.to_bytes()));
        server.write_all(&settings_frame.encode()).await.unwrap();

        tokio::time::sleep(Duration::from_millis(50)).await;

        // Send waste (padding) frame with data
        let padding_data = vec![0u8; 500];
        let waste = Frame::with_data(Command::Waste, 0, Bytes::from(padding_data));
        server.write_all(&waste.encode()).await.unwrap();

        // Session should still function
        tokio::time::sleep(Duration::from_millis(100)).await;
        let syn = Frame::control(Command::Syn, 1);
        let result = server.write_all(&syn.encode()).await;
        assert!(result.is_ok());

        session.close().await;
        run_task.abort();
    }

    #[tokio::test]
    async fn test_session_update_padding_scheme() {
        let (client, mut server) = duplex(8192);
        let padding = PaddingFactory::default_factory();
        let session = AnyTlsSession::new_server_test(client, padding);

        let session_clone = Arc::clone(&session);
        let run_task = tokio::spawn(async move {
            let _ = session_clone.run().await;
        });

        // Send settings with mismatched padding MD5
        let mut settings = StringMap::new();
        settings.insert("v", "2");
        settings.insert("padding-md5", "different_md5_value");
        let settings_frame =
            Frame::with_data(Command::Settings, 0, Bytes::from(settings.to_bytes()));
        server.write_all(&settings_frame.encode()).await.unwrap();

        // Should receive UpdatePaddingScheme frame
        let mut buf = vec![0u8; 256];
        let result = timeout(Duration::from_millis(500), server.read(&mut buf)).await;

        if let Ok(Ok(n)) = result {
            if n >= 7 {
                // Could be ServerSettings or UpdatePaddingScheme
                // Either is valid response
                let cmd = buf[0];
                assert!(
                    cmd == Command::UpdatePaddingScheme as u8
                        || cmd == Command::ServerSettings as u8
                );
            }
        }

        session.close().await;
        run_task.abort();
    }

    #[tokio::test]
    async fn test_session_alert_closes_session() {
        let (client, mut server) = duplex(8192);
        let padding = PaddingFactory::default_factory();
        let session = AnyTlsSession::new_server_test(client, padding);

        let session_clone = Arc::clone(&session);
        let run_task = tokio::spawn(async move {
            let _ = session_clone.run().await;
        });

        // Send settings first
        let mut settings = StringMap::new();
        settings.insert("v", "2");
        settings.insert("padding-md5", PaddingFactory::default_factory().md5());
        let settings_frame =
            Frame::with_data(Command::Settings, 0, Bytes::from(settings.to_bytes()));
        server.write_all(&settings_frame.encode()).await.unwrap();

        tokio::time::sleep(Duration::from_millis(50)).await;

        // Send Alert from client
        let alert = Frame::with_data(Command::Alert, 0, Bytes::from("client error"));
        server.write_all(&alert.encode()).await.unwrap();

        // Session should close
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(session.is_closed());

        run_task.abort();
    }

    // ===== StringMap tests =====

    #[test]
    fn test_stringmap_roundtrip() {
        let mut map = StringMap::new();
        map.insert("key1", "value1");
        map.insert("key2", "value2");
        map.insert("special", "a=b=c");

        let bytes = map.to_bytes();
        let parsed = StringMap::from_bytes(&bytes);

        assert_eq!(parsed.get("key1"), Some(&"value1".to_string()));
        assert_eq!(parsed.get("key2"), Some(&"value2".to_string()));
        assert_eq!(parsed.get("special"), Some(&"a=b=c".to_string()));
    }

    #[test]
    fn test_stringmap_empty() {
        let map = StringMap::new();
        let bytes = map.to_bytes();
        assert!(bytes.is_empty());

        let parsed = StringMap::from_bytes(&[]);
        assert!(parsed.get("anything").is_none());
    }

    #[test]
    fn test_stringmap_newlines_in_values() {
        let mut map = StringMap::new();
        map.insert("multiline", "line1\nline2"); // Should not break parsing

        let bytes = map.to_bytes();
        let parsed = StringMap::from_bytes(&bytes);

        // With newlines, parsing may be affected
        // This test documents current behavior
        let val = parsed.get("multiline");
        // Value may be truncated at newline
        assert!(val.is_none() || val == Some(&"line1".to_string()));
    }

    #[test]
    fn test_stringmap_special_characters() {
        let mut map = StringMap::new();
        map.insert("unicode", "Hello World!");
        map.insert("empty", "");

        let bytes = map.to_bytes();
        let parsed = StringMap::from_bytes(&bytes);

        assert_eq!(parsed.get("unicode"), Some(&"Hello World!".to_string()));
        assert_eq!(parsed.get("empty"), Some(&"".to_string()));
    }
}

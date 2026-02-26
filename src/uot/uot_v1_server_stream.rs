//! UDP-over-TCP V1 server stream implementation
//!
//! V1 packet format (each packet carries its destination address):
//! ```text
//! | ATYP | address  | port  | length | data     |
//! | u8   | variable | u16be | u16be  | variable |
//! ```
//!
//! The address portion uses the AddrParser format defined by sing-box UoT:
//! - 0x00: IPv4
//! - 0x01: IPv6
//! - 0x02: Domain

use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::ready;
use tokio::io::ReadBuf;

use super::uot_common::{parse_uot_addrparser_address, write_uot_addrparser_address};
use crate::address::NetLocation;
use crate::async_stream::{
    AsyncFlushMessage, AsyncPing, AsyncReadTargetedMessage, AsyncShutdownMessage, AsyncStream,
    AsyncTargetedMessageStream, AsyncWriteSourcedMessage,
};
use crate::slide_buffer::SlideBuffer;
use crate::util::allocate_vec;

/// Maximum UDP payload size plus framing overhead safety margin.
const BUFFER_SIZE: usize = 65535;

/// UoT V1 server stream for multi-destination UDP packets.
///
/// Each packet contains:
/// - destination address (AddrParser format)
/// - payload length (u16be)
/// - payload bytes
///
/// This wrapper converts a byte-stream transport into targeted UDP-style messages.
pub struct UotV1ServerStream<S> {
    stream: S,

    /// Read buffer that accumulates raw bytes until a full UoT packet is available.
    read_buf: SlideBuffer,

    /// Write buffer for one full encoded packet.
    write_buf: Box<[u8]>,
    write_buf_len: usize,
    write_buf_sent: usize,

    is_eof: bool,
}

impl<S: AsyncStream> UotV1ServerStream<S> {
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            read_buf: SlideBuffer::new(BUFFER_SIZE),
            write_buf: allocate_vec(BUFFER_SIZE).into_boxed_slice(),
            write_buf_len: 0,
            write_buf_sent: 0,
            is_eof: false,
        }
    }

    /// Feed bytes that were already read from the underlying stream before this wrapper
    /// was constructed.
    pub fn feed_initial_data(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }

        let len = data.len().min(self.read_buf.remaining_capacity());
        self.read_buf.extend_from_slice(&data[..len]);
    }

    /// Try to parse one complete UoT packet from the current read buffer.
    ///
    /// Returns:
    /// - `Ok(Some((location, payload_start, payload_len)))` if a full packet is available
    /// - `Ok(None)` if more bytes are needed
    /// - `Err(...)` if the buffered bytes are malformed
    #[inline]
    fn try_parse_packet(&self) -> std::io::Result<Option<(NetLocation, usize, usize)>> {
        let data = self.read_buf.as_slice();

        let (location, addr_len) = match parse_uot_addrparser_address(data)? {
            Some(result) => result,
            None => return Ok(None),
        };

        // Need length field after address
        if data.len() < addr_len + 2 {
            return Ok(None);
        }

        let payload_len = u16::from_be_bytes([data[addr_len], data[addr_len + 1]]) as usize;
        let payload_start = addr_len + 2;
        let total_len = payload_start + payload_len;

        if data.len() < total_len {
            return Ok(None);
        }

        Ok(Some((location, payload_start, payload_len)))
    }
}

impl<S: AsyncStream> AsyncReadTargetedMessage for UotV1ServerStream<S> {
    fn poll_read_targeted_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<NetLocation>> {
        let this = self.get_mut();

        if this.is_eof {
            return Poll::Ready(Ok(NetLocation::UNSPECIFIED));
        }

        loop {
            match this.try_parse_packet()? {
                Some((location, payload_start, payload_len)) => {
                    let data = this.read_buf.as_slice();
                    buf.put_slice(&data[payload_start..payload_start + payload_len]);

                    let total_consumed = payload_start + payload_len;
                    this.read_buf.consume(total_consumed);

                    return Poll::Ready(Ok(location));
                }
                None => {}
            }

            this.read_buf.maybe_compact(4096);

            if this.read_buf.remaining_capacity() == 0 {
                return Poll::Ready(Err(std::io::Error::other(
                    "UoT read buffer full but no complete packet",
                )));
            }

            let write_slice = this.read_buf.write_slice();
            let mut read_buf = ReadBuf::new(write_slice);

            match Pin::new(&mut this.stream).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => {
                    let bytes_read = read_buf.filled().len();
                    if bytes_read == 0 {
                        this.is_eof = true;
                        return Poll::Ready(Ok(NetLocation::UNSPECIFIED));
                    }
                    this.read_buf.advance_write(bytes_read);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S: AsyncStream> AsyncWriteSourcedMessage for UotV1ServerStream<S> {
    fn poll_write_sourced_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        source: &SocketAddr,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        // Flush previously buffered packet first.
        while this.write_buf_sent < this.write_buf_len {
            let remaining = &this.write_buf[this.write_buf_sent..this.write_buf_len];
            match Pin::new(&mut this.stream).poll_write(cx, remaining) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "failed to write buffered UoT packet",
                    )));
                }
                Poll::Ready(Ok(n)) => {
                    this.write_buf_sent += n;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        this.write_buf_len = 0;
        this.write_buf_sent = 0;

        let addr_len = match source {
            SocketAddr::V4(_) => 7,
            SocketAddr::V6(_) => 19,
        };
        let total_len = addr_len + 2 + buf.len();

        if total_len > this.write_buf.len() {
            return Poll::Ready(Err(std::io::Error::other(format!(
                "UoT packet too large: {total_len} > {}",
                this.write_buf.len()
            ))));
        }

        let offset = write_uot_addrparser_address(&mut this.write_buf, source);

        let payload_len = u16::try_from(buf.len()).map_err(|_| {
            std::io::Error::other(format!("UoT payload too large: {}", buf.len()))
        })?;
        this.write_buf[offset..offset + 2].copy_from_slice(&payload_len.to_be_bytes());

        let data_start = offset + 2;
        this.write_buf[data_start..data_start + buf.len()].copy_from_slice(buf);
        this.write_buf_len = data_start + buf.len();

        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncStream> AsyncFlushMessage for UotV1ServerStream<S> {
    fn poll_flush_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        while this.write_buf_sent < this.write_buf_len {
            let remaining = &this.write_buf[this.write_buf_sent..this.write_buf_len];
            match Pin::new(&mut this.stream).poll_write(cx, remaining) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "failed to flush buffered UoT packet",
                    )));
                }
                Poll::Ready(Ok(n)) => {
                    this.write_buf_sent += n;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        this.write_buf_len = 0;
        this.write_buf_sent = 0;

        Pin::new(&mut this.stream).poll_flush(cx)
    }
}

impl<S: AsyncStream> AsyncShutdownMessage for UotV1ServerStream<S> {
    fn poll_shutdown_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut this = self.get_mut();
        ready!(Pin::new(&mut this).poll_flush_message(cx))?;
        Pin::new(&mut this.stream).poll_shutdown(cx)
    }
}

impl<S: AsyncStream> AsyncPing for UotV1ServerStream<S> {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl<S: AsyncStream> AsyncTargetedMessageStream for UotV1ServerStream<S> {}

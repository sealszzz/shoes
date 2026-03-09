//! UoT V2 request parsing helpers.

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt};

use crate::address::NetLocation;
use crate::socks_handler::read_location_direct;

/// Parsed UoT V2 request mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UotV2Mode {
    Connect,
    Packet,
}

/// Parsed UoT V2 request.
#[derive(Debug, Clone)]
pub struct UotV2Request {
    pub mode: UotV2Mode,
    pub destination: NetLocation,
}

impl UotV2Request {
    #[inline]
    pub fn is_connect(&self) -> bool {
        matches!(self.mode, UotV2Mode::Connect)
    }

    #[inline]
    pub fn is_packet(&self) -> bool {
        matches!(self.mode, UotV2Mode::Packet)
    }
}

#[inline]
pub async fn read_uot_v2_request<R>(reader: &mut R) -> io::Result<UotV2Request>
where
    R: AsyncRead + Unpin,
{
    let is_connect = reader.read_u8().await?;
    let destination = read_location_direct(reader).await?;

    let mode = match is_connect {
        1 => UotV2Mode::Connect,
        0 => UotV2Mode::Packet,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid UoT V2 connect flag: {}", is_connect),
            ));
        }
    };

    Ok(UotV2Request { mode, destination })
}

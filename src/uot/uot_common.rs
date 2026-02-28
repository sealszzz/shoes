//! Common address parsing utilities for h2mux packet_addr mode and UoT.
//!
//! ## Supported address formats
//!
//! This module implements two different wire formats used by sing-box:
//!
//! 1. **SOCKS5 address format**
//!    - `0x01`: IPv4
//!    - `0x03`: Domain
//!    - `0x04`: IPv6
//!    - Used by:
//!      - h2mux packet_addr mode
//!      - UoT V2 request headers
//!
//! 2. **AddrParser format**
//!    - `0x00`: IPv4
//!    - `0x01`: IPv6
//!    - `0x02`: Domain
//!    - Used by:
//!      - UoT V1 packet payloads
//!      - UoT V2 non-connect packet payloads

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::address::{Address, NetLocation};

/// SOCKS5 ATYP values.
pub const ATYP_IPV4: u8 = 0x01;
pub const ATYP_DOMAIN: u8 = 0x03;
pub const ATYP_IPV6: u8 = 0x04;

/// AddrParser ATYP values.
pub const ADDRPARSER_ATYP_IPV4: u8 = 0x00;
pub const ADDRPARSER_ATYP_IPV6: u8 = 0x01;
pub const ADDRPARSER_ATYP_DOMAIN: u8 = 0x02;

#[inline]
pub fn parse_uot_address(data: &[u8]) -> io::Result<Option<(NetLocation, usize)>> {
    if data.is_empty() {
        return Ok(None);
    }

    let atyp = data[0];
    match atyp {
        ATYP_IPV4 => {
            if data.len() < 7 {
                return Ok(None);
            }
            let ip = Ipv4Addr::new(data[1], data[2], data[3], data[4]);
            let port = u16::from_be_bytes([data[5], data[6]]);
            Ok(Some((NetLocation::new(Address::Ipv4(ip), port), 7)))
        }
        ATYP_IPV6 => {
            if data.len() < 19 {
                return Ok(None);
            }
            let ip_bytes: [u8; 16] = data[1..17].try_into().unwrap();
            let ip = Ipv6Addr::from(ip_bytes);
            let port = u16::from_be_bytes([data[17], data[18]]);
            Ok(Some((NetLocation::new(Address::Ipv6(ip), port), 19)))
        }
        ATYP_DOMAIN => {
            if data.len() < 2 {
                return Ok(None);
            }
            let domain_len = data[1] as usize;
            let total_len = 1 + 1 + domain_len + 2;
            if data.len() < total_len {
                return Ok(None);
            }
            let domain = std::str::from_utf8(&data[2..2 + domain_len])
                .map_err(|e| io::Error::other(format!("invalid domain: {e}")))?;
            let port = u16::from_be_bytes([data[2 + domain_len], data[3 + domain_len]]);
            Ok(Some((
                NetLocation::new(Address::Hostname(domain.to_string()), port),
                total_len,
            )))
        }
        _ => Err(io::Error::other(format!("unknown UoT ATYP: {atyp}"))),
    }
}

#[inline]
pub fn write_uot_address(buf: &mut [u8], addr: &SocketAddr) -> usize {
    match addr {
        SocketAddr::V4(v4) => {
            buf[0] = ATYP_IPV4;
            buf[1..5].copy_from_slice(&v4.ip().octets());
            buf[5..7].copy_from_slice(&v4.port().to_be_bytes());
            7
        }
        SocketAddr::V6(v6) => {
            buf[0] = ATYP_IPV6;
            buf[1..17].copy_from_slice(&v6.ip().octets());
            buf[17..19].copy_from_slice(&v6.port().to_be_bytes());
            19
        }
    }
}

#[inline]
pub fn parse_uot_addrparser_address(data: &[u8]) -> io::Result<Option<(NetLocation, usize)>> {
    if data.is_empty() {
        return Ok(None);
    }

    let atyp = data[0];
    match atyp {
        ADDRPARSER_ATYP_IPV4 => {
            if data.len() < 7 {
                return Ok(None);
            }
            let ip = Ipv4Addr::new(data[1], data[2], data[3], data[4]);
            let port = u16::from_be_bytes([data[5], data[6]]);
            Ok(Some((NetLocation::new(Address::Ipv4(ip), port), 7)))
        }
        ADDRPARSER_ATYP_IPV6 => {
            if data.len() < 19 {
                return Ok(None);
            }
            let ip_bytes: [u8; 16] = data[1..17].try_into().unwrap();
            let ip = Ipv6Addr::from(ip_bytes);
            let port = u16::from_be_bytes([data[17], data[18]]);
            Ok(Some((NetLocation::new(Address::Ipv6(ip), port), 19)))
        }
        ADDRPARSER_ATYP_DOMAIN => {
            if data.len() < 2 {
                return Ok(None);
            }
            let domain_len = data[1] as usize;
            let total_len = 1 + 1 + domain_len + 2;
            if data.len() < total_len {
                return Ok(None);
            }
            let domain = std::str::from_utf8(&data[2..2 + domain_len])
                .map_err(|e| io::Error::other(format!("invalid domain: {e}")))?;
            let port = u16::from_be_bytes([data[2 + domain_len], data[3 + domain_len]]);
            Ok(Some((
                NetLocation::new(Address::Hostname(domain.to_string()), port),
                total_len,
            )))
        }
        _ => Err(io::Error::other(format!(
            "unknown UoT AddrParser ATYP: {atyp}"
        ))),
    }
}

#[inline]
pub fn write_uot_addrparser_address(buf: &mut [u8], addr: &SocketAddr) -> usize {
    match addr {
        SocketAddr::V4(v4) => {
            buf[0] = ADDRPARSER_ATYP_IPV4;
            buf[1..5].copy_from_slice(&v4.ip().octets());
            buf[5..7].copy_from_slice(&v4.port().to_be_bytes());
            7
        }
        SocketAddr::V6(v6) => {
            buf[0] = ADDRPARSER_ATYP_IPV6;
            buf[1..17].copy_from_slice(&v6.ip().octets());
            buf[17..19].copy_from_slice(&v6.port().to_be_bytes());
            19
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_uot_ipv4_address() {
        // SOCKS5 format: ATYP=0x01 for IPv4, IP=192.168.1.1, Port=8080
        let data = [ATYP_IPV4, 192, 168, 1, 1, 0x1F, 0x90];
        let (location, len) = parse_uot_address(&data).unwrap().unwrap();
        assert_eq!(len, 7);
        assert_eq!(location.port(), 8080);
        match location.address() {
            Address::Ipv4(ip) => assert_eq!(*ip, Ipv4Addr::new(192, 168, 1, 1)),
            _ => panic!("expected IPv4"),
        }
    }

    #[test]
    fn test_parse_uot_ipv6_address() {
        // SOCKS5 format: ATYP=0x04 for IPv6, IP=::1, Port=443
        let mut data = vec![ATYP_IPV6];
        data.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        data.extend_from_slice(&443u16.to_be_bytes());

        let (location, len) = parse_uot_address(&data).unwrap().unwrap();
        assert_eq!(len, 19);
        assert_eq!(location.port(), 443);
        match location.address() {
            Address::Ipv6(ip) => assert_eq!(*ip, Ipv6Addr::LOCALHOST),
            _ => panic!("expected IPv6"),
        }
    }

    #[test]
    fn test_parse_uot_domain_address() {
        // SOCKS5 format: ATYP=0x03 for Domain, Domain="example.com", Port=53
        let domain = b"example.com";
        let mut data = vec![ATYP_DOMAIN, domain.len() as u8];
        data.extend_from_slice(domain);
        data.extend_from_slice(&53u16.to_be_bytes());

        let (location, len) = parse_uot_address(&data).unwrap().unwrap();
        assert_eq!(len, 1 + 1 + domain.len() + 2);
        assert_eq!(location.port(), 53);
        match location.address() {
            Address::Hostname(h) => assert_eq!(h, "example.com"),
            _ => panic!("expected hostname"),
        }
    }

    #[test]
    fn test_parse_uot_truncated() {
        // Empty data
        assert!(parse_uot_address(&[]).unwrap().is_none());
        // Truncated IPv4
        assert!(parse_uot_address(&[ATYP_IPV4, 1, 2, 3]).unwrap().is_none());
        // Truncated IPv6
        assert!(
            parse_uot_address(&[ATYP_IPV6, 0, 0, 0, 0])
                .unwrap()
                .is_none()
        );
        // Truncated domain (no length byte)
        assert!(parse_uot_address(&[ATYP_DOMAIN]).unwrap().is_none());
        // Truncated domain (incomplete domain)
        assert!(
            parse_uot_address(&[ATYP_DOMAIN, 10, b'a', b'b'])
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn test_parse_uot_invalid() {
        // Unknown ATYP should error
        assert!(parse_uot_address(&[0xFF, 1, 2, 3, 4, 5, 6, 7]).is_err());
    }

    #[test]
    fn test_write_uot_ipv4_address() {
        let addr: SocketAddr = "192.168.1.1:8080".parse().unwrap();
        let mut buf = [0u8; 32];
        let len = write_uot_address(&mut buf, &addr);
        assert_eq!(len, 7);
        assert_eq!(buf[0], ATYP_IPV4);
        assert_eq!(&buf[1..5], &[192, 168, 1, 1]);
        assert_eq!(&buf[5..7], &0x1F90u16.to_be_bytes());
    }

    #[test]
    fn test_write_uot_ipv6_address() {
        let addr: SocketAddr = "[::1]:443".parse().unwrap();
        let mut buf = [0u8; 32];
        let len = write_uot_address(&mut buf, &addr);
        assert_eq!(len, 19);
        assert_eq!(buf[0], ATYP_IPV6);
        assert_eq!(&buf[1..17], &Ipv6Addr::LOCALHOST.octets());
        assert_eq!(&buf[17..19], &443u16.to_be_bytes());
    }
}

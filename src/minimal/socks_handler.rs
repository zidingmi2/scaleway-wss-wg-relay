//! SOCKS address codec shared with Trojan; no SOCKS listener implementation.
use crate::{
    address::{Address, NetLocation},
    stream_reader::StreamReader,
};
use std::net::Ipv4Addr;
use tokio::io::AsyncReadExt;
pub const CMD_CONNECT: u8 = 1;
pub const CMD_UDP_ASSOCIATE: u8 = 3;
pub const ADDR_TYPE_IPV4: u8 = 1;
pub const ADDR_TYPE_DOMAIN_NAME: u8 = 3;
pub const ADDR_TYPE_IPV6: u8 = 4;
pub async fn read_location<T: AsyncReadExt + Unpin>(
    stream: &mut T,
    stream_reader: &mut StreamReader,
) -> std::io::Result<NetLocation> {
    let address_type = stream_reader.read_u8(stream).await?;
    match address_type {
        ADDR_TYPE_IPV4 => {
            let address_bytes = stream_reader.read_slice(stream, 6).await?;

            let v4addr = Ipv4Addr::new(
                address_bytes[0],
                address_bytes[1],
                address_bytes[2],
                address_bytes[3],
            );

            let port = u16::from_be_bytes(address_bytes[4..6].try_into().unwrap());

            Ok(NetLocation::new(Address::Ipv4(v4addr), port))
        }
        ADDR_TYPE_IPV6 => {
            let address_bytes = stream_reader.read_slice(stream, 18).await?;

            let v6addr = std::net::Ipv6Addr::new(
                u16::from_be_bytes(address_bytes[0..2].try_into().unwrap()),
                u16::from_be_bytes(address_bytes[2..4].try_into().unwrap()),
                u16::from_be_bytes(address_bytes[4..6].try_into().unwrap()),
                u16::from_be_bytes(address_bytes[6..8].try_into().unwrap()),
                u16::from_be_bytes(address_bytes[8..10].try_into().unwrap()),
                u16::from_be_bytes(address_bytes[10..12].try_into().unwrap()),
                u16::from_be_bytes(address_bytes[12..14].try_into().unwrap()),
                u16::from_be_bytes(address_bytes[14..16].try_into().unwrap()),
            );

            let port = u16::from_be_bytes(address_bytes[16..18].try_into().unwrap());

            Ok(NetLocation::new(Address::Ipv6(v6addr), port))
        }
        ADDR_TYPE_DOMAIN_NAME => {
            let address_len = stream_reader.read_u8(stream).await? as usize;

            let address_bytes = stream_reader.read_slice(stream, address_len + 2).await?;

            let address_str = match std::str::from_utf8(&address_bytes[0..address_len]) {
                Ok(s) => s,
                Err(e) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("Failed to decode address: {e}"),
                    ));
                }
            };

            let port = u16::from_be_bytes(
                address_bytes[address_len..address_len + 2]
                    .try_into()
                    .unwrap(),
            );

            // Parses as Address since some clients pass IP addresses as hostnames.
            Ok(NetLocation::new(Address::from(address_str)?, port))
        }

        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Unknown address type: {address_type}"),
        )),
    }
}

/// Read a SOCKS5-format address directly from an AsyncRead stream.
///
/// This is a simpler version of `read_location` that doesn't use `StreamReader`.
/// Use this when the protocol has its own framing (e.g., H2 streams, AnyTLS frames).
///
/// SOCKS5 address format (also used in UoT V2 Request header):
/// - 0x01: IPv4 (4 bytes) + port (2 bytes)
/// - 0x03: Domain (1 byte len + domain) + port (2 bytes)
/// - 0x04: IPv6 (16 bytes) + port (2 bytes)
pub async fn read_location_direct<T: AsyncReadExt + Unpin>(
    stream: &mut T,
) -> std::io::Result<NetLocation> {
    let mut addr_type = [0u8; 1];
    stream.read_exact(&mut addr_type).await?;

    match addr_type[0] {
        ADDR_TYPE_IPV4 => {
            let mut buf = [0u8; 6];
            stream.read_exact(&mut buf).await?;
            let addr = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
            let port = u16::from_be_bytes([buf[4], buf[5]]);
            Ok(NetLocation::new(Address::Ipv4(addr), port))
        }
        ADDR_TYPE_IPV6 => {
            let mut buf = [0u8; 18];
            stream.read_exact(&mut buf).await?;
            let addr = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&buf[0..16]).unwrap());
            let port = u16::from_be_bytes([buf[16], buf[17]]);
            Ok(NetLocation::new(Address::Ipv6(addr), port))
        }
        ADDR_TYPE_DOMAIN_NAME => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let domain_len = len[0] as usize;

            let mut buf = vec![0u8; domain_len + 2];
            stream.read_exact(&mut buf).await?;

            let domain = std::str::from_utf8(&buf[..domain_len]).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Invalid domain encoding: {e}"),
                )
            })?;
            let port = u16::from_be_bytes([buf[domain_len], buf[domain_len + 1]]);

            // Parse as Address to handle IP literals passed as domain
            Ok(NetLocation::new(Address::from(domain)?, port))
        }
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Unknown address type: {}", addr_type[0]),
        )),
    }
}

pub fn write_location_to_vec(location: &NetLocation) -> std::io::Result<Vec<u8>> {
    let (address, port) = location.components();
    let mut vec = match address {
        Address::Ipv4(v4addr) => {
            let mut vec = Vec::with_capacity(7);
            vec.push(ADDR_TYPE_IPV4);
            vec.extend_from_slice(&v4addr.octets());
            vec
        }
        Address::Ipv6(v6addr) => {
            let mut vec = Vec::with_capacity(19);
            vec.push(ADDR_TYPE_IPV6);
            vec.extend_from_slice(&v6addr.octets());
            vec
        }
        Address::Hostname(domain_name) => {
            let domain_name_bytes = domain_name.as_bytes();
            let length = u8::try_from(domain_name_bytes.len()).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "SOCKS hostname exceeds 255 bytes",
                )
            })?;
            let mut vec = Vec::with_capacity(4 + domain_name_bytes.len());
            vec.push(ADDR_TYPE_DOMAIN_NAME);
            vec.push(length);
            vec.extend_from_slice(domain_name_bytes);
            vec
        }
    };

    vec.push((port >> 8) as u8);
    vec.push((port & 0xff) as u8);
    Ok(vec)
}

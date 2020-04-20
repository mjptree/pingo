use pnet::packet::{
    icmp::{Icmp, IcmpPacket},
    icmpv6::{Icmpv6, Icmpv6Packet},
    FromPacket
};
use pnet::transport::TransportSender;
use std::error::Error;
use std::net::IpAddr;
use std::process;
use std::time::Instant;

use crate::receiver::ResponseStatus;
use request::RequestPacket;

mod request;

/// Packet layout with sender information
///
/// The `Package` is a higher level abstraction than `RequestPacket` in that in encapsulates the
/// necessary functionality to create a ready-to-send packet on the fly and then also send it out.
/// It maintains only the necessary layout information to create new packets, not the packets
/// itself, as they are consumed by the `TransportSender`.
///
/// The `Package` does currently only apply to sending packets and cannot parse reply packets yet.
/// This is the task of the `ReplyPacket`.
///
/// The interface for both replies and responses may be unified at one point.
#[derive(Debug)]
pub struct Package {
    addr: IpAddr,
    size: usize,
    sequence: u16,
}

impl Package {
    /// Configure a new `Package` layout
    pub fn new(addr: IpAddr, size: usize) -> Self {
        Self {
            addr,
            size,
            sequence: 0,
        }
    }

    /// Get the destination IP address for this `Package`
    pub fn get_ip_addr(&self) -> &IpAddr {
        &self.addr
    }

    /// Get size of the underlying packet's payload
    pub fn get_size(&self) -> usize {
        self.size
    }

    /// Return `true` if this package is configured with the IPv4 protocol
    pub fn is_ipv4(&self) -> bool {
        self.addr.is_ipv4()
    }

    /// Return `true` if this package is configured with the IPv6 protocol
    pub fn is_ipv6(&self) -> bool {
        self.addr.is_ipv6()
    }

    /// Send this `Package`
    ///
    /// The `Package` is sent via a [`TransportSender`](tx) provided by the [`pnet`](#pnet) crate.
    ///
    /// # Errros
    ///
    /// If the transport fails, due to an error in a lower layer handled by the Operating System,
    /// then the function returns the error received by OS.
    ///
    /// # Undefined Behaviour
    ///
    /// The [`TransportSender`](tx) is expected to be configured with the correct protocol
    /// combination - i.e. IPv4/ICMP or IPv6/ICMPv6. If the [`TransportSender`](tx) is misconfigured
    /// with an invalid protocol combination, the transport may still execute successfully, but the
    /// routing behaviour, the remote response and the response layout are not predictable any more.
    ///
    /// [tx]: https://docs.rs/pnet/0.25.0/pnet/transport/struct.TransportSender.html
    /// [pnet]: https://docs.rs/pnet/0.25.0/pnet/
    pub fn send(&mut self, tx: &mut TransportSender) -> Result<(u16, Instant), Box<dyn Error>> {
        let mut packet = RequestPacket::new(&self.addr, self.size)?;
        let seq = self.sequence;
        packet.set_header_and_payload(process::id() as u16, seq, self.size);
        packet.set_checksum();

        // Stop time and send packet out into the aether
        let start = Instant::now();
        let _ = tx.send_to(packet, self.addr)?;

        // Increment the sequence counter after sending, but before returning
        self.sequence += 1;
        Ok((seq, start))
    }
}

/// A ping after receipt
///
/// The echo reply packet does not own the entire packet, but only retains the key information of
/// the packet needed to identify it and determine whether this packet is recognised by this ping
/// session.
///
/// It keeps track of the identifier field, the sequence number and the type field of the returning
/// packet. The code field is dropped, because it does not add information for identification of the
/// packet or the calculation of summary statistics
#[derive(Debug)]
pub struct ReplyPacket {
    id: u16,
    seq: u16,
    status: ResponseStatus,
    size: usize,
}

impl ReplyPacket {
    /// Get the identifier of the packet
    pub fn get_id(&self) -> u16 {
        self.id
    }

    /// Get the sequence number of the packet
    pub fn get_sequence(&self) -> u16 {
        self.seq
    }

    /// Get the value of the packet's type field
    pub fn get_type(&self) -> ResponseStatus {
        self.status
    }

    /// Get the length of the packet's payload
    pub fn get_size(&self) -> usize {
        self.size
    }
}

impl From<IcmpPacket<'_>> for ReplyPacket {
    fn from(packet: IcmpPacket) -> Self {
        let raw_packet = packet.from_packet();
        Self::from(raw_packet)
    }
}

impl From<Icmpv6Packet<'_>> for ReplyPacket {
    fn from(packet: Icmpv6Packet) -> Self {
        let raw_packet = packet.from_packet();
        Self::from(raw_packet)
    }
}

impl From<Icmp> for ReplyPacket {
    /// Parse an incoming [`Icmp`](icmp) packet into a `ReplyPacket`
    ///
    /// [`pnet`](pnet) internally handles the mapping of the type and code fields. The identifier
    /// and sequence number can be salvaged from the payload.
    ///
    /// [icmp]: https://docs.rs/pnet/0.25.0/pnet/packet/icmp/struct.Icmp.html
    /// [pnet]: https://docs.rs/pnet/0.25.0/pnet/
    fn from(packet: Icmp) -> Self {
        let mut id = [0u8; 2];
        let mut seq = [0u8; 2];
        let payload = &packet.payload;
        let status = ResponseStatus::from(packet.icmp_type);

        // Time Exceeded responses move original ICMP header to the
        if status == ResponseStatus::Expired {
            let len = payload.len();
            id.copy_from_slice(&payload[(len - 4)..(len - 2)]);
            seq.copy_from_slice(&payload[(len - 2)..(len)]);
        } else {
            id.copy_from_slice(&payload[0..2]);
            seq.copy_from_slice(&payload[2..4]);
        }
        Self {
            id: u16::from_be_bytes(id),
            seq: u16::from_be_bytes(seq),
            status,
            size: packet.payload.len() - 8,
        }
    }
}

impl From<Icmpv6> for ReplyPacket {
    /// Parse an incoming [`Icmpv6`](icmpv6) packet into a `ReplyPacket`
    ///
    /// Note that the specifications for ICMPv6 packet layouts differs from ICMP, in terms of which
    /// information the responder is required to preserve.
    ///
    /// # Undefined Behaviour
    ///
    /// For [Time Exceeded](type3) reply messages, bytes 5 - 7 are unused, which makes it impossible
    /// to uniquely identify the package, in the current design. A possible future workaround could
    /// be to push identifying information below the header, into the body of the packet.
    ///
    /// [icmpv6]: https://docs.rs/pnet/0.25.0/pnet/packet/icmpv6/index.html
    /// [type3]: https://tools.ietf.org/html/rfc4443#section-3.3
    fn from(packet: Icmpv6) -> Self {
        let mut id = [0u8; 2];
        let mut seq = [0u8; 2];
        let payload = &packet.payload;
        let status = ResponseStatus::from(packet.icmpv6_type);

        // ICMPv6 Time Exceeded messages try to preserve as much of the original packet as possible
        // but ID and sequence number are supposed to be zeroed by the responder.
        id.copy_from_slice(&payload[0..2]);
        seq.copy_from_slice(&payload[2..4]);
        Self {
            id: u16::from_be_bytes(id),
            seq: u16::from_be_bytes(seq),
            status,
            size: packet.payload.len() - 8,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_reply_from_icmp() {
        use pnet::packet::icmp::{Icmp, IcmpTypes, IcmpCode};

        let payload = vec![0u8; 28];
        let icmp = Icmp {
            icmp_type: IcmpTypes::EchoReply,
            icmp_code: IcmpCode::new(0),
            checksum: 0u16,
            payload
        };

        let packet = ReplyPacket::from(icmp);

        assert_eq!(packet.get_id(), 0);
        assert_eq!(packet.get_sequence(), 0);
        assert_eq!(packet.get_type(), ResponseStatus::Received);
        assert_eq!(packet.get_size(), 20);
    }

    #[test]
    fn parse_reply_from_icmpv6() {
        use pnet::packet::icmpv6::{Icmpv6, Icmpv6Types, Icmpv6Code};

        let payload = vec![0u8; 28];
        let icmpv6 = Icmpv6 {
            icmpv6_type: Icmpv6Types::EchoReply,
            icmpv6_code: Icmpv6Code::new(0),
            checksum: 0u16,
            payload
        };

        let packet = ReplyPacket::from(icmpv6);

        assert_eq!(packet.get_id(), 0);
        assert_eq!(packet.get_sequence(), 0);
        assert_eq!(packet.get_type(), ResponseStatus::Received);
        assert_eq!(packet.get_size(), 20);
    }
}
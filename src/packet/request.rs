use pnet::packet::{
    icmp::{echo_request::MutableEchoRequestPacket, IcmpTypes},
    icmpv6::{Icmpv6Types, MutableIcmpv6Packet},
    Packet,
};
use pnet::util::checksum;
use std::io;
use std::net::IpAddr;

/// A ping packet before send-out
///
/// Low-level abstraction for outgoing echo request messages. Although, it looks like the counter
/// part to the `ReplyPacket` struct, this object is only for internal management of setting up the
/// packet ultimately before it is pushed down into the aether.
#[derive(Debug)]
pub(super) enum RequestPacket {
    Icmp(MutableEchoRequestPacket<'static>),
    Icmpv6(MutableIcmpv6Packet<'static>),
}

impl RequestPacket {
    /// Create new echo request packet
    ///
    /// The packet layout is dynamically chosen based on the provided IP address. The underlying
    /// buffer is sufficient for the size of the payload plus the header and the type- and code
    /// fields are set before returning the finished packet.
    ///
    /// # Errors
    ///
    /// The function could theoretically return an error, if the provided buffer were smaller than
    /// the minimum required size. As the function automatically adds extra space for the header,
    /// this should never occur.
    pub fn new(ip: &IpAddr, size: usize) -> Result<Self, io::Error> {
        match ip.is_ipv4() {
            true => MutableEchoRequestPacket::owned(vec![0; size + 8])
                .map(|pkg| Self::Icmp(pkg))
                .ok_or(io::Error::new(io::ErrorKind::InvalidData, "icmp packet")),
            false => MutableIcmpv6Packet::owned(vec![0; size + 8])
                .map(|pkg| Self::Icmpv6(pkg))
                .ok_or(io::Error::new(io::ErrorKind::InvalidData, "icmpv6 packet")),
        }
        .map(|pkg| pkg.set_to_echo_request())
    }

    /// Configure this packet as echo request
    ///
    /// The first 8 bits of the packet are reserved for the type field. The type is 8 for ICMP/IPv4
    /// and 128 for ICMPv6/IPv6.
    ///
    /// The following 8 bits are technically reserved for the code field, but ICMP/ICMPv6 codes are
    /// not tracked by this application and automatically zeroed during initialization.
    fn set_to_echo_request(mut self) -> Self {
        match &mut self {
            Self::Icmp(pkg) => pkg.set_icmp_type(IcmpTypes::EchoRequest),
            Self::Icmpv6(pkg) => pkg.set_icmpv6_type(Icmpv6Types::EchoRequest),
        };
        self
    }

    /// Populate the header fields and append payload
    ///
    /// The header contains a 16-bit identifier field and a 16-bit sequence number field. The
    /// identifier is intended to be unique per process and on unix often filled with the current
    /// process' id.
    ///
    /// The sequence number is intended for unique identification of a packet, associating a request
    /// with a corresponding reply.
    ///
    /// The payload can be arbitrary content. Here it is simply filled with random bytes.
    ///
    /// # Undefined Behaviour
    ///
    /// If the provided packet size exceeds the supported MTU, the packet suffers fragmentation can
    /// possibly not be properly identified any more being sent back, even if the echo request was
    /// answered correctly by the target host.
    pub fn set_header_and_payload(&mut self, id: u16, sequence: u16, size: usize) {
        match self {
            Self::Icmp(pkg) => {
                pkg.set_identifier(id);
                pkg.set_sequence_number(sequence);
                let mut payload = vec![0u8; size];
                for x in &mut payload {
                    *x = rand::random::<u8>();
                }
                pkg.set_payload(&payload);
            }
            Self::Icmpv6(pkg) => {
                let header = [id.to_be_bytes(), sequence.to_be_bytes()].concat();
                let mut payload = vec![0u8; size];
                for x in &mut payload {
                    *x = rand::random::<u8>();
                }
                let packet = [header, payload].concat();
                pkg.set_payload(&packet);
            }
        };
    }

    /// Set the checksum field of the packet
    ///
    /// The checksum is the 16-bit one's complement of the one's complement of the sum of the
    /// packet. According to the IPv6 specification the checksum for ICMPv6 would include the ip
    /// header of the packet.
    pub fn set_checksum(&mut self) {
        match self {
            Self::Icmp(pkg) => pkg.set_checksum(checksum(pkg.packet(), 1)),

            // This is technically incorrect according to the IPv6 specification [RFC2460], but we
            // are the only consumers of the checksum.
            Self::Icmpv6(pkg) => pkg.set_checksum(checksum(pkg.packet(), 1)),
        };
    }
}

impl Packet for RequestPacket {
    fn packet(&self) -> &[u8] {
        match self {
            Self::Icmp(pkg) => pkg.packet(),
            Self::Icmpv6(pkg) => pkg.packet(),
        }
    }

    fn payload(&self) -> &[u8] {
        match self {
            Self::Icmp(pkg) => pkg.payload(),
            Self::Icmpv6(pkg) => pkg.payload(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn create_imcp_echo_request_packet() {
        let addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let mut pkg = RequestPacket::new(&addr, 20)
            .expect("Failed creating a new echo request packet");

        let id = 1u16;
        let seq = 2u16;
        pkg.set_header_and_payload(id, seq, 20);

        let packet = pkg.packet();

        // The 5 - 6th byte are reserved for the identifier
        assert_eq!(packet[5], id as u8);

        // The 7 - 8th byte are reserved for the sequence number
        assert_eq!(packet[7], seq as u8);

        // 20 bytes payload + 8 bytes header
        assert_eq!(packet.len(), 28);
    }

    #[test]
    fn create_icmpv6_echo_request_packet() {
        use std::net::Ipv6Addr;

        // ICMPv6 headers have in principle the same layout
        let addr = IpAddr::V6("::1".parse::<Ipv6Addr>().unwrap());
        let mut pkg = RequestPacket::new(&addr, 20)
            .expect("Failed creating a new echo request packet");

        let id = 3u16;
        let seq = 4u16;
        pkg.set_header_and_payload(id, seq, 20);

        let packet = pkg.packet();

        // The 5 - 6th byte are reserved for the identifier
        assert_eq!(packet[5], id as u8);

        // The 7 - 8th byte are reserved for the sequence number
        assert_eq!(packet[7], seq as u8);

        // 20 bytes payload + 8 bytes header
        assert_eq!(packet.len(), 28);
    }
}
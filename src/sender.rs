use pnet::transport::{TransportReceiver, TransportSender};
use std::error::Error;
use std::io;
use std::net::IpAddr;
use std::sync::{atomic::AtomicBool, Arc};
use std::thread;
use std::time::Duration;

use super::{Config, Dest};
use crate::packet::Package;
use crate::receiver::{Receiver, Summary};

/// A thread-safe boolean representing the receipt of an signal interrupt
pub type InterruptSignal = Arc<AtomicBool>;

/// Meta information about ping session
#[derive(Debug)]
struct Meta {
    host: String,
    ttl: u8,
    delay: Duration,
    timeout: Option<Duration>,
}

/// Sender context
#[derive(Debug)]
pub struct Sender {
    meta: Meta,
    packet: Package,
}

impl Sender {
    /// Create new Sender context from provided configuration
    ///
    /// The `Sender` coordinates the packet layout and sets up the sender/receiver environment.
    /// Depending on the destination argument provided, the `Sender` to resolve either the domain
    /// name that was provided or the provided IP address. For the further part the host name will
    /// only be kept for information purpose, the important bit for the rest of the session is the
    /// IP address.
    ///
    /// # Errors
    ///
    /// If the dns lookup fails, then this function returns an Error. This would usually occur, if
    /// the user provided an invalid destination.
    pub fn new(config: Config) -> Result<Self, Box<dyn Error>> {
        // These functions are not used anywhere else in the application
        use dns_lookup::{lookup_addr, lookup_host};

        // If the user provided an invalid destination, then this the place where it will fail
        let (addr, host) = match config.dest {
            Dest::Ip(addr) => {
                let host = lookup_addr(&addr)?;

                info!("Resolved IP {} to host {}", addr, host);

                (addr, host)
            }
            Dest::Host(host) => {
                let addr = lookup_host(&host)?[0];

                info!("Resolved host {} to IP {}", host, addr);

                (addr, host)
            }
        };

        // The meta object contains session information. As identifier for the packets servers the pid
        let meta = Meta {
            host,
            ttl: config.ttl,
            delay: config.delay,
            timeout: config.timeout,
        };

        // The packet object bundles the information required to trigger a send
        let packet = Package::new(addr, config.size);

        // Combined they make up the sender context
        Ok(Self { meta, packet })
    }

    /// Send a sequence of echo requests
    ///
    /// Main loop for the ping session. The ping starts with creating a new receiver, which then
    /// plants its listeners for a) the Signal Interrupt by the user to terminate the session and b)
    /// the incoming replies to the packets sent.
    ///
    /// No thread should generally be able to escape this context and the `Receiver` will be dropped
    /// at the end of the scope.
    ///
    /// Returns a summary of the statistics collected during this session.
    ///
    /// # Errors
    ///
    /// This function can fail at multiple points during initialization of listeners and the sending
    /// process. The general strategy is to make sure, all threads are signalled to shut down,
    /// before propagating the Errors back `main`.
    pub fn ping(mut self) -> Result<Summary, Box<dyn Error>> {
        use std::sync::atomic::Ordering;

        println!(
            "ping {} ({}) {} bytes of data",
            self.meta.host,
            self.packet.get_ip_addr(),
            self.packet.get_size()
        );

        let signal = InterruptSignal::new(AtomicBool::new(false));
        let set_signal = signal.clone();
        let _ = ctrlc::set_handler(move || {
            set_signal.store(true, Ordering::SeqCst);
            println!();

            trace!("Registered signal interrupt -- Signalling shut down to systems")
        })?;

        trace!("Start up new receiver");

        let receiver = Receiver::new(self.get_ip_addr().clone(), self.meta.ttl, self.meta.timeout);
        let (mut tx, rx) = self.open_transport_channel()?;

        // TTL is part of the IPv4 protocol. The IPv6 counterpart would be the Hop Limit, which is
        // not supported by pnet on this protocol layer
        if self.packet.is_ipv4() {
            info!("Set time to live: {}", self.meta.ttl);

            match tx.set_ttl(self.meta.ttl) {
                Ok(_) => (),
                Err(e) => {
                warn!("Error occurred while setting TTL - signalling shut down");

                signal.store(true, Ordering::SeqCst);
                reutrn Err(e);
            }
            }
        }

        // Erect listeners
        let listener_signal = signal.clone();
        let handles = receiver.start_listening(rx, listener_signal);
        let registry = receiver.get_registry();

        // Start sending out packages
        while !signal.load(Ordering::SeqCst) {
            match self.packet.send(&mut tx) {
                Ok((seq, departure)) => {
                    Receiver::register_request(registry.clone(), seq, departure);
                    thread::sleep(self.meta.delay);
                }
                Err(e) => {
                    warn!("Error occurred during send of echo request - signalling shut down");

                    signal.store(true, Ordering::SeqCst);
                    return Err(e);
                }
            }
        }

        // Cleaning up
        let listener_shut = match handles.0.join() {
            Ok(k) => {
                trace!("Successfully shut down listening thread");
                Ok(k)
            }
            Err(_) => {
                warn!("Error occurred during shut down of listener thread - signalling shut down");

                signal.store(true, Ordering::SeqCst);
                Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Listening thread panicked",
                ))
            }
        };
        let processor_shut = match handles.1.join() {
            Ok(k) => {
                trace!("Successfully shut down processing thread");
                Ok(k)
            }
            Err(_) => {
                warn!("Error occurred during shut down of processor thread - signalling shut down");

                signal.store(true, Ordering::SeqCst);
                Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Processing thread panicked",
                ))
            }
        };
        let _ = listener_shut.and(processor_shut)?;

        trace!("Successfully shut down all child threads");

        //let locked = receiver.lock().unwrap();
        Ok(receiver.summarize())
    }

    /// Open new channel for packet transmission
    ///
    /// The `Sender` picks the correct protocol based on the IP version that it has resolved. The
    /// channel has buffer of 4 KB in size. Ownership of the endpoints is later transferred to the
    /// individual sending and receiving loops.
    ///
    /// The function infers the correct protocol from the `Sender`'s defined `Package` layout.
    ///
    /// # Errors
    ///
    /// Errors during the construction of the pnet [`transport_channel`](tc) are transparently
    /// propagated back to the caller.
    ///
    /// [tc]: https://docs.rs/pnet/0.25.0/pnet/transport/fn.transport_channel.html
    fn open_transport_channel(&self) -> Result<(TransportSender, TransportReceiver), io::Error> {
        use pnet::packet::ip::IpNextHeaderProtocols::{Icmp, Icmpv6};
        use pnet::transport::{self, TransportChannelType::*, TransportProtocol::*};

        trace!("Opening transport channel to transmit network packets");

        let protocol;
        if self.packet.is_ipv4() {
            protocol = Layer4(Ipv4(Icmp));
        } else {
            protocol = Layer4(Ipv6(Icmpv6));
        }
        transport::transport_channel(4096, protocol)
    }

    /// Get the destination IP address for this ping session
    fn get_ip_addr(&self) -> &IpAddr {
        self.packet.get_ip_addr()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn create_sender_from_config() {
        use crate::{Config, Dest};

        // Custom config
        let config = Config {
            ttl: 50,
            delay: Duration::from_millis(500),
            timeout: None,
            dest: Dest::Ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
            size: 56
        };

        // Create new sender
        let sender = Sender::new(config)
            .expect("Failed configuring sender");

        assert!(sender.packet.is_ipv4());
        assert!(!sender.packet.is_ipv6());
        assert_eq!(*sender.get_ip_addr(), IpAddr::V4("127.0.0.1".parse::<Ipv4Addr>().unwrap()));
        assert_eq!(sender.packet.get_size(), 56);
        assert_eq!(sender.meta.timeout, None);
        assert_eq!(sender.meta.delay, Duration::from_millis(500));
        assert_eq!(sender.meta.ttl, 50);
    }

    #[test]
    fn create_sender_from_cli() {
        use crate::cli::App;

        // Test default config
        let config = App::parse_args().expect("Failed parsing args");

        // Create new sender
        let sender = Sender::new(config)
            .expect("Failed configuring sender");

        assert!(sender.packet.is_ipv4());
        assert!(!sender.packet.is_ipv6());
        assert_eq!(*sender.get_ip_addr(), IpAddr::V4("127.0.0.1".parse::<Ipv4Addr>().unwrap()));
        assert_eq!(sender.packet.get_size(), 56);
        assert_eq!(sender.meta.timeout, None);
        assert_eq!(sender.meta.delay, Duration::from_secs(1));
        assert_eq!(sender.meta.ttl, 56);
    }
}
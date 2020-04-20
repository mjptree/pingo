use crossbeam::queue::SegQueue;
use pnet::packet::{icmp::IcmpType, icmpv6::Icmpv6Type};
use pnet::transport::TransportReceiver;
use std::collections::HashMap;
use std::error::Error;
use std::net::IpAddr;
use std::sync::{atomic::Ordering, Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::packet::ReplyPacket;
use crate::sender::InterruptSignal;

type ListenerHandles = (JoinHandle<()>, JoinHandle<()>);

/// Current status of an echo packet
///
/// The response status maps to the values provided in the type-field of the echo packets and is
/// valid for both ICMP and ICMPv6 packets. There are many more codes officially defined, but we
/// only recognize those that are relevant to identifying an echo request response.
///
/// Mapping between pnet's [`IcmpTypes`](icmpty)/[`Icmpv6Types`](icmpv6ty) and the packet status
/// types monitored. Not all of the below listed types are currently used.
///
/// [icmpty]: https://docs.rs/pnet/0.25.0/pnet/packet/icmp/IcmpTypes/index.html
/// [icmpv6ty]: https://docs.rs/pnet/0.25.0/pnet/packet/icmpv6/Icmpv6Types/index.html
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ResponseStatus {
    Pending,
    Unreachable,
    Received,
    Request,
    Expired,
    TimedOut,

    // Catch-all for all types that we do not keep track of
    Unknown,
}

#[allow(non_upper_case_globals)]
impl From<IcmpType> for ResponseStatus {
    fn from(ty: IcmpType) -> Self {
        use pnet::packet::icmp::IcmpTypes::*;
        match ty {
            DestinationUnreachable => Self::Unreachable,
            EchoReply => Self::Received,
            EchoRequest => Self::Request,
            TimeExceeded => Self::Expired,
            _ => Self::Unknown,
        }
    }
}

#[allow(non_upper_case_globals)]
impl From<Icmpv6Type> for ResponseStatus {
    fn from(ty: Icmpv6Type) -> Self {
        use pnet::packet::icmpv6::Icmpv6Types::*;
        match ty {
            DestinationUnreachable => Self::Unreachable,
            EchoReply => Self::Received,
            EchoRequest => Self::Request,
            TimeExceeded => Self::Expired,
            _ => Self::Unknown,
        }
    }
}

/// Internal record holder for
type Registry = Arc<Mutex<HashMap<u16, (ResponseStatus, Instant, Option<Duration>)>>>;

/// Resolves echo requests and provides summary statistics
///
/// The `Receiver` registers packets before right before they go out and right after they return. It
/// is responsible for keeping track of the status of each packet sent, measuring the time in
/// transit per packet and providing summary statistics at the end of the ping session.
///
/// The `Receiver` maintains an internal `Registry` for the book keeping which can be shared across
/// threads.
pub struct Receiver {
    addr: IpAddr,
    ttl: u8,
    timeout: Option<Duration>,
    registry: Registry,
}

/// The Receiver can only be created from inside a sender context, where it places its listeners for
/// incoming/returning packets. After the Sender returns from the ping session, the Receiver will be
/// left.
impl Receiver {
    pub(crate) fn new(addr: IpAddr, ttl: u8, timeout: Option<Duration>) -> Self {
        Self {
            addr,
            ttl,
            timeout,
            registry: Arc::new(Mutex::new(HashMap::with_capacity(4))),
        }
    }

    /// Retrieve `Arc` to the internal registry
    pub(crate) fn get_registry(&self) -> Registry {
        self.registry.clone()
    }

    /// Register echo request packet right after send out
    ///
    /// The `Receiver` stores information about the starting instant and identity of a packet. It
    /// sets the status of the packet to pending. Only packets set to pending status can be resolved
    /// upon receipt.
    ///
    /// It is technically possible that the registration of the echo reply overtakes the
    /// registration of the echo request. The caller has to make sure that the registration of the
    /// reply is done after the registration of the request. This can be done by querying first
    /// whether the key already exists in the registry.
    ///
    /// # Panics
    ///
    /// This function panics if the mutex holding the registry has been poisoned.
    pub(crate) fn register_request(registry: Registry, seq: u16, start: Instant) {
        // This can only return `Some` if the reply has arrived, before the request was registered.
        let _ = registry
            .lock()
            .unwrap()
            .insert(seq, (ResponseStatus::Pending, start, None));
    }

    /// Register echo reply packet right after receipt
    ///
    /// The `Receiver` registers the receipt of a packet, completing the information for a full
    /// round-trip of the packet.
    ///
    /// The `Receiver` first checks whether the packet has already been registered and will yield
    /// until that has happened, to ensure that the necessary information from the send-out is
    /// available by the time the reply is registered.
    ///
    /// # Panics
    ///
    /// This function panics if the mutex holding the registry has been poisoned.
    pub(crate) fn register_reply(
        registry: Registry,
        seq: u16,
        status: ResponseStatus,
        lapsed: Duration,
    ) {
        use std::collections::hash_map::Entry;

        // Update only if request is registered as pending
        if let Entry::Occupied(mut entry) = registry.lock().unwrap().entry(seq) {
            if let (ResponseStatus::Pending, start, _) = entry.get_mut() {
                *entry.get_mut() = (status, *start, Some(lapsed));
            };
        };
    }

    /// Get the start time that has been recorded for packet by its sequence number
    ///
    /// If the function returns `None`, then the request with the corresponding sequence number has
    /// yet been registered.
    ///
    /// # Panics
    ///
    /// This function panics if the mutex holding the registry has been poisoned.
    pub(crate) fn get_start_time(registry: Registry, seq: u16) -> Option<Instant> {
        match registry.lock().unwrap().get(&seq) {
            Some((_, start, _)) => Some(*start),
            _ => None,
        }
    }

    /// Set up listeners for signal interrupt and incoming packets
    ///
    /// Returns the handles to the listener threads for joining.
    pub fn start_listening(
        &self,
        rx: TransportReceiver,
        sig_int: InterruptSignal,
    ) -> ListenerHandles {
        trace!("Erecting listeners");

        if self.addr.is_ipv4() {
            self.listen_to_ipv4(rx, sig_int)
        } else {
            self.listen_to_ipv6(rx, sig_int)
        }
    }

    /// Listen to incoming packets transmitted via IPv4
    ///
    /// Returns joinable handles to the listening and processing thread.
    ///
    /// Main listening loop for ICMP packets. The Listener opens 2 separate threads, connected via
    /// [crossbeam](crossbeam)'s [`SegQueue`](queue) for passing received packets over for further
    /// processing.
    ///
    /// The first thread owns the [`TransportReceiver`](rx). Its only task is accurate time keeping
    /// with the least possible amount of jitter. The listening thread will never yield. It will
    /// however unblock in regular intervals to poll, whether the user has pressed Ctrl + C.
    ///
    /// The second thread pops work packets off the queue and process them in the pace it requires.
    /// It holds a reference to the `Registry` and updates the record for the received packet upon
    /// successful identification. The processing thread will yield if idle or waiting for other
    /// threads to complete their tasks.
    ///
    /// [crossbeam]: https://docs.rs/crossbeam/0.7.3/crossbeam/
    /// [queue]: https://docs.rs/crossbeam/0.7.3/crossbeam/queue/struct.SegQueue.html
    /// [rx]: https://docs.rs/pnet/0.25.0/pnet/transport/struct.TransportReceiver.html
    fn listen_to_ipv4(&self, rx: TransportReceiver, interrupt: InterruptSignal) -> ListenerHandles {
        use pnet::transport::icmp_packet_iter;

        // One interrupt listener for each thread
        let interrupt_incoming = interrupt.clone();

        // Queue received packets for identification and registration from listening thread to
        // processing thread
        let processing_queue = Arc::new(SegQueue::<(ReplyPacket, IpAddr, Instant)>::new());
        let register_queue = processing_queue.clone();

        // Ref-counted pointers to the `TransportReceiver` to keep it alive
        let rx_thread = Arc::new(Mutex::new(rx));

        // Listener thread is responsible for time-stamping incoming packets as promptly, sending
        // the information on for processing and listen for the next packet as quick as possible
        let listener = thread::spawn(move || {
            trace!("Start listening thread for incoming ICMP packets");

            // Stream iterator over incoming packets
            let mut receiver = rx_thread.lock().unwrap();
            let mut incoming = icmp_packet_iter(&mut receiver);
            while !interrupt_incoming.load(Ordering::SeqCst) {
                // Unblock listener every 0.1 secs to check interrupt signal
                match incoming.next_with_timeout(Duration::from_millis(100)) {
                    // Timestamp and send on for processing
                    Ok(Some((packet, addr))) => {
                        let arrival = Instant::now();
                        let packet = ReplyPacket::from(packet);
                        processing_queue.push((packet, addr, arrival));
                    }

                    // Unblock and check, whether we are still listening
                    Ok(None) => (),

                    // Errors can come from the operating system. User is informed of the error, but
                    // press Ctrl + C if she decides, that the error is non-recoverable
                    Err(e) => {
                        error!("Error occurred while reading incoming: {}", e);
                        warn!("Press Ctrl + C to terminate session");
                    }
                }
            }

            trace!("Shutting down listening thread");
        });

        // ID for identification of packets
        let id = std::process::id() as u16;

        // Reference to receiver values
        let registry = self.get_registry();
        let timeout = self.timeout;
        let ttl = self.ttl;

        let processor = thread::spawn(move || {
            trace!("Start processing thread for incoming ICMP packets");

            while !interrupt.load(Ordering::SeqCst) {
                // New packet in queue to be processed
                if let Ok((pkg, addr, arrival)) = register_queue.pop() {
                    // Make sure this packet belongs to this session and is not a request itself
                    if pkg.get_id() == id && pkg.get_type() != ResponseStatus::Request {
                        'wait: loop {
                            match Receiver::get_start_time(registry.clone(), pkg.get_sequence()) {
                                Some(start) => {
                                    let lapsed = arrival.duration_since(start);
                                    let seq = pkg.get_sequence();
                                    if timeout.filter(|t| t < &lapsed).is_some() {
                                        println!(
                                            "{} bytes from {}: icmp_seq={} timed out",
                                            pkg.get_size(),
                                            addr,
                                            seq
                                        );

                                        Receiver::register_reply(
                                            registry.clone(),
                                            seq,
                                            ResponseStatus::TimedOut,
                                            lapsed,
                                        );
                                    } else if pkg.get_type() == ResponseStatus::Expired {
                                        println!(
                                            "{} bytes from {}: icmp_seq={} expired in transit",
                                            pkg.get_size(),
                                            addr,
                                            seq
                                        );

                                        Receiver::register_reply(
                                            registry.clone(),
                                            seq,
                                            ResponseStatus::TimedOut,
                                            lapsed,
                                        );
                                    } else {
                                        println!(
                                            "{} bytes from {}: icmp_seq={} ttl={} time={:.3}ms",
                                            pkg.get_size(),
                                            addr,
                                            seq,
                                            ttl,
                                            lapsed.as_secs_f64() * 1000f64
                                        );

                                        Receiver::register_reply(
                                            registry.clone(),
                                            seq,
                                            pkg.get_type(),
                                            lapsed,
                                        );
                                    }
                                    break 'wait;
                                }
                                None => {
                                    // Check whether the sender has not actually yet hung up
                                    if !interrupt.load(Ordering::SeqCst) {
                                        break 'wait;
                                    }
                                    thread::yield_now();
                                }
                            }
                        }
                    }
                }
                // Queue empty
                else {
                    thread::yield_now();
                }
            }

            trace!("Shutting down processing thread");
        });
        (listener, processor)
    }

    /// Listen to incoming packets transmitted via IPv6
    ///
    /// Returns joinable handles to the listening and processing thread.
    ///
    /// Main listening loop for ICMPv6 packets. The Listener opens 2 separate threads, connected via
    /// [crossbeam](crossbeam)'s [`SegQueue`](queue) for passing received packets over for further
    /// processing.
    ///
    /// The first thread owns the [`TransportReceiver`](rx). Its only task is accurate time keeping
    /// with the least possible amount of jitter. The listening thread will never yield. It will
    /// however unblock in regular intervals to poll, whether the user has pressed Ctrl + C.
    ///
    /// The second thread pops work packets off the queue and process them in the pace it requires.
    /// It holds a reference to the `Registry` and updates the record for the received packet upon
    /// successful identification. The processing thread will yield if idle or waiting for other
    /// threads to complete their tasks.
    ///
    /// [crossbeam]: https://docs.rs/crossbeam/0.7.3/crossbeam/
    /// [queue]: https://docs.rs/crossbeam/0.7.3/crossbeam/queue/struct.SegQueue.html
    /// [rx]: https://docs.rs/pnet/0.25.0/pnet/transport/struct.TransportReceiver.html
    fn listen_to_ipv6(&self, rx: TransportReceiver, interrupt: InterruptSignal) -> ListenerHandles {
        use pnet::transport::icmpv6_packet_iter;

        // One interrupt listener for each thread
        let interrupt_incoming = interrupt.clone();

        // Queue received packets for identification and registration from listening thread to
        // processing thread
        let processing_queue = Arc::new(SegQueue::<(ReplyPacket, IpAddr, Instant)>::new());
        let register_queue = processing_queue.clone();

        // Ref-counted pointers to the `TransportReceiver` to keep it alive
        let rx_thread = Arc::new(Mutex::new(rx));

        // Listener thread is responsible for time-stamping incoming packets as promptly, sending
        // the information on for processing and listen for the next packet as quick as possible
        let listener = thread::spawn(move || {
            trace!("Start listening thread for incoming ICMP packets");

            // Stream iterator over incoming packets
            let mut receiver = rx_thread.lock().unwrap();
            let mut incoming = icmpv6_packet_iter(&mut receiver);
            while !interrupt_incoming.load(Ordering::SeqCst) {
                // Unblock listener every 0.1 secs to check interrupt signal
                match incoming.next_with_timeout(Duration::from_millis(100)) {
                    // Timestamp and send on for processing
                    Ok(Some((packet, addr))) => {
                        let arrival = Instant::now();
                        let packet = ReplyPacket::from(packet);
                        processing_queue.push((packet, addr, arrival));
                    }

                    // Unblock and check, whether we are still listening
                    Ok(None) => (),

                    // Errors can come from the operating system. User is informed of the error, but
                    // press Ctrl + C if she decides, that the error is non-recoverable
                    Err(e) => {
                        error!("Error occurred while reading incoming: {}", e);
                        warn!("Press Ctrl + C to terminate session");
                    }
                }
            }

            trace!("Shutting down listening thread");
        });

        // ID for identification of packets
        let id = std::process::id() as u16;

        // Reference to receiver values
        let registry = self.get_registry();
        let timeout = self.timeout;
        let ttl = self.ttl;

        let processor = thread::spawn(move || {
            trace!("Start processing thread for incoming ICMP packets");

            while !interrupt.load(Ordering::SeqCst) {
                // New packet in queue to be processed
                if let Ok((pkg, addr, arrival)) = register_queue.pop() {
                    // Make sure this packet belongs to this session and is not a request itself
                    if pkg.get_id() == id && pkg.get_type() != ResponseStatus::Request {
                        // Don't forget to break out of loop, when successful!!
                        'wait: loop {
                            // Get start time returns `None` if the reply registration has overtaken
                            // the request registration. In that case yield and try again later.
                            match Receiver::get_start_time(registry.clone(), pkg.get_sequence()) {
                                Some(start) => {
                                    let lapsed = arrival.duration_since(start);
                                    let seq = pkg.get_sequence();
                                    if timeout.filter(|t| t < &lapsed).is_some() {
                                        println!(
                                            "{} bytes from {}: icmp_seq={} timed out",
                                            pkg.get_size(),
                                            addr,
                                            seq
                                        );

                                        Receiver::register_reply(
                                            registry.clone(),
                                            seq,
                                            ResponseStatus::TimedOut,
                                            lapsed,
                                        );
                                    } else if pkg.get_type() == ResponseStatus::Expired {
                                        println!(
                                            "{} bytes from {}: icmp_seq={} expired in transit",
                                            pkg.get_size(),
                                            addr,
                                            seq
                                        );

                                        Receiver::register_reply(
                                            registry.clone(),
                                            seq,
                                            ResponseStatus::TimedOut,
                                            lapsed,
                                        );
                                    } else {
                                        println!(
                                            "{} bytes from {}: icmp_seq={} ttl={} time={:.3}ms",
                                            pkg.get_size(),
                                            addr,
                                            seq,
                                            ttl,
                                            lapsed.as_secs_f64() * 1000f64
                                        );

                                        Receiver::register_reply(
                                            registry.clone(),
                                            seq,
                                            pkg.get_type(),
                                            lapsed,
                                        );
                                    }
                                    break 'wait;
                                }
                                None => {
                                    // Check whether the sender has not actually yet hung up
                                    if !interrupt.load(Ordering::Acquire) {
                                        break 'wait;
                                    }
                                    thread::yield_now();
                                }
                            }
                        }
                    }
                }
                // Queue empty
                else {
                    thread::yield_now();
                }
            }

            trace!("Shutting down processing thread");
        });
        (listener, processor)
    }

    pub fn summarize(&self) -> Summary {
        Summary {
            addr: self.addr.clone(),
            registry: self.get_registry(),
        }
    }
}

/// Summarising information about session outcome
pub struct Summary {
    addr: IpAddr,
    registry: Registry,
}

impl Summary {
    /// Summarize statistics for this ping session
    ///
    /// Stats are reported in milliseconds.
    ///
    /// Currently the summary statistics are filtered on packets, which have been identified and
    /// registered as responses. Due to the message layout differing depending on the message type,
    /// many packets may not be correctly identified and their status may remain `Pending`. In this
    /// regard the summary stats may not accurately represent the number of packets sent out and
    /// their status.
    ///
    /// For the packets that have been received however, timing is very accurate - within the given
    /// capabilities of the host system, of course.
    ///
    /// # Panics
    ///
    /// This function panics if the mutex holding the registry has been poisoned.
    pub fn tally(&self) {
        println!("--- {} ping summary statistics ---", self.addr);

        // Total number of packages that have been registered for send-out
        let registry = self.registry.lock().unwrap();
        let sent = registry
            .values()
            .filter(|&tup| {
                // Ignore packets that have been sent after ctrl + c has been pressed
                tup.0 != ResponseStatus::Pending
            })
            .count();

        // Create filtered iterator of values containing only successful responses
        let iter: Vec<_> = registry
            .values()
            .filter_map(|tup| {
                if let (ResponseStatus::Received, _, Some(lapsed)) = tup {
                    Some(lapsed)
                } else {
                    None
                }
            })
            .collect();

        // Reported metrics are min, avg, max and stdev in ms with 3 decimals precision. To
        // calculate the avg we first need to determine the count and total time in transit of all
        // successfully received reply packets.
        let init = Duration::from_micros(0);
        let (min, total, max, count) = iter.iter().fold((init, init, init, 0u32), |acc, &x| {
            let min = if acc.0 <= *x && acc.0 != init {
                acc.0
            } else {
                *x
            };

            // The total will be needed for calculating the average
            let total = acc.1 + *x;
            let max = if acc.2 >= *x { acc.2 } else { *x };
            (min, total, max, acc.3 + 1)
        });

        // Loss is reported in % with 2 decimals precision
        let loss = (sent as f64 - count as f64) * 100f64 / sent as f64;

        println!(
            "{} packets transmitted, {} packets received, {:.2}% packet loss",
            sent, count, loss
        );

        // Average time in transit per packet
        let avg = total.as_secs_f64() / count as f64;

        // Sum of squared errors
        let sse: f64 = iter
            .into_iter()
            .map(|x| (x.as_secs_f64() - avg).powi(2))
            .sum();

        // Bessel-corrected sample standard deviation. The narrowing of the SSE is only done after
        // after the division, to reduce imprecision and likelihood of overflow
        let stdev = (sse / (count as f64 - 1f64)).sqrt();

        let min = min.as_secs_f64() * 1000f64;
        let max = max.as_secs_f64() * 1000f64;
        let avg = avg * 1000f64;
        let stdev = stdev * 1000f64;

        println!(
            "Time in transit min/avg/max/stdev: {:.3}/{:.3}/{:.3}/{:.3} ms",
            min, avg, max, stdev
        );
    }
}

//! # PINGO ping application
//!
//! This crate provides the components of a UNIX ping application. It consists of two major
//! components:
//! - The main `Sender` context which keeps track of the session and package information
//! - The `Receiver` which registers outgoing and incoming messages and does all the bookkeeping
//!
//! The `Sender` spans a context, in which it places the `Receiver`. After creation, the `Receiver`
//! plants its listening and processing threads. Each packet is timestamped right before it is
//! passed down to the `TransportSender` and again right after having been handed by the
//! `TransportReceiver`.

#[macro_use]
extern crate clap;
#[macro_use]
extern crate log;

use std::net::IpAddr;
use std::time::Duration;

pub mod cli;
pub mod logger;
pub mod packet;
pub mod receiver;
pub mod sender;

/// Application configuration
///
/// The `Config` will be consumed by the `Sender`.
pub struct Config {
    pub(crate) ttl: u8,
    pub(crate) delay: Duration,
    pub(crate) timeout: Option<Duration>,
    pub(crate) dest: Dest,
    pub(crate) size: usize,
}

/// Destination for ping
///
/// The user can choose to either provide an IP-address or a host name as destination for the ping.
/// The application automatically then handles dns lookup or reverse dns lookup based on the
/// provided argument.
#[derive(Debug, PartialEq, Eq)]
enum Dest {
    Ip(IpAddr),
    Host(String),
}

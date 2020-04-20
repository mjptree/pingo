//!

use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use super::{Config, Dest};
use crate::logger::StdLogger;

/// Application initialization
pub struct App;

impl App {
    /// Retrieve user input from command line
    ///
    /// The user can modify the following parameters of the application:
    /// - destination: Either as IP address or domain name (required)
    /// - ttl: The time to live for packages (default 56) - Not available for IPv6
    /// - delay: The interval between the sending of packets (default 1,000ms)
    /// - timeout: The timeout per packet (default None)
    /// - size: The payload size per packet (default 56 bytes)
    ///
    /// Note that the transmission size is limited by the network and your network device. Network
    /// devices are only required to require a Minimum Transmission Unit and exceeding the limit
    /// risks fragmentation of network packets. The MTU includes the payload the ICMP headers and
    /// the IP headers.
    pub fn parse_args() -> Result<Config, Box<dyn Error>> {
        // Define CLI interface here
        let args = clap_app!(pingo =>
			(version: "1.0")
			(author: "Michael Prantl <michael.prantl@hotmail.de")
			(about: "Send a ping to a host or address")
			(@arg destination: +required "Host name or destination address")
			(@arg verbose: -v --verbose "Sets the level of verbosity")
			(@arg ttl: -t --ttl +takes_value "Sets the time to live (TTL) - not supported on IPv6")
			(@arg delay: -d --delay +takes_value "Delays sending the next packet (in ms)")
			(@arg timeout: -o --timout +takes_value "Sets timeout for packets (in ms)")
			(@arg size: -s --size +takes_value "Sets packet size (in Bytes)"));

        #[cfg(not(test))]
        let matches = args.get_matches();

        #[cfg(test)]
        let matches = args.get_matches_from_safe(vec!["test_app_name", "127.0.0.1"])?;

        let verbose = matches.is_present("verbose");
        StdLogger::init(verbose);

        // Default for time to live is 56 hops
        let ttl = matches.value_of("ttl").unwrap_or("56").parse::<u8>()?;

        // Default for delay is 1 sec
        let delay = matches
            .value_of("delay")
            .unwrap_or("1000")
            .parse::<u64>()
            .map(|val| Duration::from_millis(val))?;

        // Default for timeout is None
        let timeout = match matches.value_of("timeout") {
            Some(val) => match val.parse::<u64>() {
                Ok(val) => Some(Duration::from_millis(val)),
                Err(e) => return Err(e.into()),
            },
            None => None,
        };

        // This function never returns with an error
        let dest = matches
            .value_of("destination")
            .map(|val| {
                if let Ok(ip) = val.parse::<Ipv4Addr>() {
                    return Dest::Ip(IpAddr::V4(ip));
                };
                if let Ok(ip) = val.parse::<Ipv6Addr>() {
                    return Dest::Ip(IpAddr::V6(ip));
                };

                // If the input provided is not a valid destination, it will fail
                // during dns resolution
                Dest::Host(val.to_string())
            })
            // Clap states calling `unwrap` on a required value is always safe
            .unwrap();

        // Default for packet size is 56 Bytes
        let size = matches.value_of("size").unwrap_or("56").parse::<usize>()?;
        if size > 60 {
            warn!("Beware of the Maximum Transmission Unit supported by your network device");
            warn!("If you do not receive any responses, try a smaller packet size");
        }

        if let Dest::Ip(IpAddr::V6(_)) = dest {
            info!("ICMPv6 types other than echo reply may not be recognized properly");
            if matches.is_present("ttl") {
                warn!("Setting TTL with IPv6 is currently not supported");
                warn!("Continuing with your system default...");
            }
        };

        trace!("Parsed configuration.");

        Ok(Config {
            ttl,
            delay,
            timeout,
            dest,
            size,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config() {
        let config = App::parse_args().unwrap();
        assert_eq!(config.ttl, 56);
        assert_eq!(config.delay, Duration::from_millis(1000));
        assert_eq!(config.timeout, None);
        assert_eq!(
            config.dest,
            Dest::Ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
        );
        assert_eq!(config.size, 56);
    }
}

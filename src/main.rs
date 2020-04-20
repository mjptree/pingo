#[macro_use]
extern crate log;

use pingo::{cli::App, sender::Sender};

fn main() {

    let config = match App::parse_args() {
        Ok(config) => config,
        Err(e) => {
            error!("Could not parse provided argument: {}", e);
            std::process::exit(1);
        }
    };

    trace!("Set up new sender context");

    let sender = match Sender::new(config) {
        Ok(tx) => tx,
        Err(e) => {
            error!("Could not configure ping session: {}", e);
            std::process::exit(1);
        }
    };

    trace!("Start ping session");

    let summary = match sender.ping() {
        Ok(res) => res,
        Err(e) => {
            error!("An error occurred during a running ping session: {}", e);
            std::process::exit(1);
        }
    };

    trace!("Successfully ended ping session");

    summary.tally();

    trace!("Shutting down...");
}

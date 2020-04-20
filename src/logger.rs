use log::{Level, LevelFilter, Log, Metadata, Record};
use std::io::{stderr, stdout, Write};
use std::sync::{Mutex, Once};

/// Log implementation for standard output streams
pub struct StdLogger(Mutex<()>);

impl StdLogger {
    /// Initialize logger
    ///
    /// Even if this function is called multiple times, initialization will only be done once.
    ///
    /// If initialization of the logger fails, the initializer will become poisoned and subsequent
    /// calls to this function will automatically fail, too.
    pub fn init(verbose: bool) {
        static INIT: Once = Once::new();

        // Initialization may run from more than one thread
        INIT.call_once(|| {
            if verbose {
                log::set_boxed_logger(Box::new(StdLogger(Mutex::new(()))))
                    .map(|_| log::set_max_level(LevelFilter::Info))
                    .unwrap();
            } else {
                log::set_boxed_logger(Box::new(StdLogger(Mutex::new(()))))
                    .map(|_| log::set_max_level(LevelFilter::Warn))
                    .unwrap();
            }
        });
    }
}

impl Log for StdLogger {
    /// This logger is enabled by default
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }

    /// Internal call to `write`
    fn log(&self, record: &Record) {
        let _ = self.0.lock().unwrap();
        match record.level() {
            Level::Error => {
                let stderr = stderr();
                let mut handle = stderr.lock();
                let _ = writeln!(handle, "[-] {}", record.args());
            }
            Level::Warn => {
                let stdout = stdout();
                let mut handle = stdout.lock();
                let _ = writeln!(handle, "[-] {}", record.args());
            }
            Level::Info => {
                let stdout = stdout();
                let mut handle = stdout.lock();
                let _ = writeln!(handle, "[i] {}", record.args());
            }
            _ => {
                let stdout = stdout();
                let mut handle = stdout.lock();
                let _ = writeln!(handle, "[+] {}", record.args());
            }
        }
    }

    /// Flush buffered output stream
    fn flush(&self) {
        let _ = stdout().flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logger_init() {
        // Init logger
        StdLogger::init(true);

        // Call different log implementations
        trace!("trace log succeeded");
        debug!("debug log succeeded");
        info!("info log succeeded");
        warn!("warn log succeeded");
        error!("error log succeeded");
    }

    #[test]
    fn logger_enabled() {
        use log::{logger, Metadata};

        // Init logger first...
        StdLogger::init(true);

        // ... then get reference to it
        let logger = logger();
        let meta = Metadata::builder().build();

        // Assert that it is active
        assert!(logger.enabled(&meta));
    }
}

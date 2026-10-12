//! Interruption handling for a long run (docs/09 "Interruption handling").
//!
//! | Signal | Behaviour |
//! |---|---|
//! | first `SIGINT` | finish the current unit, write its journal line, close the segment, exit 0 |
//! | second `SIGINT` | abort immediately (exit 130); the unit in flight is discarded and re-runs on resume |
//! | `SIGTERM` | as the first `SIGINT`, but with a shorter grace window (default 10 s), after which abort (exit 143) |
//!
//! The handler does the only thing a signal handler may safely do — bump an atomic counter. A
//! watchdog thread (ordinary safe Rust) turns the counters into an abort, and the run loop polls
//! [`requested`] between units. The one `unsafe` call is the `signal(2)` registration itself,
//! scoped and justified like the `setrlimit`/`kill` calls in this crate.
//!
//! Children run in their own process group (see `finish`), so a terminal Ctrl-C reaches only this
//! process: an in-flight `cargo` grade is not killed half-way and then recorded as a model failure.

use std::io;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

static SIGINTS: AtomicU32 = AtomicU32::new(0);
static SIGTERMS: AtomicU32 = AtomicU32::new(0);

/// What the run loop should do at the next unit boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stop {
    None,
    /// First `SIGINT`: stop cleanly after the current unit.
    Interrupt,
    /// `SIGTERM`: stop cleanly after the current unit if it ends inside the grace window.
    Terminate,
}

/// The stop requested so far (a `SIGTERM` wins over a first `SIGINT`: it carries a deadline).
pub fn requested() -> Stop {
    if SIGTERMS.load(Ordering::SeqCst) > 0 {
        Stop::Terminate
    } else if SIGINTS.load(Ordering::SeqCst) > 0 {
        Stop::Interrupt
    } else {
        Stop::None
    }
}

/// Default `SIGTERM` grace window.
pub const DEFAULT_TERM_GRACE: Duration = Duration::from_secs(10);

/// Exit status of an immediate abort: the shell convention `128 + signal`.
pub const EXIT_SIGINT: i32 = 130;
pub const EXIT_SIGTERM: i32 = 143;

/// Install the handlers and the watchdog. Idempotent; a no-op off unix.
pub fn install(term_grace: Duration) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::sync::Once;
        static ONCE: Once = Once::new();
        let mut result = Ok(());
        ONCE.call_once(|| {
            result = imp::install(term_grace);
        });
        result
    }
    #[cfg(not(unix))]
    {
        let _ = term_grace;
        Ok(())
    }
}

#[cfg(unix)]
mod imp {
    use super::*;

    extern "C" fn on_signal(sig: libc::c_int) {
        // Async-signal-safe: atomics only.
        if sig == libc::SIGINT {
            SIGINTS.fetch_add(1, Ordering::SeqCst);
        } else if sig == libc::SIGTERM {
            SIGTERMS.fetch_add(1, Ordering::SeqCst);
        }
    }

    pub fn install(term_grace: Duration) -> io::Result<()> {
        for sig in [libc::SIGINT, libc::SIGTERM] {
            #[allow(unsafe_code)]
            // SAFETY: `on_signal` is an `extern "C" fn(c_int)` that only touches atomics, which is
            // the contract for a signal handler; `signal` takes the handler by value and
            // dereferences no memory of ours.
            let prev = unsafe { libc::signal(sig, on_signal as *const () as libc::sighandler_t) };
            if prev == libc::SIG_ERR {
                return Err(io::Error::last_os_error());
            }
        }
        std::thread::spawn(move || {
            let mut term_seen: Option<std::time::Instant> = None;
            loop {
                std::thread::sleep(Duration::from_millis(25));
                if SIGINTS.load(Ordering::SeqCst) >= 2 {
                    std::process::exit(EXIT_SIGINT);
                }
                if SIGTERMS.load(Ordering::SeqCst) > 0 {
                    let t = *term_seen.get_or_insert_with(std::time::Instant::now);
                    if t.elapsed() >= term_grace {
                        std::process::exit(EXIT_SIGTERM);
                    }
                }
            }
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requested_reflects_the_counters_and_prefers_terminate() {
        // Counters are process-global; this test owns the only mutations of them in this binary.
        assert_eq!(requested(), Stop::None);
        SIGINTS.store(1, Ordering::SeqCst);
        assert_eq!(requested(), Stop::Interrupt);
        SIGTERMS.store(1, Ordering::SeqCst);
        assert_eq!(requested(), Stop::Terminate);
        SIGINTS.store(0, Ordering::SeqCst);
        SIGTERMS.store(0, Ordering::SeqCst);
        assert_eq!(requested(), Stop::None);
    }

    #[test]
    fn exit_codes_follow_the_shell_convention() {
        assert_eq!(EXIT_SIGINT, 128 + 2);
        assert_eq!(EXIT_SIGTERM, 128 + 15);
    }
}

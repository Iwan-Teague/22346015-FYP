//! The run's egress log (P-39j): [`EgressLog`] over the attempt's
//! [`JournalWriter`]. Every hop decision — allow or refusal — is appended
//! through the writer and fsynced (the `Egress` kind fsyncs, P-39c) before
//! any byte moves (INV-43), and a poisoned writer refuses the hop: the
//! journal stays the one durable account of what left the host.
//!
//! The body is the canonical §4.5 shape (its reader-side validation is
//! P-39c; this is the first producer). Runtime values enter only through
//! typed constructors: the host is a name the airlock's URL parser
//! validated (`Ident::from_dns_host`, re-checked as a backstop), the
//! addresses are `IpAddr`s, the decision/mode/purpose texts are a closed
//! static set, and the model-supplied URL rides in its untrusted payload
//! home (`Source::Model`, §4.5).

use std::cell::RefCell;

use harness_core::{Source, Untrusted};

use harness_journal::{BlobSink, Clock, Event, EventKind, JournalFile, JournalWriter, Trusted};
use harness_sandbox::egress::{
    EgressDecision, EgressLog, EgressLogError, EgressPurpose, EgressRecord, RefuseReason,
};

/// The egress log over one attempt's journal writer. The loop hands it to
/// the web provider through `InvokeCtx::egress` for the steps of a session
/// that grants web access; `append` writes the `Egress` record at the loop
/// step the hop belongs to. The record's own `hop` counter is the
/// session-wide hop index, not this step.
///
/// The driver-side wiring (building this over the run's writer and setting
/// `ctx.egress` for a research session's web steps) is the remainder of
/// P-39j; until it lands nothing constructs this, so the dead-code lint is
/// scoped off here rather than by weakening any lint globally.
#[allow(dead_code)]
pub(crate) struct JournalEgress<'w, F: JournalFile, B: BlobSink, K: Clock> {
    w: RefCell<&'w mut JournalWriter<F, B, K>>,
    step: u64,
}

impl<'w, F: JournalFile, B: BlobSink, K: Clock> JournalEgress<'w, F, B, K> {
    /// Log hops of `step` through `w`.
    #[allow(dead_code)]
    pub(crate) fn new(w: &'w mut JournalWriter<F, B, K>, step: u64) -> Self {
        Self {
            w: RefCell::new(w),
            step,
        }
    }
}

impl<F, B, K> EgressLog for JournalEgress<'_, F, B, K>
where
    F: JournalFile,
    B: BlobSink,
    K: Clock,
{
    fn append(&self, record: &EgressRecord) -> Result<(), EgressLogError> {
        // One borrow per record; nothing else holds the writer while a
        // hop is in flight (the loop invokes one provider at a time). A
        // re-entrant append would be a harness bug, and panics here.
        let mut w = self.w.borrow_mut();
        if w.is_poisoned() {
            return Err(EgressLogError("the journal writer is poisoned".into()));
        }
        // The decision is a closed static set on the wire (§4.5): the
        // same texts `wire_str` produces, named statically.
        let decision = match &record.decision {
            EgressDecision::Allow => "allow",
            EgressDecision::Refuse(reason) => match reason {
                RefuseReason::NonGlobalAddress => "refuse:non-global-address",
                RefuseReason::NoAddress => "refuse:no-address",
                RefuseReason::DnsTimeout => "refuse:dns-timeout",
                RefuseReason::Budget => "refuse:budget",
                RefuseReason::HostNotAllowlisted => "refuse:host-not-allowlisted",
                RefuseReason::Downgrade => "refuse:downgrade",
            },
        };
        let host = harness_journal::Ident::from_dns_host(&record.host).ok_or_else(|| {
            EgressLogError(format!(
                "the hop host {:?} is not a valid egress host",
                record.host
            ))
        })?;
        // The URL is the model's (or a redirect's) text: untrusted, in its
        // typed home (§4.5). A store failure poisons the writer and the
        // hop is refused — nothing moves on an unaccounted path.
        let url = w
            .untrusted(&Untrusted::new(record.url.clone(), Source::Model))
            .map_err(|e| EgressLogError(e.to_string()))?;
        let ev = Event::new(EventKind::Egress)
            .field("decision", Trusted::Text(decision))
            .field("host", Trusted::Id(host))
            .field("hop", Trusted::U64(record.hop))
            .field("ip", record.ip.map_or(Trusted::Null, Trusted::Ip))
            .field("mode", Trusted::Text(record.mode.as_str()))
            .field("port", Trusted::U64(u64::from(record.port)))
            .field("purpose", Trusted::Text(egress_purpose_str(record.purpose)))
            .field(
                "resolved",
                Trusted::List(record.resolved.iter().map(|ip| Trusted::Ip(*ip)).collect()),
            )
            .field("url", Trusted::Untrusted(url));
        w.append(self.step, ev)
            .map(|_| ())
            .map_err(|e| EgressLogError(e.to_string()))
    }
}

/// The `Egress` purpose's wire text (§4.5); `EgressPurpose` names no
/// `as_str` of its own, so the two doors are named here. Dormant with the
/// `JournalEgress` wiring it serves (see the struct's note).
#[allow(dead_code)]
fn egress_purpose_str(p: EgressPurpose) -> &'static str {
    match p {
        EgressPurpose::Fetch => "fetch",
        EgressPurpose::Search => "search",
    }
}

#[cfg(test)]
mod tests {
    //! INV-43's failure side: a journal that cannot take the `Egress`
    //! record refuses the hop, and nothing connects.

    use super::*;
    use harness_core::RunId;
    use harness_journal::testing::{FaultFile, FaultPlan, MemBlobs};
    use harness_journal::writer::SystemClock;
    use harness_journal::Ident;
    use harness_sandbox::egress::{
        open_hop, Connector, EgressMode, HopBudgets, HopRefused, HopRequest, ResolveRefused,
        Resolver,
    };
    use std::cell::Cell;
    use std::io;
    use std::net::{IpAddr, SocketAddr, TcpStream};
    use std::rc::Rc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    struct FakeResolver;

    impl Resolver for FakeResolver {
        fn resolve(&self, _host: &str, _port: u16) -> Result<Vec<IpAddr>, ResolveRefused> {
            Ok(vec!["93.184.216.34".parse().unwrap()])
        }
    }

    #[derive(Clone)]
    struct Counting(Arc<AtomicUsize>);

    impl Connector for Counting {
        fn connect(&self, _addr: SocketAddr) -> io::Result<TcpStream> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(io::Error::other("closed"))
        }
    }

    /// A journal writer over the fault file, with the fault file's write
    /// counter cloned out (the writer keeps the file private).
    fn writer(
        plan: FaultPlan,
    ) -> (
        JournalWriter<FaultFile, MemBlobs, SystemClock>,
        Rc<Cell<usize>>,
    ) {
        let f = FaultFile::new(plan);
        let writes = f.writes.clone();
        let w = JournalWriter::start(
            f,
            MemBlobs::default(),
            SystemClock::default(),
            RunId::new(0, [7; 10]),
            1,
            harness_journal::Header::new(Ident::of("0.0.1").unwrap())
                .field("os", Trusted::Text("test")),
        )
        .unwrap();
        (w, writes)
    }

    fn hop<'a>(token: &'a str) -> HopRequest<'a> {
        HopRequest {
            hop: 0,
            url: long_url(),
            host: "example.com".into(),
            port: 443,
            mode: EgressMode::Direct,
            purpose: EgressPurpose::Fetch,
            token,
            budgets: HopBudgets::default(),
        }
    }

    /// P-39j `poisoned_writer_refuses_fetch`: the fault-injected journal
    /// file fails the `Egress` record (the write, or its fsync) and the
    /// log refuses; once poisoned, the log refuses without touching the
    /// file again. And a writer poisoned by a failed blob store refuses
    /// the whole hop through `open_hop` with ZERO dials — the decision
    /// never leaves the journal unaccounted (INV-43).
    #[test]
    fn poisoned_writer_refuses_fetch() {
        let plans = [
            FaultPlan {
                fail_write: Some(2),
                ..FaultPlan::default()
            },
            FaultPlan {
                fail_sync: Some(2),
                ..FaultPlan::default()
            },
        ];
        for plan in plans {
            let (mut w, writes) = writer(plan);
            // The log borrows the writer for as long as it exists, so each
            // append gets a fresh one; the poison (a writer property) is
            // what carries between them.
            let refused = {
                let log = JournalEgress::new(&mut w, 4);
                log.append(&allow_record(0)).unwrap_err()
            };
            let _ = refused;
            assert!(w.is_poisoned(), "the failed append poisons the writer");
            let before = w_bytes(&writes);
            {
                let log = JournalEgress::new(&mut w, 4);
                let refused = log.append(&allow_record(1)).unwrap_err();
                let _ = refused;
            }
            assert_eq!(
                w_bytes(&writes),
                before,
                "a poisoned writer is not written to again"
            );
        }

        // Any poison (here: the blob store failing under the `Egress`
        // URL payload) refuses the hop before the connector dials. The
        // URL must be longer than the journal's inline carrier
        // (`INLINE_MAX`, 4096): a short URL rides inline in the record
        // and never reaches the blobs, where the injected failure lives.
        let mut w = JournalWriter::start(
            FaultFile::new(FaultPlan::default()),
            failing_blobs(),
            SystemClock::default(),
            RunId::new(0, [7; 10]),
            1,
            harness_journal::Header::new(Ident::of("0.0.1").unwrap())
                .field("os", Trusted::Text("test")),
        )
        .unwrap();
        {
            let log = JournalEgress::new(&mut w, 4);
            let dials = Arc::new(AtomicUsize::new(0));
            let refused =
                open_hop(&log, &FakeResolver, Counting(dials.clone()), &hop("tok")).unwrap_err();
            assert!(matches!(refused, HopRefused::Log(_)), "{refused:?}");
            assert_eq!(dials.load(Ordering::SeqCst), 0, "no byte moved");
            // Still poisoned: further hops refuse at once, still nothing dials.
            let refused =
                open_hop(&log, &FakeResolver, Counting(dials.clone()), &hop("tok")).unwrap_err();
            assert!(matches!(refused, HopRefused::Log(_)), "{refused:?}");
            assert_eq!(dials.load(Ordering::SeqCst), 0);
        }
    }

    fn failing_blobs() -> MemBlobs {
        let blobs = MemBlobs::default();
        blobs.fail.set(true);
        blobs
    }

    /// Longer than the journal's inline carrier (`INLINE_MAX`): stored to
    /// the blobs instead, where this module's injected failures live.
    fn long_url() -> String {
        format!("https://example.com/{}", "a".repeat(4200))
    }

    fn allow_record(hop: u64) -> EgressRecord {
        EgressRecord {
            hop,
            decision: EgressDecision::Allow,
            url: long_url(),
            host: "example.com".into(),
            port: 443,
            mode: EgressMode::Direct,
            purpose: EgressPurpose::Fetch,
            resolved: vec![],
            ip: Some("93.184.216.34".parse().unwrap()),
        }
    }

    /// The write count the fault file saw (the plan counts from 1, the
    /// header included): a poisoned writer must not be written to again.
    fn w_bytes(writes: &Rc<Cell<usize>>) -> usize {
        writes.get()
    }
}

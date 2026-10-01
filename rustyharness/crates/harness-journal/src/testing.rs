//! Fault-injecting seams for tests (design §7.1 "Testing", INV-33).
//!
//! Compiled only for this crate's own tests or with the `fault-injection`
//! cargo feature, which only `[dev-dependencies]` enable (harness-tools'
//! INV-33 end-to-end test). A release build of the harness has no way to
//! construct a `JournalFile` other than [`crate::writer::FsFile`]: the seam
//! is sealed (review F-3), and `scripts/ci/purity.sh` checks that no normal
//! dependency edge enables this feature.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::io;
use std::rc::Rc;

use crate::reader::BlobSource;
use crate::writer::{BlobSink, JournalFile, Sealed};

/// Which call to fail. Calls are counted from 1, header included.
#[derive(Debug, Default, Clone, Copy)]
pub struct FaultPlan {
    /// Fail this `write_all` call.
    pub fail_write: Option<usize>,
    /// On the failing write, first write half of the buffer (a torn line).
    pub short_write: bool,
    /// Fail this `sync_data` call.
    pub fail_sync: Option<usize>,
}

/// An in-memory journal file that fails on demand. The shared handles let
/// a test read the bytes and the call counts after the writer is gone.
#[derive(Debug)]
pub struct FaultFile {
    /// Everything written so far.
    pub buf: Rc<RefCell<Vec<u8>>>,
    /// `write_all` calls so far.
    pub writes: Rc<Cell<usize>>,
    /// `sync_data` calls so far.
    pub syncs: Rc<Cell<usize>>,
    plan: FaultPlan,
}

impl FaultFile {
    /// A file following `plan`.
    pub fn new(plan: FaultPlan) -> Self {
        Self {
            buf: Rc::default(),
            writes: Rc::default(),
            syncs: Rc::default(),
            plan,
        }
    }
}

impl Sealed for FaultFile {}

impl JournalFile for FaultFile {
    fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        let n = self.writes.get() + 1;
        self.writes.set(n);
        if self.plan.fail_write == Some(n) {
            if self.plan.short_write {
                let half = bytes.get(..bytes.len() / 2).unwrap_or(&[]);
                self.buf.borrow_mut().extend_from_slice(half);
            }
            return Err(io::Error::other("injected write failure"));
        }
        self.buf.borrow_mut().extend_from_slice(bytes);
        Ok(())
    }

    fn sync_data(&mut self) -> io::Result<()> {
        let n = self.syncs.get() + 1;
        self.syncs.set(n);
        if self.plan.fail_sync == Some(n) {
            return Err(io::Error::other("injected fsync failure"));
        }
        Ok(())
    }
}

/// An in-memory blob store that can be told to fail; also a
/// [`BlobSource`] for the reader.
#[derive(Debug, Clone, Default)]
pub struct MemBlobs {
    /// Stored blobs by name.
    pub map: Rc<RefCell<BTreeMap<String, Vec<u8>>>>,
    /// When set, every `put` fails.
    pub fail: Rc<Cell<bool>>,
}

impl Sealed for MemBlobs {}

impl BlobSink for MemBlobs {
    fn put(&mut self, name: &str, bytes: &[u8]) -> io::Result<()> {
        if self.fail.get() {
            return Err(io::Error::other("injected blob failure"));
        }
        self.map
            .borrow_mut()
            .insert(name.to_owned(), bytes.to_vec());
        Ok(())
    }
}

impl BlobSource for MemBlobs {
    fn get(&self, name: &str) -> Option<Vec<u8>> {
        self.map.borrow().get(name).cloned()
    }
}

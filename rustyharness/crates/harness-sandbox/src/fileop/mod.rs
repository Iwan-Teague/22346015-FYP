//! The `rh-fileop/1` file-operation protocol (design §7.3).
//!
//! This module holds the protocol codec ([`proto`]) and, on macOS, the
//! confined helper that executes the requests (P-36d, §7): one fork-less
//! perl stub under its own Seatbelt profile, kept across requests and
//! asked one `rh-fileop/1` frame at a time with a per-request deadline
//! (§7.2, §7.5). Both the macOS stub and the Linux backend speak the same
//! frames (design §8.4), so the codec is built unconditionally and is
//! backend-neutral; the helper is platform code.

pub mod proto;

pub use proto::{
    CodecError, ErrorCode, Reply, Request, MAX_ITEM_LENGTH_DIGITS, MAX_LINE_BYTES,
    MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES,
};

/// The confined file-op helper (P-36d, §7): start it, send requests with
/// deadlines, let it restart.
#[cfg(target_os = "macos")]
mod helper {
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant, SystemTime};

    use crate::confine_spawn;
    use crate::fileop::proto::{CodecError, ErrorCode, Reply, Request, MAX_RESPONSE_BYTES};
    use crate::profile::{render_fileop, UnsafePath};
    use crate::ring::{Mode, Stream};
    use crate::spec::{ConfinedSpec, Context, Enforceable, SpecError, Validated};
    use crate::{BackendKind, Conformed};

    /// One reply frame is at most the response bound (§7.3); the poller
    /// reads a window at a time.
    const READ_WINDOW: usize = 64 * 1024;

    /// Everything that can go wrong between a typed request and its typed
    /// reply. Kernel refusals are NOT errors here: they arrive as
    /// [`Reply::Err`] inside `Ok` — they are the helper's answers, not
    /// lost conversations.
    #[derive(Debug, thiserror::Error)]
    pub enum FileOpError {
        /// The request ran past its deadline; the helper was stopped and
        /// will be restarted by the next request (§7.5).
        #[error("the fileop request ran past its deadline; the helper was stopped")]
        Timeout,
        /// The helper died, sent garbage or went silent past a deadline:
        /// the conversation cannot continue on this instance.
        #[error("the fileop helper was lost: {0}")]
        Lost(String),
        /// The witness does not back this backend (fail closed, as a
        /// spawn without a probe would be).
        #[error("the fileop helper needs a seatbelt witness")]
        Witness,
        /// The request or reply would not encode (a bug, not a refusal).
        #[error(transparent)]
        Codec(#[from] CodecError),
        /// The spec was refused before any helper existed.
        #[error(transparent)]
        Spec(#[from] SpecError),
        /// A root path was unsafe to render into policy text.
        #[error(transparent)]
        Path(#[from] UnsafePath),
        /// Filesystem trouble around the helper's private directory or
        /// spawn (the conversation itself never reports plain I/O).
        #[error("{0}")]
        Io(String),
    }

    /// One confined helper instance over one workspace (§7.1): a private
    /// directory holding its Seatbelt profile, one stub process serving
    /// `rh-fileop/1` frames, and enough state to restart it when it dies
    /// or times out (§7.5). Dropping it stops the helper and removes the
    /// private directory.
    pub struct FileOpHelper {
        run: Option<confine_spawn::Running>,
        /// The approved view of the spec: a restart respawns from it
        /// without re-deriving the context.
        validated: Validated,
        profile: PathBuf,
        dir: PathBuf,
        sweep: Duration,
        restarts: u32,
        /// The absolute offset into the stub's stdout already consumed by
        /// decoded replies; reply frames are read from here, never from
        /// the start of the stream.
        out_cursor: u64,
    }

    // No `Sync` is claimed; the helper is driven from one thread.
    impl FileOpHelper {
        /// Validate the spec, render the file-op profile (§7.1: no fork,
        /// the stub interpreter executable only, workspace read-write or
        /// read-only) and start the stub. `witness` must back the seatbelt
        /// backend; the helper spawns nothing otherwise (fail closed).
        pub fn start(
            spec: &ConfinedSpec,
            witness: &Conformed,
            home: Option<&Path>,
            private_root: &Path,
            sweep: Duration,
        ) -> Result<Self, FileOpError> {
            if witness.backend() != BackendKind::Seatbelt {
                return Err(FileOpError::Witness);
            }
            let dir = private_dir(private_root).map_err(|e| FileOpError::Io(e.to_string()))?;
            let this = Self::launch(spec, home, &dir, sweep);
            match this {
                Ok(this) => Ok(this),
                Err(e) => {
                    let _ = std::fs::remove_dir_all(&dir);
                    Err(e)
                }
            }
        }

        fn launch(
            spec: &ConfinedSpec,
            home: Option<&Path>,
            dir: &Path,
            sweep: Duration,
        ) -> Result<Self, FileOpError> {
            let cx = Context {
                home,
                private_dir: dir,
                enforce: Enforceable {
                    memory: true,
                    processes: true,
                },
                reserved_ports: &[],
                ports_conformed: false,
                proxy: false,
            };
            let approved = crate::spec::validate(spec, &cx)?;
            let text = render_fileop(&approved.spec)?;
            let profile = dir.join("fileop.sb");
            std::fs::write(&profile, text).map_err(|e| FileOpError::Io(e.to_string()))?;
            // The private directory outlives the process: the helper must
            // be able to restart from the same profile, so the running
            // child is NOT made responsible for cleaning it (its `Drop`
            // would delete the profile out from under the restart).
            let run = confine_spawn::spawn_fileop(&profile, &approved.spec, sweep, None)
                .map_err(|e| FileOpError::Io(e.to_string()))?;
            Ok(Self {
                run: Some(run),
                validated: approved.spec,
                profile,
                dir: dir.to_path_buf(),
                sweep,
                restarts: 0,
                out_cursor: 0,
            })
        }

        /// The stub's pid while it runs.
        pub fn pid(&self) -> Option<u32> {
            self.run.as_ref().and_then(|r| r.pid())
        }

        /// How many times this instance has (re)started a stub after the
        /// first, whether by an explicit [`restart`](Self::restart) or
        /// automatically at the next request (§7.5).
        pub fn restarts(&self) -> u32 {
            self.restarts
        }

        /// Send one request and wait for its reply with a deadline (§7.2):
        /// a kernel refusal comes back as `Ok(Reply::Err)`; a deadline
        /// miss stops the helper and returns [`FileOpError::Timeout`]; a
        /// dead or impolite helper comes back as [`FileOpError::Lost`].
        /// If the helper is not running (first use, or a previous loss),
        /// it is restarted first — a restart at the next file call, not a
        /// new instance (§7.5).
        pub fn request(&mut self, req: &Request, deadline: Duration) -> Result<Reply, FileOpError> {
            if self.run.is_none() {
                self.restart()?;
            }
            let bytes = req.encode()?;
            match self.run.as_mut() {
                Some(run) => run.send(&bytes).map_err(|e| {
                    FileOpError::Lost(format!("the control pipe refused the request: {e}"))
                })?,
                None => {
                    return Err(FileOpError::Lost(
                        "no helper to talk to after the restart".to_string(),
                    ))
                }
            }
            let deadline_at = Instant::now() + deadline;
            let mut buf: Vec<u8> = Vec::new();
            let mut cursor = self.out_cursor;
            loop {
                if let Some(exit) = self.run.as_mut().and_then(|r| r.try_status()) {
                    // The stub's stderr tail carries its final report line
                    // (and a compile error, if the text ever stops being
                    // valid perl) — name it so a loss is diagnosable.
                    let tail = self
                        .last_stderr_tail()
                        .map(|t| format!("; stub stderr: {t}"))
                        .unwrap_or_default();
                    self.run = None;
                    return Err(FileOpError::Lost(format!(
                        "the helper exited before answering (status {:?}){tail}",
                        exit.status
                    )));
                }
                let chunk = match self.run.as_ref() {
                    Some(run) => run.read(Stream::Out, cursor, READ_WINDOW, Mode::Next),
                    None => {
                        return Err(FileOpError::Lost(
                            "the helper vanished mid-request".to_string(),
                        ))
                    }
                };
                cursor = chunk.to;
                if chunk.dropped > 0 || chunk.skipped > 0 {
                    self.run = None;
                    return Err(FileOpError::Lost(
                        "the helper's reply overflowed its ring (impossible bound)".to_string(),
                    ));
                }
                buf.extend_from_slice(&chunk.bytes);
                if buf.len() > MAX_RESPONSE_BYTES {
                    self.run = None;
                    return Err(FileOpError::Lost(
                        "the helper's reply is larger than the protocol allows".to_string(),
                    ));
                }
                match Reply::decode(&buf) {
                    Ok(reply) => {
                        self.out_cursor = cursor;
                        return Ok(reply);
                    }
                    // A partial frame is normal: keep polling until the
                    // deadline. A broken frame is fatal to the stream.
                    Err(CodecError::BadFrame) => {}
                    Err(e) => {
                        self.run = None;
                        return Err(FileOpError::Lost(format!(
                            "the helper sent a broken reply: {e}"
                        )));
                    }
                }
                if Instant::now() >= deadline_at {
                    // Stop and collect so the kill domain is emptied; the
                    // next request restarts a fresh stub (§7.5).
                    if let Some(run) = self.run.take() {
                        let _ = run.stop();
                    }
                    return Err(FileOpError::Timeout);
                }
                std::thread::sleep(Duration::from_millis(2));
            }
        }

        /// The view check that starts every session (§7.1, §7.5): a ping
        /// naming a path outside the workspace must be refused by the
        /// kernel view. Any other answer means the confinement is not
        /// what the profile says and the helper must not be trusted.
        pub fn ping(
            &mut self,
            outside_probe_path: &str,
            deadline: Duration,
        ) -> Result<(), FileOpError> {
            let req = Request::Ping {
                outside_probe_path: outside_probe_path.to_string(),
            };
            match self.request(&req, deadline)? {
                Reply::Err {
                    code: ErrorCode::Denied,
                } => Ok(()),
                other => Err(FileOpError::Lost(format!(
                    "the view check failed: the probe answered {other:?}"
                ))),
            }
        }

        /// Stop the running stub (if any) and start a fresh one from the
        /// same profile and spec (§7.5). The restart counter advances.
        pub fn restart(&mut self) -> Result<(), FileOpError> {
            if let Some(run) = self.run.take() {
                let _ = run.stop();
            }
            let run = confine_spawn::spawn_fileop(&self.profile, &self.validated, self.sweep, None)
                .map_err(|e| FileOpError::Io(format!("the helper could not restart: {e}")))?;
            self.run = Some(run);
            self.restarts += 1;
            Ok(())
        }

        /// The last ~512 bytes of the helper's stderr, for a Lost report.
        fn last_stderr_tail(&self) -> Option<String> {
            let run = self.run.as_ref()?;
            let chunk = run.read(Stream::Err, 0, 512, Mode::Tail);
            Some(String::from_utf8_lossy(&chunk.bytes).into_owned())
        }

        /// Stop the helper and remove the private directory.
        fn cleanup(&mut self) {
            if let Some(run) = self.run.take() {
                let _ = run.stop();
            }
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    impl Drop for FileOpHelper {
        fn drop(&mut self) {
            self.cleanup();
        }
    }

    /// A fresh 0700 directory under `root` for one helper instance (the
    /// seatbelt backend's pattern, §7.1: one profile per instance).
    fn private_dir(root: &Path) -> std::io::Result<PathBuf> {
        use std::os::unix::fs::DirBuilderExt;
        let root = std::fs::canonicalize(root)?;
        for attempt in 0u32..16 {
            let nanos = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let dir = root.join(format!(
                "rh-fileop-{}-{nanos:x}-{}",
                std::process::id(),
                attempt
            ));
            match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
                Ok(()) => return Ok(dir),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
        }
        Err(std::io::Error::other("no unique private directory"))
    }
}

#[cfg(target_os = "macos")]
pub use helper::{FileOpError, FileOpHelper};

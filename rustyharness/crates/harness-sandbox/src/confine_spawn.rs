//! The confined spawn (design §6.3, macOS): the harness's second and last
//! reviewed spawn module. `scripts/ci/purity.sh` §2f admits the word
//! `Command` here and in `capture.rs` only, pins this file by its SHA-256,
//! and allows exactly three programs in it: `/usr/bin/sandbox-exec`,
//! `/usr/bin/perl` (the domain stub, run inside the sandbox) and `/bin/kill`
//! (the harness-side process-group kill, argv an integer). Changing this
//! file means updating `confine_spawn_sha256` there, by review.
//!
//! **Shape.** `/usr/bin/sandbox-exec -f <profile> /usr/bin/perl -e <STUB>`,
//! with a cleared environment, stdin a pipe (the control pipe), stdout and
//! stderr pipes, and its own process group. Nothing variable reaches this
//! argv but the harness-generated profile path: the program, its argv, its
//! environment and its limits travel over the control pipe, framed, so the
//! stub itself runs with an empty environment (no `PERL5OPT` or `PERL5LIB`
//! can reach it) and no payload is on any argv of the harness's making
//! (INV-23; the program's own argv is `exec.run`'s, §4.8).
//!
//! **The domain stub** (option C of the OD-5 review, F-2). Inside the
//! sandbox, the stub forks and execs the program with stdin `/dev/null`,
//! exactly the spec's environment, core dumps off and the spec's CPU,
//! file-size and memory limits (`setrlimit` through perl's `syscall`: no
//! Rust `unsafe`). It waits for the program to exit, or for the control pipe
//! to become readable: the harness closes it at the deadline, and the kernel
//! closes it if the harness dies. Then it **sweeps**: each pass sends
//! SIGKILL to every pid from 2 to 99999 (macOS's pid range) except its
//! own, and the kernel delivers it only to processes of the same sandbox
//! instance, because the profile allows `signal` only with `(target
//! same-sandbox)` (measured: E4, and the review's M-6). Passes repeat
//! until one kills nothing, for at most the sweep deadline of the frame
//! (3 s unless the caller asks for more; the stub bounds it, P-41).
//! Passes back off from 5 ms to 50 ms, so on a loaded host, where killed
//! processes are slow to exit, the sweep still converges well inside the
//! sweep grace. A `setsid` or double-forked
//! descendant cannot leave the sandbox instance, so it is swept too (E8).
//!
//! **Memory guard (FT-6, H2c).** When the spec sets a memory budget, the
//! pre-exec child reads its own virtual size (`proc_pidinfo`
//! `PROC_PIDTASKINFO`) and sets `RLIMIT_AS` to that plus the budget, so the
//! kernel refuses any `mmap`/`brk` past it. Measured enforced on macOS
//! 26.5.1 (the H2a report's "RLIMIT_AS is not enforced" was wrong for this
//! host). The limit is inherited across fork and exec, so it bounds every
//! process of the tree — each to the budget, so the tree's total is at most
//! `members * budget`; the process guard bounds `members`.
//!
//! **Process guard (FT-5, H2c).** When the spec sets a process cap, the
//! wait loop counts the sandbox instance's members (the same `kill(0)` scan
//! the sweep uses, about 15-20 ms) roughly every 240 ms, and when the
//! program's members exceed the cap it stops waiting and sweeps, reporting
//! `end=procs`. `RLIMIT_NPROC` is per user on macOS, so it cannot bound one
//! sandbox; this watchdog is the honest per-sandbox bound. Its guarantee is
//! a bound on *sustained* members: a burst between two counts is bounded
//! only by the fork rate times the interval, and the per-user ceiling
//! (`kern.maxprocperuid`) is the machine's backstop.
//!
//! **Canary interlock (start check).** Before it reads the frame or starts
//! anything, the stub checks that the signal filter is in force, against a
//! target that is certainly alive and certainly outside the sandbox: its
//! parent, the unconfined harness, which is blocked writing the frame.
//! It requires the parent pid to be above 1 (not re-parented to launchd),
//! signal 0 to it to FAIL, and the error to be exactly `EPERM` (1 on
//! Darwin): the kernel's refusal, not "no such process". Anything else
//! means the filter cannot be shown to hold, so a sweep could reach the
//! user's own processes: the stub reports `canary` with `end=start` and
//! `exec=none`, starts nothing and exits 4. A Seatbelt profile cannot be
//! changed or removed for the rest of the process's life, so one verified
//! start is enough (review follow-up 1). This also puts the signal rule
//! under the live probe: a broadened rule makes the probe's own stub
//! refuse, so no witness is minted.
//!
//! **Per-pass check.** Before each sweep pass the stub signals 0 to the
//! same parent again and accepts `EPERM` (the parent is alive and
//! still refused), `ESRCH` (3: the harness has gone, e.g. crashed), or —
//! measured on this host — a signal 0 that the kernel *accepted* while the
//! stub is already reparented to `launchd`: on macOS `kill(0, zombie)`
//! succeeds even under the profile, and a SIGKILLed harness sits in its
//! own parent as an unreaped zombie for at least one scheduler wakeup
//! (2-3 ms measured), while the stub, woken by the same death's
//! control-pipe EOF, reaches its first check within microseconds and used
//! to forfeit the crash sweep to that race every time (the conformance
//! suite's reaper thread loses it routinely). The stub can tell the two
//! cases apart without guessing: a live harness is always still its
//! parent, so `getppid() == $pp`; a reparented stub's parent cannot come
//! back, so the accepted signal cannot have reached the harness (and
//! after a verified start the filter cannot have changed). Success
//! against a parent `getppid()` still reports, or any other error, means
//! the filter cannot be shown to hold: the stub reports `canary` and
//! stops sweeping.
//!
//! **Report.** The stub's last act is one line on stderr, `rh-stub/1
//! <confirmed|unconverged|canary> status=<wait status>
//! end=<exit|stop|start|procs> kills=<n> exec=<ok|failed|limit|none>`
//! (`end=procs`: the process guard fired), and exit 0 only for `confirmed`
//! (3 for `unconverged` or a mid-run `canary`, 4 for a refused start, 90 to
//! 93 when the frame is unreadable or nothing could be forked).
//! Every member of the domain is dead before it writes, so no member can
//! write after it: the harness trusts the line only as the final bytes of
//! stderr and only with exit status 0.
//!
//! **What is not guaranteed** (named in the H2a report): every member has
//! the same signal right as the stub, so a member can kill or stop the stub
//! first. The harness then sees no valid report and reports
//! [`DomainCleanup::Unconfirmed`], never a clean stop, and kills the
//! process group from outside; a descendant that already left the group
//! with `setsid` survives (still confined). Closing that needs the
//! `sandbox_check` membership sweep (spike S-M2, an audited `unsafe`
//! crate, §6.7).

use std::io::{Read, Write};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use crate::fileop_stub::FILEOP_STUB;
use crate::ring::{Chunk, Mode, Ring, Stream, StreamTotals};
use crate::spec::{ChildStatus, ConfinedExit, DomainCleanup, Validated};
use crate::LiveOpts;

/// Which stub a confined instance runs (P-36d, §7.1): the domain stub
/// (fork a program, sweep the instance when the call ends) or the file-op
/// stub (serve `rh-fileop/1` requests; forks nothing, so the instance is
/// exactly one process). The closed enum keeps the spawn free of free
/// text: both stub texts are pinned constants.
pub(crate) enum Stub {
    Domain,
    FileOp,
}

/// The sweep deadline a call asks for unless it says otherwise: the stub
/// sweeps for at most this long (P-41: the live probe's one retry of a
/// timeout asks for triple; the stub bounds whatever the frame says to
/// 1-30 s, so a frame cannot ask for a zero or unbounded sweep).
pub const SWEEP_DEADLINE: Duration = Duration::from_secs(3);
/// How much time the stub gets ON TOP of its sweep deadline before the
/// harness kills it and reports the domain unconfirmed (the kill scan's
/// own pace; the base deadline's grace is 3 s + 2 s = 5 s, as reviewed).
const SWEEP_GRACE_MARGIN: Duration = Duration::from_secs(2);
/// How long the readers may take to reach end of file after the stub ended.
pub const READ_GRACE: Duration = Duration::from_secs(2);
/// How often the deadline closer re-checks whether its moment has come or
/// the pipe was taken from it already (a stop, a collect, or a drop).
const LIVE_TICK: Duration = Duration::from_millis(50);

/// The domain stub, run by `/usr/bin/perl -e` inside the sandbox (see the
/// module docs). No double quote appears in it, so the gate's program-literal
/// scan reads only the three programs above.
pub const STUB: &str = r#"$SIG{PIPE}='IGNORE';$SIG{TERM}='IGNORE';$SIG{INT}='IGNORE';$SIG{HUP}='IGNORE';$SIG{QUIT}='IGNORE';
my $pp=getppid();
if($pp<=1 || kill(0,$pp) || ($!+0)!=1){print STDERR qq{\nrh-stub/1 canary status=-2 end=start kills=0 exec=none\n}; exit 4}
open(my $c,'<&',\*STDIN) or exit 90; binmode $c;
sub rl{my($l,$ch)=('');while(1){my $n=sysread($c,$ch,1);return undef unless $n;return $l if $ch eq qq{\n};$l.=$ch;return undef if length($l)>64;}}
sub rn{my $n=shift;my $b='';while(length($b)<$n){my $r=sysread($c,$b,$n-length($b),length($b));return undef unless $r;}return $b}
sub item{my $n=rl();return undef unless defined $n && $n=~/^[0-9]{1,8}$/;return rn($n) if $n>0;return ''}
my $m=rl(); exit 91 unless defined $m && $m eq 'rh-stub/1';
my $li=rl(); exit 91 unless defined $li && $li=~/^lim ([0-9]{1,12}) ([0-9]{1,15}) ([0-9]{1,15}) ([0-9]{1,6})( ([0-9]{1,2}))?$/; my ($cpu,$fs,$mem,$np)=($1,$2,$3,$4); my $sw=defined($6)?$6:3; exit 91 if $sw<1 || $sw>30;
my $ac=rl(); exit 91 unless defined $ac && $ac=~/^[1-9][0-9]{0,5}$/;
my @a; for(1..$ac){my $x=item(); exit 91 unless defined $x; push @a,$x}
my $ec=rl(); exit 91 unless defined $ec && $ec=~/^[0-9]{1,6}$/;
my @e; for(1..$ec){my $x=item(); exit 91 unless defined $x; push @e,$x}
open(STDIN,'<','/dev/null') or exit 92;
pipe(my $er,my $ew) or exit 93;
my $pid=fork(); exit 93 unless defined $pid;
if($pid==0){ close $er; %ENV=(); for(@e){my($k,$v)=split(/=/,$_,2);$ENV{$k}=$v}
 for my $s ('PIPE','TERM','INT','HUP','QUIT'){$SIG{$s}='DEFAULT'}
 my $z=pack('QQ',0,0); syscall(195,4,$z);
 if($cpu>0){my $b=pack('QQ',$cpu,$cpu); if(syscall(195,0,$b)!=0){syswrite($ew,'L');exit 126}}
 if($fs>0){my $b=pack('QQ',$fs,$fs); if(syscall(195,1,$b)!=0){syswrite($ew,'L');exit 126}}
 if($mem>0){my $ti=chr(0)x96; if(syscall(336,2,$$+0,4,0,$ti,96)!=96){syswrite($ew,'L');exit 126} my $lim=unpack('Q',substr($ti,0,8))+$mem; my $b=pack('QQ',$lim,$lim); if(syscall(195,5,$b)!=0){syswrite($ew,'L');exit 126}}
 exec {$a[0]} @a; syswrite($ew,'E'); exit 127 }
close $ew;
my $st=-1; my $why='exit'; my $poll=0;
while(1){ my $w=waitpid($pid,1); if($w==$pid){$st=$?;last} my $rin='';vec($rin,fileno($c),1)=1; my $n=select(my $ro=$rin,undef,undef,0.02); if($n>0){$why='stop';last} if($np>0 && ++$poll>=12){$poll=0; my $mc=0; for my $q (2..99999){$mc++ if kill(0,$q)} if($mc-1>$np){$why='procs';last}} }
my ($k,$res)=(0,'unconverged');
my $t0=time; PASS: for my $p (1..1000){ my $hit=kill(0,$pp); my $en=$!+0; if($hit ? getppid()==$pp : ($en!=1 && $en!=3)){$res='canary';last PASS} my $n=0; for my $q (2..99999){next if $q==$$; $n++ if kill('KILL',$q)} 1 while waitpid(-1,1)>0; $k+=$n; if($n==0){$res='confirmed';last PASS} last PASS if time-$t0>=$sw; my $w=0.005*$p; $w=0.05 if $w>0.05; select(undef,undef,undef,$w) }
my $ef=''; if($res eq 'confirmed'){sysread($er,$ef,1)}
my $ex = $ef eq 'E' ? 'failed' : $ef eq 'L' ? 'limit' : 'ok';
if($st==-1){$st=-2}
print STDERR qq{\nrh-stub/1 $res status=$st end=$why kills=$k exec=$ex\n};
exit($res eq 'confirmed' ? 0 : 3);
"#;

/// One running confined call.
pub(crate) struct Running {
    child: Option<Child>,
    /// The control pipe, shared with the deadline closer (live calls): the
    /// closer drops it when the lifetime is up, and every ending path takes
    /// it, which also ends the closer.
    stdin: Arc<Mutex<Option<ChildStdin>>>,
    out: Arc<Mutex<Ring>>,
    err: Arc<Mutex<Ring>>,
    out_done: mpsc::Receiver<()>,
    err_done: mpsc::Receiver<()>,
    /// Set by the readers at end of file: live reads strip the stub's exit
    /// report from stderr only once its stream is finished (§3.2).
    out_set: Arc<AtomicBool>,
    err_set: Arc<AtomicBool>,
    started: Instant,
    deadline: Instant,
    sweep: Duration,
    cleanup_dir: Option<PathBuf>,
    /// The collected exit of an already-ended call (`try_status` is
    /// idempotent; `wait` and `stop` return it instead of collecting twice).
    finished: Option<ConfinedExit>,
}

fn lock(m: &Mutex<Ring>) -> std::sync::MutexGuard<'_, Ring> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn lock_stdin(m: &Mutex<Option<ChildStdin>>) -> std::sync::MutexGuard<'_, Option<ChildStdin>> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// What a stream reader hands back: the bounded ring it fills, a receiver
/// that fires once at end of file, and the end-of-file flag (§3.2).
type Reader = (Arc<Mutex<Ring>>, mpsc::Receiver<()>, Arc<AtomicBool>);

fn reader(mut from: impl Read + Send + 'static, cap: u64) -> std::io::Result<Reader> {
    let buf = Arc::new(Mutex::new(Ring::new(cap)));
    let (tx, rx) = mpsc::channel();
    let set = Arc::new(AtomicBool::new(false));
    let b = Arc::clone(&buf);
    let s = Arc::clone(&set);
    std::thread::Builder::new().spawn(move || {
        let mut chunk = vec![0u8; 64 * 1024];
        loop {
            match from.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let data = chunk.get(..n).unwrap_or_default();
                    lock(&b).push(data);
                }
            }
        }
        s.store(true, Ordering::Release);
        let _ = tx.send(());
    })?;
    Ok((buf, rx, set))
}

fn frame(v: &Validated, sweep: Duration) -> Vec<u8> {
    let cpu = v
        .limits
        .cpu
        .map_or(0, |c| c.as_secs() + u64::from(c.subsec_nanos() > 0));
    let fs = v.limits.file_size.unwrap_or(0);
    // The memory budget (RLIMIT_AS growth, FT-6), the process cap (the
    // watchdog threshold, FT-5) and the sweep deadline (P-41): 0 means "no
    // limit" for the first two; the deadline is clamped to what the stub
    // accepts. `validate` bounds both limits to what this line accepts
    // (spec::MAX_MEMORY, MAX_PROCESSES); the stub bounds the deadline again.
    let mem = v.limits.memory.unwrap_or(0);
    let procs = v.limits.processes.unwrap_or(0);
    let sweep = sweep.as_secs().clamp(1, 30);
    let mut h = format!(
        "rh-stub/1\nlim {cpu} {fs} {mem} {procs} {sweep}\n{}\n",
        v.argv.len()
    )
    .into_bytes();
    for a in &v.argv {
        h.extend(format!("{}\n", a.len()).into_bytes());
        h.extend_from_slice(a);
    }
    h.extend(format!("{}\n", v.env.len()).into_bytes());
    for e in &v.env {
        h.extend(format!("{}\n", e.len()).into_bytes());
        h.extend_from_slice(e);
    }
    h
}

/// Start `v` under the profile at `profile`. The stub sweeps for at most
/// `sweep` when the call ends (bounded, P-41). `cleanup_dir` is removed
/// when the call has ended.
pub(crate) fn spawn(
    profile: &Path,
    v: &Validated,
    sweep: Duration,
    cleanup_dir: Option<PathBuf>,
) -> std::io::Result<Running> {
    launch(
        profile,
        v,
        sweep,
        cleanup_dir,
        v.limits.output_bytes,
        None,
        Stub::Domain,
    )
}

/// Start `v` under the profile as a live call: output is readable from
/// bounded rings of `live.ring_bytes` while the program runs, and the
/// control pipe closes by itself once `live.lifetime` has passed since the
/// spawn, so a caller that stops reading (or dies) still gets a swept
/// domain (§4.2). Fails closed on a ring or lifetime outside its bound.
pub(crate) fn spawn_live(
    profile: &Path,
    v: &Validated,
    sweep: Duration,
    cleanup_dir: Option<PathBuf>,
    live: &LiveOpts,
) -> std::io::Result<Running> {
    if live.ring_bytes == 0 || live.ring_bytes > crate::spec::MAX_OUTPUT_BYTES {
        return Err(std::io::Error::other(
            "live ring_bytes must be within 1..=MAX_OUTPUT_BYTES",
        ));
    }
    if live.lifetime.is_zero() || live.lifetime > crate::spec::MAX_WALL {
        return Err(std::io::Error::other(
            "live lifetime must be nonzero and within MAX_WALL",
        ));
    }
    launch(
        profile,
        v,
        sweep,
        cleanup_dir,
        live.ring_bytes,
        Some(live),
        Stub::Domain,
    )
}

/// Start the file-op helper instance (P-36d, §7.1): the file-op stub, no
/// frame written (requests start at once over the control pipe), the stdout
/// ring sized to the codec's response bound so a full reply is never
/// dropped by the ring, and no live lifetime (the caller drives the helper
/// and ends it by dropping it or by its own deadline).
pub(crate) fn spawn_fileop(
    profile: &Path,
    v: &Validated,
    sweep: Duration,
    cleanup_dir: Option<PathBuf>,
) -> std::io::Result<Running> {
    launch(
        profile,
        v,
        sweep,
        cleanup_dir,
        crate::fileop::proto::MAX_RESPONSE_BYTES as u64,
        None,
        Stub::FileOp,
    )
}

/// The one launch path (§6.3): every confined child comes from here, live
/// or not. `ring_bytes` sizes both stream rings; for a plain call it is the
/// spec's output cap, so `wait` keeps the head semantics it always had.
fn launch(
    profile: &Path,
    v: &Validated,
    sweep: Duration,
    cleanup_dir: Option<PathBuf>,
    ring_bytes: u64,
    live: Option<&LiveOpts>,
    stub: Stub,
) -> std::io::Result<Running> {
    let started = Instant::now();
    let stub_text = match stub {
        Stub::Domain => STUB,
        Stub::FileOp => FILEOP_STUB,
    };
    let mut cmd = Command::new("/usr/bin/sandbox-exec");
    cmd.arg("-f")
        .arg(profile)
        .args(["/usr/bin/perl", "-e", stub_text])
        .env_clear()
        .current_dir(&v.cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut child = cmd.spawn()?;
    let parts = (child.stdin.take(), child.stdout.take(), child.stderr.take());
    let (Some(stdin), Some(stdout), Some(stderr)) = parts else {
        kill_now(&mut child);
        return Err(std::io::Error::other("missing a pipe"));
    };
    let stdin = Arc::new(Mutex::new(Some(stdin)));
    if let Some(live) = live {
        // The deadline closer (§4.2): when the lifetime is up since the
        // spawn, drop the control pipe; the stub then stops the program and
        // sweeps. A stop, a collect, or a drop that takes the pipe first
        // ends this thread within one tick.
        let closer_stdin = Arc::clone(&stdin);
        let closer_at = started + live.lifetime;
        let closer = move || {
            loop {
                if Instant::now() >= closer_at {
                    break;
                }
                if lock_stdin(&closer_stdin).is_none() {
                    return;
                }
                std::thread::sleep(LIVE_TICK);
            }
            // Lifetime up: close the control pipe (§4.2). The stub then
            // stops the program and sweeps. If the pipe is already gone,
            // the call was ended by its caller above.
            drop(lock_stdin(&closer_stdin).take());
        };
        if let Err(e) = std::thread::Builder::new().spawn(closer) {
            kill_now(&mut child);
            return Err(e);
        }
    }
    let readers =
        reader(stdout, ring_bytes).and_then(|o| reader(stderr, ring_bytes).map(|e| (o, e)));
    let ((out, out_done, out_set), (err, err_done, err_set)) = match readers {
        Ok(r) => r,
        Err(e) => {
            kill_now(&mut child);
            return Err(e);
        }
    };
    // Only the domain stub takes a frame (limits, argv, env). The file-op
    // stub reads `rh-fileop/1` requests straight away; a frame would be
    // read as a malformed request and refuse the instance (§7.1).
    if matches!(stub, Stub::Domain) {
        let mut pipe = lock_stdin(&stdin);
        if let Some(pipe) = pipe.as_mut() {
            let _ = pipe.write_all(&frame(v, sweep)).and_then(|()| pipe.flush());
        }
    }
    Ok(Running {
        child: Some(child),
        stdin,
        out,
        err,
        out_done,
        err_done,
        out_set,
        err_set,
        started,
        deadline: started + v.limits.wall,
        sweep,
        cleanup_dir,
        finished: None,
    })
}

/// SIGKILL the stub and its process group, then reap it. The group is
/// killed before the leader is reaped, so its pgid cannot be reused.
fn kill_now(child: &mut Child) {
    let _ = child.kill();
    group_kill(child.id());
    let _ = child.wait();
}

fn group_kill(pgid: u32) {
    let _ = Command::new("/bin/kill")
        .args(["-KILL", "--", &format!("-{pgid}")])
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

/// After the stub (the group leader) is reaped, members may still be alive
/// only if the stub died by a signal (a member can send one) or gave up with
/// exit 3 (unconverged, or a mid-run canary with no sweep). Exit 0 means the
/// sweep finished; 4 and 90-93 mean nothing was started; any other code means
/// the stub never ran. Used by both `wait` and `Drop` so their post-reap
/// group kill is the same decision (LOW-3).
fn members_may_remain(stub: std::process::ExitStatus) -> bool {
    stub.code().is_none() || stub.code() == Some(3)
}

/// The stub's report line, parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Report {
    pub result: String,
    pub status: i64,
    pub end: String,
    pub kills: u32,
    pub exec: String,
}

/// Find the report as the final bytes of `tail`; returns it and the offset
/// of its leading newline within `tail`.
pub(crate) fn parse_report(tail: &[u8]) -> Option<(Report, usize)> {
    let body = tail.strip_suffix(b"\n")?;
    let marker = b"\nrh-stub/1 ";
    let at = body.windows(marker.len()).rposition(|w| w == marker)?;
    let line = std::str::from_utf8(body.get(at + 1..)?).ok()?;
    // The report is the final line: nothing may follow it.
    if line.contains('\n') {
        return None;
    }
    let mut f = line.split(' ');
    if f.next()? != "rh-stub/1" {
        return None;
    }
    let result = f.next()?.to_string();
    let status = f.next()?.strip_prefix("status=")?.parse().ok()?;
    let end = f.next()?.strip_prefix("end=")?.to_string();
    let kills = f.next()?.strip_prefix("kills=")?.parse().ok()?;
    let exec = f.next()?.strip_prefix("exec=")?.to_string();
    if f.next().is_some() {
        return None;
    }
    Some((
        Report {
            result,
            status,
            end,
            kills,
            exec,
        },
        at,
    ))
}

impl Running {
    /// How long the stub may take to finish its sweep once the call ended:
    /// the deadline it was given plus a fixed margin (P-41: the grace
    /// scales, so a retried probe's longer sweep is not cut short).
    fn grace(&self) -> Duration {
        self.sweep + SWEEP_GRACE_MARGIN
    }

    /// The stub's process id, while the instance runs (P-36d: the file-op
    /// helper's identity; the instance forks nothing, so the pid is stable
    /// across requests). `None` once the call has been reaped.
    pub(crate) fn pid(&self) -> Option<u32> {
        self.child.as_ref().map(|c| c.id())
    }

    /// Write `bytes` to the stub's control pipe — the file-op helper's
    /// request channel (§7.3). Fails once the pipe is closed (a stop, a
    /// deadline, or a dead stub), which the caller treats as a lost
    /// instance.
    pub(crate) fn send(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        let mut pipe = lock_stdin(&self.stdin);
        match pipe.as_mut() {
            Some(pipe) => pipe.write_all(bytes).and_then(|()| pipe.flush()),
            None => Err(std::io::Error::other("the stub's control pipe is closed")),
        }
    }

    /// Wait for the call to end (program exit or deadline), let the stub
    /// sweep, and collect what it left.
    pub(crate) fn wait(mut self) -> ConfinedExit {
        if let Some(done) = self.finished.take() {
            return done;
        }
        let mut timed_out = false;
        let mut stub = None;
        let Some(mut child) = self.child.take() else {
            return self.lost("no child");
        };
        while stub.is_none() {
            match child.try_wait() {
                Ok(Some(s)) => stub = Some(s),
                Ok(None) if Instant::now() < self.deadline => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Ok(None) => break,
                Err(_) => break,
            }
        }
        if stub.is_none() {
            timed_out = Instant::now() >= self.deadline;
            // Close the control pipe: the stub stops the program and sweeps.
            drop(lock_stdin(&self.stdin).take());
            let until = Instant::now() + self.grace();
            while stub.is_none() && Instant::now() < until {
                match child.try_wait() {
                    Ok(Some(s)) => stub = Some(s),
                    Ok(None) => std::thread::sleep(Duration::from_millis(5)),
                    Err(_) => break,
                }
            }
        }
        drop(lock_stdin(&self.stdin).take());
        let Some(stub) = stub else {
            kill_now(&mut child);
            let mut exit = self.collect(timed_out, None);
            exit.domain = DomainCleanup::Unconfirmed(
                "the domain stub did not finish its sweep in time; the process group was killed"
                    .into(),
            );
            return exit;
        };
        let pgid = child.id();
        let exit = self.collect(timed_out, Some(stub));
        // Members may remain only if the stub was killed by a signal (a
        // member can do that) or gave up with exit 3 (unconverged, or a
        // mid-run canary: no sweep). Every other exit means the sweep
        // finished (0) or nothing was started (4: refused start; 90-93:
        // unreadable frame or no fork; any other code: the stub never ran),
        // so no group kill is sent.
        //
        // The stub is already reaped here (`try_wait` reaps; std has no
        // wait-without-reaping), so this kill comes AFTER the leader is
        // gone. While any other member of the group lives, the kernel keeps
        // the group id in use and it cannot be handed out again, so the kill
        // reaches exactly those members. If the group is already empty, the
        // kill normally reaches nothing, but it would hit a NEW process
        // group if that number had been reissued as a pid since the reap:
        // a narrow race (it needs the pid counter to come round to this
        // number in the milliseconds between the reap and this call),
        // accepted here to kill members that may remain. The stall path
        // above (`kill_now`) kills the group before reaping and has no race.
        if matches!(exit.domain, DomainCleanup::Unconfirmed(_)) && members_may_remain(stub) {
            group_kill(pgid);
        }
        exit
    }

    fn collect(&mut self, timed_out: bool, stub: Option<std::process::ExitStatus>) -> ConfinedExit {
        let _ = self.out_done.recv_timeout(READ_GRACE);
        let _ = self.err_done.recv_timeout(READ_GRACE);
        let (stdout, out_total) = {
            let r = lock(&self.out);
            (r.head(), r.total())
        };
        let (mut stderr, err_total, tail) = {
            let r = lock(&self.err);
            (r.head(), r.total(), r.tail().to_vec())
        };
        let stdout_truncated = out_total > stdout.len() as u64;
        let report = parse_report(&tail);
        let mut stderr_truncated = err_total > stderr.len() as u64;
        if let Some((_, at)) = &report {
            // Remove the report (and its leading newline) when it is in the head.
            let report_len = tail.len() - at;
            if err_total <= stderr.len() as u64 && stderr.len() >= report_len {
                stderr.truncate(stderr.len() - report_len);
                stderr_truncated = false;
            }
        }
        let stub_ok = stub.is_some_and(|s| s.success());
        let (status, domain) = match (&report, stub_ok) {
            (Some((r, _)), true) if r.result == "confirmed" => (
                status_of(r, timed_out),
                DomainCleanup::Confirmed { kills: r.kills },
            ),
            (Some((r, _)), _) => (
                status_of(r, timed_out),
                DomainCleanup::Unconfirmed(match (r.result.as_str(), r.end.as_str()) {
                    ("canary", "start") => "the domain stub refused to start: it could not \
                        verify that its signal filter is in force (canary); nothing ran"
                        .to_string(),
                    ("canary", _) => "the domain stub stopped sweeping: its signal filter \
                        check failed mid-run (canary)"
                        .to_string(),
                    ("unconverged", _) => {
                        format!(
                            "processes of the domain would not die within the sweep \
                             deadline ({} s)",
                            self.sweep.as_secs()
                        )
                    }
                    (other, _) => format!(
                        "the domain stub reported {other} (exit {:?})",
                        stub.and_then(|s| s.code())
                    ),
                }),
            ),
            (None, _) => (
                if timed_out {
                    ChildStatus::TimedOut
                } else {
                    ChildStatus::Unknown
                },
                DomainCleanup::Unconfirmed(format!(
                    "no report from the domain stub (stub status {stub:?})"
                )),
            ),
        };
        if let Some(d) = self.cleanup_dir.take() {
            let _ = std::fs::remove_dir_all(d);
        }
        ConfinedExit {
            status,
            stdout,
            stdout_truncated,
            stderr,
            stderr_truncated,
            domain,
            elapsed: self.started.elapsed(),
        }
    }

    fn lost(&mut self, why: &str) -> ConfinedExit {
        let mut e = self.collect(false, None);
        e.domain = DomainCleanup::Unconfirmed(why.into());
        e
    }

    /// Close the control pipe now. To the stub this is the stop signal: it
    /// halts the program, sweeps, and reports. It also ends the deadline
    /// closer within one tick, and it is idempotent.
    fn close_pipe(&self) {
        drop(lock_stdin(&self.stdin).take());
    }

    /// Poll a live call without blocking (§4.2): `None` while it runs,
    /// `Some` once the stub has exited, been collected, and swept. Later
    /// calls return the same exit.
    pub(crate) fn try_status(&mut self) -> Option<ConfinedExit> {
        if let Some(done) = &self.finished {
            return Some(done.clone());
        }
        let stub = match self.child.as_mut() {
            Some(child) => child.try_wait().ok().flatten(),
            None => None,
        }?;
        self.close_pipe();
        let exit = self.collect(false, Some(stub));
        if matches!(exit.domain, DomainCleanup::Unconfirmed(_)) && members_may_remain(stub) {
            if let Some(pgid) = self.child.as_ref().map(Child::id) {
                group_kill(pgid);
            }
        }
        self.child = None;
        self.finished = Some(exit.clone());
        Some(exit)
    }

    /// Read a bounded window of a live stream (§3.2). `since` is an
    /// absolute offset; the chunk's `to` is the next `since`. While the
    /// stub runs, everything it writes is delivered as-is; after it has
    /// exited, its final stderr report is never delivered: reads end where
    /// the report begins.
    pub(crate) fn read(&self, stream: Stream, since: u64, cap: usize, mode: Mode) -> Chunk {
        let (ring, done) = match stream {
            Stream::Out => (&self.out, &self.out_set),
            Stream::Err => (&self.err, &self.err_set),
        };
        let ring = lock(ring);
        let limit = if stream == Stream::Err && done.load(Ordering::Acquire) {
            let tail = ring.tail();
            parse_report(tail).map(|(_, at)| ring.total().saturating_sub((tail.len() - at) as u64))
        } else {
            None
        };
        ring.chunk_until(since, cap, mode, limit)
    }

    /// Total bytes and the running SHA-256 of each stream, retained bytes
    /// or not (§4.2).
    pub(crate) fn totals(&self) -> StreamTotals {
        let out = lock(&self.out);
        let err = lock(&self.err);
        StreamTotals {
            out_total: out.total(),
            out_sha: out.digest(),
            err_total: err.total(),
            err_sha: err.digest(),
        }
    }

    /// Stop a live call (§4.2): close the control pipe, give the stub its
    /// sweep grace, and collect. A call that will not finish in the grace
    /// is killed with its group and reported unconfirmed. Stopping an
    /// already-ended call returns the collected exit.
    pub(crate) fn stop(mut self) -> ConfinedExit {
        if let Some(done) = self.finished.take() {
            return done;
        }
        self.close_pipe();
        let Some(mut child) = self.child.take() else {
            return self.lost("no child");
        };
        let mut stub = None;
        let until = Instant::now() + self.grace();
        while stub.is_none() && Instant::now() < until {
            match child.try_wait() {
                Ok(Some(s)) => stub = Some(s),
                Ok(None) => std::thread::sleep(Duration::from_millis(5)),
                Err(_) => break,
            }
        }
        let Some(stub) = stub else {
            kill_now(&mut child);
            let mut exit = self.collect(false, None);
            exit.domain = DomainCleanup::Unconfirmed(
                "the domain stub did not finish its sweep in time; the process group was killed"
                    .into(),
            );
            return exit;
        };
        let pgid = child.id();
        let exit = self.collect(false, Some(stub));
        if matches!(exit.domain, DomainCleanup::Unconfirmed(_)) && members_may_remain(stub) {
            group_kill(pgid);
        }
        exit
    }
}

fn status_of(r: &Report, timed_out: bool) -> ChildStatus {
    if r.exec != "ok" {
        return ChildStatus::ExecFailed;
    }
    if r.end == "procs" {
        // The process guard fired and the domain was swept (FT-5).
        return ChildStatus::ProcessLimit;
    }
    if r.end == "stop" {
        return if timed_out {
            ChildStatus::TimedOut
        } else {
            ChildStatus::Unknown
        };
    }
    if r.status < 0 {
        return ChildStatus::Unknown;
    }
    let sig = (r.status & 0x7f) as i32;
    if sig != 0 {
        ChildStatus::Signaled(sig)
    } else {
        ChildStatus::Exited(((r.status >> 8) & 0xff) as i32)
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        drop(lock_stdin(&self.stdin).take());
        if let Some(mut child) = self.child.take() {
            let pgid = child.id();
            let until = Instant::now() + self.grace();
            loop {
                match child.try_wait() {
                    // Match wait()'s post-reap kill: if members may remain
                    // (stub signalled or exit 3) sweep the group (LOW-3).
                    Ok(Some(s)) => {
                        if members_may_remain(s) {
                            group_kill(pgid);
                        }
                        break;
                    }
                    Ok(None) if Instant::now() < until => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    _ => {
                        kill_now(&mut child);
                        break;
                    }
                }
            }
        }
        if let Some(d) = self.cleanup_dir.take() {
            let _ = std::fs::remove_dir_all(d);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_refused_start_parses_and_maps_to_exec_failed() {
        let tail = b"some output\nrh-stub/1 canary status=-2 end=start kills=0 exec=none\n";
        let (r, at) = parse_report(tail).unwrap();
        assert_eq!(r.result, "canary");
        assert_eq!(r.end, "start");
        assert_eq!(at, 11);
        assert_eq!(status_of(&r, false), ChildStatus::ExecFailed);
    }

    #[test]
    fn a_report_must_be_the_final_bytes() {
        assert!(
            parse_report(b"\nrh-stub/1 confirmed status=0 end=exit kills=0 exec=ok\nmore\n")
                .is_none()
        );
        assert!(parse_report(b"\nrh-stub/1 confirmed status=0 end=exit kills=0 exec=ok").is_none());
        let (r, _) =
            parse_report(b"x\nrh-stub/1 confirmed status=256 end=exit kills=2 exec=ok\n").unwrap();
        assert_eq!(status_of(&r, false), ChildStatus::Exited(1));
        assert_eq!(r.kills, 2);
    }

    #[test]
    fn the_start_check_precedes_the_frame_and_every_fork() {
        let check = STUB.find("end=start").unwrap();
        assert!(check < STUB.find("open(my $c").unwrap());
        assert!(check < STUB.find("fork()").unwrap());
        // Per pass: only EPERM (1) or ESRCH (3) lets a sweep pass run —
        // or a signal macOS accepted from an already-reparented stub,
        // whose `kill(0, zombie)` quirk would otherwise forfeit the crash
        // sweep to the reaper race every time. A parent `getppid()` still
        // reports cannot be dead, so an accepted signal means the filter
        // is off and the stub must still refuse to sweep.
        assert!(STUB
            .contains("if($hit ? getppid()==$pp : ($en!=1 && $en!=3)){$res='canary';last PASS}"));
        // The start canary is untouched: before the frame, the parent must
        // be alive and refused.
        assert!(STUB.contains("if($pp<=1 || kill(0,$pp) || ($!+0)!=1)"));
    }

    #[test]
    fn the_sweep_deadline_rides_the_frame_and_the_stub_bounds_it() {
        // The deadline is an optional fifth field of the lim line (absent
        // means the reviewed 3 s), and the stub refuses anything outside
        // 1-30 s, so a frame can ask for neither a zero nor an unbounded
        // sweep (P-41).
        assert!(STUB.contains(r#"([0-9]{1,6})( ([0-9]{1,2}))?$"#));
        assert!(STUB.contains(r#"$sw=defined($6)?$6:3"#));
        assert!(STUB.contains(r#"exit 91 if $sw<1 || $sw>30"#));
        // The sweep runs to the frame's deadline, not a hardcoded 3 s.
        assert!(STUB.contains("last PASS if time-$t0>=$sw"));
    }

    #[test]
    fn the_stub_has_no_double_quote_so_the_program_scan_reads_three_programs() {
        // The purity gate reads the confined spawn's absolute-path program
        // literals; the stub must add no double quote of its own (the memory
        // guard builds its buffer with chr(0), not a backslash-zero string).
        assert!(!STUB.contains('"'));
    }

    #[test]
    fn a_process_limit_report_maps_to_process_limit() {
        let tail = b"x\nrh-stub/1 confirmed status=-2 end=procs kills=7 exec=ok\n";
        let (r, _) = parse_report(tail).unwrap();
        assert_eq!(r.end, "procs");
        assert_eq!(r.kills, 7);
        assert_eq!(status_of(&r, false), ChildStatus::ProcessLimit);
    }

    #[test]
    fn the_frame_carries_cpu_file_size_memory_process_caps_and_sweep() {
        // Only argv/env/limits reach the frame; cwd and roots do not, and no
        // absolute-path literal is used here (the purity gate reads this
        // file's program literals).
        let f = String::from_utf8(frame(&limits_spec(), Duration::from_secs(9))).unwrap();
        assert!(
            f.starts_with("rh-stub/1\nlim 2 4096 1073741824 64 9\n"),
            "{f:?}"
        );
    }

    #[test]
    fn the_frame_sweep_is_clamped_into_the_stub_s_bound() {
        // The stub refuses 0 or anything above 30 s; the frame builder
        // clamps, so the harness can never send an unbounded sweep (P-41).
        for (ask, want) in [(0, 1), (1, 1), (30, 30), (100, 30)] {
            let f = String::from_utf8(frame(&limits_spec(), Duration::from_secs(ask))).unwrap();
            let lim = f.lines().nth(1).unwrap();
            assert!(lim.ends_with(&format!(" {want}")), "{lim:?}");
        }
    }

    /// A validated spec with every limit set, for the frame tests.
    fn limits_spec() -> Validated {
        Validated {
            argv: vec![b"p".to_vec()],
            env: vec![],
            cwd: String::new(),
            read_only: vec![],
            read_write: vec![],
            protected: vec![],
            limits: crate::spec::Limits {
                wall: Duration::from_secs(5),
                cpu: Some(Duration::from_secs(2)),
                file_size: Some(4096),
                memory: Some(1 << 30),
                processes: Some(64),
                output_bytes: 1024,
            },
        }
    }
}

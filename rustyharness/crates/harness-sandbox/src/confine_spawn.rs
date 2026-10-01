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
//! exactly the spec's environment, core dumps off and the spec's CPU and
//! file-size limits (`setrlimit` through perl's `syscall`: no Rust
//! `unsafe`). It waits for the program to exit, or for the control pipe to
//! become readable: the harness closes it at the deadline, and the kernel
//! closes it if the harness dies. Then it **sweeps**: each pass sends
//! SIGKILL to every pid from 2 to 99999 (macOS's pid range) except its
//! own, and the kernel delivers it only to processes of the same sandbox
//! instance, because the profile allows `signal` only with `(target
//! same-sandbox)` (measured: E4, and the review's M-6). Passes repeat
//! until one kills nothing (at most 50). A `setsid` or double-forked
//! descendant cannot leave the sandbox instance, so it is swept too (E8).
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
//! same parent again and accepts only `EPERM` (the parent is alive and
//! still refused) or `ESRCH` (3: the harness has gone, e.g. crashed).
//! Accepting `ESRCH` is deliberate: after a verified start the filter
//! cannot have changed, and refusing to sweep when the harness has died
//! would give up the one cleanup a crash still gets. Success, or any
//! other error, reports `canary` and stops sweeping.
//!
//! **Report.** The stub's last act is one line on stderr, `rh-stub/1
//! <confirmed|unconverged|canary> status=<wait status> end=<exit|stop|start>
//! kills=<n> exec=<ok|failed|limit|none>`, and exit 0 only for `confirmed`
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
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use crate::spec::{ChildStatus, ConfinedExit, DomainCleanup, Validated};

/// How long the stub may take to sweep after the deadline or the program's
/// exit before the harness kills it and reports the domain unconfirmed.
pub const SWEEP_GRACE: Duration = Duration::from_secs(5);
/// How long the readers may take to reach end of file after the stub ended.
pub const READ_GRACE: Duration = Duration::from_secs(2);
/// Bytes of stderr's end kept to find the stub's report.
const TAIL_BYTES: usize = 4096;

/// The domain stub, run by `/usr/bin/perl -e` inside the sandbox (see the
/// module docs). No double quote appears in it, so the gate's program-literal
/// scan reads only the three programs above.
pub const STUB: &str = r#"$SIG{PIPE}='IGNORE';$SIG{TERM}='IGNORE';$SIG{INT}='IGNORE';$SIG{HUP}='IGNORE';$SIG{QUIT}='IGNORE';
my $pp=getppid();
if($pp<=1 || kill(0,$pp) || ($!+0)!=1){print STDERR qq{\nrh-stub/1 canary status=-2 end=start kills=0 exec=none\n}; exit 4}
open(my $c,'<&',\*STDIN) or exit 90; binmode $c;
sub rl{my($l,$ch)=('');while(1){my $n=sysread($c,$ch,1);return undef unless $n;return $l if $ch eq qq{\n};$l.=$ch;return undef if length($l)>40;}}
sub rn{my $n=shift;my $b='';while(length($b)<$n){my $r=sysread($c,$b,$n-length($b),length($b));return undef unless $r;}return $b}
sub item{my $n=rl();return undef unless defined $n && $n=~/^[0-9]{1,8}$/;return rn($n) if $n>0;return ''}
my $m=rl(); exit 91 unless defined $m && $m eq 'rh-stub/1';
my $li=rl(); exit 91 unless defined $li && $li=~/^lim ([0-9]{1,12}) ([0-9]{1,15})$/; my ($cpu,$fs)=($1,$2);
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
 exec {$a[0]} @a; syswrite($ew,'E'); exit 127 }
close $ew;
my $st=-1; my $why='exit';
while(1){ my $w=waitpid($pid,1); if($w==$pid){$st=$?;last} my $rin='';vec($rin,fileno($c),1)=1; my $n=select(my $ro=$rin,undef,undef,0.02); if($n>0){$why='stop';last} }
my ($k,$res)=(0,'unconverged');
PASS: for my $p (1..50){ my $hit=kill(0,$pp); my $en=$!+0; if($hit || ($en!=1 && $en!=3)){$res='canary';last PASS} my $n=0; for my $q (2..99999){next if $q==$$; $n++ if kill('KILL',$q)} 1 while waitpid(-1,1)>0; $k+=$n; if($n==0){$res='confirmed';last PASS} select(undef,undef,undef,0.005) }
my $ef=''; if($res eq 'confirmed'){sysread($er,$ef,1)}
my $ex = $ef eq 'E' ? 'failed' : $ef eq 'L' ? 'limit' : 'ok';
if($st==-1){$st=-2}
print STDERR qq{\nrh-stub/1 $res status=$st end=$why kills=$k exec=$ex\n};
exit($res eq 'confirmed' ? 0 : 3);
"#;

#[derive(Default)]
struct Cap {
    head: Vec<u8>,
    total: u64,
    tail: Vec<u8>,
}

/// One running confined call.
pub(crate) struct Running {
    child: Option<Child>,
    stdin: Option<ChildStdin>,
    out: Arc<Mutex<Cap>>,
    err: Arc<Mutex<Cap>>,
    out_done: mpsc::Receiver<()>,
    err_done: mpsc::Receiver<()>,
    started: Instant,
    deadline: Instant,
    cleanup_dir: Option<PathBuf>,
}

fn lock(m: &Mutex<Cap>) -> std::sync::MutexGuard<'_, Cap> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn reader(
    mut from: impl Read + Send + 'static,
    cap: u64,
) -> std::io::Result<(Arc<Mutex<Cap>>, mpsc::Receiver<()>)> {
    let buf = Arc::new(Mutex::new(Cap::default()));
    let (tx, rx) = mpsc::channel();
    let b = Arc::clone(&buf);
    std::thread::Builder::new().spawn(move || {
        let mut chunk = vec![0u8; 64 * 1024];
        loop {
            match from.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let data = chunk.get(..n).unwrap_or_default();
                    let mut c = lock(&b);
                    let room = cap.saturating_sub(c.head.len() as u64) as usize;
                    c.head
                        .extend_from_slice(data.get(..room.min(n)).unwrap_or_default());
                    c.total += n as u64;
                    c.tail.extend_from_slice(data);
                    if c.tail.len() > TAIL_BYTES {
                        let cut = c.tail.len() - TAIL_BYTES;
                        c.tail.drain(..cut);
                    }
                }
            }
        }
        let _ = tx.send(());
    })?;
    Ok((buf, rx))
}

fn frame(v: &Validated) -> Vec<u8> {
    let cpu = v
        .limits
        .cpu
        .map_or(0, |c| c.as_secs() + u64::from(c.subsec_nanos() > 0));
    let fs = v.limits.file_size.unwrap_or(0);
    let mut h = format!("rh-stub/1\nlim {cpu} {fs}\n{}\n", v.argv.len()).into_bytes();
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

/// Start `v` under the profile at `profile`. `cleanup_dir` is removed when
/// the call has ended.
pub(crate) fn spawn(
    profile: &Path,
    v: &Validated,
    cleanup_dir: Option<PathBuf>,
) -> std::io::Result<Running> {
    let started = Instant::now();
    let mut cmd = Command::new("/usr/bin/sandbox-exec");
    cmd.arg("-f")
        .arg(profile)
        .args(["/usr/bin/perl", "-e", STUB])
        .env_clear()
        .current_dir(&v.cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut child = cmd.spawn()?;
    let parts = (child.stdin.take(), child.stdout.take(), child.stderr.take());
    let (Some(mut stdin), Some(stdout), Some(stderr)) = parts else {
        kill_now(&mut child);
        return Err(std::io::Error::other("missing a pipe"));
    };
    let readers = reader(stdout, v.limits.output_bytes)
        .and_then(|o| reader(stderr, v.limits.output_bytes).map(|e| (o, e)));
    let ((out, out_done), (err, err_done)) = match readers {
        Ok(r) => r,
        Err(e) => {
            kill_now(&mut child);
            return Err(e);
        }
    };
    // A stub that already died gives EPIPE here; the wait reports it.
    let _ = stdin.write_all(&frame(v)).and_then(|()| stdin.flush());
    Ok(Running {
        child: Some(child),
        stdin: Some(stdin),
        out,
        err,
        out_done,
        err_done,
        started,
        deadline: started + v.limits.wall,
        cleanup_dir,
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
    /// Wait for the call to end (program exit or deadline), let the stub
    /// sweep, and collect what it left.
    pub(crate) fn wait(mut self) -> ConfinedExit {
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
            drop(self.stdin.take());
            let until = Instant::now() + SWEEP_GRACE;
            while stub.is_none() && Instant::now() < until {
                match child.try_wait() {
                    Ok(Some(s)) => stub = Some(s),
                    Ok(None) => std::thread::sleep(Duration::from_millis(5)),
                    Err(_) => break,
                }
            }
        }
        drop(self.stdin.take());
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
        if matches!(exit.domain, DomainCleanup::Unconfirmed(_))
            && (stub.code().is_none() || stub.code() == Some(3))
        {
            group_kill(pgid);
        }
        exit
    }

    fn collect(&mut self, timed_out: bool, stub: Option<std::process::ExitStatus>) -> ConfinedExit {
        let _ = self.out_done.recv_timeout(READ_GRACE);
        let _ = self.err_done.recv_timeout(READ_GRACE);
        let (stdout, out_total) = {
            let c = lock(&self.out);
            (c.head.clone(), c.total)
        };
        let (mut stderr, err_total, tail) = {
            let c = lock(&self.err);
            (c.head.clone(), c.total, c.tail.clone())
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
                        "processes of the domain would not die within 50 sweep passes".to_string()
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
}

fn status_of(r: &Report, timed_out: bool) -> ChildStatus {
    if r.exec != "ok" {
        return ChildStatus::ExecFailed;
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
        drop(self.stdin.take());
        if let Some(mut child) = self.child.take() {
            let until = Instant::now() + SWEEP_GRACE;
            loop {
                match child.try_wait() {
                    Ok(Some(_)) => break,
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
        // Per pass: only EPERM (1) or ESRCH (3) lets a sweep pass run.
        assert!(STUB.contains("if($hit || ($en!=1 && $en!=3)){$res='canary';last PASS}"));
    }
}

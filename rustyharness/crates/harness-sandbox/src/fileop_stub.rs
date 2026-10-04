//! The file-op helper's stub (P-36d, design §7.1): the perl program that
//! runs as the single process of a confined file-op instance and serves
//! `rh-fileop/1` requests (§7.3, codec in [`crate::fileop::proto`]).
//!
//! Like the domain stub (`confine_spawn`), this text is pinned by SHA-256
//! in `scripts/ci/purity.sh` and changes only with a review of the gate:
//!
//! - It holds **no double quote**, so the gate's program-literal scan can
//!   never read one, and it names **no absolute path at all** (it spawns
//!   nothing and execs nothing; every path it touches comes from a
//!   request, workspace-relative). The gate fails if either changes.
//! - It keeps the same start canary as the domain stub: it refuses to run
//!   unless a `signal 0` to its parent fails with `EPERM`, i.e. unless it
//!   is inside a sandbox whose profile grants no `signal` (`exit 4`, the
//!   report line is the final bytes on stderr). This is what
//!   `fileop_stub_refuses_to_start_unconfined` witnesses.
//! - It forks nothing (the profile grants no `process-fork`, and the word
//!   appears nowhere): the instance holds exactly one process, so the
//!   helper's stop is a pipe close and its pid is stable across requests.
//! - Reads use the same `sysread` byte loops as the domain stub (no
//!   perlio buffering), opens carry `O_NOFOLLOW` on the last component,
//!   and every path is re-split and refused when a component is empty,
//!   `.` or `..` (§7.3: the helper re-checks what the codec checked).
//! - Per-request work ends in one reply (`ok <n>` with items, or
//!   `err <code>`); the reply names follow [`crate::fileop::proto`]'s
//!   `ErrorCode`. Symlinks are refused by the walk (semantics the kernel
//!   view already guarantees), FIFOs and non-regular files refuse fast,
//!   `replace`/`unlink`/`move` verify the expected SHA-256 first
//!   (`changed`), `move` never overwrites (`link` onto an existing name
//!   fails), and `replace` fsyncs the file and then its directory before
//!   reporting the post-write digest (H2b).
//! - On a clean end of input it reports `confirmed` like the domain stub,
//!   so the shared collect machinery needs no special case. A malformed
//!   stream (or an impossible item count) replies `err badreq` and quits
//!   with a `refused` report: the framing is broken, nothing after it can
//!   be trusted.

/// The stub text, run as `/usr/bin/perl -e FILEOP_STUB` through the same
/// confined spawn as the domain stub (no frame is written for this stub:
/// requests start at once, one at a time, and the instance ends when the
/// control pipe closes).
pub const FILEOP_STUB: &str = r#"use strict;
use warnings;
use Fcntl qw(:DEFAULT O_NOFOLLOW);
use Cwd qw(getcwd);
use Digest::SHA qw(sha256_hex);
use Time::HiRes qw(time);
use IO::Handle;
$SIG{PIPE}='IGNORE';$SIG{TERM}='IGNORE';$SIG{INT}='IGNORE';$SIG{HUP}='IGNORE';$SIG{QUIT}='IGNORE';
my $pp=getppid();
if($pp<=1 || kill(0,$pp) || ($!+0)!=1){print STDERR qq{\nrh-stub/1 canary status=-2 end=start kills=0 exec=none\n}; exit 4}
open(my $c,'<&',\*STDIN) or exit 90; binmode $c;
sub rl{my($l,$ch)=('');while(1){my $n=sysread($c,$ch,1);return undef unless $n;return $l if $ch eq qq{\n};$l.=$ch;return undef if length($l)>64;}}
sub rn{my $n=shift;my $b='';while(length($b)<$n){my $r=sysread($c,$b,$n-length($b),length($b));return undef unless $r;}return $b}
sub item{my $n=rl();return undef unless defined $n && $n=~/^[0-9]{1,8}$/;return rn($n) if $n>0;return ''}
my $root=getcwd();
my $REPLY=8388608;
my $READCAP=67108864;
my $MAXE=0;
my @FOUND;
my $FOUND_ERR;
my $FOUND_BYTES;
$| = 1;
sub out_ok{my @it=@_; my $o=qq{ok }.scalar(@it).qq{\n}; for my $x (@it){$o.=length($x).qq{\n}.$x} print $o}
sub out_err{my $code=shift; print qq{err }.$code.qq{\n}}
sub lost{out_err(q{badreq}); print STDERR qq{\nrh-stub/1 refused status=9 end=frame kills=0 exec=ok\n}; exit 9}
sub wpath{my $p=shift; return undef if !defined $p || length($p)>4096; my @c=split m{/},$p,-1; for my $x (@c){return undef if $x eq q{} || $x eq q{.} || $x eq q{..}} return $root if $p eq q{}; return $root.q{/}.$p}
sub num{my $t=shift; return undef if !defined $t || $t !~ m{^[0-9]{1,10}$}; return 0+$t}
sub digest{my $t=shift; return undef if !defined $t || $t !~ m{^[0-9a-f]{64}$}; return $t}
sub errmap{my $e=0+$!; return q{denied} if $e==1 || $e==13 || $e==30; return q{noent} if $e==2; return q{exists} if $e==17; return q{notdir} if $e==20; return q{isdir} if $e==21; return q{symlink} if $e==62; return q{nlink} if $e==66; return q{io}}
sub kindof{my @st=@_; my $t=$st[2] & 0170000; return q{dir} if $t==0040000; return q{link} if $t==0120000; return q{fifo} if $t==0010000; return q{file} if $t==0100000; return q{other}}
sub fsync_fd{my $fd=shift; open(my $h,q{<&=},$fd) or return 0; my $r=$h->sync(); close($h); return $r}
sub dirsync{my $d=shift; opendir(my $dh,$d) or return 0; my $r=fsync_fd(fileno($dh)); closedir($dh); return $r}
sub slurp{my($fh,$cap)=@_; my $b=q{}; while(length($b)<$cap){my $r=sysread($fh,$b,$cap-length($b),length($b)); last if !defined $r || $r==0;} return $b}
sub spew{my($fh,$b)=@_; my $o=0; while($o<length($b)){my $w=syswrite($fh,$b,length($b)-$o,$o); return 0 unless defined $w; $o+=$w;} return 1}
sub parentof{my $p=shift; my @c=split m{/},$p,-1; pop @c; my $d=join q{/},@c; return $d eq q{} ? $root : $root.q{/}.$d}
sub mkdirsto{my $pp=shift; my @c=split m{/},$pp,-1; my $cur=$root; for my $x (@c){$cur=$cur.q{/}.$x; if(!lstat($cur)){mkdir($cur,0755) or return 0}} return 1}
sub walk{my $p=shift; my @c=split m{/},$p,-1; my $cur=$root; my @st=lstat($cur); return (0,q{noent}) unless @st; return (0,q{notdir}) unless ($st[2] & 0170000)==0040000; for my $x (@c){$cur=$cur.q{/}.$x; @st=lstat($cur); return (0,q{noent}) unless @st; return (0,q{symlink}) if ($st[2] & 0170000)==0120000;} return (1,\@st)}
sub pwalk{my $p=shift; my @c=split m{/},$p,-1; my $cur=$root; my @st=lstat($cur); return (q{io},0) unless @st; my $missing=0; for my $x (@c){$cur=$cur.q{/}.$x; @st=lstat($cur); if(!@st){$missing++; next} return (q{symlink},0) if ($st[2] & 0170000)==0120000; return (q{notdir},0) if ($st[2] & 0170000)!=0040000; return (q{io},0) if $missing;} return (0,$missing)}
sub list_into{my($abs,$rel,$left)=@_; return if defined $FOUND_ERR; opendir(my $dh,$abs) or do{$FOUND_ERR=q{denied}; return}; my @names=sort grep { $_ ne q{.} && $_ ne q{..} } readdir($dh); closedir($dh); for my $n (@names){last if defined $FOUND_ERR; if(scalar(@FOUND)/3 >= $MAXE){$FOUND_ERR=q{toobig}; last} my @st=lstat($abs.q{/}.$n); next unless @st; my $k=kindof(@st); my $rn=$rel eq q{} ? $n : $rel.q{/}.$n; $FOUND_BYTES+=length($rn)+24; if($FOUND_BYTES>8000000){$FOUND_ERR=q{toobig}; last} push @FOUND,$rn,$k,$st[7]; if($k eq q{dir} && $left>1){list_into($abs.q{/}.$n,$rn,$left-1)}}}
sub tree_into{my($abs,$rel,$dead,$left)=@_; return if defined $FOUND_ERR; if(time()>=$dead){$FOUND_ERR=q{toobig}; return} opendir(my $dh,$abs) or do{$FOUND_ERR=q{denied}; return}; my @names=sort grep { $_ ne q{.} && $_ ne q{..} } readdir($dh); closedir($dh); for my $n (@names){last if defined $FOUND_ERR; if(scalar(@FOUND)/4 >= $MAXE){$FOUND_ERR=q{toobig}; last} my $full=$abs.q{/}.$n; my @st=lstat($full); next unless @st; my $k=kindof(@st); my $rn=$rel eq q{} ? $n : $rel.q{/}.$n; $FOUND_BYTES+=length($rn)+100; if($FOUND_BYTES>8000000){$FOUND_ERR=q{toobig}; last} my $sha=q{}; if($k eq q{file}){return if defined $FOUND_ERR; if($st[7]>$READCAP){$FOUND_ERR=q{toobig}; last} my $fh; unless(sysopen($fh,$full,O_RDONLY|O_NOFOLLOW)){$FOUND_ERR=errmap(); last} $sha=sha256_hex(slurp($fh,$READCAP)); close $fh} elsif($k eq q{dir}){if($left<=1){$FOUND_ERR=q{toobig}; last}} push @FOUND,$rn,$k,$st[7],$sha; if($k eq q{dir}){tree_into($full,$rn,$dead,$left-1)}}}
sub op_lstat{my($p)=@_; my $f=wpath($p); return (1,q{badreq}) unless defined $f; my($ok,$st)=walk($p); return (1,$st) unless $ok; my @st=@$st; return (0,kindof(@st),$st[7],sprintf(q{%o},$st[2] & 07777),$st[3])}
sub op_read{my($p,$maxt)=@_; my $f=wpath($p); return (1,q{badreq}) unless defined $f; my $max=num($maxt); return (1,q{badreq}) unless defined $max; return (1,q{toobig}) if $max>8388607; my($ok,$st)=walk($p); return (1,$st) unless $ok; my @st=@$st; return (1,q{isdir}) if ($st[2] & 0170000)==0040000; return (1,q{denied}) unless ($st[2] & 0170000)==0100000; my $fh; unless(sysopen($fh,$f,O_RDONLY|O_NOFOLLOW|O_NONBLOCK)){return (1,errmap())} my $b=slurp($fh,$max+1); close $fh; return (0,$b)}
sub op_list{my($p,$maxet,$deptht)=@_; my $f=wpath($p); return (1,q{badreq}) unless defined $f; my $maxe=num($maxet); my $depth=num($deptht); return (1,q{badreq}) unless defined $maxe && defined $depth; return (1,q{toobig}) if $maxe>100000; return (1,q{badreq}) if $depth<1 || $depth>64; my($ok,$st)=walk($p); return (1,$st) unless $ok; my @st=@$st; return (1,q{notdir}) unless ($st[2] & 0170000)==0040000; @FOUND=(); $FOUND_ERR=undef; $FOUND_BYTES=0; $MAXE=$maxe; list_into($f,q{},$depth); return (1,$FOUND_ERR) if defined $FOUND_ERR; return (0,@FOUND)}
sub op_tree{my($maxet,$deadlinet)=@_; my $maxe=num($maxet); my $ms=num($deadlinet); return (1,q{badreq}) unless defined $maxe && defined $ms; return (1,q{toobig}) if $maxe>100000; return (1,q{badreq}) if $ms<1; @FOUND=(); $FOUND_ERR=undef; $FOUND_BYTES=0; $MAXE=$maxe; my $dead=time()+$ms/1000; tree_into($root,q{},$dead,64); return (1,$FOUND_ERR) if defined $FOUND_ERR; return (0,@FOUND)}
sub op_create{my($p,$bytest,$modet,$maxdt)=@_; my $f=wpath($p); return (1,q{badreq}) unless defined $f; return (1,q{badreq}) unless defined $bytest; my $mode=num($modet); my $maxd=num($maxdt); return (1,q{badreq}) unless defined $mode && defined $maxd; my @pc=split m{/},$p,-1; pop @pc; my $pp=join q{/},@pc; my($code,$missing)=pwalk($pp); return (1,$code) if $code; return (1,q{toobig}) if $missing>$maxd; if($missing>0 && !mkdirsto($pp)){return (1,errmap())} my $fh; unless(sysopen($fh,$f,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW)){return (1,errmap())} unless(spew($fh,$bytest)){close $fh; return (1,q{io})} my $m=$mode & 07777; $m=0644 if $m==0; chmod($m,$f); fsync_fd(fileno($fh)); close $fh; return (0,$missing)}
sub op_replace{my($p,$bytest,$shat)=@_; my $f=wpath($p); return (1,q{badreq}) unless defined $f; return (1,q{badreq}) unless defined $bytest; my $want=digest($shat); return (1,q{badreq}) unless defined $want; my($ok,$st)=walk($p); return (1,$st) unless $ok; my @st=@$st; return (1,q{isdir}) if ($st[2] & 0170000)==0040000; return (1,q{denied}) unless ($st[2] & 0170000)==0100000; return (1,q{nlink}) if $st[3]>1; return (1,q{toobig}) if $st[7]>$READCAP; my $fh; unless(sysopen($fh,$f,O_RDONLY|O_NOFOLLOW)){return (1,errmap())} my $old=slurp($fh,$READCAP); my $omode=$st[2] & 07777; close $fh; return (1,q{changed}) unless sha256_hex($old) eq $want; my $dir=parentof($p); my $tmp; my $got=0; for my $n (1..100){$tmp=$dir.q{/.rh-edit-}.$$.q{-}.$n.q{.tmp}; if(sysopen(my $t,$tmp,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW)){$fh=$t; $got=1; last} return (1,errmap()) if ($!+0)!=17} return (1,q{io}) unless $got; unless(spew($fh,$bytest)){close $fh; unlink($tmp); return (1,q{io})} chmod($omode,$tmp); fsync_fd(fileno($fh)); close $fh; unless(rename($tmp,$f)){my $e=$!+0; unlink($tmp); return (1,errmap())} dirsync($dir); my $fh2; unless(sysopen($fh2,$f,O_RDONLY|O_NOFOLLOW)){return (1,q{io})} my $new=slurp($fh2,$READCAP); close $fh2; return (0,sha256_hex($new))}
sub op_unlink{my($p,$shat)=@_; my $f=wpath($p); return (1,q{badreq}) unless defined $f; my $want=digest($shat); return (1,q{badreq}) unless defined $want; my($ok,$st)=walk($p); return (1,$st) unless $ok; my @st=@$st; return (1,q{isdir}) if ($st[2] & 0170000)==0040000; return (1,q{denied}) unless ($st[2] & 0170000)==0100000; return (1,q{nlink}) if $st[3]>1; return (1,q{toobig}) if $st[7]>$READCAP; my $fh; unless(sysopen($fh,$f,O_RDONLY|O_NOFOLLOW)){return (1,errmap())} my $old=slurp($fh,$READCAP); close $fh; return (1,q{changed}) unless sha256_hex($old) eq $want; unless(unlink($f)){return (1,errmap())} dirsync(parentof($p)); return (0)}
sub op_move{my($pt,$qt,$shat,$maxdt)=@_; my $ff=wpath($pt); my $ft=wpath($qt); return (1,q{badreq}) unless defined $ff && defined $ft; return (1,q{badreq}) if $pt eq $qt; my $want=digest($shat); my $maxd=num($maxdt); return (1,q{badreq}) unless defined $want && defined $maxd; my($ok,$st)=walk($pt); return (1,$st) unless $ok; my @st=@$st; return (1,q{isdir}) if ($st[2] & 0170000)==0040000; return (1,q{denied}) unless ($st[2] & 0170000)==0100000; return (1,q{toobig}) if $st[7]>$READCAP; my $fh; unless(sysopen($fh,$ff,O_RDONLY|O_NOFOLLOW)){return (1,errmap())} my $old=slurp($fh,$READCAP); close $fh; return (1,q{changed}) unless sha256_hex($old) eq $want; my @qc=split m{/},$qt,-1; pop @qc; my $qp=join q{/},@qc; my($code,$missing)=pwalk($qp); return (1,$code) if $code; return (1,q{toobig}) if $missing>$maxd; if($missing>0 && !mkdirsto($qp)){return (1,errmap())} my @ex=lstat($ft); return (1,q{exists}) if @ex; unless(link($ff,$ft)){my $e=$!+0; return (1,q{exists}) if $e==17; return (1,errmap())} unless(unlink($ff)){return (1,errmap())} dirsync(parentof($qt)); dirsync(parentof($pt)); return (0,$missing)}
sub op_rmdir{my($p)=@_; my $f=wpath($p); return (1,q{badreq}) unless defined $f; my($ok,$st)=walk($p); return (1,$st) unless $ok; my @st=@$st; return (1,q{notdir}) unless ($st[2] & 0170000)==0040000; unless(rmdir($f)){return (1,errmap())} dirsync(parentof($p)); return (0)}
sub op_ping{return (1,q{denied})}
my %OPS=map {$_=>1} qw(lstat read list tree create replace unlink move rmdir ping);
while(1){
 my $op=rl(); last unless defined $op;
 my $cnt=rl(); lost() unless defined $cnt && $cnt=~m{^[0-9]{1,8}$} && $cnt ne q{0} && $cnt+0<=64;
 my @it;
 for my $i (1..($cnt+0)){my $x=item(); lost() unless defined $x; push @it,$x}
 if(!$OPS{$op}){out_err(q{badreq}); next}
 my @r=(1,q{badreq});
 if($op eq q{lstat}){@r=op_lstat(@it)}
 elsif($op eq q{read}){@r=op_read(@it)}
 elsif($op eq q{list}){@r=op_list(@it)}
 elsif($op eq q{tree}){@r=op_tree(@it)}
 elsif($op eq q{create}){@r=op_create(@it)}
 elsif($op eq q{replace}){@r=op_replace(@it)}
 elsif($op eq q{unlink}){@r=op_unlink(@it)}
 elsif($op eq q{move}){@r=op_move(@it)}
 elsif($op eq q{rmdir}){@r=op_rmdir(@it)}
 elsif($op eq q{ping}){@r=op_ping(@it)}
 if($r[0]){out_err($r[1])} else {out_ok(@r[1..$#r])}
}
print STDERR qq{\nrh-stub/1 confirmed status=0 end=exit kills=0 exec=ok\n};
exit 0
"#;

#[cfg(test)]
mod tests {
    use super::FILEOP_STUB;

    // The pin's absolute-path scan reads this file raw for a double quote
    // followed by a slash: a double quote is the only way to form an
    // absolute-path literal, so the stub (and this file) hold none.
    // purity.sh re-checks both facts mechanically.
    #[test]
    fn the_stub_holds_no_double_quote_so_no_absolute_path_literal_can_form() {
        assert!(!FILEOP_STUB.contains('"'));
    }

    #[test]
    fn the_start_canary_precedes_everything_else() {
        let canary = FILEOP_STUB
            .find("my $pp=getppid();")
            .expect("the stub keeps the start canary");
        let pipe = FILEOP_STUB
            .find("open(my $c")
            .expect("the stub reads its control pipe");
        let serve = FILEOP_STUB
            .find("while(1)")
            .expect("the stub serves requests");
        assert!(canary < pipe);
        assert!(pipe < serve);
        assert!(
            FILEOP_STUB.contains("if($pp<=1 || kill(0,$pp) || ($!+0)!=1)"),
            "the canary condition is byte-identical to the domain stub's"
        );
        assert!(
            FILEOP_STUB.contains("exit 4"),
            "an unconfined start refuses with exit 4"
        );
    }

    #[test]
    fn the_stub_forks_nothing() {
        assert!(!FILEOP_STUB.contains("fork"));
        assert!(!FILEOP_STUB.contains("system"));
        // The kernel reads the same promise from the profile (no
        // `process-fork`); this is the stub half of the fileop-no-fork case.
    }

    #[test]
    fn the_stub_serves_every_operation_of_the_protocol() {
        assert!(
            FILEOP_STUB.contains("qw(lstat read list tree create replace unlink move rmdir ping)"),
            "the op table names all ten operations"
        );
        for op in [
            "op_lstat",
            "op_read",
            "op_list",
            "op_tree",
            "op_create",
            "op_replace",
            "op_unlink",
            "op_move",
            "op_rmdir",
            "op_ping",
        ] {
            assert!(FILEOP_STUB.contains(op), "the stub defines {op}");
        }
    }

    #[test]
    fn the_stub_uses_nofollow_sha_and_the_frame_reader() {
        assert!(FILEOP_STUB.contains("O_NOFOLLOW"));
        assert!(FILEOP_STUB.contains("Digest::SHA"));
        assert!(FILEOP_STUB.contains("sha256_hex"));
        assert!(FILEOP_STUB.contains("fsync"));
        // The sysread byte loops (no perlio buffering), as in the domain
        // stub: a buffered reader would swallow the first request.
        assert!(FILEOP_STUB.contains("open(my $c,'<&',\\*STDIN) or exit 90; binmode $c;"));
        assert!(FILEOP_STUB.contains("sub rl{my($l,$ch)=('');"));
    }

    #[test]
    fn the_stub_reports_like_the_domain_stub_so_the_collect_machinery_is_shared() {
        assert!(FILEOP_STUB.contains("rh-stub/1 confirmed status=0 end=exit kills=0 exec=ok"));
        assert!(FILEOP_STUB.contains("rh-stub/1 canary status=-2 end=start kills=0 exec=none"));
        assert!(FILEOP_STUB.contains("rh-stub/1 refused status=9 end=frame kills=0 exec=ok"));
    }
}

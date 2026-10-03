//! Object-file load commands (P-51): the load-time dependencies and search
//! paths of a Mach-O or ELF binary, read from its bytes alone — no
//! `otool`, no `ldd`, no I/O (the caller reads the file and hands the
//! bytes in; this module is pure like the rest of the crate).
//!
//! Why: a program the `--allow-exec` flags pin (P-11) is loaded by the
//! system's dynamic linker inside the sandbox, and the linker wants the
//! program's shared libraries. A homebrew `cargo`, for example, links
//! `libgit2` from another Cellar directory, which the `rust` preset's
//! toolchain root does not cover — the first command failed with a dyld
//! error and a correct agent looked wrong. The fix lives in the trust
//! base: the CLI resolves what each pinned program needs and adds those
//! directories as read-only roots **before** anything runs. This module
//! gives it the raw material: [`parse`] returns every `LC_LOAD_DYLIB`
//! family install name and `LC_RPATH` search path of a Mach-O (thin or
//! fat, either byte order, the fat archive's slice for this host), and
//! every `DT_NEEDED` soname and `DT_RUNPATH`/`DT_RPATH` entry of an ELF.
//!
//! Bounded, never panicking: every read is length-checked, load commands
//! and dynamic entries are counted, and strings are length-capped
//! ([`MAX_STRING`]); anything past a bound, truncated or inconsistent is
//! an [`ObjError`], never a slice index out of range. The binaries are
//! untrusted-ish input: a hostile file can refuse to parse, nothing more.
//!
//! [`candidates`] expands a Mach-O install name the way dyld searches it:
//! `@executable_path`, `@loader_path` and `@rpath` (with the loading
//! image's rpaths, each itself `@`-expandable). It does no I/O: it
//! returns every candidate path in search order and the caller picks the
//! first that exists.

use std::fmt;

/// Longest one string (install name, rpath, soname) parsed from a file.
/// Real entries are well under this; the cap keeps a hostile file from
/// making the parser build huge strings.
pub const MAX_STRING: usize = 4096;

/// Most load commands in one Mach-O, and most program headers in one ELF,
/// before the file is called malformed.
pub const MAX_ENTRIES: usize = 65536;

/// Which object-file format [`parse`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// A Mach-O (thin, or a fat archive's slice).
    MachO,
    /// An ELF.
    Elf,
}

impl Format {
    /// The name in refusals.
    pub fn name(self) -> &'static str {
        match self {
            Format::MachO => "Mach-O",
            Format::Elf => "ELF",
        }
    }
}

/// The load-time facts of one object file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjFile {
    /// Which format the bytes were.
    pub format: Format,
    /// Load-time dependencies, in file order: Mach-O install names
    /// (`LC_LOAD_DYLIB`, weak, re-export, lazy, upward) or ELF sonames
    /// (`DT_NEEDED`), as written in the file (not expanded).
    pub libs: Vec<String>,
    /// Search paths as written: Mach-O `LC_RPATH` entries or ELF
    /// `DT_RUNPATH` (then legacy `DT_RPATH`) entries. The CLI expands
    /// them; see [`candidates`].
    pub rpaths: Vec<String>,
}

/// Why a file's load commands could not be read. Every variant is a
/// refusal; nothing here is a panic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjError {
    /// Fewer bytes than the smallest header.
    TooShort,
    /// No known object-file magic (a script, a text file): not refused,
    /// just not an object file ([`is_object`] is false).
    UnknownFormat,
    /// The magic says an object file, but a field, count, offset or
    /// string is out of bounds or inconsistent.
    Malformed(&'static str),
    /// A well-formed file this parser deliberately does not read (an
    /// unusual ELF class, a fat archive without this host's slice).
    Unsupported(&'static str),
}

impl fmt::Display for ObjError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ObjError::TooShort => f.write_str("shorter than an object-file header"),
            ObjError::UnknownFormat => f.write_str("no known object-file format"),
            ObjError::Malformed(why) => write!(f, "malformed object file: {why}"),
            ObjError::Unsupported(why) => write!(f, "unsupported object file: {why}"),
        }
    }
}

impl std::error::Error for ObjError {}

/// Whether the bytes start with a known object-file magic. A shell script
/// (a shebang, or any text) is not an object file and has no load-time
/// dependencies for the CLI to resolve; its interpreter is what runs.
pub fn is_object(bytes: &[u8]) -> bool {
    match bytes {
        [a, b, c, d, ..] => matches!(
            (*a, *b, *c, *d),
            (0xCF, 0xFA, 0xED, 0xFE)
                | (0xCE, 0xFA, 0xED, 0xFE)
                | (0xFE, 0xED, 0xFA, 0xCE)
                | (0xFE, 0xED, 0xFA, 0xCF)
                | (0xCA, 0xFE, 0xBA, 0xBE)
                | (0xBE, 0xBA, 0xFE, 0xCA)
                | (0x7F, b'E', b'L', b'F')
        ),
        _ => false,
    }
}

/// Read the load-time facts of `bytes` (see the module docs). The file's
/// own order is kept, duplicates included: the caller decides what a
/// repeated entry means.
pub fn parse(bytes: &[u8]) -> Result<ObjFile, ObjError> {
    match bytes {
        [0x7F, b'E', b'L', b'F', ..] => parse_elf(bytes),
        _ => parse_macho(bytes, 0),
    }
}

// ---- small readers ----------------------------------------------------------

fn u32_bounded(bytes: &[u8], off: usize, le: bool) -> Result<u32, ObjError> {
    let raw = bytes.get(off..off + 4).ok_or(ObjError::TooShort)?;
    let mut w = [0u8; 4];
    w.copy_from_slice(raw);
    Ok(if le {
        u32::from_le_bytes(w)
    } else {
        u32::from_be_bytes(w)
    })
}

/// Read a little- or big-endian integer of `size` bytes at `off` as an
/// unsigned value (the dynamic tags are two's-complement numbers whose
/// small positive values read the same either way).
fn int_at(bytes: &[u8], off: usize, size: usize, le: bool) -> Result<u64, ObjError> {
    let raw = bytes.get(off..off + size).ok_or(ObjError::TooShort)?;
    let mut buf = [0u8; 8];
    // The value goes into the buffer's head little-endian: copied
    // straight through, or reversed first for a big-endian file.
    let (head, _) = buf.split_at_mut(size);
    head.copy_from_slice(raw);
    if !le {
        head.reverse();
    }
    Ok(u64::from_le_bytes(buf))
}

/// The NUL-terminated string that starts `off` bytes into `bytes`, ended
/// before `end` and length-capped ([`MAX_STRING`]).
fn string_at(bytes: &[u8], off: usize, end: usize) -> Result<String, ObjError> {
    let rest = bytes
        .get(off..end.min(bytes.len()))
        .ok_or(ObjError::Malformed(
            "a string offset leaves its load command",
        ))?;
    let len = rest
        .iter()
        .position(|b| *b == 0)
        .ok_or(ObjError::Malformed("a string is not NUL-terminated"))?;
    if len > MAX_STRING {
        return Err(ObjError::Malformed("a string is past the length cap"));
    }
    String::from_utf8(
        rest.get(..len)
            .ok_or(ObjError::Malformed("a string leaves its load command"))?
            .to_vec(),
    )
    .map_err(|_| ObjError::Malformed("a string is not UTF-8"))
}

// ---- Mach-O -----------------------------------------------------------------

/// `MH_MAGIC_64` in the file's own byte order.
const MH_MAGIC_64: u32 = 0xfeedfacf;
/// `MH_MAGIC` (32-bit) in the file's own byte order.
const MH_MAGIC: u32 = 0xfeedface;
/// `FAT_MAGIC`, which sits on disk big-endian.
const FAT_MAGIC: u32 = 0xcafebabe;

/// `LC_REQ_DYLD`: the high bit several load commands carry.
const LC_REQ_DYLD: u32 = 0x8000_0000;
/// `LC_LOAD_DYLIB`.
const LC_LOAD_DYLIB: u32 = 0x0c;
/// `LC_LOAD_WEAK_DYLIB`.
const LC_LOAD_WEAK_DYLIB: u32 = 0x18;
/// `LC_RPATH`.
const LC_RPATH: u32 = 0x1c | LC_REQ_DYLD;
/// `LC_REEXPORT_DYLIB`.
const LC_REEXPORT_DYLIB: u32 = 0x1f | LC_REQ_DYLD;
/// `LC_LAZY_LOAD_DYLIB`.
const LC_LAZY_LOAD_DYLIB: u32 = 0x20;
/// `LC_LOAD_UPWARD_DYLIB`.
const LC_LOAD_UPWARD_DYLIB: u32 = 0x23 | LC_REQ_DYLD;

/// The fat archive's slice for this host: `CPU_TYPE_X86_64`, or (with the
/// high bit) `CPU_TYPE_ARM64`.
#[cfg(target_arch = "x86_64")]
const HOST_CPU: u32 = 0x0100_0007;
/// The fat archive's slice for this host (see the 32-bit twin above).
#[cfg(target_arch = "aarch64")]
const HOST_CPU: u32 = 0x0100_000c;

/// Parse a Mach-O: a thin image in either byte order, 32- or 64-bit, or
/// the slice of a fat (universal) archive that matches this host's CPU.
/// `depth` is the fat nesting: the format has none (a fat archive's
/// slice is thin), so a slice that is itself a fat archive — or a slice
/// whose offset points back at its own header — is refused rather than
/// walked round forever (P-55's fuzz loop found the unbounded
/// recursion).
fn parse_macho(bytes: &[u8], depth: usize) -> Result<ObjFile, ObjError> {
    let magic = u32_bounded(bytes, 0, true)?;
    if magic == FAT_MAGIC || magic == FAT_MAGIC.swap_bytes() {
        if depth > 0 {
            return Err(ObjError::Malformed("a fat slice is itself a fat archive"));
        }
        // On disk a fat header is big-endian, so the little-endian read
        // sees the byte-swapped magic; the plain magic means the (rare)
        // little-endian layout, and both keep their fields that way too.
        return fat_slice(bytes, magic == FAT_MAGIC, depth);
    }
    let le = magic == MH_MAGIC || magic == MH_MAGIC_64;
    if !le && magic != MH_MAGIC.swap_bytes() && magic != MH_MAGIC_64.swap_bytes() {
        return Err(ObjError::UnknownFormat);
    }
    let wide = if le {
        magic == MH_MAGIC_64
    } else {
        magic == MH_MAGIC_64.swap_bytes()
    };
    let header = 28 + usize::from(wide) * 4;
    let ncmds = u32_bounded(bytes, 16, le)? as usize;
    let cmds = bytes
        .get(header..)
        .ok_or(ObjError::Malformed("the header is short"))?;
    if ncmds > MAX_ENTRIES {
        return Err(ObjError::Malformed("too many load commands"));
    }
    let mut out = ObjFile {
        format: Format::MachO,
        libs: Vec::new(),
        rpaths: Vec::new(),
    };
    // Walk the load commands: each names its own size, so a hostile
    // `ncmds` cannot walk past the buffer (the size check refuses first).
    let mut off = 0;
    for _ in 0..ncmds {
        if off + 8 > cmds.len() {
            return Err(ObjError::Malformed("a load command header is short"));
        }
        let cmd = u32_bounded(cmds, off, le)?;
        let size = u32_bounded(cmds, off + 4, le)? as usize;
        if size < 8 || off + size > cmds.len() {
            return Err(ObjError::Malformed("a load command size is out of bounds"));
        }
        let body = cmds
            .get(off..off + size)
            .ok_or(ObjError::Malformed("a load command size is out of bounds"))?;
        match cmd {
            LC_LOAD_DYLIB | LC_LOAD_WEAK_DYLIB | LC_REEXPORT_DYLIB | LC_LAZY_LOAD_DYLIB
            | LC_LOAD_UPWARD_DYLIB => {
                // dylib_command: name.offset is the third field.
                let name_off = u32_bounded(body, 8, le)? as usize;
                if name_off < 24 || name_off >= body.len() {
                    return Err(ObjError::Malformed(
                        "a dylib name offset leaves its load command",
                    ));
                }
                out.libs.push(string_at(body, name_off, body.len())?);
            }
            LC_RPATH => {
                // rpath_command: path.offset is the third field.
                let path_off = u32_bounded(body, 8, le)? as usize;
                if path_off < 12 || path_off >= body.len() {
                    return Err(ObjError::Malformed(
                        "an rpath offset leaves its load command",
                    ));
                }
                out.rpaths.push(string_at(body, path_off, body.len())?);
            }
            _ => {}
        }
        off += size;
    }
    Ok(out)
}

/// The fat archive's slice for [`HOST_CPU`]: a big-endian fat header and
/// 20-byte architecture entries, each naming an offset and size into the
/// same bytes. At most 16 slices are read; a real archive has a handful.
fn fat_slice(bytes: &[u8], le: bool, depth: usize) -> Result<ObjFile, ObjError> {
    let narch = u32_bounded(bytes, 4, le)? as usize;
    if narch > 16 {
        return Err(ObjError::Malformed("too many slices in a fat archive"));
    }
    for i in 0..narch {
        let base = 8 + i * 20;
        let cpu = u32_bounded(bytes, base, le)?;
        let off = u32_bounded(bytes, base + 8, le)? as usize;
        let size = u32_bounded(bytes, base + 12, le)? as usize;
        if cpu == HOST_CPU {
            let slice = bytes
                .get(off..off.saturating_add(size))
                .ok_or(ObjError::Malformed("a fat slice leaves the file"))?;
            return parse_macho(slice, depth + 1);
        }
    }
    Err(ObjError::Unsupported(
        "a fat archive without this host's slice",
    ))
}

// ---- ELF --------------------------------------------------------------------

/// `PT_LOAD`: a segment whose virtual addresses map to file bytes.
const PT_LOAD: u32 = 1;
/// `PT_DYNAMIC`: the dynamic section's file range.
const PT_DYNAMIC: u32 = 2;
/// `DT_NEEDED`: a dependency, as an offset into the dynamic string table.
const DT_NEEDED: u64 = 1;
/// `DT_STRTAB`: the dynamic string table's virtual address.
const DT_STRTAB: u64 = 5;
/// `DT_STRSZ`: the dynamic string table's size.
const DT_STRSZ: u64 = 10;
/// `DT_RPATH`: the legacy search path.
const DT_RPATH: u64 = 15;
/// `DT_RUNPATH`: the search path a modern linker writes.
const DT_RUNPATH: u64 = 29;

/// One ELF program header, normalised to 64-bit fields.
struct Phdr {
    kind: u32,
    offset: u64,
    vaddr: u64,
    filesz: u64,
}

/// Parse an ELF: 32- or 64-bit, little- or big-endian. The dynamic
/// section (found through the program headers) holds the dependencies and
/// search paths; the string table is found through its virtual address,
/// mapped back to file bytes with the `PT_LOAD` segments.
fn parse_elf(bytes: &[u8]) -> Result<ObjFile, ObjError> {
    let class = *bytes.get(4).ok_or(ObjError::TooShort)?;
    let data = *bytes.get(5).ok_or(ObjError::TooShort)?;
    if (class != 1 && class != 2) || (data != 1 && data != 2) {
        return Err(ObjError::Unsupported("an ELF of an unknown class"));
    }
    let wide = class == 2;
    let le = data == 1;
    let word = usize::from(wide) * 4 + 4; // 8 bytes on 64-bit, 4 on 32-bit
                                          // e_phoff, e_phentsize and e_phnum sit at fixed offsets per class.
    let (phoff_off, phentsize_off, phnum_off) = if wide {
        (0x20, 0x36, 0x38)
    } else {
        (0x1c, 0x2a, 0x2c)
    };
    let phoff = int_at(bytes, phoff_off, word, le)? as usize;
    let phentsize = int_at(bytes, phentsize_off, 2, le)? as usize;
    let phnum = int_at(bytes, phnum_off, 2, le)? as usize;
    let ent = usize::from(wide) * 24 + 32; // 56 bytes on 64-bit, 32 on 32-bit
    if phentsize < ent || phnum > MAX_ENTRIES {
        return Err(ObjError::Malformed(
            "the program header table is out of bounds",
        ));
    }
    let mut phdrs = Vec::new();
    for i in 0..phnum {
        let base = phoff + i * phentsize;
        let kind = int_at(bytes, base, 4, le)? as u32;
        if !matches!(kind, PT_LOAD | PT_DYNAMIC) {
            continue;
        }
        // p_offset, p_vaddr and p_filesz sit together after p_type
        // (and p_flags on 64-bit).
        let (at_off, at_vaddr, at_filesz) = if wide { (8, 16, 32) } else { (4, 8, 16) };
        phdrs.push(Phdr {
            kind,
            offset: int_at(bytes, base + at_off, word, le)?,
            vaddr: int_at(bytes, base + at_vaddr, word, le)?,
            filesz: int_at(bytes, base + at_filesz, word, le)?,
        });
    }
    let dynamic = phdrs
        .iter()
        .find(|p| p.kind == PT_DYNAMIC)
        .ok_or(ObjError::Unsupported("an ELF without a dynamic section"))?;
    // The dynamic entries: (tag, value) pairs, ending at DT_NULL.
    let entsz = word + 8; // one tag and one value field
    if dynamic.filesz as usize > bytes.len().saturating_mul(2) {
        return Err(ObjError::Malformed("the dynamic section leaves the file"));
    }
    let count = ((dynamic.filesz as usize) / entsz).min(MAX_ENTRIES);
    let mut strtab_vaddr: Option<u64> = None;
    let mut strsz: Option<u64> = None;
    let mut entries: Vec<(u64, u64)> = Vec::new();
    for i in 0..count {
        let base = dynamic.offset as usize + i * entsz;
        let tag = int_at(bytes, base, word, le)?;
        let val = int_at(bytes, base + word, word, le)?;
        if tag == 0 {
            break;
        }
        match tag {
            DT_STRTAB => strtab_vaddr = Some(val),
            DT_STRSZ => strsz = Some(val),
            DT_NEEDED | DT_RPATH | DT_RUNPATH => entries.push((tag, val)),
            _ => {}
        }
    }
    let (Some(strvaddr), Some(sz)) = (strtab_vaddr, strsz) else {
        return Err(ObjError::Malformed(
            "a dynamic section with dependencies but no string table",
        ));
    };
    let str_off = vaddr_to_offset(&phdrs, strvaddr).ok_or(ObjError::Malformed(
        "the string table's address is not in any PT_LOAD segment",
    ))? as usize;
    let sz = sz as usize;
    if sz > MAX_ENTRIES * MAX_STRING {
        return Err(ObjError::Malformed("the string table is past the size cap"));
    }
    let strtab = bytes
        .get(str_off..str_off.saturating_add(sz))
        .ok_or(ObjError::Malformed("the string table leaves the file"))?;
    let pick = |off: u64| -> Result<String, ObjError> {
        let rest = strtab.get(off as usize..).ok_or(ObjError::Malformed(
            "a string offset leaves the string table",
        ))?;
        let len = rest
            .iter()
            .position(|b| *b == 0)
            .ok_or(ObjError::Malformed("a string is not NUL-terminated"))?;
        if len > MAX_STRING {
            return Err(ObjError::Malformed("a string is past the length cap"));
        }
        String::from_utf8(
            rest.get(..len)
                .ok_or(ObjError::Malformed("a string leaves its table"))?
                .to_vec(),
        )
        .map_err(|_| ObjError::Malformed("a string is not UTF-8"))
    };
    let mut out = ObjFile {
        format: Format::Elf,
        libs: Vec::new(),
        rpaths: Vec::new(),
    };
    for (tag, val) in entries {
        match tag {
            DT_NEEDED => out.libs.push(pick(val)?),
            DT_RUNPATH => out.rpaths.insert(0, pick(val)?),
            DT_RPATH => out.rpaths.push(pick(val)?),
            _ => {}
        }
    }
    Ok(out)
}

/// A virtual address to a file offset, through the `PT_LOAD` segment
/// whose file image covers it.
fn vaddr_to_offset(phdrs: &[Phdr], vaddr: u64) -> Option<u64> {
    phdrs
        .iter()
        .find(|p| p.kind == PT_LOAD && vaddr >= p.vaddr && vaddr < p.vaddr.saturating_add(p.filesz))
        .map(|p| p.offset + (vaddr - p.vaddr))
}

// ---- @-path expansion -------------------------------------------------------

/// The paths dyld would search for `install_name` (see the module docs),
/// in search order: `@executable_path/…` against the run program's
/// directory, `@loader_path/…` against the loading file's directory, and
/// `@rpath/…` against each of the loading image's rpaths (an rpath may
/// itself start with `@executable_path` or `@loader_path`). An absolute
/// install name is itself; anything else (a relative name, an unknown
/// `@` form) has no candidates. Duplicates are removed, order kept.
///
/// Directories and results are plain strings, not path types: this
/// module is pure, and the std path type carries filesystem methods the
/// purity gate refuses. The join is the loader's own: a `/` between
/// directory and name (no double slash when the directory ends in one),
/// with no normalisation — components like `..` are kept literally and
/// the caller canonicalises what it finds.
pub fn candidates(
    install_name: &str,
    loader_dir: &str,
    rpaths: &[String],
    exec_dir: &str,
) -> Vec<String> {
    fn join(base: &str, rest: &str) -> Option<String> {
        if rest.is_empty() {
            None
        } else if base.ends_with('/') {
            Some(format!("{base}{rest}"))
        } else {
            Some(format!("{base}/{rest}"))
        }
    }
    fn expand(s: &str, loader_dir: &str, exec_dir: &str) -> Option<String> {
        if let Some(rest) = s.strip_prefix("@executable_path/") {
            join(exec_dir, rest)
        } else if let Some(rest) = s.strip_prefix("@loader_path/") {
            join(loader_dir, rest)
        } else if s.starts_with('@') {
            None
        } else if s.starts_with('/') {
            Some(s.to_owned())
        } else {
            None
        }
    }
    let mut out: Vec<String> = Vec::new();
    if let Some(rest) = install_name.strip_prefix("@rpath/") {
        for r in rpaths {
            if let Some(base) = expand(r, loader_dir, exec_dir) {
                if let Some(c) = join(&base, rest) {
                    if !out.contains(&c) {
                        out.push(c);
                    }
                }
            }
        }
    } else if let Some(p) = expand(install_name, loader_dir, exec_dir) {
        out.push(p);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A little-endian 64-bit Mach-O dylib's bytes with the given rpaths
    /// and install names, as fixture bytes (no file involved): a header,
    /// then one load command per entry, each 4-byte aligned.
    fn macho_bytes(rpaths: &[&str], libs: &[&str]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&MH_MAGIC_64.to_le_bytes());
        v.extend_from_slice(&HOST_CPU.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes()); // cpusubtype
        v.extend_from_slice(&6u32.to_le_bytes()); // MH_DYLIB
        v.extend_from_slice(&((rpaths.len() + libs.len()) as u32).to_le_bytes()); // ncmds
        v.extend_from_slice(&0u32.to_le_bytes()); // sizeofcmds, patched below
        v.extend_from_slice(&0u32.to_le_bytes()); // flags
        v.extend_from_slice(&0u32.to_le_bytes()); // reserved
        let mut cmds: Vec<u8> = Vec::new();
        for r in rpaths {
            let len = 12 + r.len() + 1;
            let size = len.div_ceil(4) * 4;
            cmds.extend_from_slice(&LC_RPATH.to_le_bytes());
            cmds.extend_from_slice(&(size as u32).to_le_bytes());
            cmds.extend_from_slice(&12u32.to_le_bytes()); // path.offset
            cmds.extend_from_slice(r.as_bytes());
            cmds.push(0);
            cmds.resize(cmds.len() + (size - len), 0);
        }
        for l in libs {
            let len = 24 + l.len() + 1;
            let size = len.div_ceil(4) * 4;
            cmds.extend_from_slice(&LC_LOAD_DYLIB.to_le_bytes());
            cmds.extend_from_slice(&(size as u32).to_le_bytes());
            cmds.extend_from_slice(&24u32.to_le_bytes()); // name.offset
            cmds.extend_from_slice(&1u32.to_le_bytes()); // timestamp
            cmds.extend_from_slice(&0u32.to_le_bytes()); // current_version
            cmds.extend_from_slice(&0u32.to_le_bytes()); // compat_version
            cmds.extend_from_slice(l.as_bytes());
            cmds.push(0);
            cmds.resize(cmds.len() + (size - len), 0);
        }
        v[20..24].copy_from_slice(&(cmds.len() as u32).to_le_bytes());
        v.extend_from_slice(&cmds);
        v
    }

    /// Where the load commands start in [`macho_bytes`]'s output (the
    /// 64-bit header is 32 bytes).
    const CMDS_AT: usize = 32;

    #[test]
    fn macho_load_commands_parsed_from_fixture_bytes() {
        let b = macho_bytes(
            &["@loader_path/../lib"],
            &[
                "/usr/lib/libSystem.B.dylib",
                "@rpath/libgit2.1.9.dylib",
                "@rpath/libgit2.1.9.dylib",
            ],
        );
        assert!(is_object(&b));
        let o = parse(&b).unwrap();
        assert_eq!(o.format, Format::MachO);
        assert_eq!(o.rpaths, vec!["@loader_path/../lib"]);
        // File order, duplicates kept: the caller decides.
        assert_eq!(
            o.libs,
            vec![
                "/usr/lib/libSystem.B.dylib",
                "@rpath/libgit2.1.9.dylib",
                "@rpath/libgit2.1.9.dylib",
            ]
        );
        // A shell script is not an object file.
        assert!(!is_object(b"#!/bin/sh\n"));
        assert_eq!(parse(b"#!/bin/sh\n").unwrap_err(), ObjError::UnknownFormat);
    }

    #[test]
    fn rpath_and_loader_path_expanded() {
        let loader = "/opt/homebrew/Cellar/cargo/0.1/bin";
        let exec = "/opt/homebrew/bin";
        let rpaths = vec![
            "@loader_path/../lib".to_owned(),
            "@executable_path/../lib".to_owned(),
            "/opt/homebrew/opt/libgit2/lib".to_owned(),
        ];
        // @rpath tries every rpath, in order, each expanded against the
        // loading image's directory. The components are joined literally
        // (`..` stays; the caller canonicalises what it finds).
        assert_eq!(
            candidates("@rpath/libgit2.1.9.dylib", loader, &rpaths, exec),
            vec![
                "/opt/homebrew/Cellar/cargo/0.1/bin/../lib/libgit2.1.9.dylib",
                "/opt/homebrew/bin/../lib/libgit2.1.9.dylib",
                "/opt/homebrew/opt/libgit2/lib/libgit2.1.9.dylib",
            ]
        );
        // @loader_path, @executable_path and an absolute name.
        assert_eq!(
            candidates("@loader_path/libx.dylib", loader, &rpaths, exec),
            vec!["/opt/homebrew/Cellar/cargo/0.1/bin/libx.dylib"]
        );
        assert_eq!(
            candidates("@executable_path/liby.dylib", loader, &rpaths, exec),
            vec!["/opt/homebrew/bin/liby.dylib"]
        );
        assert_eq!(
            candidates("/usr/lib/libz.1.dylib", loader, &rpaths, exec),
            vec!["/usr/lib/libz.1.dylib"]
        );
        // A relative name and an unknown @ form have no candidates.
        assert!(candidates("libz.dylib", loader, &rpaths, exec).is_empty());
        assert!(candidates("@unknown_path/libz.dylib", loader, &rpaths, exec).is_empty());
    }

    /// A little-endian 64-bit ELF with one PT_LOAD covering its dynamic
    /// section: DT_STRTAB, DT_STRSZ, DT_RUNPATH, DT_NEEDED, DT_NULL.
    fn elf_bytes(runpath: &str, needed: &[&str]) -> Vec<u8> {
        let strtab_off = 0x200usize;
        let mut strings: Vec<u8> = Vec::new();
        let mut off_of = |s: &str| -> u64 {
            // DT_ string values are offsets from the table's own start.
            let off = strings.len() as u64;
            strings.extend_from_slice(s.as_bytes());
            strings.push(0);
            off
        };
        let rp = off_of(runpath);
        let names: Vec<u64> = needed.iter().map(|s| off_of(s)).collect();
        let mut dyn_bytes: Vec<u8> = Vec::new();
        let mut put = |tag: u64, val: u64| {
            dyn_bytes.extend_from_slice(&tag.to_le_bytes());
            dyn_bytes.extend_from_slice(&val.to_le_bytes());
        };
        put(DT_STRTAB, strtab_off as u64);
        put(DT_STRSZ, strings.len() as u64);
        put(DT_RUNPATH, rp);
        for n in names {
            put(DT_NEEDED, n);
        }
        put(0, 0); // DT_NULL
        let dyn_off = strtab_off + strings.len();
        let mut v = vec![0u8; dyn_off + dyn_bytes.len()];
        v[..4].copy_from_slice(b"\x7fELF");
        v[4] = 2; // ELFCLASS64
        v[5] = 1; // ELFDATA2LSB
        v[6] = 1; // EV_CURRENT
        v[0x20..0x28].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
        v[0x36..0x38].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
        v[0x38..0x3a].copy_from_slice(&2u16.to_le_bytes()); // e_phnum
        let mut load = vec![0u8; 56];
        load[0..4].copy_from_slice(&PT_LOAD.to_le_bytes());
        load[8..16].copy_from_slice(&0u64.to_le_bytes()); // p_offset
        load[16..24].copy_from_slice(&0u64.to_le_bytes()); // p_vaddr
        load[32..40].copy_from_slice(&0x1000u64.to_le_bytes()); // p_filesz
        v[64..120].copy_from_slice(&load);
        let mut pdyn = vec![0u8; 56];
        pdyn[0..4].copy_from_slice(&PT_DYNAMIC.to_le_bytes());
        pdyn[8..16].copy_from_slice(&(dyn_off as u64).to_le_bytes()); // p_offset
        pdyn[16..24].copy_from_slice(&(dyn_off as u64).to_le_bytes()); // p_vaddr
        pdyn[32..40].copy_from_slice(&(dyn_bytes.len() as u64).to_le_bytes()); // p_filesz
        v[120..176].copy_from_slice(&pdyn);
        v[strtab_off..strtab_off + strings.len()].copy_from_slice(&strings);
        v[dyn_off..].copy_from_slice(&dyn_bytes);
        v
    }

    #[test]
    fn elf_needed_and_runpath_parsed() {
        let b = elf_bytes("$ORIGIN/../lib", &["libgit2.so.1.9", "libc.so.6"]);
        assert!(is_object(&b));
        let o = parse(&b).unwrap();
        assert_eq!(o.format, Format::Elf);
        assert_eq!(o.libs, vec!["libgit2.so.1.9", "libc.so.6"]);
        assert_eq!(o.rpaths, vec!["$ORIGIN/../lib"]);
        // Not an ELF at all: the Mach-O refusal is by name.
        assert_eq!(
            parse(&[0x7f, b'E', b'L', b'G']).unwrap_err(),
            ObjError::UnknownFormat
        );
    }

    #[test]
    fn malformed_object_file_is_refused_not_panicked() {
        // The magic alone, and the header cut mid-field.
        assert_eq!(parse(&[0xcf, 0xfa]).unwrap_err(), ObjError::TooShort);
        assert_eq!(
            parse(&[0xcf, 0xfa, 0xed, 0xfe, 0, 0, 0, 0]).unwrap_err(),
            ObjError::TooShort
        );
        // A load command whose size walks past the buffer.
        let mut b = macho_bytes(&[], &["/usr/lib/libSystem.B.dylib"]);
        let at = CMDS_AT;
        b[at + 4..at + 8].copy_from_slice(&u32::MAX.to_le_bytes());
        let e = parse(&b).unwrap_err();
        assert!(matches!(e, ObjError::Malformed(_)), "{e}");
        // A load command count larger than the file can hold.
        let mut b = macho_bytes(&[], &[]);
        b[16..20].copy_from_slice(&(MAX_ENTRIES as u32 + 1).to_le_bytes());
        let e = parse(&b).unwrap_err();
        assert!(matches!(e, ObjError::Malformed(_)), "{e}");
        // A name offset inside the fixed part of the command.
        for at in [8usize, 16] {
            let mut b = macho_bytes(&[], &["/usr/lib/libSystem.B.dylib"]);
            let cmds = CMDS_AT;
            b[cmds + 8..cmds + 12].copy_from_slice(&(at as u32).to_le_bytes());
            let e = parse(&b).unwrap_err();
            assert!(matches!(e, ObjError::Malformed(_)), "{e}");
        }
        // A fat archive whose slices are all for other CPUs.
        let mut fat = Vec::new();
        fat.extend_from_slice(&FAT_MAGIC.to_be_bytes());
        fat.extend_from_slice(&1u32.to_be_bytes()); // nfat_arch
        fat.extend_from_slice(&7u32.to_be_bytes()); // CPU_TYPE_X86_64
        fat.extend_from_slice(&0u32.to_be_bytes()); // cpusubtype
        fat.extend_from_slice(&0u32.to_be_bytes()); // offset
        fat.extend_from_slice(&0u32.to_be_bytes()); // size
        fat.extend_from_slice(&0u32.to_be_bytes()); // align
        let e = parse(&fat).unwrap_err();
        assert!(matches!(e, ObjError::Unsupported(_)), "{e}");
    }

    // ---- fuzz-style robustness (P-55) ---------------------------------------
    //
    // The parser's input is untrusted-ish bytes — a pinned program can be
    // anything a build, a crash or an attacker left on the disk — so the
    // documented contract is exercised the way P-54 does for the other
    // parsers of untrusted bytes: mutated valid fixtures and plain garbage
    // from the seeded `harness_testkit::mutator`, every case reproducible
    // from the seed the loop names (seed base + case index, both carried in
    // the assert messages). Either verdict is fine; the test is that there
    // IS one, typed, and that an `Ok` stays inside the documented bounds.

    use harness_testkit::mutator::{self, XorShift64};

    /// A 32-bit big-endian Mach-O with the given rpaths and install names:
    /// the other thin shape the parser reads (the sibling of
    /// [`macho_bytes`], which is 64-bit little-endian).
    fn macho_bytes_be(rpaths: &[&str], libs: &[&str]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&MH_MAGIC.to_be_bytes());
        v.extend_from_slice(&HOST_CPU.to_be_bytes());
        v.extend_from_slice(&0u32.to_be_bytes()); // cpusubtype
        v.extend_from_slice(&6u32.to_be_bytes()); // MH_DYLIB
        v.extend_from_slice(&((rpaths.len() + libs.len()) as u32).to_be_bytes()); // ncmds
        v.extend_from_slice(&0u32.to_be_bytes()); // sizeofcmds, patched below
        v.extend_from_slice(&0u32.to_be_bytes()); // flags
        let mut cmds: Vec<u8> = Vec::new();
        for r in rpaths {
            let len = 12 + r.len() + 1;
            let size = len.div_ceil(4) * 4;
            cmds.extend_from_slice(&LC_RPATH.to_be_bytes());
            cmds.extend_from_slice(&(size as u32).to_be_bytes());
            cmds.extend_from_slice(&12u32.to_be_bytes()); // path.offset
            cmds.extend_from_slice(r.as_bytes());
            cmds.push(0);
            cmds.resize(cmds.len() + (size - len), 0);
        }
        for l in libs {
            let len = 24 + l.len() + 1;
            let size = len.div_ceil(4) * 4;
            cmds.extend_from_slice(&LC_LOAD_DYLIB.to_be_bytes());
            cmds.extend_from_slice(&(size as u32).to_be_bytes());
            cmds.extend_from_slice(&24u32.to_be_bytes()); // name.offset
            cmds.extend_from_slice(&1u32.to_be_bytes()); // timestamp
            cmds.extend_from_slice(&0u32.to_be_bytes()); // current_version
            cmds.extend_from_slice(&0u32.to_be_bytes()); // compat_version
            cmds.extend_from_slice(l.as_bytes());
            cmds.push(0);
            cmds.resize(cmds.len() + (size - len), 0);
        }
        v[20..24].copy_from_slice(&(cmds.len() as u32).to_be_bytes());
        v.extend_from_slice(&cmds);
        v
    }

    /// A fat (universal) archive whose single slice is `thin`, named for
    /// this host's CPU: the on-disk header form is big-endian, the slice
    /// sits right after the one 20-byte architecture entry.
    fn fat_bytes(thin: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&FAT_MAGIC.to_be_bytes());
        v.extend_from_slice(&1u32.to_be_bytes()); // nfat_arch
        v.extend_from_slice(&HOST_CPU.to_be_bytes()); // cputype
        v.extend_from_slice(&0u32.to_be_bytes()); // cpusubtype
        v.extend_from_slice(&28u32.to_be_bytes()); // offset: header + one entry
        v.extend_from_slice(&(thin.len() as u32).to_be_bytes()); // size
        v.extend_from_slice(&12u32.to_be_bytes()); // align (2^12)
        v.extend_from_slice(thin);
        v
    }

    /// The parser's documented output bounds, on whatever it returned: at
    /// most one string per load command or dynamic entry, so never more
    /// entries than the [`MAX_ENTRIES`] cap allows, and no string past the
    /// [`MAX_STRING`] cap.
    fn assert_within_bounds(o: &ObjFile) {
        assert!(
            o.libs.len() + o.rpaths.len() <= MAX_ENTRIES,
            "{} libs + {} rpaths is past the entry cap",
            o.libs.len(),
            o.rpaths.len()
        );
        for s in o.libs.iter().chain(o.rpaths.iter()) {
            assert!(s.len() <= MAX_STRING, "string past the cap: {s}");
        }
    }

    /// Whatever the bytes, the verdict is typed and honest: an `Ok` only
    /// for bytes whose magic names a format, within the documented
    /// bounds; `UnknownFormat` only once a magic was read at all — the
    /// only possible verdict when the leading four bytes name no format,
    /// and through a fat archive the host slice's verdict (whose own
    /// leading magic named nothing); anything else a typed [`ObjError`]
    /// (which always renders).
    fn assert_typed_verdict(bytes: &[u8], case: usize) {
        match parse(bytes) {
            Ok(o) => {
                assert!(
                    is_object(bytes),
                    "case {case}: parsed what its magic does not name"
                );
                assert_within_bounds(&o);
            }
            Err(ObjError::UnknownFormat) => {
                // The fat magics are the only ones whose parse can speak
                // for bytes other than the leading four.
                let fat = matches!(
                    bytes.get(..4),
                    Some([0xCA, 0xFE, 0xBA, 0xBE] | [0xBE, 0xBA, 0xFE, 0xCA])
                );
                assert!(
                    bytes.len() >= 4 && (!is_object(bytes) || fat),
                    "case {case}: called unknown what a magic names (len {})",
                    bytes.len()
                );
            }
            Err(e) => assert!(!e.to_string().is_empty(), "case {case}"),
        }
    }

    /// One fuzz loop: `cases` mutations of each fixture in `corpora`
    /// (seed base + running case index), each fed to the parser with its
    /// verdict checked, then re-derived from the same seed and compared —
    /// a failure is replayable from the printed case index alone.
    fn fuzz_over_images(corpora: &[Vec<u8>], cases: usize) {
        let mut case = 0usize;
        for bytes in corpora {
            for _ in 0..cases {
                let mut rng = XorShift64::new(0x5100_0000_0001 + case as u64);
                let m = mutator::mutate(bytes, &mut rng, 24);
                assert_typed_verdict(&m, case);
                let mut rng2 = XorShift64::new(0x5100_0000_0001 + case as u64);
                assert_eq!(mutator::mutate(bytes, &mut rng2, 24), m, "case {case}");
                case += 1;
            }
        }
        // Plain garbage of the fixtures' order of size gets the same
        // treatment, in its own seed range.
        for g in 0..cases {
            let mut rng = XorShift64::new(0x5F00_0000_0001 + g as u64);
            let len = 1 + rng.below(160);
            assert_typed_verdict(&mutator::garbage(&mut rng, len), g);
        }
    }

    /// The Mach-O corpora: a valid thin 64-bit image, a 32-bit
    /// big-endian one, and a fat archive whose slice is this host's.
    fn macho_corpora() -> Vec<Vec<u8>> {
        let thin = macho_bytes(
            &["@loader_path/../lib", "@executable_path/../lib"],
            &[
                "/usr/lib/libSystem.B.dylib",
                "@rpath/libgit2.1.9.dylib",
                "@rpath/libgit2.1.9.dylib",
            ],
        );
        let be = macho_bytes_be(&["@loader_path/../lib"], &["@rpath/libb.dylib"]);
        let fat = fat_bytes(&thin);
        for (label, bytes) in [("thin", &thin), ("be", &be), ("fat", &fat)] {
            let o = parse(bytes).expect(label);
            assert_eq!(o.format, Format::MachO);
        }
        vec![thin, be, fat]
    }

    /// The ELF corpus: one valid 64-bit little-endian image (the other
    /// class and byte-order shapes share the parser's bounds, which the
    /// mutations exercise).
    fn elf_corpus() -> Vec<Vec<u8>> {
        let elf = elf_bytes("$ORIGIN/../lib", &["libgit2.so.1.9", "libc.so.6"]);
        assert_eq!(parse(&elf).unwrap().format, Format::Elf);
        vec![elf]
    }

    #[test]
    fn fuzz_macho_parser_never_panics() {
        fuzz_over_images(&macho_corpora(), mutator::case_count(2_000));
    }

    /// The case the fuzz loop found (a mutated fat archive whose slice
    /// offset pointed back at its own header): a fat archive whose host
    /// slice is the fat archive itself is a typed refusal, not an
    /// unbounded `parse_macho` -> `fat_slice` recursion.
    #[test]
    fn fat_archive_pointing_at_itself_is_typed_refusal() {
        let mut fat = fat_bytes(&macho_bytes(&[], &[]));
        // The one slice's offset (bytes 16..20, big-endian) now points at
        // the fat header itself.
        fat[16..20].copy_from_slice(&0u32.to_be_bytes());
        let e = parse(&fat).unwrap_err();
        assert!(matches!(e, ObjError::Malformed(_)), "{e}");
    }

    /// The long form: `cargo test -- --ignored` with `RH_FUZZ_CASES` set
    /// drives the case count up.
    #[test]
    #[ignore]
    fn fuzz_macho_long_cases() {
        fuzz_over_images(&macho_corpora(), mutator::case_count(50_000));
    }

    #[test]
    fn fuzz_elf_parser_never_panics() {
        fuzz_over_images(&elf_corpus(), mutator::case_count(2_000));
    }

    /// The long form: `cargo test -- --ignored` with `RH_FUZZ_CASES` set
    /// drives the case count up.
    #[test]
    #[ignore]
    fn fuzz_elf_long_cases() {
        fuzz_over_images(&elf_corpus(), mutator::case_count(50_000));
    }

    #[test]
    fn fuzz_macho_truncation_at_every_byte_is_typed_error() {
        // No bytes at all is a typed refusal, not a panic.
        assert!(matches!(parse(&[]), Err(ObjError::TooShort)));
        let thin = macho_bytes(
            &["@loader_path/../lib"],
            &["/usr/lib/libSystem.B.dylib", "@rpath/libgit2.1.9.dylib"],
        );
        let fat = fat_bytes(&thin);
        for bytes in [&thin, &fat] {
            let whole = parse(bytes).unwrap();
            assert_eq!(whole.libs.len() + whole.rpaths.len(), 3);
            // Every proper prefix answers with a typed verdict, and an
            // `Ok` never reports more than the whole file does, nor
            // anything the whole file does not carry in the same place:
            // a cut can only drop whole load commands (each names its own
            // size, so a straddling one is a typed refusal), so a
            // prefix's entries are a prefix of the whole's.
            for i in 0..bytes.len() {
                match parse(&bytes[..i]) {
                    Ok(o) => {
                        assert_within_bounds(&o);
                        assert!(
                            o.libs.len() <= whole.libs.len()
                                && o.rpaths.len() <= whole.rpaths.len()
                                && whole.libs.starts_with(&o.libs[..])
                                && whole.rpaths.starts_with(&o.rpaths[..]),
                            "prefix {i} of {} invents entries",
                            bytes.len()
                        );
                    }
                    Err(e) => assert!(!e.to_string().is_empty(), "prefix {i}"),
                }
            }
        }
    }

    /// The cyclic-dependency fixture: two images, `a` naming `b` and `b`
    /// naming `a`, both through `@rpath` and the same search path — the
    /// shape a dependency cycle takes on disk. The loader would bounce
    /// between the two forever; the parser must not even notice.
    fn cyclic_pair() -> (Vec<u8>, Vec<u8>) {
        (
            macho_bytes(&["@loader_path/../lib"], &["@rpath/libb.dylib"]),
            macho_bytes(&["@loader_path/../lib"], &["@rpath/liba.dylib"]),
        )
    }

    /// The bounds loop over the mutated cyclic fixture: whatever a case
    /// leaves, an `Ok` keeps its entries inside the caps and every install
    /// name expands to at most one candidate per rpath (one of its own
    /// when there are no rpaths) — a cycle in the references cannot grow
    /// the output.
    fn fuzz_over_cyclic(cases: usize) {
        let (a, b) = cyclic_pair();
        for case in 0..cases {
            let which = if case % 2 == 0 { &a } else { &b };
            let mut rng = XorShift64::new(0x5300_0000_0001 + case as u64);
            let m = mutator::mutate(which, &mut rng, 24);
            if let Ok(o) = parse(&m) {
                assert_within_bounds(&o);
                for name in &o.libs {
                    let got = candidates(name, "/opt/tool/bin", &o.rpaths, "/opt/tool/bin");
                    assert!(
                        got.len() <= o.rpaths.len().max(1),
                        "case {case}: {name} expanded to {} candidates from {} rpaths",
                        got.len(),
                        o.rpaths.len()
                    );
                }
            }
        }
    }

    #[test]
    fn fuzz_macho_bounds_hold_on_cyclic_dependency_fixture() {
        // On the untouched pair the cycle is parsed as written: `a` names
        // `b`, `b` names `a`, duplicates and all.
        let (a, b) = cyclic_pair();
        assert_eq!(parse(&a).unwrap().libs, vec!["@rpath/libb.dylib"]);
        assert_eq!(parse(&b).unwrap().libs, vec!["@rpath/liba.dylib"]);
        // Expansion stays bounded across the cycle: one name yields at
        // most one candidate per rpath, and a search path that points
        // back into the `@`-world (`@rpath/…` as an rpath) adds none at
        // all.
        let cyclic_rpaths = vec![
            "@rpath/liba.dylib".to_owned(),
            "@loader_path/../lib".to_owned(),
        ];
        assert_eq!(
            candidates(
                "@rpath/libb.dylib",
                "/opt/tool/bin",
                &cyclic_rpaths,
                "/opt/tool/bin"
            ),
            vec!["/opt/tool/bin/../lib/libb.dylib"]
        );
        fuzz_over_cyclic(mutator::case_count(2_000));
    }

    /// The long form: `cargo test -- --ignored` with `RH_FUZZ_CASES` set
    /// drives the case count up.
    #[test]
    #[ignore]
    fn fuzz_macho_cyclic_long_cases() {
        fuzz_over_cyclic(mutator::case_count(50_000));
    }
}

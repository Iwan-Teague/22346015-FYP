//! Probing: run the OS tools (through the [`Probe`] seam) and assemble an [`HwProfile`].
//!
//! Every external call goes through [`Probe`], so [`inventory`] is tested against canned output.
//! A probe that fails never aborts the inventory: the field falls back (or stays at a neutral
//! value), a warning is recorded, and the field has no provenance entry — a reader can tell
//! "determined" from "defaulted".

use crate::parse::*;
use crate::*;
use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// How the inventory talks to the machine. Real impl: [`SystemProbe`]; tests use fixtures.
pub trait Probe {
    /// `std::env::consts::OS`-style name: `macos`, `linux`, `windows`.
    fn os(&self) -> &str;
    /// Run a program and return its stdout if it exited 0.
    fn run(&self, prog: &str, args: &[&str]) -> Option<String>;
    /// Read a whole text file.
    fn read_file(&self, path: &str) -> Option<String>;
}

/// The real machine. Each command gets a hard timeout so a wedged `system_profiler` cannot hang
/// a run before it starts.
pub struct SystemProbe {
    pub timeout: Duration,
}

impl Default for SystemProbe {
    fn default() -> Self {
        SystemProbe {
            timeout: Duration::from_secs(10),
        }
    }
}

impl Probe for SystemProbe {
    fn os(&self) -> &str {
        std::env::consts::OS
    }

    fn run(&self, prog: &str, args: &[&str]) -> Option<String> {
        let mut child = Command::new(prog)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        // Drain stdout on a thread so a large output cannot fill the pipe and stall the child.
        let mut out = child.stdout.take()?;
        let reader = std::thread::spawn(move || {
            let mut s = String::new();
            let _ = out.read_to_string(&mut s);
            s
        });
        let deadline = Instant::now() + self.timeout;
        let status = loop {
            match child.try_wait() {
                Ok(Some(st)) => break Some(st),
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(15))
                }
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
            }
        };
        let text = reader.join().ok()?;
        status.filter(|s| s.success()).map(|_| text)
    }

    fn read_file(&self, path: &str) -> Option<String> {
        std::fs::read_to_string(path).ok()
    }
}

/// Build the profile for the machine behind `probe`. `scratch` is the directory whose free
/// space matters (where task workspaces are created).
pub fn inventory(probe: &dyn Probe, scratch: &str) -> HwProfile {
    let mut b = Builder {
        probe,
        prov: Default::default(),
        warnings: Vec::new(),
    };
    let mut p = match probe.os() {
        "macos" => b.macos(),
        "linux" => b.linux(),
        other => b.unsupported(other),
    };
    // Storage free space is the same POSIX call everywhere.
    if p.storage.scratch_free_bytes.is_none() {
        if let Some(free) = probe
            .run("df", &["-Pk", scratch])
            .as_deref()
            .and_then(parse_df_pk)
        {
            p.storage.scratch_free_bytes = Some(free);
            b.prov
                .insert("storage.scratch_free_bytes".into(), "df".into());
        } else {
            b.warnings
                .push(format!("could not read free space for {scratch}"));
        }
    }
    p.provenance = b.prov;
    p.warnings = b.warnings;
    p
}

struct Builder<'a> {
    probe: &'a dyn Probe,
    prov: std::collections::BTreeMap<String, String>,
    warnings: Vec<String>,
}

impl Builder<'_> {
    fn note(&mut self, field: &str, source: &str) {
        self.prov.insert(field.into(), source.into());
    }

    fn sysctl(&self, key: &str) -> Option<String> {
        self.probe
            .run("sysctl", &["-n", key])
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    }

    fn base(&self, os: &str) -> HwProfile {
        HwProfile {
            schema: HW_SCHEMA,
            cpu: CpuInfo {
                model: "unknown".into(),
                vendor: CpuVendor::Other,
                arch: match std::env::consts::ARCH {
                    "aarch64" => Arch::Arm64,
                    "x86_64" => Arch::X86_64,
                    _ => Arch::Other,
                },
                physical_cores: 0,
                logical_cores: 0,
                performance_cores: None,
                efficiency_cores: None,
                features: Vec::new(),
            },
            ram: RamInfo {
                total_bytes: 0,
                available_bytes: None,
            },
            gpus: Vec::new(),
            os: OsInfo {
                family: os.into(),
                version: None,
                build: None,
                kernel: None,
            },
            storage: DiskInfo {
                kind: StorageKind::Unknown,
                scratch_free_bytes: None,
            },
            power: PowerHint {
                source: PowerSource::Unknown,
                chassis: Chassis::Unknown,
                low_power: None,
            },
            unified_memory: false,
            provenance: Default::default(),
            warnings: Vec::new(),
        }
    }

    fn unsupported(&mut self, os: &str) -> HwProfile {
        self.warnings.push(format!(
            "no inventory probes for OS `{os}`; profile is mostly empty"
        ));
        self.base(os)
    }

    fn macos(&mut self) -> HwProfile {
        let mut p = self.base("macos");

        // CPU
        match self.sysctl("machdep.cpu.brand_string") {
            Some(brand) => {
                p.cpu.vendor = cpu_vendor_from_brand(&brand);
                p.cpu.model = brand;
                self.note("cpu.model", "sysctl");
            }
            None => self
                .warnings
                .push("sysctl machdep.cpu.brand_string failed".into()),
        }
        if let Some(a) = self.probe.run("uname", &["-m"]) {
            p.cpu.arch = match a.trim() {
                "arm64" => Arch::Arm64,
                "x86_64" => Arch::X86_64,
                _ => Arch::Other,
            };
            self.note("cpu.arch", "uname");
        }
        if let Some(n) = self.sysctl("hw.physicalcpu").as_deref().and_then(parse_u64) {
            p.cpu.physical_cores = n as u32;
            self.note("cpu.physical_cores", "sysctl");
        }
        if let Some(n) = self.sysctl("hw.logicalcpu").as_deref().and_then(parse_u64) {
            p.cpu.logical_cores = n as u32;
            self.note("cpu.logical_cores", "sysctl");
        }
        // Apple reports the performance/efficiency split per "perflevel" (0 = fastest).
        p.cpu.performance_cores = self
            .sysctl("hw.perflevel0.physicalcpu")
            .as_deref()
            .and_then(parse_u64)
            .map(|n| n as u32);
        p.cpu.efficiency_cores = self
            .sysctl("hw.perflevel1.physicalcpu")
            .as_deref()
            .and_then(parse_u64)
            .map(|n| n as u32);
        if p.cpu.performance_cores.is_some() {
            self.note("cpu.performance_cores", "sysctl");
        }
        match p.cpu.arch {
            Arch::Arm64 => {
                // AdvSIMD is architecturally mandatory on arm64 macOS; confirm it rather than assume.
                if self.sysctl("hw.optional.AdvSIMD").as_deref() == Some("1") {
                    p.cpu.features.push("neon".into());
                    self.note("cpu.features", "sysctl");
                }
            }
            Arch::X86_64 => {
                let f = [
                    self.sysctl("machdep.cpu.features"),
                    self.sysctl("machdep.cpu.leaf7_features"),
                ]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                .join(" ");
                p.cpu.features = x86_features(&f);
                self.note("cpu.features", "sysctl");
            }
            Arch::Other => {}
        }

        // RAM
        match self.sysctl("hw.memsize").as_deref().and_then(parse_u64) {
            Some(b) => {
                p.ram.total_bytes = b;
                self.note("ram.total_bytes", "sysctl");
            }
            None => self.warnings.push("sysctl hw.memsize failed".into()),
        }
        p.ram.available_bytes = self
            .probe
            .run("vm_stat", &[])
            .as_deref()
            .and_then(parse_vm_stat);
        if p.ram.available_bytes.is_some() {
            self.note("ram.available_bytes", "vm_stat");
        }

        // GPUs
        match self
            .probe
            .run("system_profiler", &["SPDisplaysDataType", "-json"])
        {
            Some(j) => {
                p.gpus = parse_system_profiler_displays(&j);
                self.note("gpus", "system_profiler");
            }
            None => self
                .warnings
                .push("system_profiler SPDisplaysDataType failed".into()),
        }
        // Apple Silicon is unified by construction; also unified when the only GPU says so.
        p.unified_memory =
            p.cpu.vendor == CpuVendor::Apple || p.gpus.iter().any(|g| g.vendor == GpuVendor::Apple);
        self.note("unified_memory", "derived");

        // OS
        p.os.version = self
            .probe
            .run("sw_vers", &["-productVersion"])
            .map(|s| s.trim().to_string());
        p.os.build = self
            .probe
            .run("sw_vers", &["-buildVersion"])
            .map(|s| s.trim().to_string());
        p.os.kernel = self
            .probe
            .run("uname", &["-r"])
            .map(|s| s.trim().to_string());
        if p.os.version.is_some() {
            self.note("os", "sw_vers");
        }

        // Storage kind of the boot volume (a proxy for the scratch volume).
        if let Some(d) = self.probe.run("diskutil", &["info", "/"]) {
            p.storage.kind = parse_diskutil_info(&d);
            self.note("storage.kind", "diskutil");
        }

        // Power / chassis
        let model = self.sysctl("hw.model").unwrap_or_default();
        let (src, has_battery) = match self.probe.run("pmset", &["-g", "batt"]) {
            Some(s) => {
                self.note("power.source", "pmset");
                parse_pmset_batt(&s)
            }
            None => (PowerSource::Unknown, false),
        };
        p.power.source = src;
        p.power.chassis = chassis_from_mac_model(&model, has_battery);
        p.power.low_power = self
            .probe
            .run("pmset", &["-g"])
            .as_deref()
            .and_then(parse_pmset_lowpower);
        if p.power.low_power.is_some() {
            self.note("power.low_power", "pmset");
        }
        if p.power.chassis != Chassis::Unknown {
            self.note("power.chassis", "sysctl hw.model");
        }
        p
    }

    fn linux(&mut self) -> HwProfile {
        let mut p = self.base("linux");

        if let Some(c) = self
            .probe
            .read_file("/proc/cpuinfo")
            .as_deref()
            .and_then(parse_proc_cpuinfo)
        {
            p.cpu.model = c.model;
            p.cpu.vendor = c.vendor;
            p.cpu.logical_cores = c.logical;
            p.cpu.physical_cores = c.physical;
            p.cpu.features = c.features;
            self.note("cpu.model", "proc-cpuinfo");
            self.note("cpu.physical_cores", "proc-cpuinfo");
        } else {
            self.warnings.push("/proc/cpuinfo unreadable".into());
        }
        if let Some(a) = self.probe.run("uname", &["-m"]) {
            p.cpu.arch = match a.trim() {
                "aarch64" | "arm64" => Arch::Arm64,
                "x86_64" => Arch::X86_64,
                _ => Arch::Other,
            };
            self.note("cpu.arch", "uname");
        }

        if let Some((total, avail)) = self
            .probe
            .read_file("/proc/meminfo")
            .as_deref()
            .and_then(parse_meminfo)
        {
            p.ram = RamInfo {
                total_bytes: total,
                available_bytes: avail,
            };
            self.note("ram.total_bytes", "proc-meminfo");
        } else {
            self.warnings.push("/proc/meminfo unreadable".into());
        }

        // NVIDIA via nvidia-smi when present. AMD/Intel discrete detection needs sysfs/vendor
        // tools and is not probed yet: say so rather than report "cpu-only" silently.
        match self.probe.run(
            "nvidia-smi",
            &["--query-gpu=name,memory.total,memory.free,driver_version", "--format=csv,noheader,nounits"],
        ) {
            Some(s) => {
                p.gpus = parse_nvidia_smi(&s);
                self.note("gpus", "nvidia-smi");
            }
            None => self.warnings.push(
                "no nvidia-smi: NVIDIA GPUs undetected; AMD/Intel GPUs are not probed on Linux yet, so `cpu-only` may be wrong".into(),
            ),
        }

        p.os.version = self.probe.read_file("/etc/os-release").and_then(|s| {
            s.lines().find_map(|l| {
                l.strip_prefix("PRETTY_NAME=")
                    .map(|v| v.trim_matches('"').to_string())
            })
        });
        p.os.kernel = self
            .probe
            .run("uname", &["-r"])
            .map(|s| s.trim().to_string());
        if p.os.version.is_some() {
            self.note("os", "os-release");
        }

        // Power: sysfs power_supply. A BAT* entry means laptop; mains online tells AC vs battery.
        if let Some(ls) = self.probe.run("ls", &["/sys/class/power_supply"]) {
            let names: Vec<&str> = ls.split_whitespace().collect();
            let has_bat = names.iter().any(|n| n.starts_with("BAT"));
            p.power.chassis = if has_bat {
                Chassis::Laptop
            } else {
                Chassis::Desktop
            };
            let mains_online = names
                .iter()
                .filter(|n| {
                    n.starts_with("AC")
                        || n.starts_with("ADP")
                        || n.to_ascii_lowercase().contains("mains")
                })
                .any(|n| {
                    self.probe
                        .read_file(&format!("/sys/class/power_supply/{n}/online"))
                        .map(|s| s.trim() == "1")
                        .unwrap_or(false)
                });
            p.power.source = if mains_online || !has_bat {
                PowerSource::Ac
            } else {
                PowerSource::Battery
            };
            self.note("power.chassis", "sysfs");
        }
        p
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Canned machine: `run` keys are `"prog arg arg"`, files by path.
    struct Fake {
        os: &'static str,
        cmds: HashMap<String, String>,
        files: HashMap<String, String>,
    }

    impl Probe for Fake {
        fn os(&self) -> &str {
            self.os
        }
        fn run(&self, prog: &str, args: &[&str]) -> Option<String> {
            let key = std::iter::once(prog)
                .chain(args.iter().copied())
                .collect::<Vec<_>>()
                .join(" ");
            self.cmds.get(&key).cloned()
        }
        fn read_file(&self, path: &str) -> Option<String> {
            self.files.get(path).cloned()
        }
    }

    fn mac(extra: &[(&str, &str)], drop: &[&str]) -> Fake {
        let mut cmds: HashMap<String, String> = [
            ("sysctl -n machdep.cpu.brand_string", "Apple M5\n"),
            ("uname -m", "arm64\n"),
            ("sysctl -n hw.physicalcpu", "10\n"),
            ("sysctl -n hw.logicalcpu", "10\n"),
            ("sysctl -n hw.perflevel0.physicalcpu", "4\n"),
            ("sysctl -n hw.perflevel1.physicalcpu", "6\n"),
            ("sysctl -n hw.optional.AdvSIMD", "1\n"),
            ("sysctl -n hw.memsize", "25769803776\n"),
            ("sysctl -n hw.model", "Mac17,2\n"),
            ("vm_stat", "Mach Virtual Memory Statistics: (page size of 16384 bytes)\nPages free: 100.\nPages inactive: 50.\nPages speculative: 10.\n"),
            ("system_profiler SPDisplaysDataType -json", r#"{"SPDisplaysDataType":[{"sppci_model":"Apple M5","spdisplays_vendor":"sppci_vendor_Apple","sppci_cores":"10"}]}"#),
            ("sw_vers -productVersion", "26.5.1\n"),
            ("sw_vers -buildVersion", "25F80\n"),
            ("uname -r", "25.5.0\n"),
            ("diskutil info /", "   Solid State: Yes\n   Protocol: Apple Fabric\n"),
            ("pmset -g batt", "Now drawing from 'AC Power'\n -InternalBattery-0\t100%; charged\n"),
            ("pmset -g", "System-wide power settings:\n sleep                1\n lowpowermode         0\n"),
            ("df -Pk /scratch", "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/d 100 50 2048 50% /\n"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        for (k, v) in extra {
            cmds.insert(k.to_string(), v.to_string());
        }
        for k in drop {
            cmds.remove(*k);
        }
        Fake {
            os: "macos",
            cmds,
            files: HashMap::new(),
        }
    }

    #[test]
    fn macos_apple_silicon_end_to_end() {
        let p = inventory(&mac(&[], &[]), "/scratch");
        assert_eq!(p.cpu.model, "Apple M5");
        assert_eq!(p.cpu.vendor, CpuVendor::Apple);
        assert_eq!(p.cpu.arch, Arch::Arm64);
        assert_eq!((p.cpu.physical_cores, p.cpu.logical_cores), (10, 10));
        assert_eq!(
            (p.cpu.performance_cores, p.cpu.efficiency_cores),
            (Some(4), Some(6))
        );
        assert_eq!(p.cpu.features, vec!["neon"]);
        assert_eq!(p.ram.total_bytes, 24 * 1024 * 1024 * 1024);
        assert_eq!(p.ram.available_bytes, Some(160 * 16384));
        assert!(p.unified_memory);
        assert_eq!(p.os.version.as_deref(), Some("26.5.1"));
        assert_eq!(p.storage.kind, StorageKind::Nvme);
        assert_eq!(p.storage.scratch_free_bytes, Some(2048 * 1024));
        assert_eq!(
            p.power,
            PowerHint {
                source: PowerSource::Ac,
                chassis: Chassis::Laptop,
                low_power: Some(false),
            }
        );
        assert!(p.warnings.is_empty(), "{:?}", p.warnings);
        assert_eq!(
            p.provenance.get("cpu.model").map(String::as_str),
            Some("sysctl")
        );
        assert_eq!(
            p.provenance
                .get("storage.scratch_free_bytes")
                .map(String::as_str),
            Some("df")
        );
        let public = p.public();
        assert_eq!(public.hw_class, "unified-32");
        assert_eq!(public.generation.as_deref(), Some("m5"));
    }

    #[test]
    fn failed_probes_default_and_warn_without_provenance() {
        let p = inventory(
            &mac(
                &[],
                &[
                    "sysctl -n hw.memsize",
                    "system_profiler SPDisplaysDataType -json",
                    "df -Pk /scratch",
                ],
            ),
            "/scratch",
        );
        assert_eq!(p.ram.total_bytes, 0);
        assert!(!p.provenance.contains_key("ram.total_bytes"));
        assert!(!p.provenance.contains_key("gpus"));
        assert!(p.gpus.is_empty());
        assert_eq!(p.storage.scratch_free_bytes, None);
        assert_eq!(p.warnings.len(), 3, "{:?}", p.warnings);
        // Apple CPU still implies unified memory even if the GPU probe failed.
        assert!(p.unified_memory);
    }

    #[test]
    fn linux_nvidia_desktop() {
        let cpuinfo = "processor\t: 0\nmodel name\t: AMD Ryzen 9 7950X\nphysical id\t: 0\ncore id\t: 0\nflags\t: avx avx2 fma\n\nprocessor\t: 1\nmodel name\t: AMD Ryzen 9 7950X\nphysical id\t: 0\ncore id\t: 0\nflags\t: avx avx2 fma\n";
        let fake = Fake {
            os: "linux",
            cmds: [
                ("uname -m", "x86_64\n"),
                ("uname -r", "6.8.0\n"),
                ("nvidia-smi --query-gpu=name,memory.total,memory.free,driver_version --format=csv,noheader,nounits", "NVIDIA GeForce RTX 4090, 24564, 24000, 560.35.03\n"),
                ("ls /sys/class/power_supply", "\n"),
                ("df -Pk /s", "h\n/dev/x 1 1 4 1% /\n"),
            ]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
            files: [
                ("/proc/cpuinfo".to_string(), cpuinfo.to_string()),
                ("/proc/meminfo".to_string(), "MemTotal: 67108864 kB\nMemAvailable: 60000000 kB\n".to_string()),
                ("/etc/os-release".to_string(), "NAME=\"Ubuntu\"\nPRETTY_NAME=\"Ubuntu 24.04 LTS\"\n".to_string()),
            ]
            .into_iter()
            .collect(),
        };
        let p = inventory(&fake, "/s");
        assert_eq!(p.cpu.vendor, CpuVendor::Amd);
        assert_eq!(p.cpu.physical_cores, 1);
        assert_eq!(p.cpu.logical_cores, 2);
        assert!(!p.unified_memory);
        assert_eq!(p.ram.total_bytes, 64 * 1024 * 1024 * 1024);
        assert_eq!(p.os.version.as_deref(), Some("Ubuntu 24.04 LTS"));
        assert_eq!(p.power.chassis, Chassis::Desktop);
        assert_eq!(p.storage.scratch_free_bytes, Some(4096));
        let public = p.public();
        assert_eq!(public.hw_class, "vram-24");
        assert_eq!(public.generation.as_deref(), Some("ada"));
    }

    #[test]
    fn linux_without_nvidia_warns_that_cpu_only_is_unconfirmed() {
        let fake = Fake {
            os: "linux",
            cmds: HashMap::new(),
            files: HashMap::new(),
        };
        let p = inventory(&fake, "/s");
        assert!(
            p.warnings
                .iter()
                .any(|w| w.contains("cpu-only") && w.contains("may be wrong")),
            "{:?}",
            p.warnings
        );
    }

    #[test]
    fn unsupported_os_is_flagged() {
        let fake = Fake {
            os: "plan9",
            cmds: HashMap::new(),
            files: HashMap::new(),
        };
        let p = inventory(&fake, "/s");
        assert!(p.warnings.iter().any(|w| w.contains("plan9")));
        assert_eq!(p.public().hw_class, "cpu-only");
    }

    #[test]
    fn profile_round_trips_through_json() {
        let p = inventory(&mac(&[], &[]), "/scratch");
        let j = serde_json::to_string(&p).unwrap();
        let back: HwProfile = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn system_probe_runs_a_real_command_and_times_out_a_slow_one() {
        let sp = SystemProbe {
            timeout: Duration::from_millis(300),
        };
        assert_eq!(
            sp.run("echo", &["hi"]).as_deref().map(str::trim),
            Some("hi")
        );
        assert_eq!(sp.run("definitely-not-a-program-xyz", &[]), None);
        let t = Instant::now();
        assert_eq!(sp.run("sleep", &["5"]), None);
        assert!(t.elapsed() < Duration::from_secs(3));
        assert_eq!(sp.run("false", &[]), None);
    }
}

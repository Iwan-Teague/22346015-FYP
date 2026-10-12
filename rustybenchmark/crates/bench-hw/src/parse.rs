//! Pure parsers for the OS tools the inventory shells out to. No I/O: every function takes the
//! captured text, so each is tested against fixtures captured from real machines.

use crate::{Chassis, CpuVendor, GpuInfo, GpuVendor, PowerSource, StorageKind};
use std::collections::BTreeSet;

/// `sysctl -n` style scalar.
pub fn parse_u64(s: &str) -> Option<u64> {
    s.trim().parse().ok()
}

pub fn cpu_vendor_from_brand(brand: &str) -> CpuVendor {
    let b = brand.to_ascii_lowercase();
    if b.contains("apple") {
        CpuVendor::Apple
    } else if b.contains("intel") {
        CpuVendor::Intel
    } else if b.contains("amd") || b.contains("ryzen") || b.contains("epyc") {
        CpuVendor::Amd
    } else {
        CpuVendor::Other
    }
}

/// Available memory from `vm_stat`: free + inactive + speculative pages (the pages the OS can
/// hand out without swapping), times the page size announced on the first line.
pub fn parse_vm_stat(s: &str) -> Option<u64> {
    let first = s.lines().next()?;
    let page: u64 = first
        .split("page size of")
        .nth(1)?
        .split_whitespace()
        .next()?
        .parse()
        .ok()?;
    let pages = |label: &str| -> Option<u64> {
        let line = s.lines().find(|l| l.starts_with(label))?;
        line.split(':')
            .nth(1)?
            .trim()
            .trim_end_matches('.')
            .parse()
            .ok()
    };
    let total =
        pages("Pages free")? + pages("Pages inactive")? + pages("Pages speculative").unwrap_or(0);
    Some(total * page)
}

/// `pmset -g batt` → (power source, a battery is present).
pub fn parse_pmset_batt(s: &str) -> (PowerSource, bool) {
    let has_battery = s.contains("InternalBattery");
    let source = if s.contains("'AC Power'") {
        PowerSource::Ac
    } else if s.contains("'Battery Power'") {
        PowerSource::Battery
    } else {
        PowerSource::Unknown
    };
    (source, has_battery)
}

/// `pmset -g` → Low Power Mode, if the line is present (`lowpowermode 1`). `None` on hardware
/// without the setting.
pub fn parse_pmset_lowpower(s: &str) -> Option<bool> {
    s.lines().find_map(|l| {
        let mut it = l.split_whitespace();
        (it.next() == Some("lowpowermode")).then(|| it.next() == Some("1"))
    })
}

/// Mac model identifier (`MacBookPro18,1`, `Macmini9,1`, `Mac17,2`) → chassis. The newer
/// generic `MacNN,M` identifiers carry no form factor, so a battery is the tie-break.
pub fn chassis_from_mac_model(model: &str, has_battery: bool) -> Chassis {
    let m = model.trim();
    if m.starts_with("MacBook") {
        Chassis::Laptop
    } else if m.starts_with("Macmini")
        || m.starts_with("iMac")
        || m.starts_with("MacPro")
        || m.starts_with("MacStudio")
    {
        Chassis::Desktop
    } else if has_battery {
        Chassis::Laptop
    } else {
        // A Mac with no battery is a desktop; an empty/garbled model gives no evidence at all.
        if m.is_empty() {
            Chassis::Unknown
        } else {
            Chassis::Desktop
        }
    }
}

/// `diskutil info /` → storage kind.
pub fn parse_diskutil_info(s: &str) -> StorageKind {
    let field = |name: &str| -> Option<String> {
        s.lines().find_map(|l| {
            let (k, v) = l.split_once(':')?;
            (k.trim() == name).then(|| v.trim().to_string())
        })
    };
    let solid = field("Solid State");
    let proto = field("Protocol").unwrap_or_default().to_ascii_lowercase();
    match solid.as_deref() {
        Some("Yes")
            if proto.contains("apple fabric") || proto.contains("nvm") || proto.contains("pci") =>
        {
            StorageKind::Nvme
        }
        Some("Yes") => StorageKind::Ssd,
        Some("No") => StorageKind::Spinning,
        _ => StorageKind::Unknown,
    }
}

/// `df -Pk <path>` → available bytes on that volume.
pub fn parse_df_pk(s: &str) -> Option<u64> {
    let line = s.lines().nth(1)?;
    let kb: u64 = line.split_whitespace().nth(3)?.parse().ok()?;
    kb.checked_mul(1024)
}

/// x86 feature tokens (macOS `machdep.cpu.features` / `leaf7_features`, Linux `flags`),
/// reduced to the ones that matter for CPU inference, lower-cased and sorted.
pub fn x86_features(raw: &str) -> Vec<String> {
    const WANTED: &[&str] = &[
        "avx", "avx2", "avx512f", "avx512bw", "avx512vl", "fma", "f16c", "sse4_2", "amx_tile",
    ];
    let have: BTreeSet<String> = raw
        .split_whitespace()
        .map(|t| t.to_ascii_lowercase().replace('.', "_"))
        .map(|t| if t == "avx1_0" { "avx".to_string() } else { t })
        .collect();
    WANTED
        .iter()
        .filter(|w| have.contains(**w))
        .map(|s| s.to_string())
        .collect()
}

fn gpu_vendor_from_str(s: &str) -> GpuVendor {
    let s = s.to_ascii_lowercase();
    if s.contains("apple") {
        GpuVendor::Apple
    } else if s.contains("nvidia") {
        GpuVendor::Nvidia
    } else if s.contains("amd") || s.contains("ati") || s.contains("radeon") {
        GpuVendor::Amd
    } else if s.contains("intel") {
        GpuVendor::Intel
    } else {
        GpuVendor::Other
    }
}

/// `system_profiler SPDisplaysDataType -json` → GPUs. Apple Silicon reports no dedicated VRAM
/// (it shares system memory); Intel Macs with a discrete part report `spdisplays_vram`.
pub fn parse_system_profiler_displays(json: &str) -> Vec<GpuInfo> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else {
        return Vec::new();
    };
    let Some(items) = v.get("SPDisplaysDataType").and_then(|x| x.as_array()) else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(|it| {
            let model = it
                .get("sppci_model")
                .or_else(|| it.get("_name"))?
                .as_str()?
                .to_string();
            let vendor_s = it
                .get("spdisplays_vendor")
                .and_then(|x| x.as_str())
                .unwrap_or("");
            let vendor = match gpu_vendor_from_str(vendor_s) {
                GpuVendor::Other => gpu_vendor_from_str(&model),
                v => v,
            };
            let cores = it
                .get("sppci_cores")
                .and_then(|x| x.as_str())
                .and_then(|s| s.parse().ok());
            let vram_s = it
                .get("spdisplays_vram")
                .or_else(|| it.get("spdisplays_vram_shared"))
                .and_then(|x| x.as_str());
            let dedicated = it.get("spdisplays_vram").and_then(|x| x.as_str());
            let mem_total_bytes = dedicated.and_then(parse_size_gb_mb);
            let shares =
                vendor == GpuVendor::Apple || (mem_total_bytes.is_none() && vram_s.is_some());
            Some(GpuInfo {
                vendor,
                model,
                mem_total_bytes: if vendor == GpuVendor::Apple {
                    None
                } else {
                    mem_total_bytes
                },
                mem_free_bytes: None,
                driver_version: None,
                cores,
                shares_system_memory: shares
                    || (vendor == GpuVendor::Intel && mem_total_bytes.is_none()),
            })
        })
        .collect()
}

/// `"4 GB"`, `"1536 MB"` → bytes.
fn parse_size_gb_mb(s: &str) -> Option<u64> {
    let mut it = s.split_whitespace();
    let n: u64 = it.next()?.parse().ok()?;
    match it.next()?.to_ascii_uppercase().as_str() {
        "GB" => Some(n * 1024 * 1024 * 1024),
        "MB" => Some(n * 1024 * 1024),
        _ => None,
    }
}

/// Linux `/proc/meminfo` → (total, available) bytes.
pub fn parse_meminfo(s: &str) -> Option<(u64, Option<u64>)> {
    let kb = |key: &str| -> Option<u64> {
        let line = s.lines().find(|l| l.starts_with(key))?;
        line.split_whitespace()
            .nth(1)?
            .parse::<u64>()
            .ok()?
            .checked_mul(1024)
    };
    Some((kb("MemTotal:")?, kb("MemAvailable:")))
}

/// What `/proc/cpuinfo` yields.
#[derive(Debug, PartialEq, Eq)]
pub struct ProcCpu {
    pub model: String,
    pub vendor: CpuVendor,
    pub logical: u32,
    pub physical: u32,
    pub features: Vec<String>,
}

/// Linux `/proc/cpuinfo`. Physical cores are the distinct `(physical id, core id)` pairs; on
/// kernels that omit them (many ARM boards) physical falls back to logical.
pub fn parse_proc_cpuinfo(s: &str) -> Option<ProcCpu> {
    let mut model = None;
    let mut flags = String::new();
    let mut logical = 0u32;
    let mut cores = BTreeSet::new();
    let (mut phys, mut core) = (None::<String>, None::<String>);
    let mut asimd = false;
    for line in s.lines().chain(std::iter::once("")) {
        if line.trim().is_empty() {
            if let (Some(p), Some(c)) = (phys.take(), core.take()) {
                cores.insert((p, c));
            }
            continue;
        }
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let (k, v) = (k.trim(), v.trim());
        match k {
            "processor" => logical += 1,
            "model name" | "Model" | "Hardware" if model.is_none() => model = Some(v.to_string()),
            "flags" if flags.is_empty() => flags = v.to_string(),
            "Features" => asimd |= v.split_whitespace().any(|t| t == "asimd" || t == "neon"),
            "physical id" => phys = Some(v.to_string()),
            "core id" => core = Some(v.to_string()),
            _ => {}
        }
    }
    if logical == 0 {
        return None;
    }
    let model = model.unwrap_or_else(|| "unknown".into());
    let mut features = x86_features(&flags);
    if asimd {
        features.push("neon".into());
    }
    let physical = if cores.is_empty() {
        logical
    } else {
        cores.len() as u32
    };
    Some(ProcCpu {
        vendor: cpu_vendor_from_brand(&model),
        model,
        logical,
        physical,
        features,
    })
}

/// `nvidia-smi --query-gpu=name,memory.total,memory.free,driver_version --format=csv,noheader,nounits`
/// (memory in MiB).
pub fn parse_nvidia_smi(s: &str) -> Vec<GpuInfo> {
    s.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split(',').map(str::trim).collect();
            if f.len() < 4 {
                return None;
            }
            let mib = |x: &str| x.parse::<u64>().ok().map(|n| n * 1024 * 1024);
            Some(GpuInfo {
                vendor: GpuVendor::Nvidia,
                model: f[0].to_string(),
                mem_total_bytes: mib(f[1]),
                mem_free_bytes: mib(f[2]),
                driver_version: Some(f[3].to_string()),
                cores: None,
                shares_system_memory: false,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const VM_STAT: &str = "Mach Virtual Memory Statistics: (page size of 16384 bytes)\nPages free:                                    66914.\nPages active:                                 522778.\nPages inactive:                               512335.\nPages speculative:                              9637.\nPages throttled:                                   0.\n";

    #[test]
    fn vm_stat_sums_reclaimable_pages() {
        let b = parse_vm_stat(VM_STAT).unwrap();
        assert_eq!(b, (66914 + 512335 + 9637) * 16384);
    }

    #[test]
    fn vm_stat_rejects_garbage() {
        assert_eq!(parse_vm_stat("nope"), None);
        assert_eq!(parse_vm_stat(""), None);
    }

    #[test]
    fn pmset_ac_and_battery() {
        let ac = "Now drawing from 'AC Power'\n -InternalBattery-0 (id=7340131)\t100%; charged; 0:00 remaining present: true\n";
        assert_eq!(parse_pmset_batt(ac), (PowerSource::Ac, true));
        let bat = "Now drawing from 'Battery Power'\n -InternalBattery-0\t55%; discharging\n";
        assert_eq!(parse_pmset_batt(bat), (PowerSource::Battery, true));
        let desk = "Now drawing from 'AC Power'\n";
        assert_eq!(parse_pmset_batt(desk), (PowerSource::Ac, false));
        assert_eq!(parse_pmset_batt(""), (PowerSource::Unknown, false));
    }

    #[test]
    fn pmset_low_power_mode() {
        assert_eq!(
            parse_pmset_lowpower(" sleep 1\n lowpowermode         1\n"),
            Some(true)
        );
        assert_eq!(parse_pmset_lowpower(" lowpowermode 0\n"), Some(false));
        assert_eq!(parse_pmset_lowpower(" sleep 1\n displaysleep 2\n"), None);
        assert_eq!(parse_pmset_lowpower(""), None);
    }

    #[test]
    fn mac_chassis() {
        assert_eq!(
            chassis_from_mac_model("MacBookPro18,1", true),
            Chassis::Laptop
        );
        assert_eq!(
            chassis_from_mac_model("Macmini9,1", false),
            Chassis::Desktop
        );
        assert_eq!(chassis_from_mac_model("Mac17,2", true), Chassis::Laptop);
        assert_eq!(chassis_from_mac_model("Mac15,14", false), Chassis::Desktop);
        assert_eq!(chassis_from_mac_model("", false), Chassis::Unknown);
    }

    #[test]
    fn diskutil_kinds() {
        let nvme = "   Device Location:           Internal\n   Solid State:               Yes\n   Protocol:                  Apple Fabric\n";
        assert_eq!(parse_diskutil_info(nvme), StorageKind::Nvme);
        let sata = "   Solid State:               Yes\n   Protocol:                  SATA\n";
        assert_eq!(parse_diskutil_info(sata), StorageKind::Ssd);
        let hdd = "   Solid State:               No\n   Protocol:                  SATA\n";
        assert_eq!(parse_diskutil_info(hdd), StorageKind::Spinning);
        assert_eq!(parse_diskutil_info("nothing"), StorageKind::Unknown);
    }

    #[test]
    fn df_available_is_column_four_in_kib() {
        let df = "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/disk3s5 971350180 300000000 345678912 47% /System/Volumes/Data\n";
        assert_eq!(parse_df_pk(df), Some(345678912 * 1024));
        assert_eq!(parse_df_pk("only one line"), None);
    }

    #[test]
    fn x86_features_are_filtered_and_normalised() {
        let raw = "FPU VME SSE4.2 AVX1.0 FMA F16C AVX2 AVX512F";
        // Apple spells plain AVX as `AVX1.0`; it must normalise to `avx`.
        assert_eq!(
            x86_features(raw),
            vec!["avx", "avx2", "avx512f", "fma", "f16c", "sse4_2"]
        );
    }

    #[test]
    fn system_profiler_apple_silicon() {
        let j = r#"{"SPDisplaysDataType":[{"_name":"Apple M5","spdisplays_vendor":"sppci_vendor_Apple","sppci_cores":"10","sppci_model":"Apple M5"}]}"#;
        let g = parse_system_profiler_displays(j);
        assert_eq!(g.len(), 1);
        assert_eq!(g[0].vendor, GpuVendor::Apple);
        assert_eq!(g[0].cores, Some(10));
        assert!(g[0].shares_system_memory);
        assert_eq!(g[0].mem_total_bytes, None);
    }

    #[test]
    fn system_profiler_intel_mac_with_discrete_amd() {
        let j = r#"{"SPDisplaysDataType":[
            {"sppci_model":"Intel UHD Graphics 630","spdisplays_vendor":"sppci_vendor_intel","spdisplays_vram_shared":"1536 MB"},
            {"sppci_model":"AMD Radeon Pro 5500M","spdisplays_vendor":"sppci_vendor_amd","spdisplays_vram":"8 GB"}]}"#;
        let g = parse_system_profiler_displays(j);
        assert_eq!(g.len(), 2);
        assert!(g[0].shares_system_memory);
        assert_eq!(g[0].vendor, GpuVendor::Intel);
        assert!(!g[1].shares_system_memory);
        assert_eq!(g[1].vendor, GpuVendor::Amd);
        assert_eq!(g[1].mem_total_bytes, Some(8 * 1024 * 1024 * 1024));
    }

    #[test]
    fn system_profiler_garbage_is_empty() {
        assert!(parse_system_profiler_displays("not json").is_empty());
        assert!(parse_system_profiler_displays("{}").is_empty());
    }

    #[test]
    fn meminfo() {
        let m =
            "MemTotal:       32768000 kB\nMemFree:         1000 kB\nMemAvailable:   20000000 kB\n";
        assert_eq!(
            parse_meminfo(m),
            Some((32768000 * 1024, Some(20000000 * 1024)))
        );
        assert_eq!(parse_meminfo("MemTotal: 10 kB\n"), Some((10 * 1024, None)));
        assert_eq!(parse_meminfo(""), None);
    }

    #[test]
    fn cpuinfo_x86_counts_physical_cores_once() {
        // 1 socket, 2 cores, 2 threads each = 4 logical.
        let mut s = String::new();
        for (i, core) in [0, 0, 1, 1].iter().enumerate() {
            s.push_str(&format!(
                "processor\t: {i}\nmodel name\t: AMD Ryzen 7 5800X\nphysical id\t: 0\ncore id\t\t: {core}\nflags\t\t: fpu avx avx2 fma f16c sse4_2\n\n"
            ));
        }
        let c = parse_proc_cpuinfo(&s).unwrap();
        assert_eq!((c.logical, c.physical), (4, 2));
        assert_eq!(c.vendor, CpuVendor::Amd);
        assert_eq!(c.features, vec!["avx", "avx2", "fma", "f16c", "sse4_2"]);
    }

    #[test]
    fn cpuinfo_arm_without_core_ids() {
        let s = "processor\t: 0\nFeatures\t: fp asimd evtstrm\nprocessor\t: 1\nFeatures\t: fp asimd evtstrm\nModel\t\t: Raspberry Pi 5\n";
        let c = parse_proc_cpuinfo(s).unwrap();
        assert_eq!((c.logical, c.physical), (2, 2));
        assert_eq!(c.features, vec!["neon"]);
        assert_eq!(c.model, "Raspberry Pi 5");
    }

    #[test]
    fn cpuinfo_empty_is_none() {
        assert_eq!(parse_proc_cpuinfo(""), None);
    }

    #[test]
    fn nvidia_smi_csv() {
        let s = "NVIDIA GeForce RTX 4090, 24564, 23000, 560.35.03\nNVIDIA GeForce RTX 3060, 12288, 12000, 560.35.03\nbad line\n";
        let g = parse_nvidia_smi(s);
        assert_eq!(g.len(), 2);
        assert_eq!(g[0].mem_total_bytes, Some(24564 * 1024 * 1024));
        assert_eq!(g[1].driver_version.as_deref(), Some("560.35.03"));
        assert!(g.iter().all(|x| !x.shares_system_memory));
    }

    #[test]
    fn brand_vendor() {
        assert_eq!(cpu_vendor_from_brand("Apple M3 Max"), CpuVendor::Apple);
        assert_eq!(
            cpu_vendor_from_brand("Intel(R) Core(TM) i9"),
            CpuVendor::Intel
        );
        assert_eq!(cpu_vendor_from_brand("AMD Ryzen 9 7950X"), CpuVendor::Amd);
        assert_eq!(cpu_vendor_from_brand("Qualcomm"), CpuVendor::Other);
    }
}

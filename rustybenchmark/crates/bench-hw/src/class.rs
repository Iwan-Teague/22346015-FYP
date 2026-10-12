//! Bucketing: the privacy-safe public view of a machine (docs/11) and the `hw_class` ladder
//! (docs/05 "Hardware classes"). Buckets, not exact models: an exact GPU plus driver plus core
//! count plus RAM is an identifying fingerprint.

use crate::{Arch, Chassis, CpuVendor, GpuInfo, GpuVendor, HwProfile, PowerSource, HW_SCHEMA};
use serde::{Deserialize, Serialize};

const GIB: u64 = 1024 * 1024 * 1024;

/// The smallest ladder rung that holds `bytes`; `None` if it exceeds the top rung.
fn rung(bytes: u64, ladder: &[u64]) -> Option<u64> {
    ladder.iter().copied().find(|g| bytes <= g * GIB)
}

/// Unified-memory class by total RAM, e.g. a 24 GB Mac is `unified-32`.
fn unified_class(total_bytes: u64) -> String {
    match rung(total_bytes, &[16, 32, 64, 128]) {
        Some(g) => format!("unified-{g}"),
        None => "unified-128+".to_string(),
    }
}

/// Discrete-VRAM class for one card, e.g. a 24 GiB card is `vram-24`. Anything over 48 GiB is
/// `vram-80+`, the doc's top bucket.
fn vram_class(bytes: u64) -> String {
    match rung(bytes, &[8, 12, 16, 24, 32, 48]) {
        Some(g) => format!("vram-{g}"),
        None => "vram-80+".to_string(),
    }
}

/// The `hw_class` bucket for a profile (docs/05).
///
/// Order matters: unified memory wins (an Apple GPU has no VRAM figure), then discrete GPUs,
/// then integrated, then CPU-only. Several discrete cards become `multi-gpu-<n>x<class>` using
/// the *smallest* card's class, since the smallest bounds what a layer split can assume.
pub fn hw_class(p: &HwProfile) -> String {
    if p.unified_memory {
        return unified_class(p.ram.total_bytes);
    }
    let discrete: Vec<u64> = p
        .gpus
        .iter()
        .filter(|g| !g.shares_system_memory)
        .filter_map(|g| g.mem_total_bytes)
        .collect();
    match discrete.len() {
        0 => {
            if p.gpus.iter().any(|g| g.shares_system_memory) {
                "igpu".to_string()
            } else {
                "cpu-only".to_string()
            }
        }
        1 => vram_class(discrete[0]),
        n => format!(
            "multi-gpu-{n}x{}",
            vram_class(*discrete.iter().min().unwrap_or(&0))
        ),
    }
}

/// Generation tag from a marketing string: `Apple M3 Max` → `m3`, `RTX 4090` → `ada`.
/// `None` when the string is not recognised; an unknown generation is never guessed.
fn generation(vendor: GpuVendor, model: &str) -> Option<String> {
    let m = model.to_ascii_lowercase();
    match vendor {
        GpuVendor::Apple => {
            // First token that is `m<digits>` or `a<digits>`.
            m.split_whitespace()
                .find(|t| {
                    let mut c = t.chars();
                    matches!(c.next(), Some('m' | 'a'))
                        && c.clone().next().is_some()
                        && c.all(|x| x.is_ascii_digit())
                })
                .map(str::to_string)
        }
        GpuVendor::Nvidia => {
            let series = |p: &str| m.contains(p);
            if series("rtx 50") {
                Some("blackwell".into())
            } else if series("rtx 40") {
                Some("ada".into())
            } else if series("rtx 30") {
                Some("ampere".into())
            } else if series("rtx 20") || series("gtx 16") {
                Some("turing".into())
            } else if series("gtx 10") {
                Some("pascal".into())
            } else {
                None
            }
        }
        GpuVendor::Amd => {
            if m.contains("rx 9") {
                Some("rdna4".into())
            } else if m.contains("rx 7") {
                Some("rdna3".into())
            } else if m.contains("rx 6") {
                Some("rdna2".into())
            } else {
                None
            }
        }
        _ => None,
    }
}

/// The bucketed view that may appear on a leaderboard row (docs/11). Contains no exact model,
/// core count, RAM size beyond its bucket, OS build or serial.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HwPublic {
    pub schema: u32,
    pub hw_class: String,
    /// The vendor that determines the class: the GPU's, or the CPU's for `cpu-only`.
    pub vendor: String,
    /// Architecture generation where recognised (`m3`, `ada`, `rdna3`).
    pub generation: Option<String>,
    /// `<arch>-<cpu vendor>`, e.g. `arm64-apple`, `x86_64-amd`.
    pub cpu_class: String,
    pub unified_memory: bool,
    pub chassis: Chassis,
    pub power_source: PowerSource,
}

fn arch_str(a: Arch) -> &'static str {
    match a {
        Arch::Arm64 => "arm64",
        Arch::X86_64 => "x86_64",
        Arch::Other => "other",
    }
}

fn cpu_vendor_str(v: CpuVendor) -> &'static str {
    match v {
        CpuVendor::Apple => "apple",
        CpuVendor::Intel => "intel",
        CpuVendor::Amd => "amd",
        CpuVendor::Other => "other",
    }
}

fn gpu_vendor_str(v: GpuVendor) -> &'static str {
    match v {
        GpuVendor::Apple => "apple",
        GpuVendor::Nvidia => "nvidia",
        GpuVendor::Amd => "amd",
        GpuVendor::Intel => "intel",
        GpuVendor::Other => "other",
    }
}

/// The GPU that decides the class: the largest discrete card, else the first GPU.
fn deciding_gpu(p: &HwProfile) -> Option<&GpuInfo> {
    p.gpus
        .iter()
        .filter(|g| !g.shares_system_memory)
        .max_by_key(|g| g.mem_total_bytes.unwrap_or(0))
        .or_else(|| p.gpus.first())
}

pub(crate) fn public_view(p: &HwProfile) -> HwPublic {
    let class = hw_class(p);
    let (vendor, generation) = match deciding_gpu(p) {
        Some(g) if class != "cpu-only" => (
            gpu_vendor_str(g.vendor).to_string(),
            // Apple: the CPU brand carries the generation more reliably than the GPU model.
            generation(g.vendor, &g.model).or_else(|| {
                (g.vendor == GpuVendor::Apple)
                    .then(|| generation(g.vendor, &p.cpu.model))
                    .flatten()
            }),
        ),
        _ => (cpu_vendor_str(p.cpu.vendor).to_string(), None),
    };
    HwPublic {
        schema: HW_SCHEMA,
        hw_class: class,
        vendor,
        generation,
        cpu_class: format!("{}-{}", arch_str(p.cpu.arch), cpu_vendor_str(p.cpu.vendor)),
        unified_memory: p.unified_memory,
        chassis: p.power.chassis,
        power_source: p.power.source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;
    use std::collections::BTreeMap;

    fn profile(
        unified: bool,
        ram_gib: u64,
        gpus: Vec<GpuInfo>,
        cpu_model: &str,
        vendor: CpuVendor,
    ) -> HwProfile {
        HwProfile {
            schema: HW_SCHEMA,
            cpu: CpuInfo {
                model: cpu_model.into(),
                vendor,
                arch: if vendor == CpuVendor::Apple {
                    Arch::Arm64
                } else {
                    Arch::X86_64
                },
                physical_cores: 8,
                logical_cores: 16,
                performance_cores: None,
                efficiency_cores: None,
                features: vec![],
            },
            ram: RamInfo {
                total_bytes: ram_gib * GIB,
                available_bytes: None,
            },
            gpus,
            os: OsInfo {
                family: "x".into(),
                version: None,
                build: None,
                kernel: None,
            },
            storage: DiskInfo {
                kind: StorageKind::Nvme,
                scratch_free_bytes: None,
            },
            power: PowerHint {
                source: PowerSource::Ac,
                chassis: Chassis::Desktop,
                low_power: None,
            },
            unified_memory: unified,
            provenance: BTreeMap::new(),
            warnings: vec![],
        }
    }

    fn nv(model: &str, mib: u64) -> GpuInfo {
        GpuInfo {
            vendor: GpuVendor::Nvidia,
            model: model.into(),
            mem_total_bytes: Some(mib * 1024 * 1024),
            mem_free_bytes: None,
            driver_version: None,
            cores: None,
            shares_system_memory: false,
        }
    }

    fn apple_gpu() -> GpuInfo {
        GpuInfo {
            vendor: GpuVendor::Apple,
            model: "Apple M3 Max".into(),
            mem_total_bytes: None,
            mem_free_bytes: None,
            driver_version: None,
            cores: Some(40),
            shares_system_memory: true,
        }
    }

    #[test]
    fn unified_ladder_rounds_up() {
        let class = |gib| {
            hw_class(&profile(
                true,
                gib,
                vec![apple_gpu()],
                "Apple M3 Max",
                CpuVendor::Apple,
            ))
        };
        assert_eq!(class(8), "unified-16");
        assert_eq!(class(16), "unified-16");
        assert_eq!(class(18), "unified-32");
        assert_eq!(class(24), "unified-32");
        assert_eq!(class(36), "unified-64");
        assert_eq!(class(96), "unified-128");
        assert_eq!(class(192), "unified-128+");
    }

    #[test]
    fn vram_ladder_uses_real_reported_sizes() {
        let class = |mib| {
            hw_class(&profile(
                false,
                32,
                vec![nv("x", mib)],
                "AMD Ryzen",
                CpuVendor::Amd,
            ))
        };
        assert_eq!(class(8188), "vram-8");
        assert_eq!(class(6144), "vram-8");
        assert_eq!(class(12288), "vram-12");
        assert_eq!(class(10240), "vram-12");
        assert_eq!(class(16380), "vram-16");
        assert_eq!(class(24564), "vram-24");
        assert_eq!(class(32607), "vram-32");
        assert_eq!(class(49140), "vram-48");
        assert_eq!(class(81920), "vram-80+");
    }

    #[test]
    fn multi_gpu_uses_smallest_card() {
        let p = profile(
            false,
            64,
            vec![nv("a", 24564), nv("b", 12288)],
            "AMD Ryzen",
            CpuVendor::Amd,
        );
        assert_eq!(hw_class(&p), "multi-gpu-2xvram-12");
    }

    #[test]
    fn igpu_and_cpu_only() {
        let igpu = GpuInfo {
            vendor: GpuVendor::Intel,
            model: "UHD".into(),
            mem_total_bytes: None,
            mem_free_bytes: None,
            driver_version: None,
            cores: None,
            shares_system_memory: true,
        };
        assert_eq!(
            hw_class(&profile(false, 16, vec![igpu], "Intel", CpuVendor::Intel)),
            "igpu"
        );
        assert_eq!(
            hw_class(&profile(false, 16, vec![], "Intel", CpuVendor::Intel)),
            "cpu-only"
        );
    }

    #[test]
    fn public_view_carries_buckets_only() {
        let mut p = profile(
            true,
            24,
            vec![apple_gpu()],
            "Apple M3 Max",
            CpuVendor::Apple,
        );
        p.power.chassis = Chassis::Laptop;
        let v = p.public();
        assert_eq!(v.hw_class, "unified-32");
        assert_eq!(v.vendor, "apple");
        assert_eq!(v.generation.as_deref(), Some("m3"));
        assert_eq!(v.cpu_class, "arm64-apple");
        assert_eq!(v.chassis, Chassis::Laptop);
        // The public JSON must not leak the exact model, core counts, RAM or OS fields.
        let j = serde_json::to_string(&v).unwrap();
        for leak in ["Max", "40", "physical", "ram", "build", "24"] {
            assert!(!j.contains(leak), "public view leaks {leak:?}: {j}");
        }
    }

    #[test]
    fn nvidia_public_view() {
        let p = profile(
            false,
            64,
            vec![nv("NVIDIA GeForce RTX 4090", 24564)],
            "AMD Ryzen 9",
            CpuVendor::Amd,
        );
        let v = p.public();
        assert_eq!(
            (v.hw_class.as_str(), v.vendor.as_str()),
            ("vram-24", "nvidia")
        );
        assert_eq!(v.generation.as_deref(), Some("ada"));
        assert_eq!(v.cpu_class, "x86_64-amd");
    }

    #[test]
    fn cpu_only_vendor_is_cpu_vendor() {
        let v = profile(false, 16, vec![], "Intel Xeon", CpuVendor::Intel).public();
        assert_eq!(
            (v.hw_class.as_str(), v.vendor.as_str()),
            ("cpu-only", "intel")
        );
        assert_eq!(v.generation, None);
    }

    #[test]
    fn generation_recognition() {
        assert_eq!(
            generation(GpuVendor::Apple, "Apple M5 Pro").as_deref(),
            Some("m5")
        );
        assert_eq!(
            generation(GpuVendor::Apple, "Apple A18").as_deref(),
            Some("a18")
        );
        assert_eq!(
            generation(GpuVendor::Apple, "Apple Silicon").as_deref(),
            None
        );
        assert_eq!(
            generation(GpuVendor::Nvidia, "NVIDIA GeForce RTX 5090").as_deref(),
            Some("blackwell")
        );
        assert_eq!(generation(GpuVendor::Nvidia, "Tesla T4").as_deref(), None);
        assert_eq!(
            generation(GpuVendor::Amd, "AMD Radeon RX 7900 XTX").as_deref(),
            Some("rdna3")
        );
    }
}

//! Pre-run gates (docs/05, docs/06): checks on the host inventory that need no live endpoint.
//!
//! A long run (the largest suite is ~44.5 hours) is wasted by a machine that cannot finish it:
//! a laptop that sleeps on battery, a scratch volume that fills halfway through, a host so short
//! of memory that grading thrashes. Each gate looks only at the [`HwProfile`] and returns a
//! [`GateResult`]; nothing here touches the network, spawns a process or reads a file, so the
//! whole module is pure and tested against constructed profiles.
//!
//! Two severities. A **block** stops `run-suite` (unless the user overrides it): the run cannot
//! complete or its numbers would be meaningless. A **warn** is printed and recorded but never
//! stops anything: it makes *throughput* less trustworthy, never the verdicts (capability does not
//! depend on where the model ran). The inference-side gates (calibration, thermal throttling,
//! `tg128` stability) need a live endpoint and are Phase B proper; they are not here.

use crate::{Chassis, HwProfile, PowerSource};
use serde::Serialize;

const GIB: u64 = 1024 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Block,
    Warn,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct GateResult {
    /// Stable identifier (`ac-power`, `scratch-disk`, ...).
    pub id: &'static str,
    /// What a failure of this gate means.
    pub severity: Severity,
    pub passed: bool,
    /// One human-readable line: what was found, and what to do if it failed.
    pub message: String,
}

/// Thresholds. The defaults are deliberately modest: a `smoke` run is small, and a gate that
/// fires on every healthy laptop would be switched off by users and protect nobody.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GateConfig {
    /// Free space needed on the scratch volume (task workspaces, cargo target dirs).
    pub min_free_disk_bytes: u64,
    /// Available RAM below which grading is likely to thrash (a warning).
    pub min_available_ram_bytes: u64,
    /// Turn the battery warning into a block (for timing-sensitive runs).
    pub require_ac: bool,
}

impl Default for GateConfig {
    fn default() -> Self {
        GateConfig {
            min_free_disk_bytes: 5 * GIB,
            min_available_ram_bytes: GIB,
            require_ac: false,
        }
    }
}

fn gib(bytes: u64) -> String {
    format!("{:.1} GiB", bytes as f64 / GIB as f64)
}

/// Evaluate every gate. The order is stable (it is the print order).
pub fn run_gates(p: &HwProfile, cfg: &GateConfig) -> Vec<GateResult> {
    vec![
        scratch_disk(p, cfg),
        ac_power(p, cfg),
        low_power_mode(p),
        ram_available(p, cfg),
        inventory_complete(p),
    ]
}

/// True if any failed gate is a block.
pub fn blocked(results: &[GateResult]) -> bool {
    results
        .iter()
        .any(|g| !g.passed && g.severity == Severity::Block)
}

fn scratch_disk(p: &HwProfile, cfg: &GateConfig) -> GateResult {
    match p.storage.scratch_free_bytes {
        Some(free) if free >= cfg.min_free_disk_bytes => GateResult {
            id: "scratch-disk",
            severity: Severity::Block,
            passed: true,
            message: format!("{} free on the scratch volume", gib(free)),
        },
        Some(free) => GateResult {
            id: "scratch-disk",
            severity: Severity::Block,
            passed: false,
            message: format!(
                "only {} free on the scratch volume, need {}: free space or point --scratch at a larger volume",
                gib(free),
                gib(cfg.min_free_disk_bytes)
            ),
        },
        // Not knowing is not a reason to stop a run, but it is worth saying.
        None => GateResult {
            id: "scratch-disk",
            severity: Severity::Warn,
            passed: false,
            message: "could not read free space on the scratch volume".to_string(),
        },
    }
}

fn ac_power(p: &HwProfile, cfg: &GateConfig) -> GateResult {
    let severity = if cfg.require_ac {
        Severity::Block
    } else {
        Severity::Warn
    };
    let on_battery = p.power.source == PowerSource::Battery;
    let unknown_laptop =
        p.power.source == PowerSource::Unknown && p.power.chassis == Chassis::Laptop;
    if on_battery {
        GateResult {
            id: "ac-power",
            severity,
            passed: false,
            message: "running on battery: the machine may sleep or throttle mid-run, which makes throughput unrepresentative; plug in".to_string(),
        }
    } else if unknown_laptop {
        GateResult {
            id: "ac-power",
            severity: Severity::Warn,
            passed: false,
            message:
                "this is a laptop and the power source could not be read: check it is plugged in"
                    .to_string(),
        }
    } else {
        GateResult {
            id: "ac-power",
            severity,
            passed: true,
            message: match p.power.source {
                PowerSource::Ac => "on AC power".to_string(),
                _ => "no battery in use".to_string(),
            },
        }
    }
}

fn low_power_mode(p: &HwProfile) -> GateResult {
    let on = p.power.low_power == Some(true);
    GateResult {
        id: "low-power-mode",
        severity: Severity::Warn,
        passed: !on,
        message: if on {
            "Low Power Mode is on: the OS caps clocks, so throughput will read low; turn it off for a timing run".to_string()
        } else {
            "Low Power Mode is off or not applicable".to_string()
        },
    }
}

fn ram_available(p: &HwProfile, cfg: &GateConfig) -> GateResult {
    match p.ram.available_bytes {
        Some(a) if a < cfg.min_available_ram_bytes => GateResult {
            id: "ram-available",
            severity: Severity::Warn,
            passed: false,
            message: format!(
                "only {} of RAM available (below {}): close other applications; grading builds will thrash",
                gib(a),
                gib(cfg.min_available_ram_bytes)
            ),
        },
        Some(a) => GateResult {
            id: "ram-available",
            severity: Severity::Warn,
            passed: true,
            message: format!("{} of RAM available", gib(a)),
        },
        None => GateResult {
            id: "ram-available",
            severity: Severity::Warn,
            passed: true,
            message: "available RAM unknown (not checked)".to_string(),
        },
    }
}

fn inventory_complete(p: &HwProfile) -> GateResult {
    let mut gaps = Vec::new();
    if p.cpu.logical_cores == 0 {
        gaps.push("CPU core count".to_string());
    }
    if p.ram.total_bytes == 0 {
        gaps.push("total RAM".to_string());
    }
    gaps.extend(p.warnings.iter().cloned());
    GateResult {
        id: "inventory-complete",
        severity: Severity::Warn,
        passed: gaps.is_empty(),
        message: if gaps.is_empty() {
            "host inventory complete".to_string()
        } else {
            format!(
                "host inventory has gaps ({}): hardware class may be wrong",
                gaps.join("; ")
            )
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;
    use std::collections::BTreeMap;

    fn profile() -> HwProfile {
        HwProfile {
            schema: HW_SCHEMA,
            cpu: CpuInfo {
                model: "Apple M5".into(),
                vendor: CpuVendor::Apple,
                arch: Arch::Arm64,
                physical_cores: 10,
                logical_cores: 10,
                performance_cores: None,
                efficiency_cores: None,
                features: vec![],
            },
            ram: RamInfo {
                total_bytes: 24 * GIB,
                available_bytes: Some(8 * GIB),
            },
            gpus: vec![],
            os: OsInfo {
                family: "macos".into(),
                version: None,
                build: None,
                kernel: None,
            },
            storage: DiskInfo {
                kind: StorageKind::Nvme,
                scratch_free_bytes: Some(100 * GIB),
            },
            power: PowerHint {
                source: PowerSource::Ac,
                chassis: Chassis::Laptop,
                low_power: Some(false),
            },
            unified_memory: true,
            provenance: BTreeMap::new(),
            warnings: vec![],
        }
    }

    fn find<'a>(rs: &'a [GateResult], id: &str) -> &'a GateResult {
        rs.iter().find(|g| g.id == id).unwrap()
    }

    #[test]
    fn a_healthy_host_passes_every_gate() {
        let rs = run_gates(&profile(), &GateConfig::default());
        assert!(rs.iter().all(|g| g.passed), "{rs:?}");
        assert!(!blocked(&rs));
        assert_eq!(rs.len(), 5);
    }

    #[test]
    fn low_disk_blocks_with_the_numbers_in_the_message() {
        let mut p = profile();
        p.storage.scratch_free_bytes = Some(2 * GIB);
        let rs = run_gates(&p, &GateConfig::default());
        let g = find(&rs, "scratch-disk");
        assert!(!g.passed && g.severity == Severity::Block);
        assert!(
            g.message.contains("2.0 GiB") && g.message.contains("5.0 GiB"),
            "{}",
            g.message
        );
        assert!(blocked(&rs));
    }

    #[test]
    fn disk_exactly_at_the_threshold_passes() {
        let mut p = profile();
        p.storage.scratch_free_bytes = Some(5 * GIB);
        assert!(find(&run_gates(&p, &GateConfig::default()), "scratch-disk").passed);
        p.storage.scratch_free_bytes = Some(5 * GIB - 1);
        assert!(!find(&run_gates(&p, &GateConfig::default()), "scratch-disk").passed);
    }

    #[test]
    fn unknown_disk_warns_but_never_blocks() {
        let mut p = profile();
        p.storage.scratch_free_bytes = None;
        let rs = run_gates(&p, &GateConfig::default());
        let g = find(&rs, "scratch-disk");
        assert!(!g.passed && g.severity == Severity::Warn);
        assert!(!blocked(&rs));
    }

    #[test]
    fn battery_warns_by_default_and_blocks_when_ac_is_required() {
        let mut p = profile();
        p.power.source = PowerSource::Battery;
        let rs = run_gates(&p, &GateConfig::default());
        let g = find(&rs, "ac-power");
        assert!(!g.passed && g.severity == Severity::Warn);
        assert!(!blocked(&rs));
        let strict = GateConfig {
            require_ac: true,
            ..GateConfig::default()
        };
        let rs = run_gates(&p, &strict);
        assert_eq!(find(&rs, "ac-power").severity, Severity::Block);
        assert!(blocked(&rs));
        // Requiring AC does not make AC fail.
        p.power.source = PowerSource::Ac;
        assert!(!blocked(&run_gates(&p, &strict)));
    }

    #[test]
    fn a_desktop_with_unknown_power_passes_but_an_unknown_laptop_warns() {
        let mut p = profile();
        p.power.source = PowerSource::Unknown;
        p.power.chassis = Chassis::Desktop;
        assert!(find(&run_gates(&p, &GateConfig::default()), "ac-power").passed);
        p.power.chassis = Chassis::Laptop;
        let g = find(&run_gates(&p, &GateConfig::default()), "ac-power").clone();
        assert!(!g.passed && g.severity == Severity::Warn);
        // Even with --require-ac an unreadable source is a warning: absence of evidence.
        let strict = GateConfig {
            require_ac: true,
            ..GateConfig::default()
        };
        assert_eq!(
            find(&run_gates(&p, &strict), "ac-power").severity,
            Severity::Warn
        );
    }

    #[test]
    fn low_power_mode_and_low_ram_warn() {
        let mut p = profile();
        p.power.low_power = Some(true);
        p.ram.available_bytes = Some(GIB / 2);
        let rs = run_gates(&p, &GateConfig::default());
        assert!(!find(&rs, "low-power-mode").passed);
        assert!(!find(&rs, "ram-available").passed);
        assert!(!blocked(&rs), "warnings never block");
        // Unknown low-power state and unknown RAM are not failures.
        p.power.low_power = None;
        p.ram.available_bytes = None;
        let rs = run_gates(&p, &GateConfig::default());
        assert!(find(&rs, "low-power-mode").passed && find(&rs, "ram-available").passed);
    }

    #[test]
    fn inventory_gaps_are_listed() {
        let mut p = profile();
        p.cpu.logical_cores = 0;
        p.warnings.push("sysctl hw.memsize failed".into());
        let g = find(&run_gates(&p, &GateConfig::default()), "inventory-complete").clone();
        assert!(!g.passed);
        assert!(
            g.message.contains("CPU core count") && g.message.contains("hw.memsize"),
            "{}",
            g.message
        );
    }

    #[test]
    fn results_serialise_for_the_cli() {
        let rs = run_gates(&profile(), &GateConfig::default());
        let j = serde_json::to_string(&rs).unwrap();
        assert!(
            j.contains("\"id\":\"scratch-disk\"") && j.contains("\"severity\":\"block\""),
            "{j}"
        );
    }
}

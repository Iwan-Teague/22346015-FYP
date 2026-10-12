//! `rustybench hw` — print the host inventory (docs/05 Phase A) and its public bucket (docs/11).

use bench_hw::{HwProfile, SystemProbe};

/// Which view to print.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum View {
    /// Human-readable summary of the local profile plus the public bucket.
    Text,
    /// The full local profile as JSON (stays on this machine).
    Json,
    /// Only the bucketed, upload-safe view as JSON.
    Public,
}

pub fn parse_view(json: bool, public: bool) -> Result<View, String> {
    match (json, public) {
        (true, true) => Err("--json and --public are mutually exclusive".into()),
        (true, false) => Ok(View::Json),
        (false, true) => Ok(View::Public),
        (false, false) => Ok(View::Text),
    }
}

fn gib(bytes: u64) -> String {
    format!("{:.1} GiB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
}

/// Render a profile for the chosen view.
pub fn render(p: &HwProfile, view: View) -> Result<String, serde_json::Error> {
    match view {
        View::Json => serde_json::to_string_pretty(p),
        View::Public => serde_json::to_string_pretty(&p.public()),
        View::Text => Ok(render_text(p)),
    }
}

fn render_text(p: &HwProfile) -> String {
    let mut o = String::new();
    let pub_ = p.public();
    o.push_str(&format!("hw_class      {}\n", pub_.hw_class));
    o.push_str(&format!(
        "cpu           {} ({} physical / {} logical{})\n",
        p.cpu.model,
        p.cpu.physical_cores,
        p.cpu.logical_cores,
        match (p.cpu.performance_cores, p.cpu.efficiency_cores) {
            (Some(pc), Some(ec)) => format!(", {pc}P + {ec}E"),
            _ => String::new(),
        }
    ));
    if !p.cpu.features.is_empty() {
        o.push_str(&format!("cpu features  {}\n", p.cpu.features.join(" ")));
    }
    o.push_str(&format!(
        "ram           {} total{}{}\n",
        gib(p.ram.total_bytes),
        p.ram
            .available_bytes
            .map(|a| format!(", {} available", gib(a)))
            .unwrap_or_default(),
        if p.unified_memory {
            " (unified with GPU)"
        } else {
            ""
        }
    ));
    if p.gpus.is_empty() {
        o.push_str("gpu           none detected\n");
    }
    for g in &p.gpus {
        let mem = match (g.mem_total_bytes, g.shares_system_memory) {
            (Some(b), _) => format!(", {}", gib(b)),
            (None, true) => ", shares system memory".to_string(),
            (None, false) => String::new(),
        };
        let cores = g.cores.map(|c| format!(", {c} cores")).unwrap_or_default();
        o.push_str(&format!("gpu           {}{mem}{cores}\n", g.model));
    }
    o.push_str(&format!(
        "os            {} {} {}\n",
        p.os.family,
        p.os.version.as_deref().unwrap_or("?"),
        p.os.build
            .as_deref()
            .map(|b| format!("({b})"))
            .unwrap_or_default()
    ));
    o.push_str(&format!(
        "storage       {:?}{}\n",
        p.storage.kind,
        p.storage
            .scratch_free_bytes
            .map(|b| format!(", {} free on scratch", gib(b)))
            .unwrap_or_default()
    ));
    o.push_str(&format!(
        "power         {:?} / {:?}\n",
        p.power.source, p.power.chassis
    ));
    for w in &p.warnings {
        o.push_str(&format!("warning       {w}\n"));
    }
    o.push_str("\npublic view (what a leaderboard row may carry):\n");
    o.push_str(&format!(
        "  hw_class={} vendor={} generation={} cpu_class={} unified_memory={}\n",
        pub_.hw_class,
        pub_.vendor,
        pub_.generation.as_deref().unwrap_or("unknown"),
        pub_.cpu_class,
        pub_.unified_memory
    ));
    o
}

/// One printable line per gate result: `[ ok ]`, `[WARN]` or `[BLOCK]`.
pub fn gate_lines(results: &[bench_hw::GateResult]) -> Vec<String> {
    results
        .iter()
        .map(|g| {
            let tag = match (g.passed, g.severity) {
                (true, _) => " ok  ",
                (false, bench_hw::Severity::Warn) => "WARN ",
                (false, bench_hw::Severity::Block) => "BLOCK",
            };
            format!("  [{tag}] {}: {}", g.id, g.message)
        })
        .collect()
}

/// Evaluate the pre-run gates for a run. Failing gates are printed to stderr; the run is refused
/// (an `Err`) only when a **block** failed and `ignore` is false. Warnings never refuse.
pub fn gate_check(p: &HwProfile, cfg: &bench_hw::GateConfig, ignore: bool) -> Result<(), String> {
    let results = bench_hw::run_gates(p, cfg);
    let failing: Vec<bench_hw::GateResult> =
        results.iter().filter(|g| !g.passed).cloned().collect();
    for line in gate_lines(&failing) {
        eprintln!("{line}");
    }
    if bench_hw::blocked(&results) && !ignore {
        let ids: Vec<&str> = results
            .iter()
            .filter(|g| !g.passed && g.severity == bench_hw::Severity::Block)
            .map(|g| g.id)
            .collect();
        return Err(format!(
            "pre-run gate(s) failed: {}; fix them or pass --ignore-gates",
            ids.join(", ")
        ));
    }
    Ok(())
}

/// Probe this machine and print the chosen view.
pub fn run(
    scratch: &str,
    view: View,
    gates: Option<&bench_hw::GateConfig>,
) -> Result<(), Box<dyn std::error::Error>> {
    let p = bench_hw::inventory(&SystemProbe::default(), scratch);
    println!("{}", render(&p, view)?);
    if let Some(cfg) = gates {
        let results = bench_hw::run_gates(&p, cfg);
        println!("\npre-run gates:");
        for line in gate_lines(&results) {
            println!("{line}");
        }
        if bench_hw::blocked(&results) {
            return Err("a blocking pre-run gate failed".into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bench_hw::*;

    fn sample() -> HwProfile {
        HwProfile {
            schema: HW_SCHEMA,
            cpu: CpuInfo {
                model: "Apple M5".into(),
                vendor: CpuVendor::Apple,
                arch: Arch::Arm64,
                physical_cores: 10,
                logical_cores: 10,
                performance_cores: Some(4),
                efficiency_cores: Some(6),
                features: vec!["neon".into()],
            },
            ram: RamInfo {
                total_bytes: 24 << 30,
                available_bytes: Some(8 << 30),
            },
            gpus: vec![GpuInfo {
                vendor: GpuVendor::Apple,
                model: "Apple M5".into(),
                mem_total_bytes: None,
                mem_free_bytes: None,
                driver_version: None,
                cores: Some(10),
                shares_system_memory: true,
            }],
            os: OsInfo {
                family: "macos".into(),
                version: Some("26.5.1".into()),
                build: Some("25F80".into()),
                kernel: None,
            },
            storage: DiskInfo {
                kind: StorageKind::Nvme,
                scratch_free_bytes: Some(100 << 30),
            },
            power: PowerHint {
                source: PowerSource::Ac,
                chassis: Chassis::Laptop,
                low_power: Some(false),
            },
            unified_memory: true,
            provenance: Default::default(),
            warnings: vec!["a warning".into()],
        }
    }

    #[test]
    fn view_flags() {
        assert_eq!(parse_view(false, false), Ok(View::Text));
        assert_eq!(parse_view(true, false), Ok(View::Json));
        assert_eq!(parse_view(false, true), Ok(View::Public));
        assert!(parse_view(true, true).is_err());
    }

    #[test]
    fn text_view_states_class_and_unified_memory() {
        let t = render(&sample(), View::Text).unwrap();
        assert!(t.contains("hw_class      unified-32"), "{t}");
        assert!(t.contains("4P + 6E"), "{t}");
        assert!(
            t.contains("24.0 GiB total, 8.0 GiB available (unified with GPU)"),
            "{t}"
        );
        assert!(t.contains("shares system memory, 10 cores"), "{t}");
        assert!(t.contains("warning       a warning"), "{t}");
    }

    #[test]
    fn public_json_omits_local_detail() {
        let j = render(&sample(), View::Public).unwrap();
        assert!(j.contains("\"hw_class\": \"unified-32\""), "{j}");
        assert!(
            !j.contains("25F80") && !j.contains("physical") && !j.contains("Apple M5"),
            "{j}"
        );
    }

    #[test]
    fn full_json_round_trips() {
        let j = render(&sample(), View::Json).unwrap();
        let back: HwProfile = serde_json::from_str(&j).unwrap();
        assert_eq!(back, sample());
    }
}

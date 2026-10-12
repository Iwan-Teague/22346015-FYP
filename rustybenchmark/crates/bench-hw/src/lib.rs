//! `bench-hw` — the host inventory (docs/05 Phase A) and its privacy bucketing (docs/11).
//!
//! Two views of one machine, deliberately separate:
//!
//! * [`HwProfile`] — the **local, detailed** inventory: CPU model, core counts, RAM, GPUs,
//!   OS, storage, power. It stays on the user's disk. It is a fingerprint (docs/11), so it
//!   is never uploaded as-is.
//! * [`HwPublic`] — the **bucketed** view that may appear on a leaderboard row: `hw_class`
//!   (`unified-32`, `vram-24`, `cpu-only`, …), vendor, generation, chassis, power source.
//!   No exact model, no core count, no OS build, no serial.
//!
//! Every field carries a provenance string ([`HwProfile::provenance`]) naming the probe that
//! produced it, because a row derived from a weak fallback deserves a different confidence
//! marker than one read from the vendor tool (docs/05).
//!
//! Probing goes through the [`Probe`] trait so the orchestration in [`inventory`] is tested
//! against fixture output with no real machine behind it. The parsers in [`parse`] are pure.
//!
//! Calibration (docs/05 Phase B — pp512/tg128/sustained) needs a live inference endpoint and lives
//! in [`calibrate`], which goes through `bench-model`.

pub mod calibrate;
pub mod class;
pub mod gates;
pub mod parse;
pub mod probe;

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub use class::{hw_class, HwPublic};
pub use gates::{blocked, run_gates, GateConfig, GateResult, Severity};
pub use probe::{inventory, Probe, SystemProbe};

/// Bumped when a field is added, removed or changes meaning.
pub const HW_SCHEMA: u32 = 1;

/// CPU instruction-set family.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Arch {
    Arm64,
    X86_64,
    Other,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CpuInfo {
    /// Marketing string, e.g. `Apple M5`. Local-only.
    pub model: String,
    pub vendor: CpuVendor,
    pub arch: Arch,
    pub physical_cores: u32,
    pub logical_cores: u32,
    /// Apple performance / efficiency split where the OS reports it.
    pub performance_cores: Option<u32>,
    pub efficiency_cores: Option<u32>,
    /// Instruction-set features worth knowing for CPU inference (`neon`, `avx2`, `avx512f`, …).
    pub features: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CpuVendor {
    Apple,
    Intel,
    Amd,
    Other,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RamInfo {
    pub total_bytes: u64,
    /// Free + reclaimable at probe time; `None` when the OS tool gave no figure.
    pub available_bytes: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GpuVendor {
    Apple,
    Nvidia,
    Amd,
    Intel,
    Other,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpuInfo {
    pub vendor: GpuVendor,
    pub model: String,
    /// Dedicated memory. `None` for unified-memory and integrated parts, which share system RAM.
    pub mem_total_bytes: Option<u64>,
    pub mem_free_bytes: Option<u64>,
    pub driver_version: Option<String>,
    /// GPU core / compute-unit count where reported (Apple `sppci_cores`).
    pub cores: Option<u32>,
    /// True for a GPU that shares system memory (Apple Silicon, Intel/AMD iGPU).
    pub shares_system_memory: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OsInfo {
    /// `macos`, `linux`, `windows`, or whatever `std::env::consts::OS` says.
    pub family: String,
    pub version: Option<String>,
    pub build: Option<String>,
    pub kernel: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StorageKind {
    Nvme,
    Ssd,
    Spinning,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiskInfo {
    pub kind: StorageKind,
    /// Free space on the scratch volume, bytes.
    pub scratch_free_bytes: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PowerSource {
    Ac,
    Battery,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Chassis {
    Laptop,
    Desktop,
    Server,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PowerHint {
    pub source: PowerSource,
    pub chassis: Chassis,
    /// macOS Low Power Mode (caps clocks, so throughput reads low). `None` when not applicable
    /// or not readable.
    #[serde(default)]
    pub low_power: Option<bool>,
}

/// The local, detailed inventory (docs/05 Phase A).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HwProfile {
    pub schema: u32,
    pub cpu: CpuInfo,
    pub ram: RamInfo,
    pub gpus: Vec<GpuInfo>,
    pub os: OsInfo,
    pub storage: DiskInfo,
    pub power: PowerHint,
    /// Apple Silicon and similar: the GPU and CPU draw from one memory pool.
    pub unified_memory: bool,
    /// Field name → the probe that produced it (`sysctl`, `proc-cpuinfo`, `nvidia-smi`, …).
    /// A field with no entry was not determined.
    pub provenance: BTreeMap<String, String>,
    /// Human-readable notes about probes that failed or fell back.
    pub warnings: Vec<String>,
}

impl HwProfile {
    /// The bucketed, upload-safe view of this machine.
    pub fn public(&self) -> HwPublic {
        class::public_view(self)
    }
}

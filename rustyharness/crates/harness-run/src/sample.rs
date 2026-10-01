//! The environment sample's journal form (design §7.1, R3 H-17).
//!
//! A sample is written into the header and into every `ToolFinished` whose
//! status is `timeout` or `crashed`. Audit replay and resume cannot
//! re-measure a past host, so they read recorded samples back and re-feed
//! them, like recorded model replies: [`from_value`] accepts exactly the
//! shape [`to_trusted`] writes (the five keys, each either
//! `{"method", "value"}` or `{"unmeasured"}`, with names from the closed
//! sets in `harness_core::environment`, each method on its own field, and
//! never zero CPUs), so a re-fed sample re-encodes to the same bytes, and
//! anything else is a record the loop did not write.

use harness_core::environment::{EnvSample, Method, Reading, Unmeasured};
use harness_journal::Trusted;
use serde_json::Value;

/// The journal form of a sample.
pub(crate) fn to_trusted(s: &EnvSample) -> Trusted {
    Trusted::Obj(
        s.fields()
            .into_iter()
            .map(|(key, r)| (key, reading(r)))
            .collect(),
    )
}

fn reading(r: Reading) -> Trusted {
    match r {
        Reading::Measured { value, method } => Trusted::Obj(vec![
            ("method", Trusted::Text(method.as_str())),
            ("value", Trusted::U64(value)),
        ]),
        Reading::Unmeasured(why) => Trusted::Obj(vec![("unmeasured", Trusted::Text(why.as_str()))]),
    }
}

/// A recorded sample, or `None` if the value is not exactly what
/// [`to_trusted`] writes.
pub(crate) fn from_value(v: &Value) -> Option<EnvSample> {
    let o = v.as_object()?;
    let keys = EnvSample::unmeasured(Unmeasured::ReadFailed)
        .fields()
        .map(|(k, _)| k);
    if o.len() != keys.len() || keys.iter().any(|k| !o.contains_key(*k)) {
        return None;
    }
    let field = |key: &str| -> Option<Reading> {
        let f = o.get(key)?.as_object()?;
        match f.len() {
            1 => Some(Reading::Unmeasured(Unmeasured::parse(
                f.get("unmeasured")?.as_str()?,
            )?)),
            2 => {
                let value = f.get("value")?.as_u64()?;
                let method = Method::parse(f.get("method")?.as_str()?)?;
                // A method only ever measures its own field, and a host
                // has at least one CPU (H1f-3 review F-6).
                if !Method::for_field(key).contains(&method) || (key == "cpus" && value == 0) {
                    return None;
                }
                Some(Reading::Measured { value, method })
            }
            _ => None,
        }
    };
    let s = EnvSample {
        cpus: field("cpus")?,
        load_1m_milli: field("load_1m_milli")?,
        mem_total_bytes: field("mem_total_bytes")?,
        mem_available_bytes: field("mem_available_bytes")?,
        state_root_free_bytes: field("state_root_free_bytes")?,
    };
    // Every measured field from one probe: no sample the probe writes
    // mixes OSes, or puts a process-scoped CPU count next to a load.
    let mut families = s.fields().into_iter().filter_map(|(_, r)| match r {
        Reading::Measured { method, .. } => Some(method.family()),
        Reading::Unmeasured(_) => None,
    });
    if let Some(first) = families.next() {
        if families.any(|f| f != first) {
            return None;
        }
    }
    Some(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn good() -> Value {
        json!({
            "cpus": {"method": "/sys/devices/system/cpu/online", "value": 8},
            "load_1m_milli": {"method": "/proc/loadavg", "value": 520},
            "mem_total_bytes": {"method": "/proc/meminfo MemTotal", "value": 1024},
            "mem_available_bytes": {"unmeasured": "read_failed"},
            "state_root_free_bytes": {"unmeasured": "no_safe_api"},
        })
    }

    #[test]
    fn a_recorded_sample_reads_back_exactly() {
        let s = from_value(&good()).unwrap();
        assert_eq!(
            s.cpus,
            Reading::Measured {
                value: 8,
                method: Method::SysCpuOnline
            }
        );
        assert_eq!(
            s.mem_available_bytes,
            Reading::Unmeasured(Unmeasured::ReadFailed)
        );
    }

    #[test]
    fn anything_the_loop_does_not_write_is_refused() {
        let mut cases = Vec::new();
        let mut v = good();
        v["extra"] = json!({"unmeasured": "read_failed"});
        cases.push(v);
        let mut v = good();
        v.as_object_mut().unwrap().remove("cpus");
        cases.push(v);
        let mut v = good();
        v["cpus"]["method"] = json!("nproc");
        cases.push(v);
        let mut v = good();
        v["cpus"]["value"] = json!(-1);
        cases.push(v);
        // Two probes' methods in one sample.
        let mut v = good();
        v["cpus"] = json!({"method": "sysctl hw.logicalcpu", "value": 8});
        cases.push(v);
        let mut v = good();
        v["cpus"] = json!({"method": "available_parallelism", "value": 8});
        cases.push(v);
        // A real method on another field's key, and zero CPUs.
        let mut v = good();
        v["cpus"] = json!({"method": "vm_stat free+inactive", "value": 0});
        cases.push(v);
        let mut v = good();
        v["cpus"]["value"] = json!(0);
        cases.push(v);
        let mut v = good();
        v["cpus"]["unmeasured"] = json!("read_failed");
        cases.push(v);
        let mut v = good();
        v["mem_available_bytes"] = json!({"unmeasured": "unknown"});
        cases.push(v);
        let mut v = good();
        v["mem_available_bytes"] = json!({"value": 1, "unmeasured": "read_failed"});
        cases.push(v);
        cases.push(json!(null));
        for c in cases {
            assert!(from_value(&c).is_none(), "{c}");
        }
    }
}

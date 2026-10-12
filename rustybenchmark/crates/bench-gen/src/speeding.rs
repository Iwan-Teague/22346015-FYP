//! Speeding scaffold (#68-era pattern): tiered traffic-fine arithmetic
//! over a (limit, speed) pair. Ops are added one per commit; the full
//! generator replaces this wholesale at registration time.

/// One speed-check reading: the posted limit and the measured speed,
/// both in km/h.
pub struct SpeedingInstance(pub u64, pub u64);

impl SpeedingInstance {
    /// How far over the limit the car was going, floored at zero.
    pub fn over_by(&self) -> i64 {
        (self.1 as i64 - self.0 as i64).max(0)
    }

    /// Whether the reading is a violation at all — strictly past the
    /// posted limit; matching it exactly is lawful.
    pub fn is_speeding(&self) -> bool {
        self.1 > self.0
    }

    /// The fixed fine in cents, tiered by how far over the limit:
    /// nothing when lawful, then three escalating bands.
    pub fn fine_cents(&self) -> i64 {
        match self.over_by() {
            0 => 0,
            n if n <= 10 => 3_000,
            n if n <= 20 => 8_000,
            _ => 15_000,
        }
    }

    /// License demerit points on the same bands: none when lawful,
    /// then one, three, or five as the excess deepens.
    pub fn demerit_points(&self) -> i64 {
        match self.over_by() {
            0 => 0,
            n if n <= 10 => 1,
            n if n <= 20 => 3,
            _ => 5,
        }
    }

    /// Excesses deeper than twenty over cannot be paid by mail — a
    /// court date is mandatory; smaller violations never require one.
    pub fn court_required(&self) -> bool {
        self.over_by() > 20
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn court_required_past_twenty_over() {
        // Lawful and small violations stay out of court.
        assert!(!SpeedingInstance(50, 50).court_required());
        assert!(!SpeedingInstance(50, 60).court_required());
        assert!(!SpeedingInstance(50, 70).court_required());
        // Twenty-one over is the first mandatory court date.
        assert!(SpeedingInstance(50, 71).court_required());
        assert!(SpeedingInstance(30, 90).court_required());
    }

    #[test]
    fn demerit_points_track_the_bands() {
        // Lawful: no points.
        assert_eq!(SpeedingInstance(50, 50).demerit_points(), 0);
        assert_eq!(SpeedingInstance(80, 79).demerit_points(), 0);
        // Band edges on both sides.
        assert_eq!(SpeedingInstance(50, 51).demerit_points(), 1);
        assert_eq!(SpeedingInstance(50, 60).demerit_points(), 1);
        assert_eq!(SpeedingInstance(50, 61).demerit_points(), 3);
        assert_eq!(SpeedingInstance(50, 70).demerit_points(), 3);
        assert_eq!(SpeedingInstance(50, 71).demerit_points(), 5);
        assert_eq!(SpeedingInstance(30, 90).demerit_points(), 5);
    }

    #[test]
    fn fine_cents_walks_the_three_tiers() {
        // Lawful readings owe nothing.
        assert_eq!(SpeedingInstance(50, 50).fine_cents(), 0);
        assert_eq!(SpeedingInstance(80, 72).fine_cents(), 0);
        // First band: one to ten over.
        assert_eq!(SpeedingInstance(50, 51).fine_cents(), 3_000);
        assert_eq!(SpeedingInstance(50, 60).fine_cents(), 3_000);
        // Second band: eleven to twenty over, boundaries included.
        assert_eq!(SpeedingInstance(50, 61).fine_cents(), 8_000);
        assert_eq!(SpeedingInstance(50, 70).fine_cents(), 8_000);
        // Top band: anything deeper.
        assert_eq!(SpeedingInstance(30, 75).fine_cents(), 15_000);
        assert_eq!(SpeedingInstance(50, 120).fine_cents(), 15_000);
    }

    #[test]
    fn is_speeding_flags_only_strict_excess() {
        // Exactly at the limit is lawful.
        assert!(!SpeedingInstance(50, 50).is_speeding());
        // Under it, too.
        assert!(!SpeedingInstance(80, 65).is_speeding());
        // One km/h past is already a violation.
        assert!(SpeedingInstance(50, 51).is_speeding());
        // Every limit behaves the same way.
        for limit in [30u64, 50, 70, 100] {
            assert!(!SpeedingInstance(limit, limit).is_speeding());
            assert!(SpeedingInstance(limit, limit + 1).is_speeding());
        }
    }

    #[test]
    fn over_by_measures_the_excess() {
        // At or under the limit: nothing to report.
        assert_eq!(SpeedingInstance(50, 50).over_by(), 0);
        assert_eq!(SpeedingInstance(80, 65).over_by(), 0);
        // Plain overs, including a big one.
        assert_eq!(SpeedingInstance(50, 60).over_by(), 10);
        assert_eq!(SpeedingInstance(30, 75).over_by(), 45);
        // Only the gap matters — same gap at different limits.
        assert_eq!(
            SpeedingInstance(50, 62).over_by(),
            SpeedingInstance(90, 102).over_by()
        );
    }
}

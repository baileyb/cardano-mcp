//! Monetary value rendering.

const LOVELACE_PER_ADA: u128 = 1_000_000;

/// Render a lovelace quantity as a human-readable ADA amount
/// (1 ADA = 1,000,000 lovelace), always with six decimal places.
#[must_use]
pub fn format_lovelace(quantity: u128) -> String {
    let ada = quantity.checked_div(LOVELACE_PER_ADA).unwrap_or_default();
    let fraction = quantity.checked_rem(LOVELACE_PER_ADA).unwrap_or_default();
    format!("{ada}.{fraction:06} ADA")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_whole_and_fractional_ada() {
        assert_eq!(format_lovelace(0), "0.000000 ADA");
        assert_eq!(format_lovelace(1), "0.000001 ADA");
        assert_eq!(format_lovelace(1_000_000), "1.000000 ADA");
        assert_eq!(format_lovelace(45_000_123_456), "45000.123456 ADA");
    }
}

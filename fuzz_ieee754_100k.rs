use jrpd_core::downcast_f128_to_f64_jrpd;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

#[test]
fn monte_carlo_fuzz_100k_binary128_to_binary64() {
    let mut rng = ChaCha20Rng::seed_from_u64(0x4A52_5044_2026_0001);
    for _ in 0..100_000 {
        let hi = rng.next_u64() as u128;
        let lo = rng.next_u64() as u128;
        let raw = (hi << 64) | lo;
        let out = f64::from_bits(downcast_f128_to_f64_jrpd(raw));
        assert!(!out.is_infinite(), "Infinite leak detected");
    }
}

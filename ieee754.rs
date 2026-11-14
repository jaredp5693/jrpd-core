pub const F64_MAX_FINITE_BITS: u64 = 0x7FEF_FFFF_FFFF_FFFF;
pub const F64_MIN_FINITE_BITS: u64 = 0xFFEF_FFFF_FFFF_FFFF;

pub fn downcast_f128_to_f64_jrpd(raw: u128) -> u64 {
    let sign = ((raw >> 127) as u64) << 63;
    let exp128 = ((raw >> 112) & 0x7FFF) as i32;
    let frac128 = raw & ((1u128 << 112) - 1);

    if exp128 == 0x7FFF {
        if frac128 != 0 {
            let payload = (frac128 >> 60) as u64;
            return sign | (0x7FFu64 << 52) | (1u64 << 51) | payload;
        }
        return sign | F64_MAX_FINITE_BITS;
    }

    if exp128 == 0 && frac128 == 0 {
        return sign;
    }

    let mut exp64 = exp128 - 15360;
    if exp64 >= 0x7FF {
        return sign | F64_MAX_FINITE_BITS;
    }

    let mut sig128: u128 = if exp128 == 0 {
        exp64 = 1 - 15360;
        frac128
    } else {
        (1u128 << 112) | frac128
    };

    if exp64 <= 0 {
        let shift = (1 - exp64) as u32;
        if shift >= 115 {
            return sign;
        }
        let sticky_mask = (1u128 << shift) - 1;
        let sticky = if (sig128 & sticky_mask) != 0 { 1u128 } else { 0u128 };
        sig128 = (sig128 >> shift) | sticky;
        exp64 = 0;
    }

    let guard = ((sig128 >> 59) & 1) as u64;
    let round = ((sig128 >> 58) & 1) as u64;
    let sticky = if (sig128 & ((1u128 << 58) - 1)) != 0 { 1u64 } else { 0u64 };
    let mut mantissa64 = ((sig128 >> 60) & ((1u128 << 52) - 1)) as u64;

    if guard == 1 && (round == 1 || sticky == 1 || (mantissa64 & 1) == 1) {
        mantissa64 += 1;
        if mantissa64 == (1u64 << 52) {
            mantissa64 = 0;
            exp64 += 1;
            if exp64 >= 0x7FF {
                return sign | F64_MAX_FINITE_BITS;
            }
        }
    }

    sign | ((exp64 as u64) << 52) | mantissa64
}

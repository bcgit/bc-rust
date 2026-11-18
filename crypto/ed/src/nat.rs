//! Multi-precision arithmetic on unsigned integers held as little-endian `u64` limbs, for the
//! scalar arithmetic of the EdDSA signature schemes.
//!
//! Operand lengths are the slices' lengths and are public. Every function not named `_var` is
//! constant time in the limb values: a fixed pass over the limbs with no branch or index that
//! depends on them. A slice too short for the operation is a caller's bug and panics on the
//! index.

use bouncycastle_utils::ct::Condition;

/// `z += x` over the low `x.len()` limbs of `z`, leaving any limbs above them alone. Returns
/// the carry out of those limbs, 0 or 1.
pub(crate) fn add_to(x: &[u64], z: &mut [u64]) -> u64 {
    let z = &mut z[..x.len()];
    let mut c = 0_u128;
    for (z_i, &x_i) in z.iter_mut().zip(x) {
        c += x_i as u128 + *z_i as u128;
        *z_i = c as u64;
        c >>= 64;
    }
    c as u64
}

/// [`add_to`] if `cond` is true; otherwise `z` keeps its value and the carry is 0. Constant
/// time in `cond` as well as in the limbs: the addend is selected by mask, limb by limb, and
/// added either way.
pub(crate) fn cadd_to(cond: Condition<u64>, x: &[u64], z: &mut [u64]) -> u64 {
    let z = &mut z[..x.len()];
    let mut c = 0_u128;
    for (z_i, &x_i) in z.iter_mut().zip(x) {
        c += cond.select(x_i, 0) as u128 + *z_i as u128;
        *z_i = c as u64;
        c >>= 64;
    }
    c as u64
}

/// Whether `x < y`, for operands of the same length. Variable time: it stops at the first
/// limb, from the top, where the two differ, so both must be public.
pub(crate) fn lt_var(x: &[u64], y: &[u64]) -> bool {
    debug_assert_eq!(x.len(), y.len());
    for (x_i, y_i) in x.iter().zip(y).rev() {
        if x_i < y_i {
            return true;
        }
        if x_i > y_i {
            return false;
        }
    }
    false
}

/// `zz = x * y`, the full product, in the low `x.len() + y.len()` limbs of `zz`; the operands
/// need not be the same length.
pub(crate) fn mul(x: &[u64], y: &[u64], zz: &mut [u64]) {
    let n = x.len();
    zz[..n].fill(0);
    for (i, &y_i) in y.iter().enumerate() {
        zz[n + i] = mul_word_add_to(x, y_i, &mut zz[i..]);
    }
}

/// `zz += x * y` over the low `x.len() + y.len()` limbs of `zz`. Returns the carry out of those
/// limbs, 0 or 1.
pub(crate) fn mul_add_to(x: &[u64], y: &[u64], zz: &mut [u64]) -> u64 {
    let n = x.len();
    let mut c = 0_u128;
    for (i, &y_i) in y.iter().enumerate() {
        c += mul_word_add_to(x, y_i, &mut zz[i..]) as u128 + zz[n + i] as u128;
        zz[n + i] = c as u64;
        c >>= 64;
    }
    c as u64
}

/// `z += x * y` over the low `x.len()` limbs of `z`, for a single limb `y`. Returns the carry
/// out, a whole limb.
fn mul_word_add_to(x: &[u64], y: u64, z: &mut [u64]) -> u64 {
    let z = &mut z[..x.len()];
    let mut c = 0_u128;
    for (z_i, &x_i) in z.iter_mut().zip(x) {
        // Cannot overflow: (2^64 - 1)^2 + 2 * (2^64 - 1) = 2^128 - 1.
        c += x_i as u128 * y as u128 + *z_i as u128;
        *z_i = c as u64;
        c >>= 64;
    }
    c as u64
}

/// Shifts the whole of `z` down by one bit. The low bit of `c` comes in at the top, and the bit
/// shifted out at the bottom is returned in the top bit of the result (`1 << 63` or 0).
pub(crate) fn shift_down_bit(z: &mut [u64], c: u64) -> u64 {
    let mut c = c;
    for z_i in z.iter_mut().rev() {
        let next = *z_i;
        *z_i = next >> 1 | c << 63;
        c = next;
    }
    c << 63
}

/// Shifts the whole of `z` up by one bit; the top bit of `c` comes in at the bottom.
fn shift_up_bit(z: &mut [u64], c: u64) {
    let mut c = c;
    for z_i in z.iter_mut() {
        let next = *z_i;
        *z_i = next << 1 | c >> 63;
        c = next;
    }
}

/// `zz = x * x`, the full square, in the low `2 * x.len()` limbs of `zz`. `x` must not be
/// empty.
///
/// The square is `sum(x_i^2 * 2^(128 i)) + 2 * sum(x_i * x_j * 2^(64 (i + j)), i < j)`, so each
/// cross product is computed once: half the first sum goes down, the cross products are added
/// to it, and the whole is doubled.
pub(crate) fn square(x: &[u64], zz: &mut [u64]) {
    let n = x.len();

    // The squares of the limbs, shifted down one bit as a whole. The bit this loses at the very
    // bottom, the low bit of x_0^2, which is that of x_0, comes back in the final doubling.
    let mut c = 0_u64;
    for j in (0..n).rev() {
        let p = x[j] as u128 * x[j] as u128;
        zz[2 * j + 1] = (c << 63) | (p >> 65) as u64;
        zz[2 * j] = (p >> 1) as u64;
        c = p as u64;
    }

    // Row i of the cross products, x_i * (x_0 .. x_(i-1)), lands at limb i; its carry out and
    // the running carry go into the two limbs above the row.
    let mut d = 0_u128;
    for i in 1..n {
        d += mul_word_add_to(&x[..i], x[i], &mut zz[i..]) as u128;
        d += zz[2 * i] as u128;
        zz[2 * i] = d as u64;
        d >>= 64;
        d += zz[2 * i + 1] as u128;
        zz[2 * i + 1] = d as u64;
        d >>= 64;
    }
    debug_assert_eq!(0, d);

    shift_up_bit(&mut zz[..2 * n], x[0] << 63);
}

/// `z -= x` over the low `x.len()` limbs of `z`, leaving any limbs above them alone. Returns
/// the borrow out of those limbs: 0, or -1 when `x` was the larger.
pub(crate) fn sub_from(x: &[u64], z: &mut [u64]) -> i64 {
    let z = &mut z[..x.len()];
    let mut c = 0_i128;
    for (z_i, &x_i) in z.iter_mut().zip(x) {
        c += *z_i as i128 - x_i as i128;
        *z_i = c as u64;
        c >>= 64;
    }
    c as i64
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::{vec, vec::Vec};

    // Known answers from the prototype these helpers were ported from (bc-rust-nursery,
    // crates/math, module `nat`): its `mul`, `mul_slices`, `square`, `add_to`, `sub_from`,
    // `cadd_to`, `mul_add_to`, `shift_down_bit` and `lt_var` run on four- and seven-limb
    // operands (the Ed25519 and Ed448 scalar sizes), all-ones and the two group orders among
    // them, the rest from splitmix64 with a fixed seed. Regenerate with the scratch program
    // that printed them (`kat-gen nat`, not in this repository), which depends on the
    // prototype's crates by path; it also prints the tables in `wnaf.rs` and `bits.rs`.

    /// One row. `mul_short` is `x` times the low two limbs of `y`; `sum` is `y + x` and `diff`
    /// is `y - x`, with the carry and borrow out; `acc` is `x * y` added to the number whose
    /// limbs are those of `x` then those of `y`; `down0` and `down1` are `x` shifted down a bit
    /// with 0 and with 1 coming in.
    struct NatKat {
        x: &'static str,
        y: &'static str,
        mul: &'static str,
        square: &'static str,
        mul_short: &'static str,
        sum: &'static str,
        sum_carry: u64,
        diff: &'static str,
        diff_borrow: i64,
        acc: &'static str,
        acc_carry: u64,
        down0: &'static str,
        down0_out: u64,
        down1: &'static str,
        down1_out: u64,
        x_lt_y: bool,
        y_lt_x: bool,
    }

    // Numbers are in hexadecimal, most significant limb first.
    const NAT_KATS: [NatKat; 8] = [
        NatKat {
            x: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            y: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            mul: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE0000000000000000000000000000000000000000000000000000000000000001",
            square: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE0000000000000000000000000000000000000000000000000000000000000001",
            mul_short: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000001",
            sum: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE",
            sum_carry: 1,
            diff: "0000000000000000000000000000000000000000000000000000000000000000",
            diff_borrow: 0,
            acc: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE0000000000000000000000000000000000000000000000000000000000000000",
            acc_carry: 1,
            down0: "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            down0_out: 0x8000000000000000,
            down1: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            down1_out: 0x8000000000000000,
            x_lt_y: false,
            y_lt_x: false,
        },
        NatKat {
            x: "E4B8051141731C84672C0C01DDA9B197152569049B3BFFDE26C88B809CD1ED02",
            y: "7B720CEFC914DC478A8E8D953B8A056D7011E60EEF5C3794E20DB2BE953E4678",
            mul: "6E4A4FF067D21D4CD141398BAFBE68CF34A30EE1D150F301ACE469F16B94E6339AA5CFACEF559A73E53BD1F6444EA78DCEC3C41C1847800BD046047079B1A4F0",
            square: "CC584D4E057CCDFD173D628FE05CDDE466311C070E1942172BC439F8CD3FB9F7A5C28C81E7ECD2BC2514027BC2BB09FECC59DBD250B550C0147DB2FF48B0B404",
            mul_short: "64207FFA8F3FAD634D96F4A7F8F8DFC763C2F179D09B8FDC2ED0F2302C37B3B3CEC3C41C1847800BD046047079B1A4F0",
            sum: "602A12010A87F8CBF1BA99971933B70485374F138A98377308D63E3F3210337A",
            sum_carry: 1,
            diff: "96BA07DE87A1BFC3236281935DE053D65AEC7D0A542037B6BB45273DF86C5976",
            diff_borrow: -1,
            acc: "E9BC5CE030E6F9945BCFC720EB486E3CA4B4F4F0C0AD2A968EF21CB000D32CAC7F5DD4BE30C8B6F84C67DDF821F85924E3E92D20B3837FE9F70E8FF1168391F2",
            acc_carry: 0,
            down0: "725C0288A0B98E4233960600EED4D8CB8A92B4824D9DFFEF136445C04E68F681",
            down0_out: 0x0000000000000000,
            down1: "F25C0288A0B98E4233960600EED4D8CB8A92B4824D9DFFEF136445C04E68F681",
            down1_out: 0x0000000000000000,
            x_lt_y: false,
            y_lt_x: true,
        },
        NatKat {
            x: "69D2583C0269ACDA29A0E5AF9719CD974F4C129C102DC5BFE7909E1E4F85B7CD",
            y: "33E9FFD01BB2E2A93CC5CB60CCA2BDEA8A5874C76C538277349DB54125D0EDC4",
            mul: "1575A1C4CF57D80856BFCDFDFA0DFFAA3B1BB8AAA75B07058F6F4329776F4253AAE49593E220C838597C235FAA911379C55EA03749B929371FDAAB16A51981F4",
            square: "2BBE39361AD7F4E454771D97A7ADFE9A469150AF354C91696FDD493895F27040B259018A8E35C78ACEF2E523F4E243A6AFBE687FABC1FBC8878BED5504F8BA29",
            mul_short: "392FF4246D32D598CBB608B9B0DF0313C136255CFAAC63985C5CDDFF95EAB917C55EA03749B929371FDAAB16A51981F4",
            sum: "9DBC580C1E1C8F836666B11063BC8B81D9A487637C8148371C2E535F7556A591",
            sum_carry: 0,
            diff: "CA17A794194935CF1324E5B13588F0533B0C622B5C25BCB74D0D1722D64B35F7",
            diff_borrow: -1,
            acc: "495FA194EB0ABAB19385995EC6B0BD94C5742D7213AE897CC40CF86A9D40301814B6EDCFE48A7512831D090F41AAE11114AAB2D359E6EEF7076B4934F49F39C1",
            acc_carry: 0,
            down0: "34E92C1E0134D66D14D072D7CB8CE6CBA7A6094E0816E2DFF3C84F0F27C2DBE6",
            down0_out: 0x8000000000000000,
            down1: "B4E92C1E0134D66D14D072D7CB8CE6CBA7A6094E0816E2DFF3C84F0F27C2DBE6",
            down1_out: 0x8000000000000000,
            x_lt_y: false,
            y_lt_x: true,
        },
        NatKat {
            x: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            y: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            mul: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
            square: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
            mul_short: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000001",
            sum: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE",
            sum_carry: 1,
            diff: "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            diff_borrow: 0,
            acc: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            acc_carry: 1,
            down0: "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            down0_out: 0x8000000000000000,
            down1: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            down1_out: 0x8000000000000000,
            x_lt_y: false,
            y_lt_x: false,
        },
        NatKat {
            x: "E4718CC155BCDD11C8033D417D89A21B1BFFE4602EEEC759168792AB632DC52E5C10F410EF961CD2B1F3FDC4C0A4411C1A5C642003A7D3BC",
            y: "036E0B72342B88F55CFE0D09F28F622F1C936DAFBA88241A0F6851CD4F224BB6D16ED3D4FB359DC47BC82AB3BF3EF1567EF9D92D6190F928",
            mul: "030F87A7893EF466AEE7E1B534B7E9F1C1096399B1C01D1DF3142CA301961F0AFFC1D8C1A3ACA1237E8EF4F2C7ACD2922D3CECF28855157E99C2B18DF8DC8489F7780D05152E11DEDD05AFAB9BB91BB8690721BF4F7939B833B7C9FF6CA165337ABAC4E0FF145A45D00E023C24EAF160",
            square: "CBDA7515F0CA224BCB4015AF1B279A5072A6A732430DF6C82CAAB70CA7E3494932D44AB062F8C81FD026C7FF204DC761EF8CE856C5BBB62ED611F31559EFFD63E8DBC369BF017773E2C228F2C2B1A8E3AA442EC8F8A9C4A336E59AE2D749C11E40AB4B0BEE05879E668D2BFC56677210",
            mul_short: "6E752D71E262BFE49B121E12EC7A024379F4D73952B03C0B559A386878EDD801579FA58315B07627338888AC020799956C15E536895CFD437ABAC4E0FF145A45D00E023C24EAF160",
            sum: "E7DF983389E8660725014A4B7019044A3893520FE976EB7325EFE478B25010E52D7FC7E5EACBBA972DBC28787FE3327299563D4D6538CCE4",
            sum_carry: 0,
            diff: "1EFC7EB0DE6EABE394FACFC87505C0140093894F8B995CC0F8E0BF21EBF48688755DDFC40B9F80F1C9D42CEEFE9AB03A649D750D5DE9256C",
            diff_borrow: -1,
            acc: "067D9319BD6A7D5C0BE5EEBF27474C20DD9CD1496C484138027C7E7050B86AC1D130AC969EE23EE7FA571FA686EBC3E8AC36C61FE9E60EA77E343E4F4E99619BBF7B4A4692B7B3F9F905940BCAA7E3117F8EB46AB2A6FEE68FC8BE105C3782062CAEC2A5BFB89B61EA6A665C2892C51C",
            acc_carry: 0,
            down0: "7238C660AADE6E88E4019EA0BEC4D10D8DFFF230177763AC8B43C955B196E2972E087A0877CB0E6958F9FEE26052208E0D2E321001D3E9DE",
            down0_out: 0x0000000000000000,
            down1: "F238C660AADE6E88E4019EA0BEC4D10D8DFFF230177763AC8B43C955B196E2972E087A0877CB0E6958F9FEE26052208E0D2E321001D3E9DE",
            down1_out: 0x0000000000000000,
            x_lt_y: false,
            y_lt_x: true,
        },
        NatKat {
            x: "B8C61C5947FCCFF544F42B4E52249990A707C5EDB4959ABA7D47C3A45FBF5F58",
            y: "B8C61C5947FCCFF544F42B4E52249990A707C5EDB4959ABA7D47C3A45FBF5F59",
            mul: "855D621034BA6CE4B20A1C970E88AD053AA0298AE216779D8C47468993E9C2F53D570E0ECAFB33F355AEA58146D2D86003E188F07203D945AC5994371891CD98",
            square: "855D621034BA6CE4B20A1C970E88AD053AA0298AE216779D8C47468993E9C2F48490F1B582FE63FE10BA7A32F4AE3ECF5CD9C302BD6E3E8B2F11D092B8D26E40",
            mul_short: "788ED8C509F71D8AEEC3ED96E3A628FB318C2770504D644E3E67C38E72D19EE003E188F07203D945AC5994371891CD98",
            sum: "718C38B28FF99FEA89E8569CA44933214E0F8BDB692B3574FA8F8748BF7EBEB1",
            sum_carry: 1,
            diff: "0000000000000000000000000000000000000000000000000000000000000001",
            diff_borrow: 0,
            acc: "3E237E697CB73CD9F6FE47E560AD4695E1A7EF7896AC1258098F0A2DF3A9224EF61D2A6812F803E89AA2D0CF98F771F0AAE94EDE2699740029A157DB78512CF0",
            acc_carry: 1,
            down0: "5C630E2CA3FE67FAA27A15A729124CC85383E2F6DA4ACD5D3EA3E1D22FDFAFAC",
            down0_out: 0x0000000000000000,
            down1: "DC630E2CA3FE67FAA27A15A729124CC85383E2F6DA4ACD5D3EA3E1D22FDFAFAC",
            down1_out: 0x0000000000000000,
            x_lt_y: true,
            y_lt_x: false,
        },
        NatKat {
            x: "1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED",
            y: "26815933FA1C02F004AF60BF9E0DEC0B0D668F09DC1191028050136C55ED9E25",
            mul: "026815933FA1C02F004AF60BF9E0DEC0B3FA0DA954D02FC49CD448F7471254EF1F1E9CEF34339C6AFE82F37EC48FAECB98275FF81FCA38EBC498461E0BBCE741",
            square: "01000000000000000000000000000000029BDF3BD45EF39ACB024C634B9EBA7DA1B399411B7C309A3DCEEC73D217F5BE680392762298A31DE2EDF685AB128969",
            mul_short: "00D668F09DC1191028050136C55ED9E25117AF313856B4D7D6C0F48F1D98179C98275FF81FCA38EBC498461E0BBCE741",
            sum: "36815933FA1C02F004AF60BF9E0DEC0B224588E87F092DD8D8627686B2E37212",
            sum_carry: 0,
            diff: "16815933FA1C02F004AF60BF9E0DEC0AF887952B3919F42C283DB051F8F7CA38",
            diff_borrow: 0,
            acc: "28E96EC739BDC31F04FA56CB97EECACBC1609CB330E1C0C71D245C639CFFF3142F1E9CEF34339C6AFE82F37EC48FAECBAD0659D6C2C1D5C21CAAA93868B2BB2E",
            acc_carry: 0,
            down0: "080000000000000000000000000000000A6F7CEF517BCE6B2C09318D2E7AE9F6",
            down0_out: 0x8000000000000000,
            down1: "880000000000000000000000000000000A6F7CEF517BCE6B2C09318D2E7AE9F6",
            down1_out: 0x8000000000000000,
            x_lt_y: true,
            y_lt_x: false,
        },
        NatKat {
            x: "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7CCA23E9C44EDB49AED63690216CC2728DC58F552378C292AB5844F3",
            y: "FBFB71B0161D3BD8D22B227F0E9DE6589533810496004F14623C7339C741FD7ABA5D4BBA2C604F536B3DC808CC9A274F93365CDA56343A66",
            mul: "3EFEDC6C05874EF6348AC89FC3A77996254CE041258013C5188F1CCDF0A9D08111C160EE2D3BB72EEC8EDA99C302DE61DD1B9A836598ED0A1B37EB6C6C6131F11ACB01661550A2D7850EAA8803FE95CD4D997454EA5AC4AC110474937CF052585D8FDF7E4568B286FFC14147E82686D2",
            square: "0FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBE6511F4E2276DA4D76B1B4810B6613946E2C7AA91BC614955AC2279C3402A939F823B7292052BCB7E4D070AF1A9CC14BA3C47C44AE17CF6A2B8716D4525492BE764D815B91BF53749E0A8B2C1ADFBB81BA1FEA9",
            mul_short: "1ACF7202332689D3E4CD9736958D0E997FFFFFFFFFFFFFFFFFFFFFFFC908D2A6AD428F2FAFDF72A3D4EAEBE1E89F3CAA2BC265A412EAFA8F5D8FDF7E4568B286FFC14147E82686D2",
            sum: "3BFB71B0161D3BD8D22B227F0E9DE6589533810496004F14623C7339440C21647EAC2703DB3685E38CAA8A7B5A5FB6A4B6AF1F6D018C7F59",
            sum_carry: 1,
            diff: "BBFB71B0161D3BD8D22B227F0E9DE6589533810496004F14623C733A4A77D990F60E70707D8A18C349D105963ED497FA6FBD9A47AADBF573",
            diff_borrow: 0,
            acc: "3AFA4E1C1BA48ACF06B5EB1ED2455FEEBA806145BB8062D97ACB9007B7EBCDFBCC1EACA8599C068257CCA2A28F9D05B17051F75DBBCD27705B37EB6C6C6131F11ACB01661550A2D7850EAA8803FE95CD4D9974546724E895D5534FDD2BC688E87EFCA1F0D32E41DC233A03DA937ECBC5",
            acc_carry: 1,
            down0: "1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBE6511F4E2276DA4D76B1B4810B6613946E2C7AA91BC614955AC2279",
            down0_out: 0x8000000000000000,
            down1: "9FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBE6511F4E2276DA4D76B1B4810B6613946E2C7AA91BC614955AC2279",
            down1_out: 0x8000000000000000,
            x_lt_y: true,
            y_lt_x: false,
        },
    ];

    /// The limbs, least significant first, of a number in hexadecimal.
    fn limbs(hex: &str) -> Vec<u64> {
        assert_eq!(hex.len() % 16, 0);
        let count = hex.len() / 16;
        (0..count)
            .map(|i| u64::from_str_radix(&hex[16 * (count - 1 - i)..16 * (count - i)], 16).unwrap())
            .collect()
    }

    #[test]
    fn nat_operations_match_the_prototype() {
        for (i, kat) in NAT_KATS.iter().enumerate() {
            let (x, y) = (limbs(kat.x), limbs(kat.y));
            let n = x.len();

            // The products are written over a dirty buffer, with a guard limb above them.
            let mut zz = vec![0xA5A5_A5A5_A5A5_A5A5_u64; 2 * n + 1];
            mul(&x, &y, &mut zz);
            assert_eq!(zz[..2 * n], limbs(kat.mul), "mul {i}");
            assert_eq!(zz[2 * n], 0xA5A5_A5A5_A5A5_A5A5, "mul guard {i}");

            let mut zz = vec![0xA5A5_A5A5_A5A5_A5A5_u64; 2 * n + 1];
            square(&x, &mut zz);
            assert_eq!(zz[..2 * n], limbs(kat.square), "square {i}");
            assert_eq!(zz[2 * n], 0xA5A5_A5A5_A5A5_A5A5, "square guard {i}");

            let mut zz = vec![0xA5A5_A5A5_A5A5_A5A5_u64; n + 3];
            mul(&x, &y[..2], &mut zz);
            assert_eq!(zz[..n + 2], limbs(kat.mul_short), "mul_short {i}");
            assert_eq!(zz[n + 2], 0xA5A5_A5A5_A5A5_A5A5, "mul_short guard {i}");

            let mut z = y.clone();
            assert_eq!(add_to(&x, &mut z), kat.sum_carry, "sum carry {i}");
            assert_eq!(z, limbs(kat.sum), "sum {i}");

            let mut z = y.clone();
            let carry = cadd_to(Condition::<u64>::from_bool_const::<true>(), &x, &mut z);
            assert_eq!((carry, &z), (kat.sum_carry, &limbs(kat.sum)), "cadd_to true {i}");
            let mut z = y.clone();
            let carry = cadd_to(Condition::<u64>::from_bool_const::<false>(), &x, &mut z);
            assert_eq!((carry, &z), (0, &y), "cadd_to false {i}");

            let mut z = y.clone();
            assert_eq!(sub_from(&x, &mut z), kat.diff_borrow, "diff borrow {i}");
            assert_eq!(z, limbs(kat.diff), "diff {i}");

            let mut zz: Vec<u64> = x.iter().chain(&y).copied().collect();
            assert_eq!(mul_add_to(&x, &y, &mut zz), kat.acc_carry, "acc carry {i}");
            assert_eq!(zz, limbs(kat.acc), "acc {i}");

            let mut z = x.clone();
            assert_eq!(shift_down_bit(&mut z, 0), kat.down0_out, "down0 out {i}");
            assert_eq!(z, limbs(kat.down0), "down0 {i}");
            let mut z = x.clone();
            assert_eq!(shift_down_bit(&mut z, 1), kat.down1_out, "down1 out {i}");
            assert_eq!(z, limbs(kat.down1), "down1 {i}");

            assert_eq!(lt_var(&x, &y), kat.x_lt_y, "x < y {i}");
            assert_eq!(lt_var(&y, &x), kat.y_lt_x, "y < x {i}");
        }
    }

    /// splitmix64: a fixed stream of test values.
    fn next(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Operands of `n` limbs: edge patterns, then pseudo-random ones.
    fn operands(n: usize) -> Vec<Vec<u64>> {
        let mut state = 0x6E61_7400 + n as u64;
        let mut all = vec![vec![0; n], vec![u64::MAX; n]];
        for limb in 0..n {
            let mut one_limb = vec![0; n];
            one_limb[limb] = 1;
            all.push(one_limb);
            let mut top_bit = vec![u64::MAX; n];
            top_bit[limb] = 1 << 63;
            all.push(top_bit);
        }
        for _ in 0..6 {
            all.push((0..n).map(|_| next(&mut state)).collect());
        }
        all
    }

    /// Schoolbook product on 32-bit digits, in `u128` accumulators: an independent reference.
    fn reference_mul(x: &[u64], y: &[u64]) -> Vec<u64> {
        let digits = |v: &[u64]| -> Vec<u128> {
            v.iter().flat_map(|&w| [(w & 0xFFFF_FFFF) as u128, (w >> 32) as u128]).collect()
        };
        let (xd, yd) = (digits(x), digits(y));
        let mut columns = vec![0_u128; xd.len() + yd.len() + 1];
        for (i, &a) in xd.iter().enumerate() {
            for (j, &b) in yd.iter().enumerate() {
                // Split each product so that a column takes at most 2^32 * (digit count) of them.
                columns[i + j] += (a * b) & 0xFFFF_FFFF;
                columns[i + j + 1] += (a * b) >> 32;
            }
        }
        let mut carry = 0_u128;
        let mut out_digits = Vec::new();
        for column in &columns[..xd.len() + yd.len()] {
            let total = column + carry;
            out_digits.push((total & 0xFFFF_FFFF) as u64);
            carry = total >> 32;
        }
        assert_eq!(carry + columns[xd.len() + yd.len()], 0);
        out_digits.chunks(2).map(|d| d[0] | d[1] << 32).collect()
    }

    /// `x + y` with a limb of carry on top, by `u128` addition.
    fn reference_add(x: &[u64], y: &[u64]) -> Vec<u64> {
        let mut out = Vec::new();
        let mut carry = 0_u128;
        for i in 0..x.len().max(y.len()) {
            let total = carry
                + x.get(i).copied().unwrap_or(0) as u128
                + y.get(i).copied().unwrap_or(0) as u128;
            out.push(total as u64);
            carry = total >> 64;
        }
        out.push(carry as u64);
        out
    }

    #[test]
    fn mul_and_square_agree_with_schoolbook_arithmetic() {
        // One limb against u128 directly.
        for &(a, b) in
            &[(u64::MAX, u64::MAX), (0, 5), (0x1234_5678_9ABC_DEF0, 0xFEDC_BA98_7654_3211)]
        {
            let product = a as u128 * b as u128;
            let mut zz = [0_u64; 2];
            mul(&[a], &[b], &mut zz);
            assert_eq!(zz, [product as u64, (product >> 64) as u64]);
            let square_of_a = a as u128 * a as u128;
            square(&[a], &mut zz);
            assert_eq!(zz, [square_of_a as u64, (square_of_a >> 64) as u64]);
        }
        for n in 1..=5 {
            let all = operands(n);
            for x in &all {
                let mut zz = vec![0x5A5A_5A5A_5A5A_5A5A_u64; 2 * n];
                square(x, &mut zz);
                assert_eq!(zz, reference_mul(x, x), "square {x:x?}");
                for y in &all {
                    let mut zz = vec![0x5A5A_5A5A_5A5A_5A5A_u64; 2 * n];
                    mul(x, y, &mut zz);
                    assert_eq!(zz, reference_mul(x, y), "{x:x?} * {y:x?}");
                    // Operands of different lengths.
                    let short = &y[..n.div_ceil(2)];
                    let mut zz = vec![0x5A5A_5A5A_5A5A_5A5A_u64; n + short.len()];
                    mul(x, short, &mut zz);
                    assert_eq!(zz, reference_mul(x, short), "{x:x?} * {short:x?}");
                }
            }
        }
    }

    /// `zz += x * y` against the reference product and sum, with the carry out as the top limb.
    #[test]
    fn mul_add_to_agrees_with_schoolbook_arithmetic() {
        for n in 1..=4 {
            let all = operands(n);
            for (i, x) in all.iter().enumerate() {
                for y in &all {
                    let start: Vec<u64> =
                        all[(i + 1) % all.len()].iter().chain(y).copied().collect();
                    let mut zz = start.clone();
                    let carry = mul_add_to(x, y, &mut zz);
                    zz.push(carry);
                    assert_eq!(zz, reference_add(&reference_mul(x, y), &start));
                }
            }
        }
    }

    /// Addition and subtraction against `u128` arithmetic, the conditional form both ways, and
    /// the limbs above the operand left alone.
    #[test]
    fn add_and_sub_agree_with_u128_arithmetic() {
        for n in 1..=4 {
            let all = operands(n);
            for x in &all {
                for y in &all {
                    let expected = reference_add(x, y);
                    let mut z = y.clone();
                    z.push(0x77);
                    assert_eq!(add_to(x, &mut z), expected[n]);
                    assert_eq!((&z[..n], z[n]), (&expected[..n], 0x77));

                    let on = Condition::<u64>::from_bool_const::<true>();
                    let mut z = y.clone();
                    z.push(0x77);
                    assert_eq!(cadd_to(on, x, &mut z), expected[n]);
                    assert_eq!((&z[..n], z[n]), (&expected[..n], 0x77));
                    let off = Condition::<u64>::from_bool_const::<false>();
                    let mut z = y.clone();
                    assert_eq!(cadd_to(off, x, &mut z), 0);
                    assert_eq!(&z, y);

                    // (y + x) - x is y again, with a borrow exactly when the sum carried, and
                    // y - x borrows exactly when y < x.
                    let mut z = expected[..n].to_vec();
                    z.push(0x77);
                    assert_eq!(sub_from(x, &mut z), -(expected[n] as i64));
                    assert_eq!((&z[..n], z[n]), (&y[..], 0x77));
                    let mut z = y.clone();
                    assert_eq!(sub_from(x, &mut z), -(lt_var(y, x) as i64));
                    assert_eq!(add_to(x, &mut z), lt_var(y, x) as u64);
                    assert_eq!(&z, y);
                }
            }
        }
        // Two limbs against u128 directly.
        let (a, b) = (0xFFFF_FFFF_0000_0001_8000_0000_0000_0000_u128, u128::MAX - 5);
        let split = |v: u128| [v as u64, (v >> 64) as u64];
        let mut z = split(b);
        assert_eq!(add_to(&split(a), &mut z), 1);
        assert_eq!(z, split(a.wrapping_add(b)));
        let mut z = split(a);
        assert_eq!(sub_from(&split(b), &mut z), -1);
        assert_eq!(z, split(a.wrapping_sub(b)));
    }

    /// `lt_var` on ordered pairs: the answer is the highest limb that differs, whatever the
    /// limbs below it say.
    #[test]
    fn lt_var_orders_by_the_highest_differing_limb() {
        assert!(!lt_var(&[], &[]));
        assert!(!lt_var(&[5, 5, 5], &[5, 5, 5]));
        for limb in 0..3 {
            let mut larger = [5_u64; 3];
            larger[limb] = 6;
            assert!(lt_var(&[5, 5, 5], &larger), "limb {limb}");
            assert!(!lt_var(&larger, &[5, 5, 5]), "limb {limb}");
            // The limbs below the deciding one point the other way.
            for low in 0..limb {
                let mut smaller = [5_u64; 3];
                smaller[low] = 9;
                assert!(lt_var(&smaller, &larger), "limbs {low} < {limb}");
                assert!(!lt_var(&larger, &smaller), "limbs {low} < {limb}");
            }
        }
        for n in 1..=2 {
            let all = operands(n);
            for x in &all {
                for y in &all {
                    let value =
                        |v: &[u64]| v.iter().rev().fold(0_u128, |acc, &w| acc << 64 | w as u128);
                    assert_eq!(lt_var(x, y), value(x) < value(y), "{x:x?} < {y:x?}");
                }
            }
        }
    }

    /// The shift against `u128` on two limbs: the bit coming in lands at the top, the bit going
    /// out comes back at the top of the return value.
    #[test]
    fn shift_down_bit_agrees_with_u128_arithmetic() {
        let all = operands(2);
        for x in &all {
            let value = (x[1] as u128) << 64 | x[0] as u128;
            for c in [0_u64, 1] {
                let mut z = x.clone();
                let out = shift_down_bit(&mut z, c);
                let expected = value >> 1 | (c as u128) << 127;
                assert_eq!(z, [expected as u64, (expected >> 64) as u64], "{x:x?} {c}");
                assert_eq!(out, (x[0] & 1) << 63, "{x:x?} {c}");
            }
        }
        // Only the low bit of the carry in is used.
        let mut z = [0_u64, 0];
        assert_eq!(shift_down_bit(&mut z, 2), 0);
        assert_eq!(z, [0, 0]);
    }
}

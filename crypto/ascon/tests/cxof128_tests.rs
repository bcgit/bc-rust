//! Ascon-CXOF128 tests (NIST SP 800-232 §5.3).
//!
//! Embedded NIST LWC known-answer vectors (always-on; full sweep in `bc_test_data.rs`) plus
//! domain-separation, streaming/byte-at-a-time equivalence, trait-API, and misuse-guard tests.

use bouncycastle_ascon::ascon_cxof128::AsconCXof128;
use bouncycastle_ascon::ascon_xof128::AsconXof128;
use bouncycastle_core::errors::HashError;
use bouncycastle_core::traits::XOF;
use bouncycastle_hex as hex;

/// Embedded NIST LWC Ascon-CXOF128 vectors `(message, customization Z, 512-bit output)` in hex,
/// spanning empty/non-empty customization and message. (Counts 1, 2, 3, 35, 36 of
/// LWC_CXOF_KAT_128_512.txt; each output is 64 bytes.)
const CXOF_KAT: &[(&str, &str, &str)] = &[
    (
        "",
        "",
        "4F50159EF70BB3DAD8807E034EAEBD44C4FA2CBBC8CF1F05511AB66CDCC529905CA12083FC186AD899B270B1473DC5F7EC88D1052082DCDFE69FB75D269E7B74",
    ),
    (
        "",
        "10",
        "0C93A483E7D574D49FE52CCE03EE646117977D57A8AA57704AB4DAF44B501430FF6AC11A5D1FD6F2154B5C65728268270C8BB578508487B8965718ADA6272FD6",
    ),
    (
        "",
        "1011",
        "D1106C7622E79FE955BD9D79E03B918E770FE0E0CDDDE28BEB924B02C5FC936B33ACCA299C89ECA5D71886CBBFA4D54A21C55FDE2B679F5E2488063A1719DC32",
    ),
    (
        "00",
        "10",
        "63FA8BA86382F2D544580F51322D080424B42C556EB74503CD73CF052BB993BD6F5210984C71C9C445F43CCC5B158226E509BD339CD634414377F79411AA8D5C",
    ),
    (
        "00",
        "1011",
        "DF7909DD1F371E54ABBABB50DDEE195720D7EF1BB2CF2271C36A76C19908178BA3255E5A3D31D994C1D217A67AE4D13681AC1ABC4FAA2ECDD1681520BC7D7347",
    ),
];

fn dh(s: &str) -> Vec<u8> {
    let s = s.trim();
    if s.is_empty() { Vec::new() } else { hex::decode(s).expect("valid hex") }
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i as u8).wrapping_mul(7).wrapping_add(1)).collect()
}

#[test]
fn cxof128_embedded_kat() {
    for (msg_hex, z_hex, md_hex) in CXOF_KAT {
        let msg = dh(msg_hex);
        let z = dh(z_hex);
        let expected = dh(md_hex);
        let got = AsconCXof128::with_customization(&z).hash_xof(&msg, expected.len());
        assert_eq!(got, expected, "msg={msg_hex} z={z_hex}");
    }
}

#[test]
fn cxof128_domain_separation() {
    let msg = pattern(48);

    let out_z1 = AsconCXof128::with_customization(b"context-1").hash_xof(&msg, 64);
    let out_z2 = AsconCXof128::with_customization(b"context-2").hash_xof(&msg, 64);
    assert_ne!(out_z1, out_z2, "different customization strings must give different output");

    // Empty-customization CXOF128 must differ from XOF128 (different IV).
    let cxof_empty = AsconCXof128::new().hash_xof(&msg, 64);
    let xof = AsconXof128::new().hash_xof(&msg, 64);
    assert_ne!(cxof_empty, xof, "CXOF128 (empty Z) must differ from XOF128");
}

#[test]
fn cxof128_prefix_property_and_streaming() {
    let z = b"cust";
    let msg = pattern(70);
    let full = AsconCXof128::with_customization(z).hash_xof(&msg, 100);

    // Squeezing in several calls yields the same stream (prefix property).
    let mut x = AsconCXof128::with_customization(z);
    x.absorb(&msg).unwrap();
    let mut piecewise = Vec::new();
    for n in [30usize, 40, 30] {
        let mut part = vec![0u8; n];
        x.squeeze_into(&mut part);
        piecewise.extend_from_slice(&part);
    }
    assert_eq!(piecewise, full, "incremental squeeze must equal a single squeeze");

    // Absorbing in chunks equals one-shot absorb.
    for chunk in [1usize, 8, 9, 64] {
        let mut xc = AsconCXof128::with_customization(z);
        for piece in msg.chunks(chunk) {
            xc.absorb(piece).unwrap();
        }
        let mut got = vec![0u8; 100];
        xc.squeeze_into(&mut got);
        assert_eq!(got, full, "chunked absorb mismatch (chunk={chunk})");
    }
}

#[test]
fn cxof128_byte_at_a_time_matches_one_shot() {
    let msg = pattern(40); // > 8 bytes so update_byte triggers full-block absorption
    let cref = AsconCXof128::with_customization(b"zz").hash_xof(&msg, 48);
    let mut c = AsconCXof128::with_customization(b"zz");
    for &b in &msg {
        c.update_byte(b);
    }
    let mut o = [0u8; 48];
    c.squeeze_into(&mut o);
    assert_eq!(o.to_vec(), cref, "CXOF128 update_byte mismatch");
}

#[test]
fn cxof128_trait_wrappers_match_inherent() {
    let msg = pattern(50);
    let cref = AsconCXof128::with_customization(b"z").hash_xof(&msg, 40);

    let mut c = AsconCXof128::with_customization(b"z");
    c.absorb(&msg).unwrap();
    assert_eq!(c.squeeze(40), cref);

    let mut c = AsconCXof128::with_customization(b"z");
    c.absorb(&msg).unwrap();
    let mut o = [0u8; 40];
    assert_eq!(c.squeeze_out(&mut o), 40);
    assert_eq!(o.to_vec(), cref);

    let mut o = [0u8; 40];
    assert_eq!(AsconCXof128::with_customization(b"z").hash_xof_out(&msg, &mut o), 40);
    assert_eq!(o.to_vec(), cref);
}

#[test]
fn cxof128_unsupported_partial_ops_return_err() {
    let mut c = AsconCXof128::new();
    assert!(c.absorb_last_partial_byte(0, 3).is_err());
    assert!(AsconCXof128::new().squeeze_partial_byte_final(3).is_err());
    let mut b = 0u8;
    assert!(AsconCXof128::new().squeeze_partial_byte_final_out(3, &mut b).is_err());
}

#[test]
fn cxof128_absorb_after_squeeze_errors() {
    let mut x = AsconCXof128::with_customization(b"z");
    x.absorb(b"data").unwrap();
    let mut out = [0u8; 8];
    x.squeeze_into(&mut out);
    // Absorbing after squeezing has begun is reported as an error rather than a panic.
    assert!(matches!(x.absorb(b"more"), Err(HashError::InvalidState(_))));
}

#[test]
fn cxof128_suspendable_state() {
    use bouncycastle_core::errors::SuspendableError;
    use bouncycastle_core::traits::Suspendable;
    use bouncycastle_core_test_framework::suspendable_state::TestFrameworkSuspendableState;

    let z = b"customization";
    let data: Vec<u8> = (0..30u8).collect();

    // Reference: uninterrupted absorb + squeeze under the same customization string.
    let mut r = AsconCXof128::with_customization(z);
    r.update(&data);
    let mut expected = [0u8; 40];
    r.squeeze_into(&mut expected);

    // Suspend mid-absorb, resume, finish, and confirm the squeezed output matches. (The
    // customization string was already absorbed at construction and is not part of the state.)
    let mut x = AsconCXof128::with_customization(z);
    x.update(&data[..5]);
    TestFrameworkSuspendableState::new().test(&x);

    let serialized = x.clone().suspend();
    let mut resumed = AsconCXof128::from_suspended(serialized).unwrap();
    resumed.update(&data[5..]);
    let mut out = [0u8; 40];
    resumed.squeeze_into(&mut out);
    assert_eq!(out, expected, "resumed CXOF output must match uninterrupted output");

    // A corrupted state tag must be rejected.
    let mut busted = serialized;
    busted[3] ^= 0xFF;
    assert!(matches!(AsconCXof128::from_suspended(busted), Err(SuspendableError::InvalidData)));

    // Cross-type guard: an Ascon-XOF128 state (same serialized length) must be rejected by
    // Ascon-CXOF128 via the state tag.
    let mut xof = AsconXof128::new();
    xof.update(&data);
    let xof_state = xof.suspend();
    assert!(matches!(
        AsconCXof128::from_suspended(xof_state),
        Err(SuspendableError::InvalidData)
    ));
}

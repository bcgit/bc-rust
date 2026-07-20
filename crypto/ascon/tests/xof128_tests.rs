//! Ascon-XOF128 tests (NIST SP 800-232 §5.2).
//!
//! Embedded NIST LWC known-answer vectors (always-on; full sweep in `bc_test_data.rs`) plus the
//! prefix property, streaming/byte-at-a-time equivalence, trait-API, and misuse-guard tests.

use bouncycastle_ascon::ascon_xof128::AsconXof128;
use bouncycastle_core::errors::HashError;
use bouncycastle_core::traits::XOF;
use bouncycastle_hex as hex;

/// Embedded NIST LWC Ascon-XOF128 vectors `(message, 512-bit output)` in hex, spanning empty,
/// sub-block, exact-block, and multi-block messages. (Counts 1, 2, 9, 17, 33 of
/// LWC_XOF_KAT_128_512.txt; each output is 64 bytes.)
const XOF_KAT: &[(&str, &str)] = &[
    (
        "",
        "473D5E6164F58B39DFD84AACDB8AE42EC2D91FED33388EE0D960D9B3993295C6AD77855A5D3B13FE6AD9E6098988373AF7D0956D05A8F1665D2C67D1A3AD10FF",
    ),
    (
        "00",
        "51430E0438ECDF642B393630D977625F5F337656BA58AB1E960784AC32A16E0D446405551F5469384F8EA283CF12E64FA72C426BFEBAEA3AA1529E2C4AB23A2F",
    ),
    (
        "0001020304050607",
        "8D1886F5D3EC4AF8D15B44BC62B74DA6EA91BC28FB82F9C34079B5ED6E38B6C951803D7DFB3C5E512A0EF5E4060062A6FD067F9C73EF9BEE527411BDA67FC896",
    ),
    (
        "000102030405060708090A0B0C0D0E0F",
        "10BFEDC5F6442D3E1D8C324878CE1DDF73B01CAFC365589283AC4CBB98E48DE3CEDA8A41BB0983D539E4D90F6458C5C781724FAD641ED3CDB4779931097440B3",
    ),
    (
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        "2E5F3403F4171471CC7934B51982CECE8D6628435DB70E89880F3BE4E0B7B05232DFE63C44A836D771337C9C5A2688D1B71ECABE0D5C2006FEF36EF3186138AD",
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
fn xof128_embedded_kat() {
    for (msg_hex, md_hex) in XOF_KAT {
        let msg = dh(msg_hex);
        let expected = dh(md_hex);
        let got = AsconXof128::new().hash_xof(&msg, expected.len());
        assert_eq!(got, expected, "msg={msg_hex}");
    }
}

#[test]
fn xof128_prefix_property_and_streaming() {
    let msg = pattern(70);
    let full = AsconXof128::new().hash_xof(&msg, 100);

    // Squeezing in several calls yields the same stream (prefix property).
    let mut x = AsconXof128::new();
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
        let mut xc = AsconXof128::new();
        for piece in msg.chunks(chunk) {
            xc.absorb(piece).unwrap();
        }
        let mut got = vec![0u8; 100];
        xc.squeeze_into(&mut got);
        assert_eq!(got, full, "chunked absorb mismatch (chunk={chunk})");
    }
}

#[test]
fn xof128_byte_at_a_time_matches_one_shot() {
    let msg = pattern(40); // > 8 bytes so update_byte triggers full-block absorption
    let xref = AsconXof128::new().hash_xof(&msg, 48);
    let mut x = AsconXof128::new();
    for &b in &msg {
        x.update_byte(b);
    }
    let mut o = [0u8; 48];
    x.squeeze_into(&mut o);
    assert_eq!(o.to_vec(), xref, "XOF128 update_byte mismatch");
}

#[test]
fn xof128_trait_wrappers_match_inherent() {
    let msg = pattern(50);
    let xref = AsconXof128::new().hash_xof(&msg, 40);

    let mut x = AsconXof128::new();
    x.absorb(&msg).unwrap();
    assert_eq!(x.squeeze(40), xref);

    let mut x = AsconXof128::new();
    x.absorb(&msg).unwrap();
    let mut o = [0u8; 40];
    assert_eq!(x.squeeze_out(&mut o), 40);
    assert_eq!(o.to_vec(), xref);

    let mut o = [0u8; 40];
    assert_eq!(AsconXof128::new().hash_xof_out(&msg, &mut o), 40);
    assert_eq!(o.to_vec(), xref);
}

#[test]
fn xof128_unsupported_partial_ops_return_err() {
    let mut x = AsconXof128::new();
    assert!(x.absorb_last_partial_byte(0, 3).is_err());
    assert!(AsconXof128::new().squeeze_partial_byte_final(3).is_err());
    let mut b = 0u8;
    assert!(AsconXof128::new().squeeze_partial_byte_final_out(3, &mut b).is_err());
}

#[test]
fn xof128_absorb_after_squeeze_errors() {
    let mut x = AsconXof128::new();
    x.absorb(b"data").unwrap();
    let mut out = [0u8; 8];
    x.squeeze_into(&mut out);
    // Absorbing after squeezing has begun is a usage error; the trait API reports it as an error
    // rather than panicking.
    assert!(matches!(x.absorb(b"more"), Err(HashError::InvalidState(_))));
}

#[test]
fn xof128_suspendable_state() {
    use bouncycastle_ascon::ascon_cxof128::AsconCXof128;
    use bouncycastle_core::errors::SuspendableError;
    use bouncycastle_core::traits::Suspendable;
    use bouncycastle_core_test_framework::suspendable_state::TestFrameworkSuspendableState;

    let data: Vec<u8> = (0..30u8).collect();

    // Reference: uninterrupted absorb + squeeze.
    let mut r = AsconXof128::new();
    r.update(&data);
    let mut expected = [0u8; 40];
    r.squeeze_into(&mut expected);

    // Suspend mid-absorb, resume, finish, and confirm the squeezed output matches.
    let mut x = AsconXof128::new();
    x.update(&data[..5]);
    TestFrameworkSuspendableState::new().test(&x);

    let serialized = x.clone().suspend();
    let mut resumed = AsconXof128::from_suspended(serialized).unwrap();
    resumed.update(&data[5..]);
    let mut out = [0u8; 40];
    resumed.squeeze_into(&mut out);
    assert_eq!(out, expected, "resumed XOF output must match uninterrupted output");

    // A corrupted state tag must be rejected.
    let mut busted = serialized;
    busted[3] ^= 0xFF;
    assert!(matches!(AsconXof128::from_suspended(busted), Err(SuspendableError::InvalidData)));

    // Cross-type guard: an Ascon-CXOF128 state (same serialized length) must be rejected by
    // Ascon-XOF128 via the state tag.
    let mut c = AsconCXof128::with_customization(b"z");
    c.update(&data);
    let c_state = c.suspend();
    assert!(matches!(AsconXof128::from_suspended(c_state), Err(SuspendableError::InvalidData)));
}

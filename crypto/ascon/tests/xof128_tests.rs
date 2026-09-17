//! Ascon-XOF128 tests (NIST SP 800-232 §5.2).
//!
//! Embedded NIST LWC known-answer vectors (always-on; full sweep in `bc_test_data.rs`) plus the
//! prefix property, streaming/byte-at-a-time equivalence, trait-API, partial-input rejection,
//! and suspend/resume tests.

use bouncycastle_ascon::ascon_xof128::{AsconXof128, AsconXof128Squeezer};
use bouncycastle_core::errors::HashError;
use bouncycastle_core::traits::{Hash, Suspendable, XOF, XOFSqueezer};
use bouncycastle_core_test_framework::xof::TestFrameworkXOF;
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

        let got = AsconXof128::new().xof(&msg, expected.len());

        assert_eq!(got, expected, "msg={msg_hex}");

        let mut framework = TestFrameworkXOF::new();

        // This implementation intentionally supports only byte-aligned Ascon-XOF128 input.
        framework.enable_partial_byte_tests = false;

        framework.test_xof(AsconXof128::new, &msg, &expected);
    }
}

#[test]
fn xof128_prefix_property_and_streaming() {
    let msg = pattern(70);

    let full = AsconXof128::new().xof(&msg, 100);

    // Squeezing in several calls yields the same continuous stream.
    let mut x = AsconXof128::new();
    x.do_update(&msg);

    let mut squeezer = x.into_squeezer();
    let mut piecewise = Vec::new();

    for n in [30usize, 40, 30] {
        let mut part = vec![0u8; n];
        let written = squeezer.do_output_out(&mut part);

        assert_eq!(written, n);
        piecewise.extend_from_slice(&part);
    }

    assert_eq!(piecewise, full, "incremental squeeze must equal a single squeeze");

    // Absorbing in chunks equals one-shot input.
    for chunk in [1usize, 8, 9, 64] {
        let mut xc = AsconXof128::new();

        for piece in msg.chunks(chunk) {
            xc.do_update(piece);
        }

        let mut got = vec![0u8; 100];
        let written = xc.into_squeezer().do_output_out(&mut got);

        assert_eq!(written, got.len());

        assert_eq!(got, full, "chunked absorb mismatch (chunk={chunk})");
    }
}

#[test]
fn xof128_byte_at_a_time_matches_one_shot() {
    let msg = pattern(40);

    let reference = AsconXof128::new().xof(&msg, 48);

    let mut x = AsconXof128::new();

    for &b in &msg {
        x.do_update(&[b]);
    }

    let mut out = [0u8; 48];
    let written = x.into_squeezer().do_output_out(&mut out);

    assert_eq!(written, out.len());

    assert_eq!(out.to_vec(), reference, "XOF128 byte-at-a-time absorb mismatch");
}

#[test]
fn xof128_unsupported_partial_input_returns_err() {
    // num_bits == 0 is byte-aligned input and must behave like ordinary finalization.
    assert!(AsconXof128::new().into_squeezer_partial_bits(0xFF, 0).is_ok());

    assert!(AsconXof128::new().do_final_partial_bits(0x80, 0).is_ok());

    // Genuine partial-byte input is intentionally unsupported.
    assert!(matches!(
        AsconXof128::new().into_squeezer_partial_bits(0xA0, 3),
        Err(HashError::InvalidInput(_))
    ));

    assert!(matches!(
        AsconXof128::new().do_final_partial_bits(0xA0, 3),
        Err(HashError::InvalidInput(_))
    ));

    let mut out = [0u8; 32];

    assert!(matches!(
        AsconXof128::new().do_final_partial_bits_out(0xA0, 3, &mut out),
        Err(HashError::InvalidInput(_))
    ));

    // Eight bits is not a partial byte.
    assert!(matches!(
        AsconXof128::new().into_squeezer_partial_bits(0xFF, 8),
        Err(HashError::InvalidLength(_))
    ));
}

#[test]
fn xof128_absorb_then_squeeze_type_transition() {
    let mut x = AsconXof128::new();
    x.do_update(b"data");

    let mut squeezer = x.into_squeezer();

    let first = squeezer.do_output(8);
    let second = squeezer.do_output(8);

    let whole = AsconXof128::new().xof(b"data", 16);

    assert_eq!(
        [first, second].concat(),
        whole,
        "successive reads must continue the same XOF stream"
    );

    // There is deliberately no runtime "absorb after squeeze" test anymore.
    // into_squeezer() consumes AsconXof128, and the resulting squeezer does not implement
    // Hash::do_update, so that invalid state cannot be expressed.
}

#[test]
fn xof128_suspendable_state() {
    use bouncycastle_ascon::ascon_cxof128::AsconCXof128;
    use bouncycastle_core::errors::SuspendableError;
    use bouncycastle_core_test_framework::suspendable_state::TestFrameworkSuspendableState;

    let data: Vec<u8> = (0..30u8).collect();

    // Reference: uninterrupted absorb + squeeze.
    let mut reference = AsconXof128::new();
    reference.do_update(&data);

    let mut expected = [0u8; 40];
    reference.into_squeezer().do_output_out(&mut expected);

    // Suspend mid-absorb, resume, finish, and confirm the squeezed output matches.
    let mut x = AsconXof128::new();
    x.do_update(&data[..5]);

    TestFrameworkSuspendableState::new().test(&x);

    let serialized = x.clone().suspend();

    let mut resumed = AsconXof128::from_suspended(serialized).unwrap();
    resumed.do_update(&data[5..]);

    let mut out = [0u8; 40];
    resumed.into_squeezer().do_output_out(&mut out);

    assert_eq!(out, expected, "resumed XOF output must match uninterrupted output");

    // A corrupted state tag must be rejected.
    let mut busted = serialized;
    busted[3] ^= 0xFF;

    assert!(matches!(AsconXof128::from_suspended(busted), Err(SuspendableError::InvalidData)));

    // Cross-type guard: an Ascon-CXOF128 state has the same serialized length but a different
    // state tag, so Ascon-XOF128 must reject it.
    let mut c = AsconCXof128::with_customization(b"z").unwrap();
    c.do_update(&data);

    let c_state = c.suspend();

    assert!(matches!(AsconXof128::from_suspended(c_state), Err(SuspendableError::InvalidData)));

    // An inconsistent buf_pos/squeezing combination must be rejected: buf_pos == RATE (8)
    // is only valid once squeezing has begun.
    let mut bad = serialized;
    let len = bad.len();

    bad[len - 2] = 8;
    bad[len - 1] = 0;

    assert!(matches!(AsconXof128::from_suspended(bad), Err(SuspendableError::InvalidData)));

    // Suspend after squeezing has begun and confirm that restoring the squeezer continues the
    // same stream.
    let mut sq = AsconXof128::new();
    sq.do_update(&data);

    let mut sq = sq.into_squeezer();

    let mut head = [0u8; 5];
    sq.do_output_out(&mut head);

    let squeezing_state = sq.clone().suspend();

    // A squeezing state must not be accepted as the absorbing AsconXof128 type.
    assert!(matches!(
        AsconXof128::from_suspended(squeezing_state),
        Err(SuspendableError::InvalidData)
    ));

    let mut resumed_sq = AsconXof128Squeezer::from_suspended(squeezing_state).unwrap();

    let mut tail = [0u8; 35];
    resumed_sq.do_output_out(&mut tail);

    let mut combined = Vec::new();
    combined.extend_from_slice(&head);
    combined.extend_from_slice(&tail);

    assert_eq!(combined, expected, "resuming mid-squeeze must continue the same output stream");
}

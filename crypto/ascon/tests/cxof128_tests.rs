//! Ascon-CXOF128 tests (NIST SP 800-232 §5.3).
//!
//! Embedded NIST LWC known-answer vectors (always-on; full sweep in `bc_test_data.rs`) plus
//! domain-separation, streaming/byte-at-a-time equivalence, trait-API, partial-input rejection,
//! and suspend/resume tests.

use bouncycastle_ascon::ascon_cxof128::{AsconCXof128, AsconCXof128Squeezer};
use bouncycastle_ascon::ascon_xof128::AsconXof128;
use bouncycastle_core::errors::HashError;
use bouncycastle_core::traits::{Hash, Suspendable, XOF, XOFSqueezer};
use bouncycastle_core_test_framework::xof::TestFrameworkXOF;
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

        let got = AsconCXof128::with_customization(&z).unwrap().xof(&msg, expected.len());

        assert_eq!(got, expected, "msg={msg_hex} z={z_hex}");

        // AsconCXof128::default() uses an empty customization string, so the generic XOF
        // framework, which constructs a fresh value itself, only applies directly to empty-Z
        // vectors. Non-empty customization is exercised explicitly by the other tests below.
        if z.is_empty() {
            let mut framework = TestFrameworkXOF::new();

            // SP 800-232 Ascon-CXOF128 operates on byte strings in this implementation, so
            // non-byte-aligned final input is deliberately unsupported.
            framework.enable_partial_byte_tests = false;

            framework.test_xof(AsconCXof128::new, &msg, &expected);
        }
    }
}

#[test]
fn cxof128_domain_separation() {
    let msg = pattern(48);

    let out_z1 = AsconCXof128::with_customization(b"context-1").unwrap().xof(&msg, 64);

    let out_z2 = AsconCXof128::with_customization(b"context-2").unwrap().xof(&msg, 64);

    assert_ne!(out_z1, out_z2, "different customization strings must give different output");

    // Empty-customization CXOF128 must differ from XOF128 because the two functions use
    // different initialization/domain separation.
    let cxof_empty = AsconCXof128::new().xof(&msg, 64);
    let xof = AsconXof128::new().xof(&msg, 64);

    assert_ne!(cxof_empty, xof, "CXOF128 (empty Z) must differ from XOF128");
}

#[test]
fn cxof128_prefix_property_and_streaming() {
    let z = b"cust";
    let msg = pattern(70);

    let full = AsconCXof128::with_customization(z).unwrap().xof(&msg, 100);

    // Reading from one squeezer in several calls must produce exactly the same continuous
    // stream as requesting the whole output in one shot.
    let mut x = AsconCXof128::with_customization(z).unwrap();
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

    // Absorbing the message in chunks must equal absorbing it in one call.
    for chunk in [1usize, 8, 9, 64] {
        let mut xc = AsconCXof128::with_customization(z).unwrap();

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
fn cxof128_byte_at_a_time_matches_one_shot() {
    let msg = pattern(40);

    let reference = AsconCXof128::with_customization(b"zz").unwrap().xof(&msg, 48);

    let mut c = AsconCXof128::with_customization(b"zz").unwrap();

    for &b in &msg {
        c.do_update(&[b]);
    }

    let mut out = [0u8; 48];
    let written = c.into_squeezer().do_output_out(&mut out);

    assert_eq!(written, out.len());
    assert_eq!(out.to_vec(), reference, "CXOF128 byte-at-a-time absorb mismatch");
}

#[test]
fn cxof128_unsupported_partial_input_returns_err() {
    // num_bits == 0 means there is no partial byte and must behave exactly like ordinary
    // finalization / into_squeezer.
    assert!(AsconCXof128::new().into_squeezer_partial_bits(0xFF, 0).is_ok());

    assert!(AsconCXof128::new().do_final_partial_bits(0x80, 0).is_ok());

    // Real partial-byte input is deliberately unsupported by Ascon-CXOF128.
    assert!(matches!(
        AsconCXof128::new().into_squeezer_partial_bits(0xA0, 3),
        Err(HashError::InvalidInput(_))
    ));

    assert!(matches!(
        AsconCXof128::new().do_final_partial_bits(0xA0, 3),
        Err(HashError::InvalidInput(_))
    ));

    let mut out = [0u8; 32];

    assert!(matches!(
        AsconCXof128::new().do_final_partial_bits_out(0xA0, 3, &mut out),
        Err(HashError::InvalidInput(_))
    ));

    // More than seven bits is not a partial byte at all.
    assert!(matches!(
        AsconCXof128::new().into_squeezer_partial_bits(0xFF, 8),
        Err(HashError::InvalidLength(_))
    ));
}

#[test]
fn cxof128_absorb_then_squeeze_type_transition() {
    let mut x = AsconCXof128::with_customization(b"z").unwrap();
    x.do_update(b"data");

    let mut squeezer = x.into_squeezer();

    let first = squeezer.do_output(8);
    let second = squeezer.do_output(8);

    let whole = AsconCXof128::with_customization(b"z").unwrap().xof(b"data", 16);

    assert_eq!(
        [first, second].concat(),
        whole,
        "successive reads must continue the same XOF stream"
    );

    // There is deliberately no "absorb after squeeze" runtime test anymore.
    // `into_squeezer()` consumes the AsconCXof128, and the returned squeezer does not implement
    // Hash::do_update, so that invalid state is prevented by the type system.
}

#[test]
fn cxof128_suspendable_state() {
    use bouncycastle_core::errors::SuspendableError;
    use bouncycastle_core_test_framework::suspendable_state::TestFrameworkSuspendableState;

    let z = b"customization";
    let data: Vec<u8> = (0..30u8).collect();

    // Reference: uninterrupted absorb + squeeze under the same customization string.
    let mut reference = AsconCXof128::with_customization(z).unwrap();
    reference.do_update(&data);

    let mut expected = [0u8; 40];
    reference.into_squeezer().do_output_out(&mut expected);

    // Suspend in the absorbing phase, resume, finish the remaining input, and confirm that
    // the output matches the uninterrupted computation. The customization string has already
    // been folded into the sponge state at construction time.
    let mut x = AsconCXof128::with_customization(z).unwrap();
    x.do_update(&data[..5]);

    TestFrameworkSuspendableState::new().test(&x);

    let serialized = x.clone().suspend();

    let mut resumed = AsconCXof128::from_suspended(serialized).unwrap();
    resumed.do_update(&data[5..]);

    let mut out = [0u8; 40];
    resumed.into_squeezer().do_output_out(&mut out);

    assert_eq!(out, expected, "resumed CXOF output must match uninterrupted output");

    // A corrupted state tag must be rejected.
    let mut busted = serialized;
    busted[3] ^= 0xFF;

    assert!(matches!(AsconCXof128::from_suspended(busted), Err(SuspendableError::InvalidData)));

    // Cross-type guard: an Ascon-XOF128 state has the same serialized length but a different
    // state tag, so Ascon-CXOF128 must reject it.
    let mut xof = AsconXof128::new();
    xof.do_update(&data);

    let xof_state = xof.suspend();

    assert!(matches!(AsconCXof128::from_suspended(xof_state), Err(SuspendableError::InvalidData)));

    // An inconsistent buf_pos/squeezing combination must be rejected: buf_pos == RATE (8)
    // is only valid after squeezing has begun.
    let mut bad = serialized;
    let len = bad.len();

    bad[len - 2] = 8;
    bad[len - 1] = 0;

    assert!(matches!(AsconCXof128::from_suspended(bad), Err(SuspendableError::InvalidData)));

    // Suspend after squeezing has actually begun and confirm that restoring the squeezer
    // continues the same stream.
    let mut sq = AsconCXof128::with_customization(z).unwrap();
    sq.do_update(&data);

    let mut sq = sq.into_squeezer();

    let mut head = [0u8; 5];
    sq.do_output_out(&mut head);

    let squeezing_state = sq.clone().suspend();

    // A squeezing state belongs to AsconCXof128Squeezer, not the absorbing AsconCXof128 type.
    assert!(matches!(
        AsconCXof128::from_suspended(squeezing_state),
        Err(SuspendableError::InvalidData)
    ));

    let mut resumed_sq = AsconCXof128Squeezer::from_suspended(squeezing_state).unwrap();

    let mut tail = [0u8; 35];
    resumed_sq.do_output_out(&mut tail);

    let mut combined = Vec::new();
    combined.extend_from_slice(&head);
    combined.extend_from_slice(&tail);

    assert_eq!(combined, expected, "resuming mid-squeeze must continue the same output stream");
}

#[test]
fn cxof128_customization_length_bound() {
    // SP 800-232 §5.3: the customization string shall be at most 2048 bits (256 bytes).
    let ok = vec![0u8; 256];

    assert!(AsconCXof128::with_customization(&ok).is_ok());

    let too_long = vec![0u8; 257];

    assert!(matches!(AsconCXof128::with_customization(&too_long), Err(HashError::InvalidInput(_))));
}

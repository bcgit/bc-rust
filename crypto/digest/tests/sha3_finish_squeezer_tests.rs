//! `finish_squeezer` on SHAKE, cSHAKE, KMACXOF, TupleHashXOF and ParallelHashXOF: the squeezing
//! half lent out where the sponge sits must produce the stream `XOF::into_squeezer` does, however
//! it is read. The official vectors are run through it in the `sha3_*_bc-test-data.rs` files.

use bouncycastle_core::errors::HashError;
use bouncycastle_core::hazmat::finish_token;
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::symmetric_key::MacGenerationKey;
use bouncycastle_core::traits::{Hash, XOF, XOFSqueezer};
use bouncycastle_digest::sha3::kmac::{KMAC128Key, KMAC256Key, KMACXOF128, KMACXOF256};
use bouncycastle_digest::sha3::{CSHAKE128, CSHAKE256, SHAKE128, SHAKE256};

/// A message of `len` bytes with no period that divides a sponge rate.
fn message(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 + i / 251) as u8).collect()
}

fn key() -> KeyMaterial<32> {
    KeyMaterial::<32>::from_bytes_as_type(&message(32), KeyType::MACKey).unwrap()
}

/// For messages around the block boundaries and an output of more than three blocks: the
/// borrowed squeezer read in two pieces at every split, in one piece, through `do_output`, and
/// across two borrows, against `into_squeezer` read once.
fn matches_into_squeezer<X: XOF + Clone>(
    make: impl Fn() -> X,
    borrow: impl for<'a> Fn(&'a mut X) -> Box<dyn XOFSqueezer + 'a>,
) {
    let rate = make().block_bitlen() / 8;
    let total = 3 * rate + 7;
    for msg_len in [0, 1, rate - 1, rate, rate + 1, 2 * rate + 5] {
        let mut absorbed = make();
        absorbed.do_update(&message(msg_len));
        let expected = absorbed.clone().into_squeezer().do_output(total);
        assert_eq!(expected.len(), total);

        for split in 0..=total {
            let mut x = absorbed.clone();
            let mut out = vec![0xAAu8; total];
            let mut squeezer = borrow(&mut x);
            assert_eq!(squeezer.do_output_out(&mut out[..split]), split);
            assert_eq!(squeezer.do_output_out(&mut out[split..]), total - split);
            assert_eq!(out, expected, "msg_len {msg_len}, split at {split}");
        }

        for split in [0, 1, rate - 1, rate, rate + 1, 2 * rate, total] {
            // The allocating reads.
            let mut x = absorbed.clone();
            let mut squeezer = borrow(&mut x);
            let mut out = squeezer.do_output(split);
            out.extend(squeezer.do_output(total - split));
            assert_eq!(out, expected, "msg_len {msg_len}, do_output split at {split}");

            // A second borrow goes on from where the first stopped.
            let mut x = absorbed.clone();
            let mut out = borrow(&mut x).do_output(split);
            out.extend(borrow(&mut x).do_output(total - split));
            assert_eq!(out, expected, "msg_len {msg_len}, two borrows split at {split}");
        }
    }
}

#[test]
fn shake_matches_into_squeezer() {
    matches_into_squeezer(SHAKE128::new, |x| Box::new(x.finish_squeezer(&finish_token())));
    matches_into_squeezer(SHAKE256::new, |x| Box::new(x.finish_squeezer(&finish_token())));
}

/// Customized, so the domain separator is cSHAKE's "00", and uncustomized, where it is SHAKE's.
#[test]
fn cshake_matches_into_squeezer() {
    for (n, s) in [(&b"name"[..], &b"custom"[..]), (b"", b"custom"), (b"", b"")] {
        matches_into_squeezer(
            || CSHAKE128::new(n, s),
            |x| Box::new(x.finish_squeezer(&finish_token())),
        );
        matches_into_squeezer(
            || CSHAKE256::new(n, s),
            |x| Box::new(x.finish_squeezer(&finish_token())),
        );
    }
}

/// Read with `do_output`, a KMACXOF is the `right_encode(0)` stream of SP 800-185 Sec 4.3.1.
#[test]
fn kmacxof_matches_into_squeezer() {
    matches_into_squeezer(
        || KMACXOF128::new(&key(), b"custom", false).unwrap(),
        |x| Box::new(x.finish_squeezer(&finish_token())),
    );
    matches_into_squeezer(
        || KMACXOF256::new(&key(), b"", false).unwrap(),
        |x| Box::new(x.finish_squeezer(&finish_token())),
    );
}

/// A final read that is also the first binds its length: the fixed-length KMAC of Sec 4.3, which
/// is not a prefix of the stream. After a `do_output` it continues the stream.
#[test]
fn kmacxof_final_read_binds_the_length() {
    let msg = message(300);
    let token = finish_token();

    let mut x = KMACXOF128::new(&key(), b"custom", false).unwrap();
    x.do_update(&msg);
    let stream = x.clone().into_squeezer().do_output(200);

    let mut out = [0xAAu8; 48];
    assert_eq!(x.clone().finish_squeezer(&token).do_output_final_out(&mut out), 48);
    let kmac = KMAC128Key::<48>::with_params(&key(), b"custom").unwrap().mac(&msg);
    assert_eq!(out, kmac);
    assert_ne!(out[..], stream[..48]);
    assert_eq!(x.clone().finish_squeezer(&token).do_output_final(48), kmac);
    // The length is the buffer's, not a constant: another length is another function.
    assert_ne!(x.clone().finish_squeezer(&token).do_output_final(47)[..], kmac[..47]);

    // More than one block of output, on the 256-bit function.
    let mut y = KMACXOF256::new(&key(), b"", false).unwrap();
    y.do_update(&msg);
    let kmac = KMAC256Key::<200>::with_params(&key(), b"").unwrap().mac(&msg);
    assert_eq!(y.clone().finish_squeezer(&token).do_output_final(200), kmac);
    assert_eq!(y.clone().into_squeezer().do_output_final(200), kmac);

    // A read before the final one has chosen the stream, in the same borrow or an earlier one.
    let mut a = x.clone();
    let mut squeezer = a.finish_squeezer(&token);
    let mut out = squeezer.do_output(60);
    out.extend(squeezer.do_output_final(140));
    assert_eq!(out, stream);
    let mut b = x.clone();
    let mut out = b.finish_squeezer(&token).do_output(60);
    let mut rest = [0u8; 140];
    assert_eq!(b.finish_squeezer(&token).do_output_final_out(&mut rest), 140);
    out.extend(rest);
    assert_eq!(out, stream);
}

/// The partial-byte form against `into_squeezer_partial_bits`, for every bit count, and NIST's
/// SHAKE128 answer for the 4-bit message 0001 (CAVP SHAKE128ShortMsg, bit-oriented, Len = 4).
#[test]
fn partial_bits_match_into_squeezer_partial_bits() {
    let token = finish_token();
    let mut shake = SHAKE128::new();
    assert_eq!(
        shake.finish_squeezer_partial_bits(&token, 0x10, 4).unwrap().do_output(16),
        bouncycastle_core::hex::decode("d40238024b040a954d9c2c89daf480e5").unwrap(),
    );

    for num_bits in 0..=7usize {
        for msg_len in [0usize, 5, 167, 168] {
            let mut x = SHAKE128::new();
            x.do_update(&message(msg_len));
            let expected =
                x.clone().into_squeezer_partial_bits(0xA5, num_bits).unwrap().do_output(400);
            let got =
                x.finish_squeezer_partial_bits(&token, 0xA5, num_bits).unwrap().do_output(400);
            assert_eq!(got, expected, "SHAKE128, {num_bits} bits after {msg_len} bytes");

            let mut x = SHAKE256::new();
            x.do_update(&message(msg_len));
            let expected =
                x.clone().into_squeezer_partial_bits(0xA5, num_bits).unwrap().do_output(400);
            let got =
                x.finish_squeezer_partial_bits(&token, 0xA5, num_bits).unwrap().do_output(400);
            assert_eq!(got, expected, "SHAKE256, {num_bits} bits after {msg_len} bytes");

            for (n, s) in [(&b"name"[..], &b"custom"[..]), (b"", b"")] {
                let mut x = CSHAKE128::new(n, s);
                x.do_update(&message(msg_len));
                let expected =
                    x.clone().into_squeezer_partial_bits(0xA5, num_bits).unwrap().do_output(400);
                let got =
                    x.finish_squeezer_partial_bits(&token, 0xA5, num_bits).unwrap().do_output(400);
                assert_eq!(got, expected, "cSHAKE128, {num_bits} bits after {msg_len} bytes");

                let mut x = CSHAKE256::new(n, s);
                x.do_update(&message(msg_len));
                let expected =
                    x.clone().into_squeezer_partial_bits(0xA5, num_bits).unwrap().do_output(400);
                let got =
                    x.finish_squeezer_partial_bits(&token, 0xA5, num_bits).unwrap().do_output(400);
                assert_eq!(got, expected, "cSHAKE256, {num_bits} bits after {msg_len} bytes");
            }
        }
    }
}

/// A rejected call leaves the sponge as it was, in either phase.
#[test]
fn partial_bits_errors_change_nothing() {
    let token = finish_token();
    let mut reference = SHAKE256::new();
    reference.do_update(b"abc");
    let expected = reference.into_squeezer().do_output(300);

    let mut x = SHAKE256::new();
    x.do_update(b"abc");
    for bad in [8usize, 9, 64, usize::MAX] {
        assert!(matches!(
            x.finish_squeezer_partial_bits(&token, 0xFF, bad),
            Err(HashError::InvalidLength(_))
        ));
    }
    // Still absorbing: the rest of the message goes in and the output is the whole message's.
    let mut whole = SHAKE256::new();
    whole.do_update(b"abcdef");
    x.do_update(b"def");
    let mut after_def = x.clone();
    assert_eq!(
        after_def.finish_squeezer(&token).do_output(300),
        whole.into_squeezer().do_output(300)
    );

    // Once output has begun there is nowhere for message bits to go; no bits is a plain borrow.
    let mut y = SHAKE256::new();
    y.do_update(b"abc");
    let mut out = y.finish_squeezer_partial_bits(&token, 0, 0).unwrap().do_output(100);
    for bits in 1..=7usize {
        assert!(matches!(
            y.finish_squeezer_partial_bits(&token, 0xFF, bits),
            Err(HashError::InvalidState(_))
        ));
    }
    assert!(matches!(
        y.finish_squeezer_partial_bits(&token, 0xFF, 8),
        Err(HashError::InvalidLength(_))
    ));
    out.extend(y.finish_squeezer_partial_bits(&token, 0xFF, 0).unwrap().do_output(200));
    assert_eq!(out, expected);

    let mut c = CSHAKE128::new(b"name", b"custom");
    c.do_update(b"abc");
    let expected = c.clone().into_squeezer().do_output(300);
    assert!(matches!(
        c.finish_squeezer_partial_bits(&token, 0xFF, 8),
        Err(HashError::InvalidLength(_))
    ));
    let mut out = c.finish_squeezer(&token).do_output(100);
    assert!(matches!(
        c.finish_squeezer_partial_bits(&token, 0xFF, 1),
        Err(HashError::InvalidState(_))
    ));
    out.extend(c.finish_squeezer_partial_bits(&token, 0, 0).unwrap().do_output(200));
    assert_eq!(out, expected);
}

// ---- a finished sponge takes no more input and is not finished again ------------------------
//
// `finish_squeezer` leaves the value in the caller's hands. Everything below must hold in a
// release build as it does in a debug one: none of it is behind `debug_assertions`.

use bouncycastle_core::traits::Suspendable;
use std::panic::{AssertUnwindSafe, catch_unwind};

/// `f` must panic with the sponge's refusal and nothing else.
fn refused<R>(what: &str, f: impl FnOnce() -> R) {
    let payload = catch_unwind(AssertUnwindSafe(f))
        .map(|_| ())
        .expect_err(&format!("{what}: a finished sponge was used again without a panic"));
    let msg = payload
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
        .unwrap_or_default();
    assert!(msg.contains("the sponge has been finished"), "{what}: panicked with {msg:?}");
}

/// Every way the `Hash` and `XOF` traits take input or finish, on a value that has lent out its
/// squeezer, with and without a read through it: each is refused, and no output is written.
fn finished_takes_nothing<X: XOF + Clone>(
    name: &str,
    make: impl Fn() -> X,
    borrow: impl for<'a> Fn(&'a mut X) -> Box<dyn XOFSqueezer + 'a>,
) {
    let token = finish_token();
    for read_first in [false, true] {
        let mut finished = make();
        finished.do_update(b"a secret");
        if read_first {
            assert_eq!(borrow(&mut finished).do_output(16).len(), 16);
        } else {
            drop(borrow(&mut finished));
        }
        let at = |what: &str| format!("{name}, read first {read_first}: {what}");

        // Input of any length, the empty one included, then the read a caller would make.
        for n in [0usize, 1, 8, 32, 136, 200] {
            let mut x = finished.clone();
            let mut out = [0xAAu8; 32];
            refused(&at(&format!("do_update of {n}")), || {
                x.do_update(&message(n));
                borrow(&mut x).do_output_out(&mut out);
            });
            assert_eq!(out, [0xAAu8; 32], "{}", at("output after a refused update"));
        }

        // The hash finals, by value and where the value sits.
        let mut out = [0xAAu8; 64];
        refused(&at("do_final"), || finished.clone().do_final());
        refused(&at("do_final_out"), || finished.clone().do_final_out(&mut out));
        let mut x = finished.clone();
        refused(&at("finish_into"), || x.finish_into(&token, &mut out));
        refused(&at("do_final_partial_bits, no bits"), || {
            drop(finished.clone().do_final_partial_bits_out(0, 0, &mut out))
        });
        // With bits, a type that takes none answers with its error first; none gives output.
        let with_bits = catch_unwind(AssertUnwindSafe(|| {
            finished.clone().do_final_partial_bits_out(0xA0, 3, &mut out)
        }));
        assert!(!matches!(with_bits, Ok(Ok(_))), "{}", at("do_final_partial_bits, 3 bits"));
        // A final clears what lies past the digest before it does anything else (the `_out`
        // rule); the digest's own bytes are never written.
        assert_eq!(out[..32], [0xAAu8; 32], "{}", at("output after a refused final"));
        assert!(out[32..].iter().all(|&b| b == 0xAA || b == 0), "{}", at("past the digest"));
        out = [0xAAu8; 64];

        // The consuming XOF forms.
        refused(&at("into_squeezer"), || finished.clone().into_squeezer());
        refused(&at("into_squeezer_partial_bits"), || {
            drop(finished.clone().into_squeezer_partial_bits(0, 0))
        });
        refused(&at("xof"), || finished.clone().xof(b"more", 32));
        refused(&at("xof_out"), || finished.clone().xof_out(b"more", &mut out));
        refused(&at("xof_out, no data"), || finished.clone().xof_out(b"", &mut out));
        assert_eq!(out, [0xAAu8; 64], "{}", at("output after a refused xof"));

        // Lending the squeezer again is the one thing left, and goes on with the stream.
        let mut reference = make();
        reference.do_update(b"a secret");
        let expected = reference.into_squeezer().do_output(48);
        let skip = if read_first { 16 } else { 0 };
        let mut x = finished.clone();
        assert_eq!(borrow(&mut x).do_output(48 - skip), expected[skip..], "{}", at("again"));
    }
}

#[test]
fn a_finished_shake_takes_nothing() {
    finished_takes_nothing("SHAKE128", SHAKE128::new, |x| {
        Box::new(x.finish_squeezer(&finish_token()))
    });
    finished_takes_nothing("SHAKE256", SHAKE256::new, |x| {
        Box::new(x.finish_squeezer(&finish_token()))
    });
    // The partial-byte form finishes as the whole-byte one does.
    let mut x = SHAKE256::new();
    let _ = x.finish_squeezer_partial_bits(&finish_token(), 0xA0, 3).unwrap();
    refused("SHAKE256 after finish_squeezer_partial_bits", || x.do_update(b"more"));
}

#[test]
fn a_finished_cshake_takes_nothing() {
    for (n, s) in [(&b"name"[..], &b"custom"[..]), (b"", b"")] {
        finished_takes_nothing(
            "cSHAKE128",
            || CSHAKE128::new(n, s),
            |x| Box::new(x.finish_squeezer(&finish_token())),
        );
        finished_takes_nothing(
            "cSHAKE256",
            || CSHAKE256::new(n, s),
            |x| Box::new(x.finish_squeezer(&finish_token())),
        );
    }
    let mut x = CSHAKE128::new(b"name", b"custom");
    let _ = x.finish_squeezer(&finish_token());
    let mut out = [0xAAu8; 32];
    refused("cSHAKE128 hash", || x.clone().hash(b"more"));
    refused("cSHAKE128 hash_out", || x.clone().hash_out(b"more", &mut out));
    assert_eq!(out, [0xAAu8; 32]);
}

/// KMACXOF pads at its first read, not at `finish_squeezer`; it is finished from the call all
/// the same, so the "read first: false" half of the suite is the one that matters here.
#[test]
fn a_finished_kmacxof_takes_nothing() {
    finished_takes_nothing(
        "KMACXOF128",
        || KMACXOF128::new(&key(), b"custom", false).unwrap(),
        |x| Box::new(x.finish_squeezer(&finish_token())),
    );
    finished_takes_nothing(
        "KMACXOF256",
        || KMACXOF256::new(&key(), b"", false).unwrap(),
        |x| Box::new(x.finish_squeezer(&finish_token())),
    );
    let token = finish_token();
    for read_first in [false, true] {
        let mut x = KMACXOF256::new(&key(), b"", false).unwrap();
        let mut squeezer = x.finish_squeezer(&token);
        if read_first {
            squeezer.do_output(8);
        }
        let mut out = [0xAAu8; 32];
        refused("KMACXOF256 hash", || x.clone().hash(b"more"));
        refused("KMACXOF256 hash_out", || x.clone().hash_out(b"more", &mut out));
        assert_eq!(out, [0xAAu8; 32]);
    }
    // A finished KMACXOF is not suspended: unread, its sponge is still absorbing and the state
    // would resume as a KMACXOF taking input; read, no type resumes it.
    for read_first in [false, true] {
        let mut x = KMACXOF128::new(&key(), b"custom", false).unwrap();
        let mut squeezer = x.finish_squeezer(&token);
        if read_first {
            squeezer.do_output(8);
        }
        refused("KMACXOF128 suspend", || x.suspend());
    }
}

/// A SHAKE suspended after it lent out its squeezer writes a squeezing state, which the
/// squeezer type resumes at the same place in the stream; the SHAKE type refuses it.
#[test]
fn a_finished_shake_suspends_as_its_squeezer() {
    let mut shake = SHAKE128::new();
    shake.do_update(b"abc");
    let mut expected = shake.clone().into_squeezer();
    let head = expected.do_output(8);
    assert_eq!(shake.finish_squeezer(&finish_token()).do_output(8), head);
    let state = shake.suspend();
    assert!(SHAKE128::from_suspended(state).is_err());
    let mut resumed = <SHAKE128 as XOF>::Squeezer::from_suspended(state).unwrap();
    assert_eq!(resumed.do_output(64), expected.do_output(64));
}

/// A cSHAKE finished where it sits is not suspended, as KMACXOF, TupleHashXOF and
/// ParallelHashXOF are not: no type resumes the state it would write.
#[test]
fn a_finished_cshake_is_not_suspended() {
    let mut cshake = CSHAKE128::new(b"name", b"custom");
    cshake.do_update(b"abc");
    let _ = cshake.finish_squeezer(&finish_token()).do_output(8);
    refused("cSHAKE128 suspend after finish_squeezer", || cshake.suspend());

    let mut cshake = CSHAKE256::new(b"name", b"custom");
    let mut out = [0u8; 64];
    cshake.finish_into(&finish_token(), &mut out);
    refused("cSHAKE256 suspend after finish_into", || cshake.suspend());

    // Unfinished, it still suspends and resumes.
    let mut cshake = CSHAKE128::new(b"name", b"custom");
    cshake.do_update(b"abc");
    let state = cshake.clone().suspend();
    let mut resumed = CSHAKE128::from_suspended(state).unwrap();
    assert_eq!(resumed.into_squeezer().do_output(32), cshake.into_squeezer().do_output(32));
}

/// The same rule after a hash final taken where the value sits, which is how the library's own
/// code finishes a hash it holds.
#[test]
fn a_value_finished_by_finish_into_takes_nothing() {
    let token = finish_token();
    let mut out = [0u8; 64];

    let mut shake = SHAKE256::new();
    shake.do_update(b"a secret");
    shake.finish_into(&token, &mut out);
    refused("SHAKE256 after finish_into", || shake.do_update(b"more"));

    let mut cshake = CSHAKE256::new(b"", b"custom");
    cshake.finish_into(&token, &mut out);
    refused("cSHAKE256 after finish_into", || cshake.do_update(b"more"));

    let mut kmac = KMACXOF256::new(&key(), b"", false).unwrap();
    kmac.finish_into(&token, &mut out);
    refused("KMACXOF256 after finish_into", || kmac.do_update(b"more"));
}

// ---- TupleHashXOF and ParallelHashXOF ------------------------------------------------------

use bouncycastle_digest::sha3::parallelhash::{
    ParallelHash128, ParallelHash256, ParallelHashXOF128, ParallelHashXOF256,
};
use bouncycastle_digest::sha3::tuplehash::{
    TupleHash128, TupleHash256, TupleHashXOF128, TupleHashXOF256,
};
use core::num::NonZeroUsize;

fn block(n: usize) -> NonZeroUsize {
    NonZeroUsize::new(n).unwrap()
}

/// Read with `do_output`, the `right_encode(0)` streams of SP 800-185 Sec 5.3.1 and 6.3.1. Each
/// `do_update` is a tuple element for TupleHash, and fills 7- and 200-byte blocks for
/// ParallelHash, so the short last block is flushed by the borrow.
#[test]
fn tuplehashxof_and_parallelhashxof_match_into_squeezer() {
    matches_into_squeezer(
        || TupleHashXOF128::new(b"custom"),
        |x| Box::new(x.finish_squeezer(&finish_token())),
    );
    matches_into_squeezer(
        || TupleHashXOF256::new(b""),
        |x| Box::new(x.finish_squeezer(&finish_token())),
    );
    for b in [7, 200] {
        matches_into_squeezer(
            || ParallelHashXOF128::new(block(b), b"custom"),
            |x| Box::new(x.finish_squeezer(&finish_token())),
        );
        matches_into_squeezer(
            || ParallelHashXOF256::new(block(b), b""),
            |x| Box::new(x.finish_squeezer(&finish_token())),
        );
    }
}

/// A final read that is also the first binds its length: the fixed-length TupleHash of Sec 5.3
/// and ParallelHash of Sec 6.3.
#[test]
fn tuplehashxof_and_parallelhashxof_final_read_binds_the_length() {
    let token = finish_token();
    let msg = message(300);

    let mut x = TupleHashXOF128::new(b"custom");
    x.do_update(&msg[..100]);
    x.do_update(&msg[100..]);
    let mut fixed = TupleHash128::new(b"custom", 48).unwrap();
    fixed.do_update(&msg[..100]);
    fixed.do_update(&msg[100..]);
    assert_eq!(x.finish_squeezer(&token).do_output_final(48), fixed.do_final());

    let mut x = TupleHashXOF256::new(b"");
    x.do_update(&msg);
    let mut fixed = TupleHash256::new(b"", 200).unwrap();
    fixed.do_update(&msg);
    assert_eq!(x.finish_squeezer(&token).do_output_final(200), fixed.do_final());

    for b in [7, 200, 1000] {
        let mut x = ParallelHashXOF128::new(block(b), b"custom");
        x.do_update(&msg);
        let mut fixed = ParallelHash128::new(block(b), b"custom", 48).unwrap();
        fixed.do_update(&msg);
        assert_eq!(x.finish_squeezer(&token).do_output_final(48), fixed.do_final(), "{b}");

        let mut x = ParallelHashXOF256::new(block(b), b"");
        x.do_update(&msg);
        let mut fixed = ParallelHash256::new(block(b), b"", 200).unwrap();
        fixed.do_update(&msg);
        assert_eq!(x.finish_squeezer(&token).do_output_final(200), fixed.do_final(), "{b}");
    }
}

/// Finished from the call, as KMACXOF is; and a finished value is not suspended.
#[test]
fn a_finished_tuplehashxof_or_parallelhashxof_takes_nothing() {
    finished_takes_nothing(
        "TupleHashXOF128",
        || TupleHashXOF128::new(b"custom"),
        |x| Box::new(x.finish_squeezer(&finish_token())),
    );
    finished_takes_nothing(
        "TupleHashXOF256",
        || TupleHashXOF256::new(b""),
        |x| Box::new(x.finish_squeezer(&finish_token())),
    );
    finished_takes_nothing(
        "ParallelHashXOF128",
        || ParallelHashXOF128::new(block(7), b"custom"),
        |x| Box::new(x.finish_squeezer(&finish_token())),
    );
    finished_takes_nothing(
        "ParallelHashXOF256",
        || ParallelHashXOF256::new(block(200), b""),
        |x| Box::new(x.finish_squeezer(&finish_token())),
    );
    let mut t = TupleHashXOF128::new(b"");
    let _ = t.finish_squeezer(&finish_token());
    refused("TupleHashXOF128 suspend", || t.clone().suspend());
    let mut p = ParallelHashXOF128::new(block(7), b"");
    p.do_update(b"abc");
    let _ = p.finish_squeezer(&finish_token());
    refused("ParallelHashXOF128 suspend", || p.clone().suspend());
}

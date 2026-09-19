//! Regenerates `src/p256_comb_table.rs`'s `COMB_TABLE_X`/`COMB_TABLE_Y` from scratch and prints
//! them as Rust source, using only the crate's public point arithmetic (this binary, like every
//! `examples/` target, only sees the crate's public API -- `p256_comb_table` is `pub(crate)`, so
//! the actual "does the checked-in table still match" check lives in that module's own unit test,
//! which can see it; this binary is for producing the values to paste in when the construction
//! ever changes).
//!
//! ```text
//! cargo run -p bouncycastle-ec --example generate_p256_comb_table
//! ```

use bouncycastle_ec::p256::P256FieldElement;
use bouncycastle_ec::p256_point::P256JacobianPoint;

const WIDTH: usize = 6;
const BITS: usize = 256;
const TABLE_SIZE: usize = 1 << WIDTH;

// SP 800-186 (Feb 2023) §3.2.1.3, the P-256 base point G.
const G_X: [u64; 4] =
    [0xf4a13945d898c296, 0x77037d812deb33a0, 0xf8bce6e563a440f2, 0x6b17d1f2e12c4247];
const G_Y: [u64; 4] =
    [0xcbb6406837bf51f5, 0x2bce33576b315ece, 0x8ee7eb4a7c0f9e16, 0x4fe342e2fe1a7f9b];

fn print_limbs(limbs: [u64; 4]) {
    println!(
        "    [0x{:016x}, 0x{:016x}, 0x{:016x}, 0x{:016x}],",
        limbs[0], limbs[1], limbs[2], limbs[3]
    );
}

fn main() {
    let d = BITS.div_ceil(WIDTH);

    let g = P256JacobianPoint::from_affine(
        P256FieldElement::from_limbs(G_X),
        P256FieldElement::from_limbs(G_Y),
    );

    let mut pow2 = [g; WIDTH];
    for i in 1..WIDTH {
        let mut p = pow2[i - 1];
        for _ in 0..d {
            p = p.double();
        }
        pow2[i] = p;
    }

    let mut table = [P256JacobianPoint::INFINITY; TABLE_SIZE];
    for bit in (0..WIDTH).rev() {
        let step = 1usize << bit;
        let pw = pow2[bit];
        let mut i = step;
        while i < TABLE_SIZE {
            table[i] = table[i - step].add(&pw);
            i += 2 * step;
        }
    }

    println!("pub(crate) const COMB_TABLE_X: [[u64; 4]; {TABLE_SIZE}] = [");
    for point in &table {
        match point.to_affine() {
            None => print_limbs([0, 0, 0, 0]),
            Some((x, _)) => print_limbs(x.to_limbs()),
        }
    }
    println!("];");
    println!();
    println!("pub(crate) const COMB_TABLE_Y: [[u64; 4]; {TABLE_SIZE}] = [");
    for point in &table {
        match point.to_affine() {
            None => print_limbs([0, 0, 0, 0]),
            Some((_, y)) => print_limbs(y.to_limbs()),
        }
    }
    println!("];");
}

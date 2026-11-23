# The Bouncy Castle Crypto Package For Rust

[![Rust Style](https://github.com/bcgit/bc-rust/actions/workflows/rust-style.yml/badge.svg)](https://github.com/bcgit/bc-rust/actions/workflows/rust-style.yml)
[![Rust Build](https://github.com/bcgit/bc-rust/actions/workflows/rust-build.yml/badge.svg)](https://github.com/bcgit/bc-rust/actions/workflows/rust-build.yml)
[![Rust Tests](https://github.com/bcgit/bc-rust/actions/workflows/rust-test.yml/badge.svg)](https://github.com/bcgit/bc-rust/actions/workflows/rust-test.yml)
[![Rust Docs](https://github.com/bcgit/bc-rust/actions/workflows/rust-docs.yml/badge.svg)](https://github.com/bcgit/bc-rust/actions/workflows/rust-docs.yml)

> [!WARNING]
> This package is currently in ALPHA, meaning that it is not complete or production-ready and will be evolving rapidly
over the coming months.
> The set of cryptographic algorithms is still growing, and we are releasing it in order to get feedback from the
community on the API and build structure.


The Bouncy Castle Crypto package is a Rust implementation of cryptographic algorithms, it was developed by the Legion of
the Bouncy Castle, a registered Australian Charity, with a little help! The Legion, and the latest goings on with this
package, can be found at https://www.bouncycastle.org.

The aim of this package is to bring the Bouncy Castle team's experience building easy-to-use and FIPS-validated
cryptography to Rust. The build system is designed so that you can build the entire library, a single family of
algorithms, or anything in between. It also comes with a command-line interface for all the supported algorithms.

If you are interested in purchasing a support contract or accelerating the development of this package, please contact
us at [office@bouncycastle.org](mailto:office@bouncycastle.org)
or [mike@bouncycastle.org](mailto:mike@bouncycastle.org).

# Sponsors and Contributors

See [CONTRIBUTORS.md](CONTRIBUTORS.md) and [our sponsorship page](https://www.bouncycastle.org/engage/contributors/#Rust-contributors)

# Docs and Benches

During ALPHA, we're just publishing docs and benchmark results unofficially on github.

Rust crate docs are available here: https://bcgit.github.io/bc-rust/bouncycastle/

Benchmark data is available here: https://bcgit.github.io/bc-rust/benches/report/index.html

A basic script that reports lines-of-code and some basic code quality metrics is available
here: https://bcgit.github.io/bc-rust/code_stats.txt

# Portability, Performance, and Memory-Safety

This project does not attempt to be the fastest or the most constant-time. There exist excellent cryptographic libraries
that include hand-optimized assembly that will always beat Bouncy Castle Rust on performance benchmarks, as well as
having a smaller memory and code-size footprint. Many of these libraries also use formal methods to prove the
constant-time and memory-safety security properties of their code.

Bouncy Castle Rust aims to take a different approach: this is a pure-Rust implementation that strictly forbids unsafe
rust code by placing:

```rust
#![forbid(unsafe_code)]
```

at the top of every sub-crate, with one exception: `bouncycastle-utils` holds the constant-time and secure-zeroization
code that cannot be accomplished reliably within safe rust, jailed to two of its modules. We also avoid (except where
absolutely necessary) third-party dependencies which could themselves introduce unsafe code.

This gives maximum portability because our code will compile on any platform supported by the Rust compiler. It also
means that our code automatically inherits all the memory and type safety guarantees of Rust. However, it unfortunately
means that we cannot guarantee constant-time since the Rust compiler itself does not guarantee constant-time. We do a
best-effort to write constant-time code; for example our Hex and Base64 implementations are both based on the
constant-time implementation recommended in [(Sieck, 2021)](https://arxiv.org/pdf/2108.04600.pdf), and our cryptographic
primitives use bitshift-and-XOR constructions instead of loop-and-if constructions but we cannot fully guarantee that
the Rust compiler does not make optimizations that break the constant-time properties. This means that Bouncy Castle
Rust should be constant-time enough for most applications, however, if your threat model includes resisting attacks by
bad guys with soldering irons, oscilloscopes and electron microscopes, then this might not be the cryptographic library
for you and if you get in touch with us, we would be happy to recommend an alternative project that uses
formally-verified assembly more suited to your needs.

# Roadmap

This alpha release includes the following cryptographic primitives:

* Hex (constant-time)
* Base64 (constant-time)
* Hashes: SHA-2, SHA-3 and its derived functions (SHAKE, cSHAKE, KMAC, TupleHash, ParallelHash), BLAKE2, BLAKE3,
  RIPEMD, SM3, and SHA-1 for existing protocols
* MACs and KDFs: HMAC, HKDF, CMAC, GMAC, Poly1305, PBKDF2, scrypt, the SP 800-56C and X9.63 KDFs, and the SP 800-108
  KDFs
* The NIST HashDRBG random number generator
* Block ciphers (AES, ARIA, Camellia, SM4, Triple-DES) under the usual modes, including GCM, GCM-SIV, CCM, XTS and key
  wrap, plus ChaCha20-Poly1305 and Ascon
* Signatures (Ed25519, Ed448, ML-DSA, ECDSA, SM2, RSA)
* Key Establishment (X25519, X448, ML-KEM, ECDH, RSA, and HPKE over them)

But more than anything, the alpha release focuses on the design of the public trait and error type system contained in
the `bouncycastle-core` crate.

Next up will be to round out the set of cryptographic primitives, SLH-DSA being the main one still missing.

(an earlier draft of this roadmap left out RSA, ECDSA and ECDH on purpose; there has been a change of heart, and they
are implemented on the same terms as everything else: fixed-width constant-time arithmetic, no runtime-described
parameters.)

After that, we'll tackle in some kind of order (depending on public interest and funding):

* PKIX (DER, X.509, CMS, CMP)
* TLS 1.3
* C foreign function interface to link to openssl as a provider (rustle)
* JWT & CWT
* FIPS certification framework and test harnesses
* Refining the library's build system (no_std, feature granularity, build and release packaging, etc)

## Community feedback is most welcome!

As this is an alpha release, we're eagerly looking for feedback from the community. We would especially like feedback on
the following areas:

* Public API ergonomics and granularity of exposed functionality.
* Certification / compliance concerns.
* Prioritization of roadmap items above.

You can reach us at [office@bouncycastle.org](mailto:office@bouncycastle.org)
or [mike@bouncycastle.org](mailto:mike@bouncycastle.org).

## Building

This project is structured as a cargo workspace of family crates (digests, symmetric ciphers, elliptic curves and so
on), with each cryptographic algorithm a module of its family.

You can build the main library and the `bc-rust` command-line utility with:

```
cargo build -p cli
```

The utility exposes every primitive as a streaming stdin-to-stdout subcommand; `bc-rust --help`
lists them and `bc-rust <subcommand> --help` the flags. For example:

```
echo -n abc | target/debug/bc-rust sha256 -x
target/debug/bc-rust rng --len 32 > key.bin
target/debug/bc-rust aes256-gcm -d encrypt --key-file key.bin < plain > cipher
target/debug/bc-rust aes256-gcm -d decrypt --key-file key.bin < cipher
```

Values given inline (`--key`, `--iv`, ...) are hex; files are raw bytes, or hex text with the global
`--hex-input` flag. The shell tests under `cli/tests/` (`cli/tests/test_all.sh`) show every
subcommand in use.

Or you can build a single family crate by name, for example:

```
cargo build -p bouncycastle-digest
```

... or any other cargo magic that you wish :)

## Legal

This software is distributed under a license based on the MIT X Consortium license. To view the
license, [see here](https://www.bouncycastle.org/licence.html).

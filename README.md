# The Bouncy Castle Crypto Package For Rust

> [!WARNING]
> This package is currently in ALPHA, meaning that it is not complete or production-ready and will be evolving rapidly over the coming months.
> We are releasing only a small set of cryptographic algorithms in order to get feedback from the community on the API and build structure.


The Bouncy Castle Crypto package is a Rust implementation of cryptographic algorithms, it was developed by the Legion of the Bouncy Castle, a registered Australian Charity, with a little help! The Legion, and the latest goings on with this package, can be found at https://www.bouncycastle.org.

The aim of this package is to bring the Bouncy Castle team's experience building easy-to-use and FIPS-validated cryptography to Rust. The build system is designed so that you can build the entire library, a single algorithm, or anything in between. It also comes with a command-line interface for all the supported algorithms.

If you are interested in purchasing a support contract or accelerating the development of this package, please contact us at [office@bouncycastle.org](mailto:office@bouncycastle.org) or [mike@bouncycastle.org](mailto:mike@bouncycastle.org).

## Docs and Benches

During ALPHA, we're just publishing docs and benchmark results unofficially on github.

Rust crate docs are available here: https://bcgit.github.io/bc-rust/bouncycastle/

Benchmark data is available here: https://bcgit.github.io/bc-rust/benches/report/index.html

A basic script that reports lines-of-code and some basic code quality metrics is available here: https://bcgit.github.io/bc-rust/code_stats.txt

## Portability, Performance, and Memory-Safety

This project does not attempt to be the fastest or the most constant-time.
There exist excellent cryptographic libraries that include hand-optimized assembly that will always beat Bouncy Castle Rust
on performance benchmarks, as well as having a smaller memory and code-size footprint.
Many of these libraries also use formal methods to prove the constant-time and memory-safety security properties of their code.

Bouncy Castle Rust aims to take a different approach: this is a pure-Rust implementation that strictly forbids unsafe rust code by placing:

```rust
#![forbid(unsafe_code)]
```
at the top of every sub-crate.
We also avoid (except where absolutely necessary) third-party depencendencies which could themselves introduce unsafe code.

This gives maximum portability because our code will compile on any platform supported by the Rust compiler.
It also means that our code automatically inherits all the memory and type safety guarantees of Rust.
However, it unfortunately means that we cannot guarantee constant-time since the Rust compiler itself does not guarantee constant-time.
We do a best-effort to write constant-time code; for example our Hex and Base64 implementations are both based on the constant-time implementation recommended in (Sieck, 2021)](https://arxiv.org/pdf/2108.04600.pdf),
and our cryptographic primitives use bitshift-and-XOR constructions instead of loop-and-if constructions but we cannot fully
guarantee that the Rust compiler does not make optimizations that break the constant-time properties.
This means that Bouncy Castle Rust should be constant-time enough for most applications, however, if your threat model includes
resisting attacks by bad guys with soldering irons, oscilloscopes and electron microscopes, then this might not be the cryptographic library for you
and if you get in touch with us, we would be happy to recommend an alternative project that uses formally-verified assembly more suited to your needs.

## Roadmap

This alpha release includes the following cryptographic primitives:

* Hex (constant-time)
* Base64 (constant-time)
* SHA-2
* SHA-3
* HMAC
* HKDF
* The NIST HashDRBG random number generator

But more than anything, the alpha release focuses on the design of the public trait and error type system contained in the `core-interface` sub-crate.

Next up will be to round out the set of cryptographic primitives:

* Block ciphers (AES)
* Signatures (Ed25519, Ed448, ML-DSA, SLH-DSA)
* Key Establishment (X25519, X448, ML-KEM)

(yes, you have noticed that RSA, ECDSA and ECDH are not on the list. I suppose we could, but we'd really rather not.)

After that, we'll tackle in some kind of order (depending on public interest and funding):

* PKIX (DER, X.509, CMS, CMP)
* TLS 1.3
* C foreign function interface to link to openssl as a provider (rustle)
* JWT & CWT
* FIPS certification framework and test harnesses
* Refining the library's build system (no_std, feature granularity, build and release packaging, etc)

## Community feedback is most welcome!

As this is an alpha release, we're eagerly looking for feedback from the community. We would especially like feedback on the following areas:

* Public API ergonomics and granularity of exposed functionality.
* Certification / compliance concerns.
* Prioritization of roadmap items above.

You can reach us at [office@bouncycastle.org](mailto:office@bouncycastle.org) or [mike@bouncycastle.org](mailto:mike@bouncycastle.org).


## Building

This project is structured as a cargo workspace with each cryptographic algorithm segmented into a sub-crate.

You can build the main library and the `bc-rust` command-line utility with:

```
cargo build
```

Or you can build a single sub-crate by name, for example:

```
cargo build -p sha3
```

... or any other cargo magic that you wish :)

## Legal

This software is distributed under a license based on the MIT X Consortium license. To view the license, [see here](https://www.bouncycastle.org/licence.html).

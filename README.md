# The Bouncy Castle Crypto Package For Rust

> [!WARNING]
> This package is currently in ALPHA, meaning that it is not complete or production-ready and will be evolving rapidly
over the coming months.
> We are releasing only a small set of cryptographic algorithms in order to get feedback from the community on the API
and build structure.


The Bouncy Castle Crypto package is a Rust implementation of cryptographic algorithms, it was developed by the Legion of
the Bouncy Castle, a registered Australian Charity, with a little help! The Legion, and the latest goings on with this
package, can be found at https://www.bouncycastle.org.

The aim of this package is to bring the Bouncy Castle team's experience building easy-to-use and FIPS-validated
cryptography to Rust. The build system is designed so that you can build the entire library, a single algorithm, or
anything in between. It also comes with a command-line interface for all the supported algorithms.

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
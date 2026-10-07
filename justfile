# -------- BC-RUST JUSTFILE HELP --------
# tl;dr - use "just" command to run default "recipe" for validation builds and tests (equivalent to "just validate-all")
# use "just --list" to see all available recipes

# All crates must be validated individually, to ensure that dependency graphs for each crate are configured to support
# building outside of a "workspace" build in all supported feature combinations

# The logic to generate all test combos using simple lists may not be obvious.
# It relies on recursive dependencies on smaller recipes,
# which eventually call a single recipe that builds, tests, or benchmarks a single cargo package using "-p".
# This design requires the unstable lists feature to invoke recipe dependencies more than once,
# using the list variables defined below as dependency arguments.
# The docs say: "Dependencies may be invoked once per element of a list with *(recipe *argument)"
# https://github.com/casey/just/tree/master#lists

set unstable
set lists

# -------- ALL CRATES LIST --------
# every crate should go here.
# this ensures that nothing breaks for default "std" builds
all-crates := [
  "bouncycastle-base64",
  "bouncycastle-core",
  "bouncycastle-core-test-framework",
  "bouncycastle-factory",
  "bouncycastle-hex",
  "bouncycastle-hkdf",
  "bouncycastle-hmac",
  "bouncycastle-mldsa",
  "bouncycastle-mldsa-lowmemory",
  "bouncycastle-mlkem",
  "bouncycastle-mlkem-lowmemory",
  "bouncycastle-rng",
  "bouncycastle-sha2",
  "bouncycastle-sha3",
  "bouncycastle-utils",
  "cli",
  "bouncycastle",
]

# -------- NO-STD-SELF CRATES LIST --------
# crates that can build with no_std enabled in their lib.rs, but not all of their release dependencies can.
# builds can be validated by building with --no-default-features for a target tuple that does support std.
# tests are performed in an std environment.
# this list MUST be updated in PRs that add this level of no_std support for crates.
no-std-self-crates := [
  
]

# -------- NO-STD-COMPLETE CRATES LIST --------
# crates that can build with no_std enabled in their lib.rs, and their release dependencies can as well.
# builds can be validated by building with --no-default-features for a target tuple that does NOT support std
# i.e., --target thumbv7em-none-eabi
# tests must still be done in an std environment.
# this list MUST be updated in PRs that add this complete level of no_std support for crates.
no-std-complete-crates := [
  "bouncycastle-core",
]

# do a thorough validation of all crates, individually and as a workspace
[default]
validate-all: test-all-variants build-release-all-variants

# -------- TESTS SECTION --------

# test all crates, individually and as a workspace, for all levels of std support
test-all-variants: test-all-no-std-complete test-all-no-std-self test-all test-workspace

test-workspace:
  cargo test --workspace

test-all: *(test-crate *all-crates)

test-all-no-std-self: *(test-crate-no-std-self *no-std-self-crates)

test-all-no-std-complete: *(test-crate-no-std-complete *no-std-complete-crates)

test-crate crate:
  cargo test -p {{crate}}

test-crate-no-std-self crate:
  cargo test -p {{crate}} --no-default-features

test-crate-no-std-complete crate:
  cargo test -p {{crate}} --no-default-features

# -------- RELEASE BUILDS SECTION --------

# build all crates in release, individually and as a workspace, for all levels of std support
build-release-all-variants: build-release-all-no-std-complete build-release-all-no-std-self build-release-all build-release-workspace

build-release-workspace:
  cargo build --release --workspace

build-release-all: *(build-release-crate *all-crates)

build-release-all-no-std-self: *(build-release-crate-no-std-self *no-std-self-crates)

build-release-all-no-std-complete: *(build-release-crate-no-std-complete *no-std-complete-crates)

build-release-crate crate:
  cargo build --release -p {{crate}}

build-release-crate-no-std-self crate:
  cargo build --release -p {{crate}} --no-default-features

build-release-crate-no-std-complete crate:
  cargo build --release -p {{crate}} --no-default-features --target thumbv7em-none-eabi

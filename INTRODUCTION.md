The Legion of the Bouncy Castle is pleased to (finally) be releasing an alpha version of a brand new, from-scratch, Bouncy Castle cryptography library written natively in Rust.

# Why a new BC in Rust?

First, a history of the Bouncy Castle project.

The Bouncy Castle project started in 1999 with the goal of providing a high-quality open source cryptographic library. Bouncy Castle has forks in Java, and C#; both platforms that have their own native crypto providers, and yet Bouncy Castle has thrived by providing a crypto library built painstakingly against the NIST FIPS specifications which makes it easy to certify, and due to it being fully open source with a small agile and responsive maintenance team.

Why a new Bouncy Castle in Rust? We have great respect for the [Rust Crypto project](https://github.com/RustCrypto) which has collected contributions from a wide range of developers and which covers a wide range of cryptographic primitives. That said, using it feels like it is a collection of contributions from multiple contributors without central cohesive design and interfaces. We felt that the Rust ecosystem was in need of a Bouncy Castle.

# Design philosophy

## Serving both ends of the complexity spectrum

When you sit down to write a greenfield crypto library, you have to think of a spectrum of people who will use it, with a wide range of use cases and level of familiarity with cryptography. At one extreme you have developers building applications in a highly regulated space such as government or financial services where every aspect of the cryptography from internal security parameters to key lifetimes are strictly regulated. At the other extreme you have students and hobbyists who are using your library to explore cryptography and want it to be simple and just work. In the middle you have full-stack developers who are building production applications that need to be secure, but where the developer doesn't really want to learn any more cryptography than strictly necessary to get their feature working.

To this end, BC-Rust does expose, through `pub` structs and traits, the algorithm guts and parameters that NIST allows to be changed. For example, the HMAC-based Key Derivation Function (HKDF) is a complex two-step algorithm with many exposed parameters. If your application requires you to use the fully-parametrized version of HKDF, you can do so via these public APIs of BC-Rust's HKDF implementation:

```rust
impl<H: Hash + Default> HKDF<H> {
    do_extract_init(salt: &impl KeyMaterial) -> Result<usize, MACError>;
    
    do_extract_update_key(ikm: &impl KeyMaterial) -> Result<usize, MACError>;
    
    do_extract_update_bytes(ikm_chunk: &[u8]) -> Result<usize, MACError>;
    
    do_extract_final() -> Result<impl KeyMaterial, MACError>;
    
    expand_out(
            prk: &impl KeyMaterial,
            info: &[u8],
            L: usize,
            okm: &mut impl KeyMaterial,
        ) -> Result<usize, KDFError>
}
```

That is, including the choice of hash function `H`, 7 adjustable input parameters spread across 5 function calls, which is enough to make a novice cryptographer's head spin! Plenty of rope to hang yourself with. To this end, we also offer a much simplified KDF trait and KDFFactory that lets you do the whole operation in two very straightforward lines of code:

```rust
let mut kdf = KDFFactory::new("HKDF-SHA256")?;
let new_key = kdf.derive_key(&seed_key, b"additional_input")?;
```

or even one line if you need a KDF and aren't picky about which one:

```rust
let new_key = KDFFactory::default().derive_key(&seed_key, b"additional_input")?;
```


## Library features and functionality

### FIPS certification

The primary design goal is straightforward FIPS certification. To this end, the BC-Rust source code is matched as line-for-line as is practical against the sample algorithms in NIST's FIPS, SP, and IG documents; down to function structure and variable names. In some cases, this means forgoing possible performance optimizations in favor of code readability and correspondence with the spec. We're ok with that.

A few other design principles that we employ are described below.


### No unsafe code!

Yes, in many cases you can improve performance by skirting the strict type and memory safety system of Rust, including by directly embedding assembly code. But to us, this undermines the primary reason that you're developing in Rust in the first place. We're not saying that we'll _never_ include unsafe code in the future, but we have no plans to do so in the short-term, and we would only do so with great care and only after employing rigorous processes such as formal correctness verification.


### If it compiles, then it's safe

That means that, where possible, we turn runtime errors into compile-time errors. For example, you _could_ design your SHA3 object to expose the internal KECCAK object that requires some fiddly parameters such as `rate` in order to instantiate it correctly and securely, but then you either allow people to create wierd non-standard things such as SHA3-257, or you end up with a constructor that throws nitpicky runtime errors about being parametrized incorrectly. Instead, we take the approach of hiding the parameters in a system of private traits and structs that only allow construction of NIST-approved and secure instances. For example, consider how our SHA3 object is constructed internally:

```rust
impl<PARAMS: SHA3Params> SHA3<PARAMS> {
  pub fn new() -> Self;
}
```

where `SHA3Params` carries all the fiddly parameters. We've made it a private trait so you can't make one, even if you wanted to; you have to choose from the ones built-in to the library. We then hide all of this behind simplified public types:

```rust
pub type SHA3_224 = SHA3<SHA3_224Params>;
pub type SHA3_256 = SHA3<SHA3_256Params>;
pub type SHA3_384 = SHA3<SHA3_384Params>;
pub type SHA3_512 = SHA3<SHA3_512Params>;
pub type SHAKE128 = SHAKE<SHAKE128Params>;
pub type SHAKE256 = SHAKE<SHAKE256Params>;
```

so that in the end `SHA3_256::new().hash(&data)` just does what you expect. The "If it compiles, then it's safe" paradigm is, however, still somewhat aspirational and not a total _fait accompli_, and as the library matures, we will continue to find ways to refine our type system to turn ever more runtime error conditions into compile-time conditions.

### KeyMaterial wrapper

In a cryptographic application, sometimes an array of bytes is just data, like config data read from a binary file, and sometimes it's the private key to decrypt your database. Keeping those two contexts cleanly separated is not only good hygiene, but it helps avoid vulnerabilities from creeping into your code base. Trust us, it's not just junior developers who fail to think about preventing the private key from getting logged in an error trace, or who lose track of the fact that this 512 bits of seed material went through SHA-256 and is therefore only at the 128-bit security strength now.

To help reduce developer mistakes of this kind, we decided to build Bouncy Castle Rust from the beginning around a `KeyMaterial` object that is designed to prevent, or at least force the developer to think about, many of these types of key material misuses.

The core stucture is:

```rust
pub struct KeyMaterialInternal<const KEY_LEN: usize> {
    buf: [u8; KEY_LEN],
    key_len: usize,
    key_type: KeyType,
    security_strength: SecurityStrength,
    allow_hazardous_operations: bool,
}
```

along with the following matadata tracking enums:

```rust
pub enum KeyType {
    Zeroized,
    BytesLowEntropy,
    BytesFullEntropy,
    Seed,
    MACKey,
    SymmetricCipherKey,
}

pub enum SecurityStrength { None, _112bit, _128bit, _192bit, _256bit, }
```

While the `KeyMaterial` is fundamentally just a buffer of bytes, it tracks many of the things that cause problems if you fail to think about them, and it provides a number of utility functions such as a Drop that guarantees that the memory is zeroized when the object goes out of scope, a `.concatenate()` that correctly preserves the key type and security strength of the two keys being concatenated, a `.truncate()` that automatically downgrade the security strength accordingly, various guards against instantiating a full-entropy key from an all-zero buffer, and so forth.

The `KeyMaterial` object is used consistently across the library and any functions that manipulate a key material object will properly update the metadata to track any changes made to the key's entropy or security strength. For example, a `KeyMaterial512{ key_type: MACKey, security_strength: _256bit}` will have its security strength downgraded to 128 bit if you pass it through a SHA256-based KDF, indicating that it is no longer sufficient to generate a full-strength AES256 or ML-DSA-87.  

Of course, there will always be things developers need to do that the library did not provide a utility function for, for example, you may actually need an all-zero MACKey in order to implement certain standardized MAC algorithms. To the end, the library will allow you to, for example, force a key type to any full-entropy key type and security strength, or even get a direct immutable or mutable reference to the underlying buffer via `.ref_to_bytes()` and `ref_to_bytes_mut()`, but only with use of the `allow_hazardous_operations` flag:

```rust
key.allow_hazardous_operations();

// In here, you can do whatever you want to the key,
// but you are responsible for updating its metadata.

key.drop_hazardous_operations();
```

In keeping with Rust's general philosophy around unsafe code, the idea is not to prevent developers from doing what they need with their data, but rather to tag sections of source code that require more careful scrutiny from human reviewers and static analysis tools.

### Minimal external dependencies

The Rust ecosystem provides a great wealth of publicly-available crates. That said, for something as fundamental as a cryptography library, every external dependency becomes a supply-chain liability. By shipping someone else's code, you become responsible and liable for that code. That ranges from outright malicious or compromised upstream dependencies, to critical vulnerabilities that you get no advanced warning about, to maintenance headaches if you need a feature added to an upstream dependency only to discover that the maintainer has moved on and nobody is maintaining it anymore. So, while it's difficult to build a modern software project with zero external dependencies, we consider each one with great care and try to reproduce functionality internally where practical.

### Designed for lightweight devices

Most people don't put "Java" or "DotNet" in the same sentence as "embedded microcontroller". This is not entirely fair as there are some incredibly lightweight JVMs, such as [Java Card](https://www.oracle.com/java/java-card/), but generally speaking, you'd be right to think that any device too small to run linux will not have a fun time with a java-based library. BC-Rust, however, is designed to go as small as you need. First, is the code structure breaking everything into its own sub-crate. For example, if you only need SHA2, then you can build only SHA2 (plus the small number of support and utility crates such as error types and math functions). Over time we plan to further granularize this by making use of rust cargo's excellent features system. Speaking of features, most rust applications are perfectly fine to compile against the rust standard runtime library (libstd); after all it brings great convenience features such as dynamically-sized arrays (Vec), stack overflow protection, and so forth. But when you get down to devices so small that they don't offer dynamic memory allocation (heap memory), then libstd doesn't work -- so no Vec for you! BC-Rust is designed towards eventually supporting a no_std build. For example, most of the public APIs in BC-Rust are twinned into a more ergonomic version that will return the result in a newly-allocated Vec of bytes, and also a version that takes a mutable slice of memory into which to write the result, as exemplified by the Hash trait:

```rust
pub trait Hash {
    //...
    /// A static one-shot API that hashes the provided data.
    /// `data` can be of any length, including zero bytes.
    fn hash(self, data: &[u8]) -> Vec<u8>;

    /// A static one-shot API that hashes the provided data into the provided output slice.
    /// `data` can be of any length, including zero bytes.
    /// The return value is the number of bytes written.
    fn hash_out(self, data: &[u8], output: &mut [u8]) -> Result<usize, HashError>;
    //...
}
```

We're also including a few other bells-and-whistles and hygiene items such as benchmark code, unit tests constructed to satisfy the mutation test framework cargo-mutants, as well as providing a `bc-rust` executable that provides a command-line interface to (a simplified subset of) the library's cryptographic primitives.

# Roadmap

This alpha release includes the following cryptographic primitives:

* Hex (constant-time)
* Base64 (both performant and constant-time variants)
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
* JWT & CWT
* FIPS certification framework and test harnesses
* Refining the library's build system (no_std, feature granularity, build and release packaging, etc)

# Community feedback is most welcome!

As this is an alpha release, we're eagerly looking for feedback from the community. We would especially like feedback on the following areas:

* Public API ergonomics and granularity of exposed functionality.
* Certification / compliance concerns.
* Prioritization of roadmap items above.

You can reach us at <some email address>

Sincerely,
Mike Ounsworth (lead maintainer of BC-Rust), on behalf of the Legion of the Bouncy Castle and the entire Bouncy Castle community

//! Hybrid Public Key Encryption (HPKE), as specified in RFC 9180.
//!
//! This module is HPKE itself, in its four modes: a setup on the recipient's public key gives
//! the sender `enc` and an encryption context, the same setup on the private key gives the
//! recipient its context, and the contexts seal and open the messages of the exchange and
//! export secrets from it (RFC 9180 Sections 5 and 6).
//!
//! The KEM is the key's: every key with the
//! [`EncapsulatingKey`](bouncycastle_core::kem_key::EncapsulatingKey) or
//! [`DecapsulatingKey`](bouncycastle_core::kem_key::DecapsulatingKey) role over `()` whose
//! algorithm is a [`bouncycastle_dhkem::HpkeKem`] is an HPKE key: X25519's and X448's
//! (`bouncycastle_ed::x25519`, `bouncycastle_ed::x448`) and the ECC CDH keys over P-256, P-384
//! and P-521 (`bouncycastle_eccdh`), each through `bouncycastle-dhkem`'s generic DHKEM.
//!
//! The Base and PSK modes are [`HpkeSender`] and [`HpkeRecipient`]. The Auth and AuthPSK modes
//! (RFC 9180 Sections 5.1.3 and 5.1.4), in which the sender also uses a key pair of its own
//! whose public key the recipient holds, are [`HpkeAuthSender`] and [`HpkeAuthRecipient`].
//!
//! # Usage Examples
//!
//! ## Encrypting to a public key
//!
//! The suite is the KEM of the key, here DHKEM(X25519, HKDF-SHA256), and the KDF and AEAD named
//! by the parameters. The contexts seal and open in step; each message has its own nonce,
//! derived from its position.
//!
//! ```
//! use bouncycastle_aes::AES128Key;
//! use bouncycastle_cipher::modes::GCM;
//! use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait};
//! use bouncycastle_ed::x25519::keygen;
//! use bouncycastle_hybrid::hpke::{HpkeParams, HpkeRecipient, HpkeSender, NT};
//! use bouncycastle_rng::HashDRBG_SHA512;
//! use bouncycastle_sha2::SHA256;
//!
//! let mut rng = HashDRBG_SHA512::new_from_os();
//! let (pk_r, sk_r) = keygen(&mut rng).unwrap();
//! let params = HpkeParams::<SHA256, AES128Key<GCM>>::new(b"application info");
//!
//! // The sender: `enc` goes to the recipient with the ciphertexts.
//! let (enc, mut sender) = pk_r.setup_sender(&mut rng, params)?;
//! let mut ct = [0u8; 5 + NT];
//! sender.seal_out(b"aad", b"hello", &mut ct)?;
//!
//! // The recipient, with the same parameters.
//! let mut recipient = sk_r.setup_recipient(&enc, params)?;
//! let mut pt = [0u8; 5 + NT];
//! let n = recipient.open_out(b"aad", &ct, &mut pt)?;
//! assert_eq!(&pt[..n], b"hello");
//!
//! // Both sides can export secrets bound to the exchange.
//! let (mut a, mut b) = (KeyMaterial::<32>::new(), KeyMaterial::<32>::new());
//! sender.export_out(b"exporter context", &mut a);
//! recipient.export_out(b"exporter context", &mut b);
//! assert_eq!(a.ref_to_bytes(), b.ref_to_bytes());
//! # Ok::<(), bouncycastle_hybrid::hpke::HpkeError>(())
//! ```
//!
//! To authenticate the sender by its key pair, the setups are
//! `pk_r.setup_auth_sender(&mut rng, &sk_s, params)` and
//! `sk_r.setup_auth_recipient(&enc, &pk_s, params)`.
//! With a pre-shared key the parameters are `params.with_psk(Psk::new(&psk, b"psk id")?)` on
//! both sides. A single message needs no context: `pk_r.seal_out(..)` and `sk_r.open_out(..)`
//! are a setup and one message, and `send_export_out` and `receive_export_out` a setup and one
//! export, for which the AEAD can be [`ExportOnly`].
//!
//! # Memory Usage
//!
//! Nothing here allocates, and there are no lookup tables of this module's own. An
//! [`HpkeContext`] holds the AEAD's key object, a 12-byte base nonce, the sequence number
//! and the exporter secret.
//!
//! Peak stack usage in bytes for DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM, as the
//! deepest frame chain from the `mem_usage_benches` hpke harness's `measure` wrapper down, the
//! wrapper's own frame included (release build, x86-64, rustc 1.97.0-nightly). The setups
//! include the KEM operation; the figures for the DHKEM alone are in
//! `bouncycastle_ed::x25519`'s and `bouncycastle_eccdh`'s Memory Usage tables.
//!
//! | Operation              | Stack |
//! |------------------------|-------|
//! | `setup_sender`         | 4,728 |
//! | `setup_recipient`      | 3,832 |
//! | `setup_auth_sender`    | 4,760 |
//! | `setup_auth_recipient` | 3,832 |
//! | `seal_out`             | 1,280 |
//! | `open_out`             | 1,264 |
//! | `export_out`           | 1,936 |
//!
//! # 🚨 Security Considerations 🚨
//!
//! * **The Base mode does not authenticate the sender.** Anyone with the recipient's public key
//!   can send; the PSK mode shows the sender held the pre-shared key, and nothing more.
//! * **The Auth modes authenticate a key pair, and only while the recipient's key is safe.** A
//!   message that opens was sealed by a holder of the sender's private key or of the
//!   recipient's own: whoever has the recipient's private key can forge messages from any
//!   sender to it (key-compromise impersonation, RFC 9180 Sections 4.1 and 9.1.1). The sender's
//!   identity is its public key and nothing else; bind any other identifier through `info`
//!   (Section 5.1.3).
//! * **A pre-shared key must be a key, not a password** (RFC 9180 Section 9.5): HKDF does not
//!   slow a dictionary attack. [`Psk`] requires 32 bytes credited with 256 bits.
//! * **Messages open only in the order they were sealed**, and a context is for one direction
//!   (Section 9.8); a reply needs its own setup, or keys exported from this one.
//! * **The plaintext's length is not hidden** (Section 9.7.6): a ciphertext is 16 bytes longer.
//! * **There is no forward secrecy against the recipient's compromise** (Section 9.7.4): its
//!   private key opens every exchange ever made to it.
//! * **`info` and the PSK identifier are not secret** and are not sent by HPKE; both sides must
//!   already agree on them.
//! * **A context is returned by value** from its setup, a move that does not wipe where it was
//!   built; the context itself wipes its key, nonce and exporter secret when dropped.
//! * The crate's own source is `no_std`, but `bouncycastle-core`, which it depends on, is not yet.

mod scheme;

pub use scheme::*;

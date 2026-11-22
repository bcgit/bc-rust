//! `Ascon_AEAD128` is not `Clone` (issue #173): a copy would continue with the same key, nonce
//! and state. Checked at compile time: `NotClone<A>` has one impl for every type and a second
//! for every `Clone` type, so `<T as NotClone<_>>` can be inferred only for a `T` that is not
//! `Clone`. The key, which is `Clone`, is the control: for it the impl has to be named.

use bouncycastle_cipher::{Decrypting, Encrypting};
use bouncycastle_symmetric::ascon::{Ascon_AEAD128, AsconAEAD128Key};

trait NotClone<A> {
    fn witness() {}
}
impl<T: ?Sized> NotClone<()> for T {}
impl<T: ?Sized + Clone> NotClone<u8> for T {}

#[test]
fn the_workers_are_not_clone() {
    <Ascon_AEAD128<Encrypting> as NotClone<_>>::witness();
    <Ascon_AEAD128<Decrypting> as NotClone<_>>::witness();
}

#[test]
fn the_key_is_clone() {
    <AsconAEAD128Key as NotClone<u8>>::witness();
    <AsconAEAD128Key as NotClone<()>>::witness();
}

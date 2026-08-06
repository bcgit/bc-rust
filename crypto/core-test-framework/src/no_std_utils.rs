//! Useful wrappers for Vec-using utilities that may be missing from other crates in `no_std` builds

use bouncycastle_hex as hex;

/// One-shot encode from bytes to a hex-encoded string using a constant-time implementation.
pub fn hex_decode<T: AsRef<[u8]>>(input: T) -> Result<Vec<u8>, hex::HexError> {
    let inref = input.as_ref();
    let mut out: Vec<u8> = vec![0u8; inref.len() / 2];
    let bytes_written = hex::decode_out(inref, &mut out)?;
    out.truncate(bytes_written);
    Ok(out)
}
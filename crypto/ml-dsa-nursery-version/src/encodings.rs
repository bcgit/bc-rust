//! Implements FIPS 204 section 7.2 "Encodings of ML-DSA Keys and Signatures"

use bouncycastle_core_interface::errors::SignatureError;
use crate::{mldsa, mldsa::MlDsaEngine, poly_vec_k::PolyVecK, poly_vec_l::PolyVecL, MLDSAParams, MLDSAPublickey, POLY_T1PACKED_LEN};
use bouncycastle_utils::{Result, arrays};

/// Algorithm 22 from FIPS 204.
pub(crate) fn pk_encode<PARAMS: MLDSAParams>(pk: MLDSAPublickey<PARAMS>, output: &mut [u8]) -> Result<usize, SignatureError> {
    if output.len() < PARAMS::PK_LEN {
        return Err(SignatureError::InvalidLength("Output buffer too small"));
    }
    
    output[0..32].copy_from_slice(&pk.rho);
    for i in 0..PARAMS::K {
        output[i * POLY_T1PACKED_LEN..(i + 1) * POLY_T1PACKED_LEN]
            .copy_from_slice(&pk.t1[i].poly_t1_pack())
    }
    Ok(PARAMS::PK_LEN)
}

pub(crate) fn pack_public_key(t1: &PolyVecK, engine: &MlDsaEngine, output: &mut [u8]) {
    for i in 0..engine.k {
        output[i * POLY_T1PACKED_LEN..(i + 1) * POLY_T1PACKED_LEN]
            .copy_from_slice(&t1[i].poly_t1_pack())
    }
}

pub(crate) fn unpack_public_key(t1: &mut PolyVecK, engine: &MlDsaEngine, pk: &[u8]) {
    for i in 0..engine.k {
        t1.vec[i].poly_t1_unpack(
            arrays::copy_of_range( // todo -- there must be a more rustaceous way to do this
                pk,
                i * mldsa::POLY_T1PACKED_BYTES,
                mldsa::SEED_BYTES + (i + 1) * mldsa::POLY_T1PACKED_BYTES,
            )
            .as_slice(),
        );
    }
}

pub(crate) fn pack_secret_key(
    t0: &PolyVecK,
    s1: &PolyVecL,
    s2: &PolyVecK,
    engine: &MlDsaEngine,
    out_t0: &mut [u8],
    out_s1: &mut [u8],
    out_s2: &mut [u8],
) -> Result<()> {
    for i in 0..engine.l {
        s1.vec[i].poly_eta_pack(out_s1, i * engine.poly_eta_packed_bytes)?;
    }
    for i in 0..engine.k {
        s2.vec[i].poly_eta_pack(out_s2, i * engine.poly_eta_packed_bytes)?;
    }
    for i in 0..engine.k {
        t0.vec[i].poly_t0_pack(out_t0, i * mldsa::POLY_T0PACKED_BYTES);
    }
    Ok(())
}

pub(crate) fn unpack_secret_key(
    t0: &mut PolyVecK,
    s1: &mut PolyVecL,
    s2: &mut PolyVecK,
    engine: &MlDsaEngine,
    t0_enc: &[u8],
    s1_enc: &[u8],
    s2_enc: &[u8],
) {
    for i in 0..engine.l {
        s1.vec[i].poly_eta_unpack(s1_enc, i * engine.poly_eta_packed_bytes);
    }
    for i in 0..engine.k {
        s2.vec[i].poly_eta_unpack(s2_enc, i * engine.poly_eta_packed_bytes);
    }
    for i in 0..engine.k {
        t0.vec[i].poly_t0_unpack(t0_enc, i * mldsa::POLY_T0PACKED_BYTES);
    }
}

pub(crate) fn pack_signature(
    sig: &mut [u8],
    z: &PolyVecL,
    h: &PolyVecK,
    engine: &MlDsaEngine,
) -> Result<()> {
    let mut end = engine.c_tilde;

    for i in 0..engine.l {
        z.vec[i].pack_z(sig, end + i * engine.poly_z_packed_bytes)?
    }
    end += engine.l * engine.poly_z_packed_bytes;

    for i in 0..engine.omega as usize + engine.k {
        sig[end + i] = 0;
    }

    let mut k = 0;
    for i in 0..engine.k {
        for j in 0..mldsa::N {
            if h.vec[i].coeffs[j] != 0 {
                sig[end + k] = j as u8;
                k += 1;
            }
            sig[end + engine.omega as usize + i] = k as u8;
        }
    }
    Ok(())
}

pub(crate) fn unpack_signature(
    z: &mut PolyVecL,
    h: &mut PolyVecK,
    sig: &[u8],
    engine: &MlDsaEngine,
) -> Result<bool> {
    let mut end = engine.c_tilde;
    for i in 0..engine.l {
        z.vec[i].unpack_z(
            arrays::copy_of_range(
                sig,
                end + i * engine.poly_z_packed_bytes,
                end + (i + 1) * engine.poly_z_packed_bytes,
            )
            .as_slice(),
        )?;
    }
    end += engine.l * engine.poly_z_packed_bytes;

    let mut k = 0usize;
    for i in 0..engine.k {
        for x in h.vec[i].coeffs.iter_mut() {
            *x = 0;
        }

        if (sig[end + engine.omega as usize + i] as usize) < k
            || (sig[end + engine.omega as usize + i] as i32) > engine.omega
        {
            return Ok(false);
        }

        for j in k..sig[end + engine.omega as usize + i] as usize {
            if j > k && sig[end + j] <= sig[end + j - 1] {
                return Ok(false);
            }
            h.vec[i].coeffs[sig[end + j] as usize] = 1;
        }

        k = sig[end + engine.omega as usize + i] as usize;
    }
    for j in k..engine.omega as usize {
        if sig[end + j] != 0 {
            return Ok(false);
        }
    }
    Ok(true)
}

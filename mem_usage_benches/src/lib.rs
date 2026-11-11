// The bins name the shared harness through the crate, and are modules of this lib as well, so
// the crate has to be nameable from inside itself.
extern crate self as mem_usage_benches;

pub mod block_cipher_mem_usage;

mod bench_aes_mem_usage;
mod bench_aria_mem_usage;
mod bench_ascon_mem_usage;
mod bench_blake2_mem_usage;
mod bench_blake3_mem_usage;
mod bench_camellia_mem_usage;
mod bench_ccm_mem_usage;
mod bench_chacha20_mem_usage;
mod bench_chacha20_poly1305_mem_usage;
mod bench_eccdh_mem_usage;
mod bench_ecdsa_mem_usage;
mod bench_mldsa_mem_usage;
mod bench_mlkem_mem_usage;
mod bench_poly1305_mem_usage;
mod bench_sha2_mem_usage;
mod bench_sha3_mem_usage;
mod bench_sm2_mem_usage;
mod bench_sm3_mem_usage;
mod bench_sm4_mem_usage;

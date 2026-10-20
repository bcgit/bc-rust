//! Raw primitives whose safe use is the caller's responsibility.
//!
//! An item lives under a `hazmat` module when it is a correct, tested primitive whose
//! *composition* is the caller's responsibility, or that otherwise carry non-trivial
//! Security Considerations which are the caller's responsibility.
//!
//! Part of the design intention is to allow static code analyzers to easily find and flag
//! such uses with a simple search such as
//!
//! ```text
//! grep -rnE --include='*.rs' 'use .*::hazmat::'
//! ```

mod ctr_key_stream;
mod ecb;

pub use ctr_key_stream::CtrKeyStream;
pub use ecb::Ecb;

//! The feature word a back end's detector computes once and every later `detect()` reads. Every
//! back end that asks at run time holds one, so the x86_64 back end will reuse it as `arm64_le`
//! does.

use core::sync::atomic::{AtomicU32, Ordering};

/// A probed feature word, with [`INIT`] set once it has been probed.
pub(crate) struct FeatureCache(AtomicU32);

/// Set in the cached word once the probe has run, so a CPU with no features is not probed again.
const INIT: u32 = 1 << 31;

impl FeatureCache {
    /// An empty cache: the first [`get`](Self::get) probes.
    pub(crate) const fn new() -> Self {
        Self(AtomicU32::new(0))
    }

    /// The feature word, from `probe` on the first call and cached after.
    pub(crate) fn get(&self, probe: fn() -> u32) -> u32 {
        // Two first callers may both probe. Both compute the same word, since what the operating
        // system reports does not change while the process runs, and an aligned atomic store
        // cannot tear, so the cache ends up holding that word. `Relaxed` is enough because nothing
        // else is published through it.
        let cached = self.0.load(Ordering::Relaxed);
        if cached & INIT != 0 {
            return cached;
        }
        let probed = probe() | INIT;
        self.0.store(probed, Ordering::Relaxed);
        probed
    }
}

#[cfg(test)]
mod tests {
    //! A unit test because the cache is crate-private: it is the only way to pin that the probe
    //! runs once and its word is kept, a word with no features included.

    use super::*;
    use core::sync::atomic::AtomicUsize;

    static SOME_CALLS: AtomicUsize = AtomicUsize::new(0);
    static NONE_CALLS: AtomicUsize = AtomicUsize::new(0);

    fn probe_some() -> u32 {
        SOME_CALLS.fetch_add(1, Ordering::Relaxed);
        0b101
    }

    fn probe_none() -> u32 {
        NONE_CALLS.fetch_add(1, Ordering::Relaxed);
        0
    }

    #[test]
    fn the_cached_word_is_marked_and_kept() {
        let cache = FeatureCache::new();
        let first = cache.get(probe_some);
        assert_eq!(first, 0b101 | INIT);
        assert_eq!(cache.get(probe_some), first);
        assert_eq!(SOME_CALLS.load(Ordering::Relaxed), 1, "the probe runs once");

        let none = FeatureCache::new();
        assert_eq!(none.get(probe_none), INIT);
        assert_eq!(none.get(probe_none), INIT);
        assert_eq!(NONE_CALLS.load(Ordering::Relaxed), 1, "no features is cached too");
    }
}

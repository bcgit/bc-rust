//! What a comparison of two runs puts down to a public value, for the ECDSA, SM2 and symmetric
//! stack harnesses, each of which includes this file as its `public` module.

/// Whether the bytes `i..end`, in which the stack copies `before` and `after` of two runs differ,
/// are pieces of `public_before` in the first run and the same pieces of `public` in the second,
/// one after another: two public values can lie side by side, in any order, and a value returned
/// by value can be staged in chunks out of order (Ed448's signature, on x86-64 with rustc 1.100,
/// as bytes 23..39 then 0..7). Each piece is at least four bytes, which both runs match by chance
/// at a given place in the image with odds of 2^-64, but for a last piece that carries on where
/// the one before it ended in the image, and for a whole run shorter than that whose place in the
/// image carries on into the bytes beside it, the same in both runs (where the two images happen
/// to agree), to four bytes in all.
pub fn public_run(
    before: &[u8],
    after: &[u8],
    i: usize,
    end: usize,
    public_before: &[u8],
    public: &[u8],
) -> bool {
    // How many bytes from `p` match the image from `at`, in both runs.
    let matching = |p: usize, at: usize| {
        (0..(end - p).min(public.len() - at))
            .take_while(|l| {
                public_before[at + l] == before[p + l] && public[at + l] == after[p + l]
            })
            .count()
    };
    let mut p = i;
    // Where in the image the last piece ended.
    let mut piece_end: Option<usize> = None;
    while p < end {
        let (len, at) = (0..public.len()).map(|at| (matching(p, at), at)).max().unwrap_or((0, 0));
        if len >= 4 {
            p += len;
            piece_end = Some(at + len);
            continue;
        }
        let rest = end - p;
        // How many bytes beside `i..end` match the image beside `at..at + rest`, in both runs.
        let beside = |at: usize| {
            let below = (1..=i.min(at))
                .take_while(|k| {
                    public_before[at - k] == before[i - k] && public[at - k] == after[i - k]
                })
                .count();
            let above = (0..(before.len() - end).min(public.len() - at - rest))
                .take_while(|k| {
                    public_before[at + rest + k] == before[end + k]
                        && public[at + rest + k] == after[end + k]
                })
                .count();
            below + above
        };
        return match piece_end {
            None => (0..public.len().saturating_sub(rest - 1))
                .any(|at| matching(p, at) == rest && rest + beside(at) >= 4),
            Some(at) => at < public.len() && matching(p, at) == rest,
        };
    }
    true
}

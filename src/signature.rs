//! Default Signature factory (release 0.1.2alpha recovery).
//! Exposes a single opinionated default instantiation rather than every knob.

/// Factory for default signature algorithm instances.
#[derive(Debug, Default, Clone)]
pub struct SignatureFactory;

impl SignatureFactory {
    pub fn new() -> Self {
        Self
    }

    /// Name of the default signature scheme this factory builds.
    pub fn default_algorithm(&self) -> &'static str {
        "default"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_algorithm_is_stable() {
        assert_eq!(SignatureFactory::new().default_algorithm(), "default");
    }
}

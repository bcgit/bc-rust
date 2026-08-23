//! Default KEM factory (release 0.1.2alpha recovery).
//! Keeps the surface small: only the default instantiation is exposed.

/// Factory for default KEM algorithm instances.
#[derive(Debug, Default, Clone)]
pub struct KemFactory;

impl KemFactory {
    pub fn new() -> Self {
        Self
    }

    /// Name of the default KEM scheme this factory builds.
    pub fn default_algorithm(&self) -> &'static str {
        "default"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_algorithm_is_stable() {
        assert_eq!(KemFactory::new().default_algorithm(), "default");
    }
}

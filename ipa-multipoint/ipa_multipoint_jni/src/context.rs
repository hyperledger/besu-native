use ipa_multipoint::committer::DefaultCommitter;
use ipa_multipoint::crs::CRS;
use ipa_multipoint::lagrange_basis::PrecomputedWeights;


/// Context holds all of the necessary components needed for cryptographic operations
/// in the Verkle Trie. This includes:
/// - Updating the verkle trie
/// - Generating proofs
///
/// This is useful for caching purposes, since the context can be reused for multiple
/// function calls. More so because the Context is relatively expensive to create
/// compared to making a function call.
pub struct Context {
    pub crs: CRS,
    pub committer: DefaultCommitter,

    pub precomputed_weights: PrecomputedWeights,
}

impl Default for Context {
    fn default() -> Self {
        Self::new()
    }
}

impl Context {
    pub fn new() -> Self {
        let crs = CRS::default();
        let committer = DefaultCommitter::new(&crs.G);
        let precomputed_weights = PrecomputedWeights::new(256);

        Self {
            crs,
            committer,
            precomputed_weights,
        }
    }
}


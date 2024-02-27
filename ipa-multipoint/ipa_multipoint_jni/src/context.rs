use crate::traits::*;
use crate::types::*;

use banderwagon::Fr;
use ipa_multipoint::committer::{DefaultCommitter, Committer};
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

impl Committable for Context {
    fn commit(&self, values: Vec<ScalarBytes>) -> CommitmentBytes {
        let frs: Vec<Fr> = values.iter().map(|x| x.to_scalar()).collect();
        // CommitmentBytes::from(self.committer.commit_lagrange(&frs))
        self.committer.commit_lagrange(&frs).into()
    }

    fn commit_sparse(&self, values: Vec<(ScalarBytes, u8)>) -> CommitmentBytes {
        let frs: Vec<(Fr, usize)> = values.iter()
            .map(|(s, i)| (s.to_scalar(), *i as usize))
            .collect();
        CommitmentBytes::from(self.committer.commit_sparse(frs))
    }
}

impl Updatable for Context {
    fn update(&self, commitment: CommitmentBytes, value: ScalarEdit) -> CommitmentBytes {
        let old_commitment = commitment.to_element();
        let delta_commitment = self.committer.scalar_mul(value.to_scalar(), value.index as usize);
        CommitmentBytes::from(old_commitment + delta_commitment)
    }

    fn update_sparse(&self, commitment: CommitmentBytes, values: Vec<ScalarEdit>) -> CommitmentBytes {
        let old_commitment = commitment.to_element();
        let deltas: Vec<(Fr, usize)> = values.iter().map(|x| x.to_tuple()).collect();
        let delta_commitment = self.committer.commit_sparse(deltas);
        CommitmentBytes::from(old_commitment + delta_commitment)
    }
}

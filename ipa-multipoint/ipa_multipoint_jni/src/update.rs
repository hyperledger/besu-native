use std::collections::HashMap;

use ark_ff::PrimeField;
use banderwagon::{Element, Fr};
use ipa_multipoint::committer::Committer;

use crate::context::Context;
use crate::bytes::{CommitmentBytes, ScalarBytes};


pub trait CommitUpdate {
    fn commit_update(&self, commitment: CommitmentBytes, delta: ScalarBytesDelta, index: u8) -> CommitmentBytes;
    fn commit_update_sparse(&self, commitment: CommitmentBytes, deltas: HashMap<u8, ScalarBytesDelta>) -> CommitmentBytes;
}

/// Data for a commitment update
#[derive(Clone, Copy, Debug)]
pub struct ScalarBytesDelta {
    new: ScalarBytes,
    old: ScalarBytes,
}

impl ScalarBytesDelta {
    fn to_fr(&self) -> Fr {
        let old = Fr::from_le_bytes_mod_order(&self.old);
        let new = Fr::from_le_bytes_mod_order(&self.new);
        new - old
    }
}

impl CommitUpdate for Context {
    fn commit_update(&self, commitment: CommitmentBytes, delta: ScalarBytesDelta, index: u8) -> CommitmentBytes {
        let old_commitment = Element::from_bytes_unchecked_uncompressed(commitment);
        let delta_commitment = self.committer
            .scalar_mul(delta.to_fr(), index as usize);
        (old_commitment + delta_commitment).to_bytes_uncompressed()
    }

    fn commit_update_sparse(&self, commitment: CommitmentBytes, deltas: HashMap<u8, ScalarBytesDelta>) -> CommitmentBytes {

        let old_commitment = Element::from_bytes_unchecked_uncompressed(commitment);
        let delta_values: Vec<(Fr, usize)> = deltas.iter()
            .map(|(i, d)| (d.to_fr(), *i as usize))
            .collect();
        let delta_commitment = self.committer.commit_sparse(delta_values);
        (old_commitment + delta_commitment).to_bytes_uncompressed()
    }
}


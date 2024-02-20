use std::collections::HashMap;

use ark_ff::PrimeField;
use banderwagon::Fr;
use ipa_multipoint::committer::Committer;

use crate::context::Context;
use crate::bytes::{CommitmentBytes, ScalarBytes};


pub trait Commit {
    fn commit(&self, values: Vec<ScalarBytes>) -> CommitmentBytes;
    fn commit_sparse(&self, values: HashMap<u8, ScalarBytes>) -> CommitmentBytes;
}

impl Commit for Context {
    fn commit(&self, values: Vec<ScalarBytes>) -> CommitmentBytes {
        let frs: Vec<Fr> = values.iter().map(|x| Fr::from_le_bytes_mod_order(x)).collect();
        self.committer.commit_lagrange(&frs).to_bytes_uncompressed()
    }

    fn commit_sparse(&self, values: HashMap<u8, ScalarBytes>) -> CommitmentBytes {
        let frs: Vec<(Fr, usize)> = values.iter()
            .map(|(i, d)| (Fr::from_le_bytes_mod_order(d), *i as usize))
            .collect();
        self.committer.commit_sparse(frs).to_bytes_uncompressed()
    }
}

#[cfg(test)]
mod commit_test {
    use super::*;

    #[test]
    fn test_empty_commit() {
        assert_eq!(1, 1);
    }
}

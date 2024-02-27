use crate::types::*;

pub trait Committable {
    fn commit(&self, values: Vec<ScalarBytes>) -> CommitmentBytes;
    fn commit_sparse(&self, values: Vec<(ScalarBytes, u8)>) -> CommitmentBytes;
}

pub trait Updatable {
    fn update(&self, commitment: CommitmentBytes, value: ScalarEdit) -> CommitmentBytes;
    fn update_sparse(&self, commitment: CommitmentBytes, values: Vec<ScalarEdit>) -> CommitmentBytes;
}

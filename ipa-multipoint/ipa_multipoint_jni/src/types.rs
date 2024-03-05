/// A serialized uncompressed group element
#[derive(Clone, Copy, Debug)]
pub struct CommitmentBytes(pub(crate) [u8; 64]);

#[derive(Clone, Copy, Debug)]
pub struct CommitmentBytesCompressed(pub(crate) [u8; 32]);

/// A serialized scalar field element
/// It is at most 32-bytes, little-endian.
/// A value with fewer bytes is equal to its zero right padded counterpart.
// pub struct ScalarBytes(Bytes);
#[derive(Clone, Copy, Debug)]
pub struct ScalarBytes(pub(crate) [u8; 32]);

/// Data for a commitment update
#[derive(Clone, Copy, Debug)]
pub struct ScalarEdit {
    pub index: u8,
    pub old: ScalarBytes,
    pub new: ScalarBytes,
}

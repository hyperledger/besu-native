use banderwagon::{Element, CanonicalSerialize};
use crate::bytes::{CommitmentBytes, CommitmentBytesCompressed, ScalarBytes};

pub fn compress_commitment(commitment: CommitmentBytes) -> CommitmentBytesCompressed {
    let mut res = Element::from_bytes_unchecked_uncompressed(commitment).to_bytes();
    res.reverse();
    res
}

pub fn map_to_scalars(commitment: CommitmentBytes) -> ScalarBytes {
    let element = Element::from_bytes_unchecked_uncompressed(commitment);
    let fr = Element::map_to_scalar_field(&element);
    let mut bytes = [0u8; 32];
    fr.serialize_compressed(&mut bytes[..])
        .expect("Failed to serialize scalar to bytes");
    bytes
}

pub fn batch_map_to_scalars(commitments: Vec<CommitmentBytes>) -> Vec<ScalarBytes> {
    let elements: Vec<Element> = commitments.iter()
        .map(|bytes| Element::from_bytes_unchecked_uncompressed(*bytes))
        .collect();
    let scalars: Vec<ScalarBytes> = Element::batch_map_to_scalar_field(&elements)
        .iter()
        .map(|fr| {
            let mut bytes = [0u8; 32];
            fr.serialize_compressed(&mut bytes[..])
              .expect("Failed to serialize scalar to bytes");
            bytes
        })
        .collect();
    scalars
}


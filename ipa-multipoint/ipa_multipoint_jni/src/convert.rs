use crate::types::*;
use banderwagon::{CanonicalSerialize, Element, Fr, PrimeField};


impl CommitmentBytes {
    pub fn to_element(self: &Self) -> Element {
        Element::from_bytes_unchecked_uncompressed(self.0)
    }

    pub fn compress(self: &Self) -> CommitmentBytesCompressed {
        CommitmentBytesCompressed::from(self.to_element())
    }

    pub fn to_scalar(self: &Self) -> Fr {
        self.to_element().map_to_scalar_field()
    }
}

impl From<Element> for CommitmentBytes {
    fn from(element: Element) -> Self {
        Self(element.to_bytes_uncompressed())
    }
}

impl From<&[u8]> for CommitmentBytes {
    fn from(slice: &[u8]) -> Self {
        if slice.len() != 64 { panic!("CommitmentBytes not 64-bytes: {:?}", slice) }
        let mut array = [0u8; 64];
        array[..slice.len()].copy_from_slice(&slice);
        Self(array)
    }
}

impl CommitmentBytesCompressed {
    pub fn to_element(self: &Self) -> Element {
        Element::from_bytes(&self.0).expect("Deserialisation of compressed commitment failed.")
    }
}

impl From<Element> for CommitmentBytesCompressed {
    fn from(element: Element) -> Self {
        let mut res = element.to_bytes();
        res.reverse();
        Self(res)
    }
}

impl ScalarBytes {
    pub fn to_scalar(self: &Self) -> Fr {
        Fr::from_le_bytes_mod_order(&self.0)

    }
}

impl From<&Fr> for ScalarBytes {
    fn from(scalar: &Fr) -> Self {
        let mut bytes = [0u8; 32];
        scalar.serialize_compressed(&mut bytes[..]).expect("Failed to serialize scalar to bytes");
        Self(bytes)
    }
}

impl From<&[u8]> for ScalarBytes {
    fn from(slice: &[u8]) -> Self {
        if slice.len() > 32 { panic!("ScalarBytes cannot be more than 32 bytes") }
        let mut bytes = [0u8; 32];
        bytes[..slice.len()].copy_from_slice(&slice);
        Self(bytes)
    }
}

impl ScalarEdit {
    pub fn to_scalar(&self) -> Fr {
        self.new.to_scalar() - self.old.to_scalar()
    }

    pub fn to_tuple(&self) -> (Fr, usize) {
        (self.to_scalar(), self.index as usize)
    }
}

// Optimised vectorized version of to_scalar
pub fn to_scalars(commitments: &Vec<CommitmentBytes>) -> Vec<ScalarBytes> {
    let elements: Vec<Element> = commitments.iter().map(|x| x.to_element()).collect();
    Element::batch_map_to_scalar_field(&elements)
        .iter().map(|fr| ScalarBytes::from(fr)).collect()
}

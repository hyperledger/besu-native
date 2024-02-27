use crate::types::*;
use rlp::{DecoderError, Decodable, Rlp};


impl Decodable for CommitmentBytes {
    fn decode(rlp: &'_ Rlp) -> Result<Self, DecoderError> {
        rlp.decoder().decode_value(|bytes| Ok(CommitmentBytes::from(bytes)))
    }
}
impl Decodable for ScalarBytes {
    fn decode(rlp: &'_ Rlp) -> Result<Self, DecoderError> {
        rlp.decoder().decode_value(|bytes| Ok(ScalarBytes::from(bytes)))
    }
}

// RLP Decode [index, old, new]
impl Decodable for ScalarEdit {
    fn decode(rlp: &'_ Rlp) -> Result<Self, DecoderError> {
        Ok(Self {
            index: rlp.val_at(0)?,
            old: rlp.val_at::<ScalarBytes>(1)?,
            new: rlp.val_at::<ScalarBytes>(2)?,
        })
    }
}

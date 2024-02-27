use crate::types::*;
use rlp::{Encodable, RlpStream};


impl Encodable for CommitmentBytes {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.append(&self.0.to_vec());
    }
}

impl Encodable for CommitmentBytesCompressed {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.append(&self.0.to_vec());
    }
}

impl Encodable for ScalarBytes {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.append(&self.0.to_vec());
    }
}

impl Encodable for ScalarEdit {
    fn rlp_append(&self, s: &mut RlpStream) {
        let stream = s.begin_list(3);
        stream.append(&self.index).append(&self.old).append(&self.new);
    }
}

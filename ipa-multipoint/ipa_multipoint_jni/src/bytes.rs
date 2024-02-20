#[derive(Debug, Clone)]
pub enum Error {
    CommitmentLengthError { len: usize },
    CommitmentsLengthNotAligned { len: usize },
    ScalarSizeTooBig { size: u8 },
    ScalarLengthError { size: u8, len: usize },
    ScalarsLengthNotAligned { size: u8, len: usize },
}

/// A serialized uncompressed group element
pub type CommitmentBytes = [u8; 64];
pub type CommitmentBytesCompressed = [u8; 32];

/// A serialized scalar field element
pub type ScalarBytes = [u8; 32];

/// This is the identity element of the group
pub const ZERO_COMMITMENT: CommitmentBytes = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 0-15
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 15-31
    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 32-47
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 48-64
];

pub const ZERO_SCALAR: ScalarBytes = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 0-15
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 16-31
];

pub fn try_commitment_from(data: &[u8]) -> Result<CommitmentBytes, Error> {
    if data.len() != 64 {
        return Err(Error::CommitmentLengthError { len: data.len() })
    }
    Ok(data.try_into().unwrap())
}

pub fn try_commitment_vec_from(data: &[u8]) -> Result<Vec<CommitmentBytes>, Error> {
    let chunks = data.chunks_exact(64);
    if !chunks.remainder().is_empty() {
        return Err(Error::CommitmentsLengthNotAligned { len: data.len() })
    }
    let ret = chunks.map(|chunk| chunk.try_into().unwrap()).collect();
    Ok(ret)
}

pub fn try_scalar_from(size: u8, data: &[u8]) -> Result<ScalarBytes, Error> {
    if size > 32 {
        return Err(Error::ScalarSizeTooBig { size: size })
    }
    if data.len() != size.into() {
        return Err(Error::ScalarLengthError { size: size, len: data.len() })
    }
    let mut result = [0u8; 32];
    result[..size.into()].copy_from_slice(data);
    Ok(result)
}

pub fn try_scalar_vec_from(size: u8, data: &[u8]) -> Result<Vec<ScalarBytes>, Error> {
    if size > 32 {
        return Err(Error::ScalarSizeTooBig { size: size })
    }
    let chunks = data.chunks_exact(size.into());
    if !chunks.remainder().is_empty() {
        return Err(Error::ScalarsLengthNotAligned { size: size, len: data.len() })
    }
    let ret = chunks
       .map(|chunk| {
            let mut array = [0u8; 32];
            array[..size.into()].copy_from_slice(chunk);
            array
        })
       .collect();
    Ok(ret)
}

#[cfg(test)]
mod bytes_test {
    use super::*;

    #[test]
    fn test_commitment_vec_from() {
        let input: [u8; 128] = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
            32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
            48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
            32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
            48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
        ];
        let first: CommitmentBytes = input[..64].try_into().unwrap();
        let second: CommitmentBytes = input[64..].try_into().unwrap();
        let expected: Vec<CommitmentBytes> = vec![first, second];
        let observed = try_commitment_vec_from(&input).unwrap();
        assert_eq!(expected, observed);
    }

    #[test]
    fn test_idempotency_commitment_from() {
        let input: CommitmentBytes = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
            32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
            48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
        ];
        let observed: CommitmentBytes = try_commitment_from(&input).unwrap();
        assert_eq!(input, observed);
    }
}


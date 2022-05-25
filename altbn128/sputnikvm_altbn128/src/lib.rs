// Derived from SputnikVM
// https://github.com/ETCDEVTeam/sputnikvm/blob/8ce6d085a0773196a198400ca9721e19bd7ed8a0/precompiled/bn128/src/lib.rs
// SPDX-License-Identifier: Apache-2.0
use std::rc::Rc;
use std::io::Write;

#[derive(Debug, Clone)]
pub enum RuntimeError {
    /// Input was a bad format.
    BadFormat,
}

#[no_mangle]
pub extern "C" fn altbn128_add_precompiled(
    i: *const ::std::os::raw::c_char,
    i_len: u32,
    o: *mut ::std::os::raw::c_char,
    o_len: *mut u32,
) -> u32 {
    let input_i8: &[libc::c_char] = unsafe { std::slice::from_raw_parts(i, i_len as usize) };
    let input: &[u8] = unsafe { std::mem::transmute(input_i8) };

    let raw_out_i8: &mut [libc::c_char] = unsafe { std::slice::from_raw_parts_mut(o, o_len as usize) };
    let mut raw_out: &mut [u8] = unsafe { std::mem::transmute(raw_out_i8) };

    return match altbn128_add_precompiled_impl(input) {
        Ok(result) => {
            let written = raw_out.write(result.as_ref());
            if let Ok(bytes_written) = written {
                unsafe { *o_len = bytes_written as u32 };
                0u32
            } else {
                1u32
            }
        }
        Err(_error) => {
            1u32
        }
    }
}

fn altbn128_add_precompiled_impl(data: &[u8]) -> Result<Rc<Vec<u8>>, RuntimeError> {
    use bn::{AffineG1, Fq, Group, G1};

    // Padding data to be at least 32 * 4 bytes.
    let mut data: Vec<u8> = data.into();
    while data.len() < 32 * 4 {
        data.push(0);
    }

    let px =
        Fq::from_slice(&data[0..32]).map_err(|_| RuntimeError::BadFormat)?;
    let py =
        Fq::from_slice(&data[32..64]).map_err(|_| RuntimeError::BadFormat)?;
    let qx =
        Fq::from_slice(&data[64..96]).map_err(|_| RuntimeError::BadFormat)?;
    let qy = Fq::from_slice(&data[96..128])
        .map_err(|_| RuntimeError::BadFormat)?;

    let p = if px == Fq::zero() && py == Fq::zero() {
        G1::zero()
    } else {
        AffineG1::new(px, py)
            .map_err(|_| RuntimeError::BadFormat)?
            .into()
    };
    let q = if qx == Fq::zero() && qy == Fq::zero() {
        G1::zero()
    } else {
        AffineG1::new(qx, qy)
            .map_err(|_| RuntimeError::BadFormat)?
            .into()
    };

    let mut output = vec![0u8; 64];
    if let Some(ret) = AffineG1::from_jacobian(p + q) {
        ret.x().to_big_endian(&mut output[0..32]).unwrap();
        ret.y().to_big_endian(&mut output[32..64]).unwrap();
    }

    Ok(Rc::new(output))
}

#[no_mangle]
pub extern "C" fn altbn128_mul_precompiled(
    i: *const ::std::os::raw::c_char,
    i_len: u32,
    o: *mut ::std::os::raw::c_char,
    o_len: *mut u32,
) -> u32 {
    let input_i8: &[libc::c_char] = unsafe { std::slice::from_raw_parts(i, i_len as usize) };
    let input: &[u8] = unsafe { std::mem::transmute(input_i8) };

    let raw_out_i8: &mut [libc::c_char] = unsafe { std::slice::from_raw_parts_mut(o, o_len as usize) };
    let mut raw_out: &mut [u8] = unsafe { std::mem::transmute(raw_out_i8) };

    return match altbn128_mul_precompiled_impl(input) {
        Ok(result) => {
            let written = raw_out.write(result.as_ref());
            if let Ok(bytes_written) = written {
                unsafe { *o_len = bytes_written as u32 };
                0u32
            } else {
                1u32
            }
        }
        Err(_error) => {
            1u32
        }
    }
}

fn altbn128_mul_precompiled_impl(data: &[u8]) -> Result<Rc<Vec<u8>>, RuntimeError> {
    use bn::{AffineG1, Fq, Fr, Group, G1};

    // Padding data to be at least 32 * 4 bytes.
    let mut data: Vec<u8> = data.into();
    while data.len() < 32 * 3 {
        data.push(0);
    }

    let px =
        Fq::from_slice(&data[0..32]).map_err(|_| RuntimeError::BadFormat)?;
    let py =
        Fq::from_slice(&data[32..64]).map_err(|_| RuntimeError::BadFormat)?;
    let fr =
        Fr::from_slice(&data[64..96]).map_err(|_| RuntimeError::BadFormat)?;

    let p = if px == Fq::zero() && py == Fq::zero() {
        G1::zero()
    } else {
        AffineG1::new(px, py)
            .map_err(|_| RuntimeError::BadFormat)?
            .into()
    };

    let mut output = vec![0u8; 64];
    if let Some(ret) = AffineG1::from_jacobian(p * fr) {
        ret.x().to_big_endian(&mut output[0..32]).unwrap();
        ret.y().to_big_endian(&mut output[32..64]).unwrap();
    };

    Ok(Rc::new(output))
}


#[no_mangle]
pub extern "C" fn altbn128_pairing_precompiled(
    i: *const ::std::os::raw::c_char,
    i_len: u32,
    o: *mut ::std::os::raw::c_char,
    o_len: *mut u32,
) -> u32 {
    let input_i8: &[libc::c_char] = unsafe { std::slice::from_raw_parts(i, i_len as usize) };
    let input: &[u8] = unsafe { std::mem::transmute(input_i8) };

    let raw_out_i8: &mut [libc::c_char] = unsafe { std::slice::from_raw_parts_mut(o, o_len as usize) };
    let mut raw_out: &mut [u8] = unsafe { std::mem::transmute(raw_out_i8) };

    return match altbn128_pairing_precompiled_impl(input) {
        Ok(result) => {
            let written = raw_out.write(result.as_ref());
            if let Ok(bytes_written) = written {
                unsafe { *o_len = bytes_written as u32 };
                0u32
            } else {
                1u32
            }
        }
        Err(_error) => {
            1u32
        }
    }
}

fn altbn128_pairing_precompiled_impl(data: &[u8]) -> Result<Rc<Vec<u8>>, RuntimeError> {
    use bn::{pairing, AffineG1, AffineG2, Fq, Fq2, Group, Gt, G1, G2};

    fn read_one(s: &[u8]) -> Result<(G1, G2), RuntimeError> {
        let ax =
            Fq::from_slice(&s[0..32]).map_err(|_| RuntimeError::BadFormat)?;
        let ay = Fq::from_slice(&s[32..64])
            .map_err(|_| RuntimeError::BadFormat)?;
        let bay = Fq::from_slice(&s[64..96])
            .map_err(|_| RuntimeError::BadFormat)?;
        let bax = Fq::from_slice(&s[96..128])
            .map_err(|_| RuntimeError::BadFormat)?;
        let bby = Fq::from_slice(&s[128..160])
            .map_err(|_| RuntimeError::BadFormat)?;
        let bbx = Fq::from_slice(&s[160..192])
            .map_err(|_| RuntimeError::BadFormat)?;

        let ba = Fq2::new(bax, bay);
        let bb = Fq2::new(bbx, bby);

        let b = if ba.is_zero() && bb.is_zero() {
            G2::zero()
        } else {
            AffineG2::new(ba, bb)
                .map_err(|_| RuntimeError::BadFormat)?
                .into()
        };
        let a = if ax.is_zero() && ay.is_zero() {
            G1::zero()
        } else {
            AffineG1::new(ax, ay)
                .map_err(|_| RuntimeError::BadFormat)?
                .into()
        };

        Ok((a, b))
    }

    if data.len() % 192 != 0 {
        return Err(RuntimeError::BadFormat);
    }

    let ele_len = data.len() / 192;

    let mut acc = Gt::one();
    for i in 0..ele_len {
        let (a, b) = read_one(&data[i * 192..i * 192 + 192])?;
        acc = acc * pairing(a, b);
    }

    let mut output = vec![0u8; 32];
    if acc == Gt::one() {
        output[31] = 1u8;
    }

    Ok(Rc::new(output))
}

// Copyright contributors to Hyperledger Besu
// SPDX-License-Identifier: Apache-2.0

mod arith;
mod mpnat;

use std::rc::Rc;
use std::io::Write;

use core::{
    cmp::{min, Ordering},
    mem::size_of,
};

#[derive(Debug, Clone)]
pub enum RuntimeError {
    /// Input was a bad format.
    BadFormat,
}


#[no_mangle]
pub extern "C" fn modexp_precompiled(
    i: *const std::os::raw::c_char,
    i_len: u32,
    o: *mut std::os::raw::c_char,
    o_len: *mut u32,
) -> u32 {
    let input_i8: &[libc::c_char] = unsafe { std::slice::from_raw_parts(i, i_len as usize) };
    let input: &[u8] = unsafe { std::mem::transmute(input_i8) };

    let raw_out_i8: &mut [libc::c_char] = unsafe { std::slice::from_raw_parts_mut(o, o_len as usize) };
    let mut raw_out: &mut [u8] = unsafe { std::mem::transmute(raw_out_i8) };
    let answer = modexp_precompiled_impl(input);

    let written = raw_out.write(answer.as_slice());
    if let Ok(bytes_written) = written {
        unsafe { *o_len = bytes_written as u32 };
        0u32
    } else {
        1u32
    }
}


/// from revm - https://github.com/bluealloy/revm/blob/main/crates/revm_precompiles/src/modexp.rs
macro_rules! read_u64_with_overflow {
    ($input:expr,$from:expr,$to:expr, $overflow_limit:expr) => {{
        const SPLIT: usize = 32 - size_of::<u64>();
        let len = $input.len();
        let from_zero = min($from, len);
        let from = min(from_zero + SPLIT, len);
        let to = min($to, len);
        let overflow_bytes = &$input[from_zero..from];

        let mut len_bytes = [0u8; size_of::<u64>()];
        len_bytes[..to - from].copy_from_slice(&$input[from..to]);
        let out = u64::from_be_bytes(len_bytes) as usize;
        let overflow = !(out < $overflow_limit && overflow_bytes.iter().all(|&x| x == 0));
        (out, overflow)
    }};
}

/// from revm - https://github.com/bluealloy/revm/blob/main/crates/revm_precompiles/src/modexp.rs
fn modexp_precompiled_impl(input: &[u8]) -> Rc<Vec<u8>> {
    let len = input.len();
    let (base_len, base_overflow) = read_u64_with_overflow!(input, 0, 32, u32::MAX as usize);
    let (exp_len, exp_overflow) = read_u64_with_overflow!(input, 32, 64, u32::MAX as usize);
    let (mod_len, mod_overflow) = read_u64_with_overflow!(input, 64, 96, u32::MAX as usize);

    if base_overflow || mod_overflow {
        return Rc::new(Vec::new());
    }

    if base_len == 0 && mod_len == 0 {
        return Rc::new(Vec::new());
    }
    // set limit for exp overflow
    if exp_overflow {
        return Rc::new(Vec::new());
    }
    let base_start = 96;
    let base_end = base_start + base_len;
    let exp_end = base_end + exp_len;
    let mod_end = exp_end + mod_len;

    let read_big = |from: usize, to: usize| {
        let mut out = vec![0; to - from];
        let from = min(from, len);
        let to = min(to, len);
        out[..to - from].copy_from_slice(&input[from..to]);
        out
    };

    let base = read_big(base_start, base_end);
    let exponent = read_big(base_end, exp_end);
    let modulus = read_big(exp_end, mod_end);
    let bytes = modexp(base.as_slice(), exponent.as_slice(), modulus.as_slice());

    // write output to given memory, left padded and same length as the modulus.
    // always true except in the case of zero-length modulus, which leads to
    // output of length and value 1.
    match bytes.len().cmp(&mod_len) {
        Ordering::Equal => Rc::new(bytes.to_vec()),
        Ordering::Less => {
            let mut ret = Vec::with_capacity(mod_len);
            ret.extend(core::iter::repeat(0).take(mod_len - bytes.len()));
            ret.extend_from_slice(&bytes[..]);
            Rc::new(ret.to_vec())
        }
        Ordering::Greater => Rc::new(Vec::new()),
    }
}

// from aurora
/// Computes `(base ^ exp) % modulus`, where all values are given as big-endian
/// encoded bytes.
pub fn modexp(base: &[u8], exp: &[u8], modulus: &[u8]) -> Vec<u8> {
    let mut x = mpnat::MPNat::from_big_endian(base);
    let m = mpnat::MPNat::from_big_endian(modulus);
    if m.digits.len() == 1 && m.digits[0] == 0 {
        return Vec::new();
    }
    let result = x.modpow(exp, &m);
    result.to_big_endian()
}

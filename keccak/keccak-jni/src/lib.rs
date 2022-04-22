/*
 * Copyright Besu Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

extern crate jni;
extern crate tiny_keccak;

use tiny_keccak::{Hasher, Keccak};

#[no_mangle]
pub extern "C" fn compute(
    i: *const ::std::os::raw::c_char,
    i_len: u32,
    o: *mut ::std::os::raw::c_char
){
    let input_i8: &[i8] = unsafe { std::slice::from_raw_parts(i, i_len as usize) };
    let input: &[u8] = unsafe { std::mem::transmute(input_i8) };

    let raw_out_i8: &mut [i8] = unsafe { std::slice::from_raw_parts_mut(o, 32 as usize) };
    let mut raw_out: &mut [u8] = unsafe { std::mem::transmute(raw_out_i8) };

    let mut keccak = Keccak::v256();
    keccak.update(&input);
    keccak.finalize(&mut raw_out);
}

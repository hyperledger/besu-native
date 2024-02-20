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
pub mod bytes;
pub mod commit;
pub mod context;
pub mod map;
pub mod update;

use crate::commit::Commit;
use crate::context::Context;
use crate::bytes::{try_scalar_vec_from, try_commitment_vec_from, try_commitment_from};
use crate::map::{compress_commitment, batch_map_to_scalars};

use jni::objects::JClass;
use jni::sys::jbyteArray;
use jni::JNIEnv;

// use std::os::raw::c_int;
use once_cell::sync::Lazy;

// TODO: Use a pointer here instead. This is only being used so that the interface does not get changed.
// TODO: and bindings do not need to be modified.
pub static CONFIG: Lazy<Context> = Lazy::new(Context::default);


/// Commit receives a list of 32 byte scalars and returns a 32 byte scalar
/// Scalar is actually the map_to_field(commitment) because we want to reuse the commitment in parent node.
/// This is ported from rust-verkle.
#[no_mangle]
pub extern "system" fn Java_org_hyperledger_besu_nativelib_ipamultipoint_LibIpaMultipoint_commit(
    env: JNIEnv, _class: JClass<'_>, byte_size: u8, values: jbyteArray
) -> jbyteArray {
    let input = match env.convert_byte_array(values) {
        Ok(s) => s,
        Err(_) => {
            env.throw_new(
                "java/lang/IllegalArgumentException",
                "Invalid input: could not convert to bytes.")
               .expect("Failed to throw exception for commit inputs.");
            return std::ptr::null_mut();
        }
    };
    let scalars = match try_scalar_vec_from(byte_size, &input) {
        Ok(s) => s,
        Err(_) => {
            env.throw_new(
                "java/lang/IllegalArgumentException",
                "Invalid input length. Should be a multiple of 32-bytes.")
           .expect("Failed to throw exception");
            return std::ptr::null_mut();
            // env.throw_new("java/lang/IllegalArgumentException", "Invalid input length. Should be at most 256 elements of 32-bytes.")
        }
    };
    let commitment = CONFIG.commit(scalars);
    let result = match env.byte_array_from_slice(&commitment) {
        Ok(s) => s,
        Err(_) => {
            env.throw_new(
                "java/lang/IllegalArgumentException",
                "Invalid commitment output. Couldn't convert to byte array.")
            .expect("Couldn't convert to byte array");
            return std::ptr::null_mut();
        }
    };
    result
}

#[no_mangle]
pub extern "system" fn Java_org_hyperledger_besu_nativelib_ipamultipoint_LibIpaMultipoint_commitCompressed(
    env: JNIEnv, _class: JClass<'_>, byte_size: u8, input: jbyteArray
) -> jbyteArray {
    let input = match env.convert_byte_array(input) {
        Ok(s) => s,
        Err(_) => {
            env.throw_new(
                "java/lang/IllegalArgumentException",
                "Invalid input: could not convert to bytes.")
               .expect("Failed to throw exception for commit inputs.");
            return std::ptr::null_mut();
        }
    };
    let scalars = match try_scalar_vec_from(byte_size, &input) {
        Ok(s) => s,
        Err(_) => {
            env.throw_new(
                "java/lang/IllegalArgumentException",
                "Invalid input length. Should be a multiple of 32-bytes.")
           .expect("Failed to throw exception");
            return std::ptr::null_mut();
            // env.throw_new("java/lang/IllegalArgumentException", "Invalid input length. Should be at most 256 elements of 32-bytes.")
        }
    };
    let commitment = CONFIG.commit(scalars);
    let compressed = compress_commitment(commitment);
    let result = match env.byte_array_from_slice(&compressed) {
        Ok(s) => s,
        Err(_) => {
            env.throw_new(
                "java/lang/IllegalArgumentException",
                "Invalid commitment output. Couldn't convert to byte array.")
            .expect("Couldn't convert to byte array");
            return std::ptr::null_mut();
        }
    };
    result
}

#[no_mangle]
pub extern "system" fn Java_org_hyperledger_besu_nativelib_ipamultipoint_LibIpaMultipoint_compressCommitment(
    env: JNIEnv, _class: JClass<'_>, input: jbyteArray
) -> jbyteArray {
    let input = match env.convert_byte_array(input) {
        Ok(s) => s,
        Err(_) => {
            env.throw_new(
                "java/lang/IllegalArgumentException",
                "Invalid input: could not convert to bytes.")
               .expect("Failed to throw exception for commit inputs.");
            return std::ptr::null_mut();
        }
    };
    let commitment = match try_commitment_from(&input) {
        Ok(s) => s,
        Err(_) => {
            env.throw_new(
                "java/lang/IllegalArgumentException",
                "Invalid commitment input. Should be 64-bytes.")
               .expect("Failed to throw exception for commit inputs.");
            return std::ptr::null_mut();
        }
    };
    let compressed = compress_commitment(commitment);
    let result = match env.byte_array_from_slice(&compressed) {
        Ok(s) => s,
        Err(_) => {
            env.throw_new(
                "java/lang/IllegalArgumentException",
                "Invalid commitment output. Couldn't convert to byte array.")
            .expect("Couldn't convert to byte array");
            return std::ptr::null_mut();
        }
    };
    result
}

#[no_mangle]
pub extern "system" fn Java_org_hyperledger_besu_nativelib_ipamultipoint_LibIpaMultipoint_mapCommitmentToScalar(
    env: JNIEnv, _class: JClass<'_>, input: jbyteArray
) -> jbyteArray {
    let input = match env.convert_byte_array(input) {
        Ok(s) => s,
        Err(_) => {
            env.throw_new(
                "java/lang/IllegalArgumentException",
                "Invalid input: could not convert to bytes.")
               .expect("Failed to throw exception for commit inputs.");
            return std::ptr::null_mut();
        }
    };
    let commitments = match try_commitment_vec_from(&input) {
        Ok(s) => s,
        Err(_) => {
            env.throw_new(
                "java/lang/IllegalArgumentException",
                "Invalid input length. Should be a multiple of 64-bytes.")
           .expect("Failed to throw exception");
            return std::ptr::null_mut();
        }
    };
    let scalars = batch_map_to_scalars(commitments);
    let flattened: Vec<u8> = scalars.into_iter().flatten().collect();
    let result = match env.byte_array_from_slice(&flattened) {
        Ok(s) => s,
        Err(_) => {
            env.throw_new(
                "java/lang/IllegalArgumentException",
                "Invalid scalars output. Couldn't convert to byte array.")
            .expect("Couldn't convert to byte array");
            return std::ptr::null_mut();
        }
    };
    result
}


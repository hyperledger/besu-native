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
pub mod context;
pub mod convert;
pub mod decoding;
pub mod encoding;
pub mod traits;
pub mod types;

use crate::context::Context;
use crate::convert::to_scalars;
use crate::traits::*;
use crate::types::*;

use jni::objects::JClass;
use jni::sys::jbyteArray;
use jni::JNIEnv;

use once_cell::sync::Lazy;
use rlp::{Rlp, decode, decode_list, encode, encode_list};

// TODO: Use a pointer here instead. This is only being used so that the interface does not get changed.
// TODO: and bindings do not need to be modified.
pub static CTX: Lazy<Context> = Lazy::new(Context::default);

/// Commit receives a list of 32 byte scalars and returns a 32 byte scalar
/// Scalar is actually the map_to_field(commitment) because we want to reuse the commitment in parent node.
/// This is ported from rust-verkle.
#[no_mangle]
pub extern "system" fn Java_org_hyperledger_besu_nativelib_ipamultipoint_LibIpaMultipoint_commit(
    env: JNIEnv, _class: JClass<'_>, values: jbyteArray
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
    let decoder = Rlp::new(&input);
    let scalars: Vec<ScalarBytes> = match decoder.as_list() {
        Ok(s) => s,
        Err(_) => {
            env.throw_new(
                "java/lang/IllegalArgumentException",
                "Decode error for commit a vector of ScalarBytes.")
           .expect("Failed to throw exception");
            return std::ptr::null_mut();
        }
    };
    let commitment = CTX.commit(scalars);
    let out = encode(&commitment);
    let result = match env.byte_array_from_slice(&out) {
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
pub extern "system" fn Java_org_hyperledger_besu_nativelib_ipamultipoint_LibIpaMultipoint_commitAsCompressed(
    env: JNIEnv, _class: JClass<'_>, values: jbyteArray
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
    let decoder = Rlp::new(&input);
    let scalars: Vec<ScalarBytes> = match decoder.as_list() {
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
    let commitment = CTX.commit(scalars);
    let compressed = commitment.compress();
    let out = encode(&compressed);
    let result = match env.byte_array_from_slice(&out) {
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
pub extern "system" fn Java_org_hyperledger_besu_nativelib_ipamultipoint_LibIpaMultipoint_updateSparse(
    env: JNIEnv, _class: JClass<'_>, commitment: jbyteArray, values: jbyteArray
) -> jbyteArray {
    let commitment = match env.convert_byte_array(commitment) {
        Ok(s) => s,
        Err(_) => {
            env.throw_new(
                "java/lang/IllegalArgumentException",
                "Invalid input: could not convert to bytes.")
               .expect("Failed to throw exception for commit inputs.");
            return std::ptr::null_mut();
        }
    };
    let values = match env.convert_byte_array(values) {
        Ok(s) => s,
        Err(_) => {
            env.throw_new(
                "java/lang/IllegalArgumentException",
                "Invalid input: could not convert to bytes.")
               .expect("Failed to throw exception for commit inputs.");
            return std::ptr::null_mut();
        }
    };
    let old_commitment: CommitmentBytes = decode(&commitment).expect("Decode Commitment Error");
    let deltas: Vec<ScalarEdit> = decode_list(&values);
    let commitment = CTX.update_sparse(old_commitment, deltas);
    let out = encode(&commitment);
    let result = match env.byte_array_from_slice(&out) {
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
pub extern "system" fn Java_org_hyperledger_besu_nativelib_ipamultipoint_LibIpaMultipoint_toCompressed(
    env: JNIEnv, _class: JClass<'_>, commitment: jbyteArray
) -> jbyteArray {
    let commitment = match env.convert_byte_array(commitment) {
        Ok(s) => s,
        Err(_) => {
            env.throw_new(
                "java/lang/IllegalArgumentException",
                "Invalid input: could not convert to bytes.")
               .expect("Failed to throw exception for commit inputs.");
            return std::ptr::null_mut();
        }
    };
    let commitment: CommitmentBytes = decode(&commitment).expect("Commitment decode error");
    let compressed = commitment.compress();
    let out = encode(&compressed);
    let result = match env.byte_array_from_slice(&out) {
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
pub extern "system" fn Java_org_hyperledger_besu_nativelib_ipamultipoint_LibIpaMultipoint_toCompressedVec(
    env: JNIEnv, _class: JClass<'_>, commitments: jbyteArray
) -> jbyteArray {
    let input = match env.convert_byte_array(commitments) {
        Ok(s) => s,
        Err(_) => {
            env.throw_new(
                "java/lang/IllegalArgumentException",
                "Invalid input: could not convert to bytes.")
               .expect("Failed to throw exception for commit inputs.");
            return std::ptr::null_mut();
        }
    };
    let commitments: Vec<CommitmentBytes> = decode_list(&input);
    let compressed: Vec<CommitmentBytesCompressed> = commitments.iter().map(|x| x.compress()).collect();
    let out = encode_list(&compressed);
    let result = match env.byte_array_from_slice(&out) {
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
pub extern "system" fn Java_org_hyperledger_besu_nativelib_ipamultipoint_LibIpaMultipoint_toScalar(
    env: JNIEnv, _class: JClass<'_>, commitment: jbyteArray
) -> jbyteArray {
    let commitment = match env.convert_byte_array(commitment) {
        Ok(s) => s,
        Err(_) => {
            env.throw_new(
                "java/lang/IllegalArgumentException",
                "Invalid input: could not convert to bytes.")
               .expect("Failed to throw exception for commit inputs.");
            return std::ptr::null_mut();
        }
    };
    let commitment: CommitmentBytes = decode(&commitment).expect("Commitment decode error");
    let scalar = commitment.to_scalar();
    let out = encode(&ScalarBytes::from(&scalar));
    let result = match env.byte_array_from_slice(&out) {
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
pub extern "system" fn Java_org_hyperledger_besu_nativelib_ipamultipoint_LibIpaMultipoint_toScalarVec(
    env: JNIEnv, _class: JClass<'_>, commitments: jbyteArray
) -> jbyteArray {
    let input = match env.convert_byte_array(commitments) {
        Ok(s) => s,
        Err(_) => {
            env.throw_new(
                "java/lang/IllegalArgumentException",
                "Invalid input: could not convert to bytes.")
               .expect("Failed to throw exception for commit inputs.");
            return std::ptr::null_mut();
        }
    };
    let commitments: Vec<CommitmentBytes> = decode_list(&input);
    let scalars = to_scalars(&commitments);
    let out = encode_list(&scalars);
    let result = match env.byte_array_from_slice(&out) {
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
